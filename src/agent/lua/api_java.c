#include <agent/lua_java.h>
#include <agent/lua_engine.h>
#include <agent/globals.h>
#include <agent/hook.h>
#include <agent/agent.h>
#include <agent/bridge_dex.h>
#include <agent/hook_java.h>

#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#define MAX_PARAMS 16
#define MAX_CLASS_NAME 256
#define MAX_REGISTERED_METHODS 16

typedef struct {
    char method_name[64];
    int lua_ref;
} RegisteredMethod;

typedef struct {
    RegisteredMethod methods[MAX_REGISTERED_METHODS];
    int method_count;
    lua_State* L;
} CallbackRegistry;

static jclass    g_bridge_class = NULL;
static jmethodID g_bridge_ctor  = NULL;

typedef struct {
    jclass clazz;
    char class_name[MAX_CLASS_NAME];
} JavaClassWrapper;

typedef struct {
    char param_types[MAX_PARAMS];           // 'I', 'Z', 'L', '[' etc.
    char param_class_names[MAX_PARAMS][MAX_CLASS_NAME];
    int param_count;
    char return_type;
    char return_class_name[MAX_CLASS_NAME];
} ParsedSignature;

static jobject g_class_loader = NULL;
static jmethodID g_load_class_method = NULL;

static bool setup_class_loader(JNIEnv* env) {
    if (g_class_loader != NULL) {
        return true;
    }

    // This used to go through
    // Thread.currentThread().getContextClassLoader() -- which returns
    // NULL on the agent's own injected thread, since it was never set up
    // by the Android runtime with a context ClassLoader the way a normal
    // app thread is (confirmed via logcat: "Failed to get ClassLoader").
    // ActivityThread.currentApplication().getClassLoader() doesn't depend
    // on which thread calls it -- it's the actual Application singleton's
    // own loader, always set once the app has started.
    jclass activity_thread_class = (*env)->FindClass(env, "android/app/ActivityThread");
    if (!activity_thread_class) {
        LOGE("Failed to find ActivityThread class");
        (*env)->ExceptionClear(env);
        return false;
    }

    jmethodID current_application = (*env)->GetStaticMethodID(
            env, activity_thread_class, "currentApplication", "()Landroid/app/Application;");
    if (!current_application) {
        LOGE("Failed to find ActivityThread.currentApplication()");
        (*env)->ExceptionClear(env);
        return false;
    }

    jobject application = (*env)->CallStaticObjectMethod(env, activity_thread_class, current_application);
    if (!application) {
        LOGE("ActivityThread.currentApplication() returned null");
        return false;
    }

    jclass context_class = (*env)->FindClass(env, "android/content/Context");
    jmethodID get_class_loader = context_class ?
        (*env)->GetMethodID(env, context_class, "getClassLoader", "()Ljava/lang/ClassLoader;") : NULL;
    if (!get_class_loader) {
        LOGE("Failed to find Context.getClassLoader()");
        (*env)->ExceptionClear(env);
        return false;
    }

    jobject class_loader = (*env)->CallObjectMethod(env, application, get_class_loader);
    if (!class_loader) {
        LOGE("Application.getClassLoader() returned null");
        return false;
    }

    g_class_loader = (*env)->NewGlobalRef(env, class_loader);

    jclass class_loader_class = (*env)->FindClass(env, "java/lang/ClassLoader");
    g_load_class_method = (*env)->GetMethodID(
            env, class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");

    LOGI("ClassLoader setup complete (via ActivityThread.currentApplication())");
    return true;
}

static jclass find_class(JNIEnv* env, const char* class_name) {
    // Convert dot notation to slash notation for JNI (e.g. "javax.net.ssl.SSLContext" -> "javax/net/ssl/SSLContext")
    char jni_class_name[256];
    strncpy(jni_class_name, class_name, sizeof(jni_class_name) - 1);
    jni_class_name[sizeof(jni_class_name) - 1] = '\0';
    for (size_t i = 0; jni_class_name[i] != '\0'; i++) {
        if (jni_class_name[i] == '.') {
            jni_class_name[i] = '/';
        }
    }

    jclass clazz = (*env)->FindClass(env, jni_class_name);
    if (clazz) {
        (*env)->ExceptionClear(env);
        LOGI("Found class via FindClass: %s", jni_class_name);
        return clazz;
    }
    (*env)->ExceptionClear(env);

    if (!setup_class_loader(env)) {
        LOGE("ClassLoader setup failed");
        return NULL;
    }

    // loadClass needs dot notation - convert back from slash to dot
    char java_class_name[256];
    strncpy(java_class_name, jni_class_name, sizeof(java_class_name) - 1);
    java_class_name[sizeof(java_class_name) - 1] = '\0';

    for (size_t i = 0; java_class_name[i] != '\0'; i++) {
        if (java_class_name[i] == '/') {
            java_class_name[i] = '.';
        }
    }

    jstring class_name_str = (*env)->NewStringUTF(env, java_class_name);
    clazz = (jclass)(*env)->CallObjectMethod(
            env, g_class_loader, g_load_class_method, class_name_str);

    (*env)->DeleteLocalRef(env, class_name_str);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("Failed to load class: %s", class_name);
        return NULL;
    }

    LOGI("Found class via ClassLoader: %s", class_name);
    return clazz;
}

static ParsedSignature parse_signature(const char* sig) {
    ParsedSignature result;
    memset(&result, 0, sizeof(result));

    const char* p = sig;

    if (*p != '(') {
        LOGE("Invalid signature: %s", sig);
        return result;
    }
    p++;

    while (*p && *p != ')' && result.param_count < MAX_PARAMS) {
        if (*p == 'L') {
            result.param_types[result.param_count] = 'L';
            p++;

            size_t class_idx = 0;
            while (*p && *p != ';' && class_idx < MAX_CLASS_NAME - 1) {
                result.param_class_names[result.param_count][class_idx++] = *p++;
            }
            result.param_class_names[result.param_count][class_idx] = '\0';

            if (*p == ';') p++;
            result.param_count++;
        } else if (*p == '[') {
            result.param_types[result.param_count] = '[';
            result.param_class_names[result.param_count][0] = '\0';
            result.param_count++;
            p++;
            if (*p == 'L') {
                while (*p && *p != ';') p++;
                if (*p == ';') p++;
            } else if (*p) {
                p++;
            }
        } else {
            // Primitive type: I, Z, B, C, S, J, F, D, V
            result.param_types[result.param_count] = *p;
            result.param_class_names[result.param_count][0] = '\0';
            result.param_count++;
            p++;
        }
    }

    if (*p == ')') p++;

    // Return type
    if (*p == 'L') {
        result.return_type = 'L';
        p++;
        size_t class_idx = 0;
        while (*p && *p != ';' && class_idx < MAX_CLASS_NAME - 1) {
            result.return_class_name[class_idx++] = *p++;
        }
        result.return_class_name[class_idx] = '\0';
    } else if (*p == '[') {
        result.return_type = '[';
        result.return_class_name[0] = '\0';
    } else if (*p) {
        result.return_type = *p;
        result.return_class_name[0] = '\0';
    }

    LOGI("Parsed signature: %d params, return type: %c", result.param_count, result.return_type);

    return result;
}

//=============================================================================
// Java.use() 
//=============================================================================
static JavaClassWrapper* java_use(JNIEnv* env, const char* class_name) {
    jclass clazz = find_class(env, class_name);
    if (!clazz) {
        return NULL;
    }

    // Take a global reference (it lives as long as the wrapper)
    jclass global_clazz = (jclass)(*env)->NewGlobalRef(env, clazz);
    (*env)->DeleteLocalRef(env, clazz);

    // Create the wrapper
    JavaClassWrapper* wrapper = (JavaClassWrapper*)malloc(sizeof(JavaClassWrapper));
    if (!wrapper) {
        (*env)->DeleteGlobalRef(env, global_clazz);
        return NULL;
    }

    wrapper->clazz = global_clazz;
    strncpy(wrapper->class_name, class_name, MAX_CLASS_NAME - 1);
    wrapper->class_name[MAX_CLASS_NAME - 1] = '\0';

    return wrapper;
}


static jobject JNICALL native_invoke_callback(JNIEnv* env, jclass clazz,
    jlong callbackPtr, jstring methodName, jstring returnType, jobjectArray args)
{
    CallbackRegistry* reg = (CallbackRegistry*)(uintptr_t)callbackPtr;
    if (!reg || !reg->L) return NULL;

    const char* name = (*env)->GetStringUTFChars(env, methodName, NULL);
    if (!name) return NULL;

    int lua_ref = LUA_NOREF;
    for (int i = 0; i < reg->method_count; i++) {
        if (strcmp(reg->methods[i].method_name, name) == 0) {
            lua_ref = reg->methods[i].lua_ref;
            break;
        }
    }

    if (lua_ref == LUA_NOREF) {
        (*env)->ReleaseStringUTFChars(env, methodName, name);
        return NULL;
    }

    lua_State* L = reg->L;
    lua_rawgeti(L, LUA_REGISTRYINDEX, lua_ref);

    int arg_count = 0;
    if (args) {
        arg_count = (*env)->GetArrayLength(env, args);
        for (int i = 0; i < arg_count; i++) {
            jobject arg = (*env)->GetObjectArrayElement(env, args, i);
            if (!arg) {
                lua_pushnil(L);
            } else {
                jclass string_class = (*env)->FindClass(env, "java/lang/String");
                if ((*env)->IsInstanceOf(env, arg, string_class)) {
                    const char* str = (*env)->GetStringUTFChars(env, (jstring)arg, NULL);
                    lua_pushstring(L, str);
                    (*env)->ReleaseStringUTFChars(env, (jstring)arg, str);
                } else {
                    lua_pushinteger(L, (lua_Integer)(uintptr_t)arg);
                }
                (*env)->DeleteLocalRef(env, arg);
            }
        }
    }

    jobject result = NULL;
    if (lua_pcall(L, arg_count, 1, 0) != LUA_OK) {
        LOGE("registerClass callback error [%s]: %s", name, lua_tostring(L, -1));
        lua_pop(L, 1);
    } else {
        const char* ret_type = (*env)->GetStringUTFChars(env, returnType, NULL);

        if (ret_type && strcmp(ret_type, "boolean") == 0) {
            jclass bool_class = (*env)->FindClass(env, "java/lang/Boolean");
            jmethodID value_of = (*env)->GetStaticMethodID(env, bool_class, "valueOf", "(Z)Ljava/lang/Boolean;");
            jboolean val = lua_toboolean(L, -1);
            result = (*env)->CallStaticObjectMethod(env, bool_class, value_of, val);
        } else if (ret_type && strcmp(ret_type, "int") == 0) {
            jclass int_class = (*env)->FindClass(env, "java/lang/Integer");
            jmethodID value_of = (*env)->GetStaticMethodID(env, int_class, "valueOf", "(I)Ljava/lang/Integer;");
            jint val = (jint)lua_tointeger(L, -1);
            result = (*env)->CallStaticObjectMethod(env, int_class, value_of, val);
        } else if (!lua_isnil(L, -1) && lua_isuserdata(L, -1)) {
            jobject* obj_ud = (jobject*)lua_touserdata(L, -1);
            result = *obj_ud;
        }

        if (ret_type) (*env)->ReleaseStringUTFChars(env, returnType, ret_type);
        lua_pop(L, 1);
    }

    (*env)->ReleaseStringUTFChars(env, methodName, name);
    return result;
}

static JNINativeMethod g_native_methods[] = {
    { "nativeInvoke",
      "(JLjava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
      (void*)native_invoke_callback }
};

static int init_bridge_dex(JNIEnv* env) {
    if (g_bridge_class) return 0;

    jobject byte_buf = (*env)->NewDirectByteBuffer(env, (void*)bridge_dex, bridge_dex_len);
    if (!byte_buf) {
        LOGE("Failed to create ByteBuffer for bridge DEX");
        return -1;
    }

    jclass loader_class = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    if (!loader_class) {
        LOGE("Failed to find InMemoryDexClassLoader");
        return -1;
    }

    jmethodID loader_ctor = (*env)->GetMethodID(env, loader_class, "<init>",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject loader = (*env)->NewObject(env, loader_class, loader_ctor, byte_buf, NULL);
    if (!loader) {
        LOGE("Failed to create InMemoryDexClassLoader");
        return -1;
    }

    jmethodID load_class = (*env)->GetMethodID(env, loader_class, "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring class_name = (*env)->NewStringUTF(env, "com.renef.lab.RenefInvocationHandler");
    jclass bridge = (jclass)(*env)->CallObjectMethod(env, loader, load_class, class_name);
    if (!bridge || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("Failed to load RenefInvocationHandler");
        return -1;
    }

    (*env)->RegisterNatives(env, bridge, g_native_methods, 1);

    g_bridge_class = (*env)->NewGlobalRef(env, bridge);
    g_bridge_ctor = (*env)->GetMethodID(env, g_bridge_class, "<init>", "(J)V");

    (*env)->DeleteLocalRef(env, byte_buf);
    (*env)->DeleteLocalRef(env, loader);
    (*env)->DeleteLocalRef(env, bridge);
    (*env)->DeleteLocalRef(env, class_name);

    LOGI("Bridge DEX loaded, native method registered");
    return 0;
}

//=============================================================================
// $new() 
//=============================================================================
static jobject java_new(JNIEnv* env, JavaClassWrapper* wrapper,
                        const char* constructor_sig, jvalue* args) {

    jmethodID constructor = (*env)->GetMethodID(env, wrapper->clazz, "<init>", constructor_sig);
    if (!constructor) {
        LOGE("Constructor not found: %s", constructor_sig);
        (*env)->ExceptionClear(env);
        return NULL;
    }

    jobject instance = (*env)->NewObjectA(env, wrapper->clazz, constructor, args);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("Failed to create instance");
        return NULL;
    }

    LOGI("Created new instance of %s", wrapper->class_name);
    return instance;
}

//=============================================================================
// Static method CALL
//=============================================================================
static jvalue call_static_method(JNIEnv* env, JavaClassWrapper* wrapper,
                                 const char* method_name, const char* signature,
                                 jvalue* args) {
    jvalue result;
    memset(&result, 0, sizeof(result));

    jmethodID method = (*env)->GetStaticMethodID(env, wrapper->clazz, method_name, signature);
    if (!method) {
        LOGE("Static method not found: %s%s", method_name, signature);
        (*env)->ExceptionClear(env);
        return result;
    }

    ParsedSignature parsed = parse_signature(signature);

    switch (parsed.return_type) {
        case 'V':
            (*env)->CallStaticVoidMethodA(env, wrapper->clazz, method, args);
            break;
        case 'Z':
            result.z = (*env)->CallStaticBooleanMethodA(env, wrapper->clazz, method, args);
            break;
        case 'I':
            result.i = (*env)->CallStaticIntMethodA(env, wrapper->clazz, method, args);
            break;
        case 'J':
            result.j = (*env)->CallStaticLongMethodA(env, wrapper->clazz, method, args);
            break;
        case 'F':
            result.f = (*env)->CallStaticFloatMethodA(env, wrapper->clazz, method, args);
            break;
        case 'D':
            result.d = (*env)->CallStaticDoubleMethodA(env, wrapper->clazz, method, args);
            break;
        case 'L':
        case '[':
            result.l = (*env)->CallStaticObjectMethodA(env, wrapper->clazz, method, args);
            break;
        default:
            LOGE("Unknown return type: %c", parsed.return_type);
    }

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    return result;
}

static void lua_to_jvalue(JNIEnv* env, lua_State* L , ParsedSignature* sig, jvalue* args, int start_pos){
    for (int i = 0; i < sig->param_count; i++) {
        int stack_pos = start_pos + i;


        switch(sig->param_types[i]){
        case 'I':
            args[i].i = lua_tointeger(L, stack_pos);
            break;
        case 'Z':
            args[i].z = lua_toboolean(L, stack_pos);
            break;
        case '[':
        case 'L':
            if (lua_isnil(L, stack_pos)) {
                args[i].l = NULL;
            } else if (lua_isinteger(L, stack_pos)) {
                // Raw ART Object* from hook args (e.g. args[2] = x2 register)
                // Must convert to JNI reference before passing to JNI calls
                // NOTE: must check before lua_isstring, which returns true for integers in Lua 5.4
                void* raw_ptr = (void*)(uintptr_t)lua_tointeger(L, stack_pos);
                args[i].l = raw_ptr_to_jni_ref(env, raw_ptr);
            } else if (lua_type(L, stack_pos) == LUA_TSTRING) {
                args[i].l = (*env)->NewStringUTF(env, lua_tostring(L, stack_pos));
            } else if (lua_isuserdata(L, stack_pos)) {
                jobject* obj_ud = (jobject*)lua_touserdata(L, stack_pos);
                args[i].l = *obj_ud;
            } else {
                args[i].l = NULL;
            }
            break;
        case 'F':
            args[i].f = lua_tonumber(L, stack_pos);
            break;
        case 'D':
            args[i].d = lua_tonumber(L, stack_pos);
            break;
        case 'B':
            args[i].b = lua_tointeger(L, stack_pos);
            break;
        case 'S':
            args[i].s = lua_tointeger(L, stack_pos);
            break;
        case 'C':
            args[i].c = lua_tointeger(L, stack_pos);
            break;
        case 'J':
            args[i].j = lua_tointeger(L, stack_pos);
            break;
        }
    }
}

//=============================================================================
// Instance method CALL
//=============================================================================
static jvalue call_instance_method(JNIEnv* env, jobject instance,
                                   const char* method_name, const char* signature,
                                   jvalue* args) {
    jvalue result;
    memset(&result, 0, sizeof(result));

    jclass clazz = (*env)->GetObjectClass(env, instance);
    jmethodID method = (*env)->GetMethodID(env, clazz, method_name, signature);
    if (!method) {
        LOGE("Instance method not found: %s%s", method_name, signature);
        (*env)->ExceptionClear(env);
        return result;
    }

    ParsedSignature parsed = parse_signature(signature);

    switch (parsed.return_type) {
        case 'V':
            (*env)->CallVoidMethodA(env, instance, method, args);
            break;
        case 'Z':
            result.z = (*env)->CallBooleanMethodA(env, instance, method, args);
            break;
        case 'I':
            result.i = (*env)->CallIntMethodA(env, instance, method, args);
            break;
        case 'J':
            result.j = (*env)->CallLongMethodA(env, instance, method, args);
            break;
        case 'F':
            result.f = (*env)->CallFloatMethodA(env, instance, method, args);
            break;
        case 'D':
            result.d = (*env)->CallDoubleMethodA(env, instance, method, args);
            break;
        case 'L':
        case '[':
            result.l = (*env)->CallObjectMethodA(env, instance, method, args);
            break;
        default:
            LOGE("Unknown return type: %c", parsed.return_type);
    }

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    return result;
}

//=============================================================================
// Lua Bindings
//=============================================================================

#define JAVA_WRAPPER_MT "JavaClassWrapper"
#define JAVA_INSTANCE_MT "JavaInstance"

static int lua_java_register_class(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }

    if (init_bridge_dex(env) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to load bridge DEX");
        return 2;
    }

    lua_getfield(L, 1, "implements");
    if (!lua_istable(L, -1)) {
        lua_pushnil(L);
        lua_pushstring(L, "implements must be a table");
        return 2;
    }

    int iface_count = luaL_len(L, -1);
    jclass iface_classes[16];
    for (int i = 0; i < iface_count && i < 16; i++) {
        lua_rawgeti(L, -1, i + 1);
        const char* iface_name = lua_tostring(L, -1);
        iface_classes[i] = find_class(env, iface_name);
        if (!iface_classes[i]) {
            lua_pushnil(L);
            lua_pushfstring(L, "Interface not found: %s", iface_name);
            return 2;
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    CallbackRegistry* reg = (CallbackRegistry*)malloc(sizeof(CallbackRegistry));
    memset(reg, 0, sizeof(CallbackRegistry));
    reg->L = L;

    lua_getfield(L, 1, "methods");
    if (lua_istable(L, -1)) {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            if (lua_isstring(L, -2) && lua_isfunction(L, -1)) {
                const char* mname = lua_tostring(L, -2);
                int ref = luaL_ref(L, LUA_REGISTRYINDEX);
                strncpy(reg->methods[reg->method_count].method_name, mname, 63);
                reg->methods[reg->method_count].lua_ref = ref;
                reg->method_count++;
            } else {
                lua_pop(L, 1);
            }
        }
    }
    lua_pop(L, 1);

    jlong ptr = (jlong)(uintptr_t)reg;
    jobject handler = (*env)->NewObject(env, g_bridge_class, g_bridge_ctor, ptr);
    if (!handler) {
        LOGE("Failed to create RenefInvocationHandler");
        free(reg);
        lua_pushnil(L);
        return 1;
    }

    jclass proxy_class = (*env)->FindClass(env, "java/lang/reflect/Proxy");
    jmethodID new_proxy = (*env)->GetStaticMethodID(env, proxy_class, "newProxyInstance",
        "(Ljava/lang/ClassLoader;[Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;");

    jclass class_class = (*env)->FindClass(env, "java/lang/Class");
    jobjectArray iface_array = (*env)->NewObjectArray(env, iface_count, class_class, NULL);
    for (int i = 0; i < iface_count; i++) {
        (*env)->SetObjectArrayElement(env, iface_array, i, iface_classes[i]);
    }

    jobject class_loader = NULL;
    if (g_class_loader) {
        class_loader = g_class_loader;
    } else {
        setup_class_loader(env);
        class_loader = g_class_loader;
    }

    jobject proxy = (*env)->CallStaticObjectMethod(env, proxy_class, new_proxy,
        class_loader, iface_array, handler);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        free(reg);
        lua_pushnil(L);
        lua_pushstring(L, "Proxy creation failed");
        return 2;
    }

    jobject global_proxy = (*env)->NewGlobalRef(env, proxy);
    (*env)->DeleteLocalRef(env, proxy);
    (*env)->DeleteLocalRef(env, handler);
    (*env)->DeleteLocalRef(env, iface_array);

    jobject* ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
    *ud = global_proxy;
    luaL_getmetatable(L, JAVA_INSTANCE_MT);
    lua_setmetatable(L, -2);

    LOGI("registerClass: proxy created with %d methods, %d interfaces", reg->method_count, iface_count);
    return 1;
}

/* Real-world bug, found in the field (byte[] signing input
 * for an RSA/HMAC-signed API request kept hashing to the same signature
 * regardless of input): this function previously handled ONLY object
 * arrays. For a primitive type name/descriptor ("byte", "[B", "int", ...),
 * `find_class(env, class_name)` either failed outright ("byte" is not a
 * resolvable class) or, for a descriptor like "[B", resolved to the *array*
 * class itself -- which NewObjectArray then (mis)used as the *element*
 * type, silently building a 2D byte[][] instead of a byte[], and the
 * following loop only ever wrote elements when `lua_isuserdata()` was true
 * (true for jobject wrappers, never for plain Lua numbers) -- so every
 * primitive array came out either nil or all-zero. The field workaround was
 * to build the array via `java.lang.reflect.Array.newInstance`/`setByte`
 * by hand in Lua; this fixes it at the source instead.
 *
 * Primitive element types are now handled directly with the matching JNI
 * New<Type>Array/Set<Type>ArrayElement calls. For "byte"/"[B" specifically,
 * `data` may also be a Lua *string* (not just a table of numbers) -- the
 * natural way to hand over a raw byte buffer (e.g. a signing input) without
 * manually building a 256-entry number table first.
 */
typedef enum {
    JARR_OBJECT, JARR_BYTE, JARR_INT, JARR_LONG, JARR_SHORT,
    JARR_BOOLEAN, JARR_CHAR, JARR_FLOAT, JARR_DOUBLE
} JavaArrayKind;

static JavaArrayKind classify_array_kind(const char* name) {
    if (strcmp(name, "byte") == 0 || strcmp(name, "[B") == 0) return JARR_BYTE;
    if (strcmp(name, "int") == 0 || strcmp(name, "[I") == 0) return JARR_INT;
    if (strcmp(name, "long") == 0 || strcmp(name, "[J") == 0) return JARR_LONG;
    if (strcmp(name, "short") == 0 || strcmp(name, "[S") == 0) return JARR_SHORT;
    if (strcmp(name, "boolean") == 0 || strcmp(name, "[Z") == 0) return JARR_BOOLEAN;
    if (strcmp(name, "char") == 0 || strcmp(name, "[C") == 0) return JARR_CHAR;
    if (strcmp(name, "float") == 0 || strcmp(name, "[F") == 0) return JARR_FLOAT;
    if (strcmp(name, "double") == 0 || strcmp(name, "[D") == 0) return JARR_DOUBLE;
    return JARR_OBJECT;
}

static int lua_java_array(lua_State* L) {
    const char* class_name = luaL_checkstring(L, 1);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }

    JavaArrayKind kind = classify_array_kind(class_name);

    if (kind == JARR_BYTE && lua_type(L, 2) == LUA_TSTRING) {
        size_t len;
        const char* s = lua_tolstring(L, 2, &len);
        jbyteArray arr = (*env)->NewByteArray(env, (jsize)len);
        if (!arr) {
            lua_pushnil(L);
            lua_pushstring(L, "Failed to create byte array");
            return 2;
        }
        /* (unsigned char) -> jbyte is the correct two's-complement
         * reinterpretation (0..255 -> -128..127); no manual offset needed. */
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)len, (const jbyte*)s);
        jobject global = (*env)->NewGlobalRef(env, arr);
        (*env)->DeleteLocalRef(env, arr);
        jobject* result = (jobject*)lua_newuserdata(L, sizeof(jobject));
        *result = global;
        luaL_getmetatable(L, JAVA_INSTANCE_MT);
        lua_setmetatable(L, -2);
        return 1;
    }

    luaL_checktype(L, 2, LUA_TTABLE);
    int len = luaL_len(L, 2);

    if (kind != JARR_OBJECT) {
        jarray arr = NULL;
        switch (kind) {
            case JARR_BYTE:    arr = (*env)->NewByteArray(env, len); break;
            case JARR_INT:     arr = (*env)->NewIntArray(env, len); break;
            case JARR_LONG:    arr = (*env)->NewLongArray(env, len); break;
            case JARR_SHORT:   arr = (*env)->NewShortArray(env, len); break;
            case JARR_BOOLEAN: arr = (*env)->NewBooleanArray(env, len); break;
            case JARR_CHAR:    arr = (*env)->NewCharArray(env, len); break;
            case JARR_FLOAT:   arr = (*env)->NewFloatArray(env, len); break;
            case JARR_DOUBLE:  arr = (*env)->NewDoubleArray(env, len); break;
            default: break; /* unreachable */
        }
        if (!arr) {
            lua_pushnil(L);
            lua_pushfstring(L, "Failed to create %s array", class_name);
            return 2;
        }

        for (int i = 0; i < len; i++) {
            lua_rawgeti(L, 2, i + 1);
            switch (kind) {
                case JARR_BYTE: {
                    jbyte v = (jbyte)(int64_t)luaL_checkinteger(L, -1);
                    (*env)->SetByteArrayRegion(env, (jbyteArray)arr, i, 1, &v);
                    break;
                }
                case JARR_INT: {
                    jint v = (jint)luaL_checkinteger(L, -1);
                    (*env)->SetIntArrayRegion(env, (jintArray)arr, i, 1, &v);
                    break;
                }
                case JARR_LONG: {
                    jlong v = (jlong)luaL_checkinteger(L, -1);
                    (*env)->SetLongArrayRegion(env, (jlongArray)arr, i, 1, &v);
                    break;
                }
                case JARR_SHORT: {
                    jshort v = (jshort)luaL_checkinteger(L, -1);
                    (*env)->SetShortArrayRegion(env, (jshortArray)arr, i, 1, &v);
                    break;
                }
                case JARR_BOOLEAN: {
                    jboolean v = lua_toboolean(L, -1) ? JNI_TRUE : JNI_FALSE;
                    (*env)->SetBooleanArrayRegion(env, (jbooleanArray)arr, i, 1, &v);
                    break;
                }
                case JARR_CHAR: {
                    jchar v = (jchar)luaL_checkinteger(L, -1);
                    (*env)->SetCharArrayRegion(env, (jcharArray)arr, i, 1, &v);
                    break;
                }
                case JARR_FLOAT: {
                    jfloat v = (jfloat)luaL_checknumber(L, -1);
                    (*env)->SetFloatArrayRegion(env, (jfloatArray)arr, i, 1, &v);
                    break;
                }
                case JARR_DOUBLE: {
                    jdouble v = (jdouble)luaL_checknumber(L, -1);
                    (*env)->SetDoubleArrayRegion(env, (jdoubleArray)arr, i, 1, &v);
                    break;
                }
                default: break; /* unreachable */
            }
            lua_pop(L, 1);
        }

        jobject global = (*env)->NewGlobalRef(env, arr);
        (*env)->DeleteLocalRef(env, arr);
        jobject* result = (jobject*)lua_newuserdata(L, sizeof(jobject));
        *result = global;
        luaL_getmetatable(L, JAVA_INSTANCE_MT);
        lua_setmetatable(L, -2);
        return 1;
    }

    jclass element_class = find_class(env, class_name);
    if (!element_class) {
        lua_pushnil(L);
        lua_pushfstring(L, "Class not found: %s", class_name);
        return 2;
    }

    jobjectArray arr = (*env)->NewObjectArray(env, len, element_class, NULL);
    if (!arr) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to create array");
        return 2;
    }

    for (int i = 0; i < len; i++) {
        lua_rawgeti(L, 2, i + 1);
        if (lua_isuserdata(L, -1)) {
            jobject* ud = (jobject*)lua_touserdata(L, -1);
            (*env)->SetObjectArrayElement(env, arr, i, *ud);
        }
        lua_pop(L, 1);
    }

    jobject global = (*env)->NewGlobalRef(env, arr);
    (*env)->DeleteLocalRef(env, arr);

    jobject* result = (jobject*)lua_newuserdata(L, sizeof(jobject));
    *result = global;
    luaL_getmetatable(L, JAVA_INSTANCE_MT);
    lua_setmetatable(L, -2);
    return 1;
}

// Java.use("com.example.Class") -> JavaClassWrapper userdata
//=============================================================================
// Java.enumerateLoadedClasses()
//=============================================================================
//
// Enumerates class NAMES loaded via the app's own context ClassLoader, by
// walking BaseDexClassLoader -> DexPathList.dexElements[] -> Element.dexFile
// -> DexFile.entries(). All field access below is via GetFieldID/
// GetObjectField -- deliberately NOT java.lang.reflect.Field -- because
// Android's hiddenapi policy only gates java.lang.reflect call sites;
// plain JNI field access from native code is exempt, the same reason real
// Frida uses this exact approach on Android instead of reflection. pathList/
// dexElements/dexFile are private fields, which is fine for JNI the same
// way it's fine everywhere else in this codebase (e.g. find_class()'s own
// use of the context ClassLoader above).
//
// Deliberately NOT implemented in this pass: Java.choose() (enumerating
// LIVE INSTANCES of a class). That needs ART garbage-collector heap
// walking, not classloader/dex introspection -- a fundamentally different
// and much higher-risk piece of work. Research done on a real device
// (Android 15/API 35): libart.so DOES export
// art::ClassLinker::VisitClasses (useful for a class-object visitor, which
// this function doesn't even need, since Java.use() already resolves any
// class NAME this returns into a usable wrapper) but does NOT export any
// stable, directly-callable "visit every live object/instance of a class"
// symbol in its dynamic symbol table -- only internal, ABI-fragile pieces
// that vary across Android versions/OEM builds and would risk corrupting
// or crashing the target if driven incorrectly from outside. The honest,
// lower-risk alternative for a future pass: trigger
// android.os.Debug.dumpHprofData() (a stable public API) and parse the
// resulting heap dump host-side -- a static snapshot, not live references
// usable for further calls like Frida's Java.choose(), but safe.
static int lua_java_enumerate_loaded_classes(lua_State* L) {
    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }

    if (!setup_class_loader(env)) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to resolve context ClassLoader");
        return 2;
    }

    jclass dex_loader_class = (*env)->FindClass(env, "dalvik/system/BaseDexClassLoader");
    if (!dex_loader_class || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        lua_pushnil(L);
        lua_pushstring(L, "BaseDexClassLoader class not found");
        return 2;
    }

    if (!(*env)->IsInstanceOf(env, g_class_loader, dex_loader_class)) {
        lua_pushnil(L);
        lua_pushstring(L, "Context ClassLoader is not a BaseDexClassLoader");
        return 2;
    }

    jfieldID pathlist_field = (*env)->GetFieldID(env, dex_loader_class, "pathList", "Ldalvik/system/DexPathList;");
    jclass pathlist_class = (*env)->FindClass(env, "dalvik/system/DexPathList");
    if (!pathlist_field || !pathlist_class || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        lua_pushnil(L);
        lua_pushstring(L, "DexPathList introspection failed");
        return 2;
    }

    jobject path_list = (*env)->GetObjectField(env, g_class_loader, pathlist_field);
    jfieldID elements_field = (*env)->GetFieldID(env, pathlist_class, "dexElements", "[Ldalvik/system/DexPathList$Element;");
    if (!path_list || !elements_field || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        lua_pushnil(L);
        lua_pushstring(L, "dexElements field not found");
        return 2;
    }

    jobjectArray elements = (jobjectArray)(*env)->GetObjectField(env, path_list, elements_field);
    if (!elements) {
        lua_pushnil(L);
        lua_pushstring(L, "dexElements is null");
        return 2;
    }

    jclass element_class = (*env)->FindClass(env, "dalvik/system/DexPathList$Element");
    jfieldID dexfile_field = element_class ? (*env)->GetFieldID(env, element_class, "dexFile", "Ldalvik/system/DexFile;") : NULL;
    jclass dexfile_class = (*env)->FindClass(env, "dalvik/system/DexFile");
    jmethodID entries_method = dexfile_class ? (*env)->GetMethodID(env, dexfile_class, "entries", "()Ljava/util/Enumeration;") : NULL;
    if (!element_class || !dexfile_field || !dexfile_class || !entries_method || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, elements);
        lua_pushnil(L);
        lua_pushstring(L, "DexFile.entries() introspection failed");
        return 2;
    }

    jclass enum_class = (*env)->FindClass(env, "java/util/Enumeration");
    jmethodID has_more = (*env)->GetMethodID(env, enum_class, "hasMoreElements", "()Z");
    jmethodID next_elem = (*env)->GetMethodID(env, enum_class, "nextElement", "()Ljava/lang/Object;");

    lua_newtable(L); // result array
    int result_idx = 1;

    jsize n_elements = (*env)->GetArrayLength(env, elements);
    for (jsize i = 0; i < n_elements; i++) {
        jobject element = (*env)->GetObjectArrayElement(env, elements, i);
        if (!element) continue;

        jobject dex_file = (*env)->GetObjectField(env, element, dexfile_field);
        if (!dex_file) {
            (*env)->DeleteLocalRef(env, element);
            continue;
        }

        jobject enumeration = (*env)->CallObjectMethod(env, dex_file, entries_method);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, dex_file);
            (*env)->DeleteLocalRef(env, element);
            continue;
        }

        while (enumeration && (*env)->CallBooleanMethod(env, enumeration, has_more)) {
            jstring class_name = (jstring)(*env)->CallObjectMethod(env, enumeration, next_elem);
            if (class_name) {
                const char* name = (*env)->GetStringUTFChars(env, class_name, NULL);
                if (name) {
                    lua_pushstring(L, name);
                    lua_rawseti(L, -2, result_idx++);
                    (*env)->ReleaseStringUTFChars(env, class_name, name);
                }
                (*env)->DeleteLocalRef(env, class_name);
            }
        }

        if (enumeration) (*env)->DeleteLocalRef(env, enumeration);
        (*env)->DeleteLocalRef(env, dex_file);
        (*env)->DeleteLocalRef(env, element);
    }

    (*env)->DeleteLocalRef(env, elements);

    return 1;
}

static int lua_java_use(lua_State* L) {
    const char* class_name = luaL_checkstring(L, 1);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }

    JavaClassWrapper* wrapper = java_use(env, class_name);
    if (!wrapper) {
        lua_pushnil(L);
        lua_pushstring(L, "Class not found");
        return 2;
    }

    JavaClassWrapper** ud = (JavaClassWrapper**)lua_newuserdata(L, sizeof(JavaClassWrapper*));
    *ud = wrapper;

    // Metatable ekle
    luaL_getmetatable(L, JAVA_WRAPPER_MT);
    lua_setmetatable(L, -2);

    return 1;
}

static int lua_java_new(lua_State* L) {
    JavaClassWrapper** ud = (JavaClassWrapper**)luaL_checkudata(L, 1, JAVA_WRAPPER_MT);
    JavaClassWrapper* wrapper = *ud;
    const char* sig = luaL_optstring(L, 2, "()V");

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to get JNIEnv");
        return 2;
    }
    

    jvalue args[MAX_PARAMS];
    memset(args, 0, sizeof(args));

    ParsedSignature parsed = parse_signature(sig);
    lua_to_jvalue(env, L, &parsed, args, 3);
    
    // Explicit script->target call, native hooks must be
    // able to fire inside it (see hook_outcall_begin in native.c).
    int outcall_prev = hook_outcall_begin();
    jobject instance = java_new(env, wrapper, sig, args);
    hook_outcall_end(outcall_prev);
    if (!instance) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to create instance");
        return 2;
    }

    jobject global_instance = (*env)->NewGlobalRef(env, instance);
    (*env)->DeleteLocalRef(env, instance);

    jobject* inst_ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
    *inst_ud = global_instance;

    luaL_getmetatable(L, JAVA_INSTANCE_MT);
    lua_setmetatable(L, -2);

    return 1;
}

static int lua_java_call_static(lua_State* L) {
    JavaClassWrapper** ud = (JavaClassWrapper**)luaL_checkudata(L, 1, JAVA_WRAPPER_MT);
    JavaClassWrapper* wrapper = *ud;
    const char* method_name = luaL_checkstring(L, 2);
    const char* sig = luaL_checkstring(L, 3);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        return 1;
    }

    jvalue args[MAX_PARAMS];
    memset(args, 0, sizeof(args));
    
    ParsedSignature parsed = parse_signature(sig);
    lua_to_jvalue(env,L,&parsed,args,4);
    

    int outcall_prev = hook_outcall_begin(); // see lua_java_new
    jvalue result = call_static_method(env, wrapper, method_name, sig, args);
    hook_outcall_end(outcall_prev);



    switch (parsed.return_type) {
        case 'V':
            return 0;
        case 'Z':
            lua_pushboolean(L, result.z);
            return 1;
        case 'I':
            lua_pushinteger(L, result.i);
            return 1;
        case 'J':
            lua_pushinteger(L, (lua_Integer)result.j);
            return 1;
        case 'F':
            lua_pushnumber(L, result.f);
            return 1;
        case 'D':
            lua_pushnumber(L, result.d);
            return 1;
        case 'L':
        case '[':
            if (result.l) {
                jclass string_class = (*env)->FindClass(env, "java/lang/String");
                if ((*env)->IsInstanceOf(env, result.l, string_class)) {
                    const char* str = (*env)->GetStringUTFChars(env, (jstring)result.l, NULL);
                    lua_pushstring(L, str);
                    (*env)->ReleaseStringUTFChars(env, (jstring)result.l, str);
                } else {
                    jobject global = (*env)->NewGlobalRef(env, result.l);
                    jobject* obj_ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
                    *obj_ud = global;
                    luaL_getmetatable(L, JAVA_INSTANCE_MT);
                    lua_setmetatable(L, -2);
                }
                (*env)->DeleteLocalRef(env, result.l);
            } else {
                lua_pushnil(L);
            }
            return 1;
        default:
            lua_pushnil(L);
            return 1;
    }
}

static int lua_java_call_instance(lua_State* L) {
    jobject* ud = (jobject*)luaL_checkudata(L, 1, JAVA_INSTANCE_MT);
    jobject instance = *ud;
    const char* method_name = luaL_checkstring(L, 2);
    const char* sig = luaL_checkstring(L, 3);

    JNIEnv* env = get_jni_env();
    if (!env) {
        lua_pushnil(L);
        return 1;
    }

    jvalue args[MAX_PARAMS];
    memset(args, 0, sizeof(args));

    ParsedSignature parsed = parse_signature(sig);
    lua_to_jvalue(env,L,&parsed,args,4);
    
    int outcall_prev = hook_outcall_begin(); // see lua_java_new
    jvalue result = call_instance_method(env, instance, method_name, sig, args);
    hook_outcall_end(outcall_prev);

    switch (parsed.return_type) {
        case 'V':
            return 0;
        case 'Z':
            lua_pushboolean(L, result.z);
            return 1;
        case 'I':
            lua_pushinteger(L, result.i);
            return 1;
        case 'J':
            lua_pushinteger(L, (lua_Integer)result.j);
            return 1;
        case 'F':
            lua_pushnumber(L, result.f);
            return 1;
        case 'D':
            lua_pushnumber(L, result.d);
            return 1;
        case 'L':
        case '[':
            if (result.l) {
                jclass string_class = (*env)->FindClass(env, "java/lang/String");
                if ((*env)->IsInstanceOf(env, result.l, string_class)) {
                    const char* str = (*env)->GetStringUTFChars(env, (jstring)result.l, NULL);
                    lua_pushstring(L, str);
                    (*env)->ReleaseStringUTFChars(env, (jstring)result.l, str);
                } else {
                    jobject global = (*env)->NewGlobalRef(env, result.l);
                    jobject* obj_ud = (jobject*)lua_newuserdata(L, sizeof(jobject));
                    *obj_ud = global;
                    luaL_getmetatable(L, JAVA_INSTANCE_MT);
                    lua_setmetatable(L, -2);
                }
                (*env)->DeleteLocalRef(env, result.l);
            } else {
                lua_pushnil(L);
            }
            return 1;
        default:
            lua_pushnil(L);
            return 1;
    }
}

static int lua_java_wrapper_gc(lua_State* L) {
    JavaClassWrapper** ud = (JavaClassWrapper**)luaL_checkudata(L, 1, JAVA_WRAPPER_MT);
    JavaClassWrapper* wrapper = *ud;

    if (wrapper) {
        JNIEnv* env = get_jni_env();
        if (env && wrapper->clazz) {
            (*env)->DeleteGlobalRef(env, wrapper->clazz);
        }
        free(wrapper);
    }

    return 0;
}

static int lua_java_instance_gc(lua_State* L) {
    jobject* ud = (jobject*)luaL_checkudata(L, 1, JAVA_INSTANCE_MT);
    jobject instance = *ud;

    if (instance) {
        JNIEnv* env = get_jni_env();
        if (env) {
            (*env)->DeleteGlobalRef(env, instance);
        }
    }

    return 0;
}

static const luaL_Reg java_wrapper_methods[] = {
    {"new", lua_java_new},
    {"call", lua_java_call_static},
    {"__gc", lua_java_wrapper_gc},
    {NULL, NULL}
};

static int lua_java_instance_index(lua_State* L) {
    const char* key = luaL_checkstring(L, 2);
    if (strcmp(key, "raw") == 0) {
        jobject* ud = (jobject*)lua_touserdata(L, 1);
        if (*ud) {
            JNIEnv* env = get_jni_env();
            if (env) {
                void* raw = jni_ref_to_raw_ptr(env, *ud);
                lua_pushinteger(L, (lua_Integer)(uintptr_t)raw);
            } else {
                lua_pushinteger(L, (lua_Integer)(uintptr_t)*ud);
            }
        } else {
            lua_pushinteger(L, 0);
        }
        return 1;
    }
    if (strcmp(key, "call") == 0) {
        lua_pushcfunction(L, lua_java_call_instance);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

static const luaL_Reg java_instance_methods[] = {
    {"__gc", lua_java_instance_gc},
    {NULL, NULL}
};

void lua_register_java(lua_State* L) {
    luaL_newmetatable(L, JAVA_WRAPPER_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, java_wrapper_methods, 0);
    lua_pop(L, 1);

    luaL_newmetatable(L, JAVA_INSTANCE_MT);
    lua_pushcfunction(L, lua_java_instance_index);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, java_instance_methods, 0);
    lua_pop(L, 1);

    lua_newtable(L);

    lua_pushcfunction(L, lua_java_use);
    lua_setfield(L, -2, "use");

    lua_pushcfunction(L, lua_java_register_class);
    lua_setfield(L, -2, "registerClass");

    lua_pushcfunction(L, lua_java_array);
    lua_setfield(L, -2, "array");

    lua_pushcfunction(L, lua_java_enumerate_loaded_classes);
    lua_setfield(L, -2, "enumerateLoadedClasses");

    lua_setglobal(L, "Java");

    LOGI("Java API registered");
}
