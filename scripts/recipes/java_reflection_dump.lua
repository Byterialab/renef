-- Generic Java Reflection / Recon Helpers (Recipe / Template)
--
-- What this does: exposes a small set of global helper functions, built
-- entirely on top of Renef's real Java.use()/:call() API plus the standard
-- JDK reflection classes (java.lang.Class, java.lang.reflect.Field/Method/
-- Array/Modifier), to recon an app's classes at runtime without needing a
-- decompiled APK open at all times:
--
--   dump_class_schema(class_name)
--       Structural dump: declared fields (modifiers, type, name) and
--       declared methods (modifiers, return type, name, parameter types)
--       of any loaded class, by name.
--
--   dump_instance_fields(instance [, class_name])
--       Dumps the LIVE field VALUES of a java.lang.Object you already have
--       a handle to (e.g. captured from a hook's args[1], or returned by
--       Java.use(...):new(...)). Uses Field.setAccessible(true) so private
--       fields are included.
--
--   java_tostring(raw_or_instance)
--       Generic "toString() of anything" helper - works on a JavaInstance
--       userdata OR a raw ART object pointer (e.g. straight out of a hook's
--       args[N]), via java.lang.String.valueOf(Object). This is the trick
--       that makes the rest of this file possible: Renef's Java bridge has
--       no dedicated "cast raw pointer -> JavaInstance" call, but passing a
--       raw integer into any Object-typed ('L'/'[') argument slot IS
--       converted to a real jobject internally (see src/agent/lua/
--       api_java.c: lua_to_jvalue(), the LUA_TNUMBER branch calls
--       raw_ptr_to_jni_ref()) - the same mechanism Renef's own hook engine
--       uses for args[1]="this". So String.valueOf(Object) doubles as a
--       universal "describe this raw pointer" primitive.
--
--   hook on java/lang/reflect/Method.invoke(...)
--       Logs every reflective method call happening in the process: the
--       invoked method's full signature (via Method.toString()), the
--       target object's class (if non-static), and the argument count.
--       Useful recon for apps that hide behavior behind reflection to dodge
--       static analysis or simple hooks on the "real" method name.
--
-- Depends on (real Renef Lua API - see renef-doc/docs/api/java.md,
-- hook.md):
--   Java.use(class_name):call(method, sig, ...)   -- static calls
--   instance:call(method, sig, ...)                 -- instance calls
--   instance.raw                                     -- raw ART pointer
--   hook(class, method, signature, callbacks)        -- Java.lang.reflect.
--     Method.invoke hook below
--
-- THIS IS A TEMPLATE / GENERIC TOOLKIT, not app-specific recon. It only
-- knows how to walk whatever class names you give it - finding the
-- INTERESTING class names in a specific target app is still on you (jadx/
-- apktool, or just watching the Method.invoke hook fire during normal use).
--
-- Usage:
--   renef> l scripts/recipes/java_reflection_dump.lua
--   renef> exec dump_class_schema("android.os.Build")
--   renef> exec dump_class_schema("java.lang.String")
--   renef> watch        -- see Method.invoke recon log as the app runs
--   renef> exec reflection_stats()
--
-- Note on enable_method_invoke_hook: it is off by default. The hook fires
-- on every reflective call in the process (the framework uses reflection
-- all the time), so it is noisy, and with the Java hook engine used before
-- 0.4.0 (still used on Android 11 and older) that traffic alone crashed
-- the target within 10-20 s. dump_class_schema() and hook_all_overloads()
-- are not affected. Turn it on when you need the recon log, and try it on
-- your target before relying on it.

__hook_type__ = "trampoline"

local CONFIG = {
    -- Hook java.lang.reflect.Method.invoke() process-wide to log reflective
    -- calls. Fires on every reflective call in the process (framework code
    -- uses reflection too), so expect noisy output on a busy app.
    -- Defaults to false: see the note above.
    enable_method_invoke_hook = false,

    -- Cap how many fields/methods/array elements we print per dump, so a
    -- huge class (or a huge args[] array) can't flood the console.
    max_items = 200,
}

local stats = {
    invoke_calls = 0,
}

-- =====================================================================
-- CORE HELPERS
-- =====================================================================

local String_ = Java.use("java/lang/String")
local Class_ = Java.use("java/lang/Class")
local ReflectArray_ = Java.use("java/lang/reflect/Array")
local Modifier_ = Java.use("java/lang/reflect/Modifier")

-- Generic "describe anything" helper - see header comment for how this
-- works on a raw ART pointer with no cast API involved.
function java_tostring(obj)
    if obj == nil or obj == 0 then
        return "null"
    end
    if type(obj) == "string" then
        return obj
    end
    if not String_ then
        return tostring(obj)
    end
    local ok, s = pcall(function()
        return String_:call("valueOf", "(Ljava/lang/Object;)Ljava/lang/String;", obj)
    end)
    if ok and s then
        return s
    end
    return tostring(obj)
end

-- Resolve a java.lang.Class object for `name` (accepts "a.b.C" or "a/b/C").
-- Tries plain Class.forName first (bootstrap/system classloader - works for
-- java.*/android.* framework classes), then falls back to the current
-- Application's own ClassLoader for app-defined classes, mirroring the
-- fallback Java.use() itself documents in api/java.md.
local function resolve_class(name)
    if not Class_ then return nil end
    local dotted = string.gsub(name, "/", ".")

    local ok, cls = pcall(function()
        return Class_:call("forName", "(Ljava/lang/String;)Ljava/lang/Class;", dotted)
    end)
    if ok and cls then
        return cls
    end

    local ok2, cls2 = pcall(function()
        local ActivityThread = Java.use("android/app/ActivityThread")
        local app = ActivityThread and ActivityThread:call("currentApplication", "()Landroid/app/Application;")
        if not app then return nil end
        local loader = app:call("getClassLoader", "()Ljava/lang/ClassLoader;")
        if not loader then return nil end
        return Class_:call("forName",
            "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;",
            dotted, true, loader)
    end)
    if ok2 and cls2 then
        return cls2
    end

    return nil
end

-- Iterate a java object[] (returned by reflection calls like
-- getDeclaredFields()) using java.lang.reflect.Array, since array objects
-- have no callable instance methods of their own.
local function for_each_array_element(array_obj, fn)
    if not array_obj or not ReflectArray_ then return 0 end
    local ok, len = pcall(function()
        return ReflectArray_:call("getLength", "(Ljava/lang/Object;)I", array_obj)
    end)
    if not ok or not len then return 0 end
    local n = math.min(len, CONFIG.max_items)
    for i = 0, n - 1 do
        local ok2, elem = pcall(function()
            return ReflectArray_:call("get", "(Ljava/lang/Object;I)Ljava/lang/Object;", array_obj, i)
        end)
        if ok2 then
            fn(elem, i)
        end
    end
    return len
end

-- =====================================================================
-- dump_class_schema(class_name) - structural dump (no instance needed)
-- =====================================================================
function dump_class_schema(class_name)
    local cls = resolve_class(class_name)
    if not cls then
        print("[!] Could not resolve class: " .. tostring(class_name))
        return
    end

    print(string.format("=== %s ===", class_name))

    local fields = cls:call("getDeclaredFields", "()[Ljava/lang/reflect/Field;")
    print("-- fields --")
    local field_count = for_each_array_element(fields, function(field)
        local name = field:call("getName", "()Ljava/lang/String;")
        local mods = field:call("getModifiers", "()I")
        local mod_str = Modifier_ and Modifier_:call("toString", "(I)Ljava/lang/String;", mods) or tostring(mods)
        local ftype = field:call("getType", "()Ljava/lang/Class;")
        local type_name = ftype and ftype:call("getName", "()Ljava/lang/String;") or "?"
        print(string.format("  %s %s %s", mod_str, type_name, name))
    end)

    local methods = cls:call("getDeclaredMethods", "()[Ljava/lang/reflect/Method;")
    print("-- methods --")
    local method_count = for_each_array_element(methods, function(method)
        -- Method:toString() already gives a fully formatted signature, e.g.
        -- "public final java.lang.String android.os.Build.toString()" -
        -- no need to re-assemble it field by field.
        print("  " .. java_tostring(method))
    end)

    print(string.format("(%d field(s), %d method(s)%s)",
        field_count, method_count,
        (field_count > CONFIG.max_items or method_count > CONFIG.max_items)
            and ", truncated at CONFIG.max_items" or ""))
end

-- =====================================================================
-- dump_instance_fields(instance [, class_name]) - live field VALUES
-- =====================================================================
function dump_instance_fields(instance, class_name)
    if not instance then
        print("[!] dump_instance_fields: nil instance")
        return
    end

    local cls
    if class_name then
        cls = resolve_class(class_name)
    end
    if not cls then
        local ok, c = pcall(function()
            return instance:call("getClass", "()Ljava/lang/Class;")
        end)
        if ok then cls = c end
    end
    if not cls then
        print("[!] dump_instance_fields: could not resolve the instance's class")
        return
    end

    local cls_name = cls:call("getName", "()Ljava/lang/String;")
    print(string.format("=== instance of %s ===", cls_name or "?"))

    local fields = cls:call("getDeclaredFields", "()[Ljava/lang/reflect/Field;")
    for_each_array_element(fields, function(field)
        local name = field:call("getName", "()Ljava/lang/String;")
        local ok = pcall(function()
            field:call("setAccessible", "(Z)V", true)
        end)
        local ok2, value = pcall(function()
            return field:call("get", "(Ljava/lang/Object;)Ljava/lang/Object;", instance)
        end)
        if ok2 then
            print(string.format("  %s = %s", name, java_tostring(value)))
        else
            print(string.format("  %s = <inaccessible>", name))
        end
    end)
end

-- =====================================================================
-- hook_all_overloads(class_name, method_name, callbacks)
--
-- Discovers every overload of a native method by name (via
-- Class.getDeclaredMethods() + Method.getParameterTypes(), the same
-- reflection this file already uses for dump_class_schema()) and installs
-- the SAME hook() callbacks on each one, building each overload's JNI
-- signature itself instead of asking the caller to write out N signatures
-- by hand. The real bottleneck used to be the MAX_JAVA_HOOKS capacity
-- limit -- now that MAX_JAVA_HOOKS is 128, bulk installation like this is
-- viable where it wasn't before.
--
-- Capacity/partial-failure handling: hook()'s own install path already
-- raises a specific, clean Lua error when MAX_JAVA_HOOKS is hit --
-- this function just pcall()s each overload's install and keeps going,
-- so one overload failing (capacity, or any other install error) doesn't
-- abort the rest. Returns (installed_count, failed_count, error_list).
-- =====================================================================
local PRIMITIVE_JNI_TYPE = {
    int = "I", boolean = "Z", byte = "B", char = "C", short = "S",
    long = "J", float = "F", double = "D", ["void"] = "V",
}

-- Class -> JNI type descriptor. Class.getName() already returns names in
-- JNI-ish form except using '.' instead of '/' for package separators
-- (and primitives spelled out, e.g. "int" not "I") -- array types (incl.
-- primitive arrays like "[I") come back already-correct apart from that
-- same '.'-vs-'/' difference in any embedded object type name.
local function class_to_jni_type(cls)
    local name = cls:call("getName", "()Ljava/lang/String;")
    if not name then return "Ljava/lang/Object;" end
    if name:sub(1, 1) == "[" then
        return (name:gsub("%.", "/"))
    end
    if PRIMITIVE_JNI_TYPE[name] then
        return PRIMITIVE_JNI_TYPE[name]
    end
    return "L" .. name:gsub("%.", "/") .. ";"
end

function hook_all_overloads(class_name, method_name, callbacks)
    local cls = resolve_class(class_name)
    if not cls then
        return 0, 0, {"class not resolved: " .. tostring(class_name)}
    end

    local methods = cls:call("getDeclaredMethods", "()[Ljava/lang/reflect/Method;")
    local installed, failed = 0, 0
    local errors = {}

    for_each_array_element(methods, function(method)
        local name = method:call("getName", "()Ljava/lang/String;")
        if name == method_name then
            local param_types = method:call("getParameterTypes", "()[Ljava/lang/Class;")
            local sig = "("
            for_each_array_element(param_types, function(pt)
                sig = sig .. class_to_jni_type(pt)
            end)
            local ret_type = method:call("getReturnType", "()Ljava/lang/Class;")
            sig = sig .. ")" .. class_to_jni_type(ret_type)

            local ok, err = pcall(hook, class_name, method_name, sig, callbacks)
            if ok then
                installed = installed + 1
                print(string.format("[hook_all_overloads] %s.%s%s -> installed", class_name, method_name, sig))
            else
                failed = failed + 1
                table.insert(errors, sig .. ": " .. tostring(err))
                print(string.format("[hook_all_overloads] %s.%s%s -> FAILED: %s",
                    class_name, method_name, sig, tostring(err)))
            end
        end
    end)

    print(string.format("[hook_all_overloads] %s.%s: %d installed, %d failed",
        class_name, method_name, installed, failed))
    return installed, failed, errors
end

-- =====================================================================
-- Recon hook: log every java.lang.reflect.Method.invoke() call
-- =====================================================================
if CONFIG.enable_method_invoke_hook then
    local ok, err = pcall(hook, "java/lang/reflect/Method", "invoke",
        "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", {
        onEnter = function(args)
            stats.invoke_calls = stats.invoke_calls + 1

            -- args[1] = this (the Method object itself) - Method.toString()
            -- gives the full declaring-class + return type + name + params.
            local method_desc = java_tostring(args[1])

            -- args[2] = target object (0/null for static methods). We only
            -- have a raw pointer here, not a JavaInstance, so we can't call
            -- target:call("getClass", ...) directly - fall back to the
            -- object's own toString() via java_tostring(), which for most
            -- classes already includes enough info to identify it (default
            -- Object.toString() is "pkg.ClassName@hash" when not overridden).
            local target_desc = "<static>"
            if args[2] ~= 0 then
                local ok_t, desc = pcall(java_tostring, args[2])
                target_desc = ok_t and desc or "<object>"
            end

            local argc = 0
            if args[3] ~= 0 then
                local ok_a, len = pcall(function()
                    return ReflectArray_:call("getLength", "(Ljava/lang/Object;)I", args[3])
                end)
                if ok_a then argc = len end
            end

            print(string.format("[reflect] %s on %s (argc=%d)", method_desc, target_desc, argc))
        end
    })
    if ok then
        print("[OK] java.lang.reflect.Method.invoke() recon hook installed")
    else
        print("[skip] Method.invoke hook failed: " .. tostring(err))
    end
end

-- =====================================================================
-- CONTROL FUNCTIONS
-- =====================================================================
function reflection_stats()
    print("=== Reflection Recon Statistics ===")
    print(string.format("Method.invoke() calls observed: %d", stats.invoke_calls))
end

print("=== Java Reflection Dump Helpers (template) ===")
print("")
print("Commands:")
print("  exec dump_class_schema(\"android.os.Build\")   -- fields/methods of a class")
print("  exec dump_instance_fields(someInstance)         -- live field values")
print("  exec reflection_stats()                          -- Method.invoke() counter")
print("")
print("Loaded. 'watch' to see Method.invoke() recon output as the app runs.")
