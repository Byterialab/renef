/*
 * Bounded, thread-safe output queue -- see include/agent/output_queue.h
 * for the "why". Summary of the design:
 *
 *   - A fixed-capacity byte ring buffer holds the raw message bytes.
 *   - A parallel fixed-capacity ring of lengths records message
 *     boundaries, so the writer thread can pull whole messages back out
 *     (and so "drop oldest" drops whole messages, not partial ones).
 *   - output_queue_push() only ever touches the ring under a plain
 *     pthread_mutex that is held for O(memcpy) time -- never while doing
 *     socket I/O. It is safe to call from inside a hook callback while
 *     the caller holds g_lua_mutex.
 *   - A single writer thread (started once from output_queue_init())
 *     blocks on a condvar, pops whole messages off the ring, and performs
 *     the real (possibly blocking) write(g_output_client_fd, ...) outside
 *     of any lock shared with producers.
 *   - When the ring is full, the oldest message(s) are dropped to make
 *     room and a drop counter is bumped. The writer thread reports a
 *     "[dropped N messages, output queue full]" notice line (direct
 *     write, bypassing the ring) right before the next real message it
 *     delivers, whenever that counter is non-zero.
 *
 * Two queues, two sockets:
 *
 *   - the REPLY queue carries what the command being executed prints, to
 *     the command socket (g_output_client_fd), exactly as before;
 *   - the EVENT queue carries what everything else prints - hook
 *     callbacks, the syscall tracer, agent threads - to a second
 *     connection the server opens for that purpose (see
 *     output_queue_set_event_fd and the "@events" handshake in agent.c).
 *
 * Without the second connection (older servers, gadget mode) everything
 * goes to the command socket as it always did. With it, a command's reply
 * contains the command's output and nothing else: a hook that prints all
 * the time no longer ends up in front of the next `hooks` or `md`, and a
 * peer that does not read events cannot hold up replies, because each
 * queue has its own writer thread.
 */

#include <agent/output_queue.h>
#include <agent/globals.h>
#include <agent/hook.h>

#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

#define TAG "RENEF_OUTQ"
#define OQ_LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define OQ_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* Total bytes the ring can hold across all queued messages. */
#define OUTQ_CAPACITY_BYTES (256 * 1024)

/* Max number of distinct queued messages (entries), independent of the
 * byte capacity above -- caps metadata overhead if many tiny messages
 * are pushed rapidly. */
#define OUTQ_MAX_ENTRIES 2048

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;

    /* Byte ring. */
    unsigned char bytes[OUTQ_CAPACITY_BYTES];
    size_t byte_head;   /* index of oldest byte */
    size_t byte_used;   /* number of valid bytes currently queued */

    /* Message-length ring (parallel to the byte ring's message framing). */
    size_t lengths[OUTQ_MAX_ENTRIES];
    size_t entry_head;  /* index of oldest entry */
    size_t entry_count;

    /* Messages dropped since the last time the writer thread reported
     * them to the host. Only ever incremented under `lock`; read/reset
     * by the writer thread under `lock` too. */
    unsigned long drop_count;

    /* Sequence counters for output_queue_flush(): every message ever
     * accepted by push bumps pushed_seq; every message that has left the
     * queue - written to the socket OR dropped - bumps consumed_seq.
     * "Everything queued before now has been dealt with" is therefore
     * consumed_seq >= (pushed_seq sampled at the time of the call). */
    unsigned long long pushed_seq;
    unsigned long long consumed_seq;
    pthread_cond_t consumed;

    int started;

    /* Single consumer (this queue's writer thread), so one static buffer
     * as large as the whole ring is enough - and it must not be malloc():
     * it is filled with the queue lock held, and a hook callback that is
     * itself inside the process allocator may be waiting for that lock in
     * print(). */
    char read_buf[OUTQ_CAPACITY_BYTES];
} OutputQueue;

#define OUTQ_INITIALIZER { \
    .lock = PTHREAD_MUTEX_INITIALIZER, \
    .not_empty = PTHREAD_COND_INITIALIZER, \
    .consumed = PTHREAD_COND_INITIALIZER, \
}

static OutputQueue g_reply_q = OUTQ_INITIALIZER;   /* -> command socket */
static OutputQueue g_event_q = OUTQ_INITIALIZER;   /* -> event socket   */

/* The event socket. Written only by the event writer thread and replaced
 * by the command thread; every use of the descriptor happens under
 * g_event_fd_lock with non-blocking calls, so a descriptor that was closed
 * (and whose number the process may already have reused for something
 * else) is never written to. g_event_fd_hint mirrors it for the lock-free
 * "is there an event channel at all" test in output_queue_push(). */
static pthread_mutex_t g_event_fd_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_event_fd = -1;
static volatile int g_event_fd_hint = -1;

/* Thread that executes commands: its output is the reply. */
static volatile pid_t g_command_tid = 0;

/* Caller must hold q->lock. Drops the single oldest queued message
 * (if any), freeing up its bytes and its entry slot, and bumps
 * drop_count. */
static void outq_drop_oldest_locked(OutputQueue* q) {
    if (q->entry_count == 0) {
        return;
    }
    size_t oldest_len = q->lengths[q->entry_head];
    q->entry_head = (q->entry_head + 1) % OUTQ_MAX_ENTRIES;
    q->entry_count--;

    q->byte_head = (q->byte_head + oldest_len) % OUTQ_CAPACITY_BYTES;
    q->byte_used -= oldest_len;

    q->drop_count++;
    q->consumed_seq++;
    pthread_cond_broadcast(&q->consumed);
}

/* Caller must hold q->lock. Copies `len` bytes into the ring at the
 * current tail (byte_head + byte_used, mod capacity), handling
 * wraparound. Caller is responsible for having made room first. */
static void outq_append_bytes_locked(OutputQueue* q, const char* data, size_t len) {
    size_t tail = (q->byte_head + q->byte_used) % OUTQ_CAPACITY_BYTES;
    size_t first_chunk = OUTQ_CAPACITY_BYTES - tail;
    if (first_chunk > len) {
        first_chunk = len;
    }
    memcpy(q->bytes + tail, data, first_chunk);
    if (first_chunk < len) {
        memcpy(q->bytes, data + first_chunk, len - first_chunk);
    }
    q->byte_used += len;
}

/* Caller must hold q->lock. Reads `len` bytes out of the ring
 * starting at byte_head (NOT advancing byte_head -- the caller does
 * that as part of popping the entry), handling wraparound, into a
 * freshly malloc'd buffer. Returns NULL on allocation failure. */
static char* outq_read_bytes_locked(OutputQueue* q, size_t len) {
    if (len > sizeof(q->read_buf)) {
        return NULL;
    }
    char* out = q->read_buf;
    size_t first_chunk = OUTQ_CAPACITY_BYTES - q->byte_head;
    if (first_chunk > len) {
        first_chunk = len;
    }
    memcpy(out, q->bytes + q->byte_head, first_chunk);
    if (first_chunk < len) {
        memcpy(out + first_chunk, q->bytes, len - first_chunk);
    }
    return out;
}

static void outq_push(OutputQueue* q, const char* data, size_t len) {
    pthread_mutex_lock(&q->lock);

    if (len > OUTQ_CAPACITY_BYTES) {
        /* A single message can never fit; drop it outright rather than
         * evicting the entire queue to make room for it. */
        q->drop_count++;
        pthread_mutex_unlock(&q->lock);
        return;
    }

    /* Make room: evict oldest messages until both the byte budget and
     * the entry-count budget can accommodate the new message. */
    while (q->entry_count >= OUTQ_MAX_ENTRIES ||
           q->byte_used + len > OUTQ_CAPACITY_BYTES) {
        outq_drop_oldest_locked(q);
    }

    outq_append_bytes_locked(q, data, len);
    q->lengths[(q->entry_head + q->entry_count) % OUTQ_MAX_ENTRIES] = len;
    q->entry_count++;
    q->pushed_seq++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

int output_queue_is_event_context(void) {
    if (g_event_fd_hint < 0) {
        return 0;               /* no event channel: one stream, as before */
    }
    pid_t cmd = g_command_tid;
    return cmd != 0 && gettid() != cmd;
}

void output_queue_push(const char* data, size_t len) {
    if (!data || len == 0) {
        return;
    }
    outq_push(output_queue_is_event_context() ? &g_event_q : &g_reply_q, data, len);
}

void output_queue_set_command_thread(void) {
    g_command_tid = gettid();
}

int output_queue_has_event_channel(void) {
    return g_event_fd_hint >= 0;
}

void output_queue_set_event_fd(int fd) {
    pthread_mutex_lock(&g_event_fd_lock);
    int old = g_event_fd;
    g_event_fd = fd;
    g_event_fd_hint = fd;
    pthread_mutex_unlock(&g_event_fd_lock);
    if (old >= 0 && old != fd) {
        shutdown(old, SHUT_RDWR);
        close(old);
    }
    if (fd < 0) {
        /* Nobody is going to read what is still queued for the old peer. */
        pthread_mutex_lock(&g_event_q.lock);
        while (g_event_q.entry_count > 0) {
            outq_drop_oldest_locked(&g_event_q);
        }
        g_event_q.drop_count = 0;
        pthread_mutex_unlock(&g_event_q.lock);
    }
}

/* Blocks until every message that was queued for the COMMAND socket before
 * this call has left the queue (written to the socket, or dropped), or
 * until timeout_ms elapses. Returns 1 if that point was reached, 0 on
 * timeout.
 *
 * Used by the command loop to put a command's completion marker on the
 * wire strictly AFTER all output that command produced: print() only
 * enqueues, so without this a directly-written "done" could overtake the
 * command's own last lines, and those would then be read as the start of
 * the NEXT command's response.
 *
 * The event queue is deliberately not waited for: its peer may not be
 * reading at all, and events are not part of any reply. */
int output_queue_flush(int timeout_ms) {
    OutputQueue* q = &g_reply_q;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    int ok = 1;
    pthread_mutex_lock(&q->lock);
    unsigned long long target = q->pushed_seq;
    while (q->consumed_seq < target) {
        if (pthread_cond_timedwait(&q->consumed, &q->lock, &deadline) != 0) {
            ok = (q->consumed_seq >= target);
            break;
        }
    }
    pthread_mutex_unlock(&q->lock);
    return ok;
}

/* Writes one message to the event socket. Never blocks inside a system
 * call while holding g_event_fd_lock: a full socket (the server is not
 * reading right now) is waited for with poll() outside the lock, during
 * which producers keep filling the queue and the oldest events are
 * dropped. Gives up on the message when the channel goes away. */
static void event_write(const char* msg, size_t len) {
    size_t off = 0;
    while (off < len) {
        pthread_mutex_lock(&g_event_fd_lock);
        int fd = g_event_fd;
        ssize_t n = -1;
        int err = EBADF;
        if (fd >= 0) {
            n = send(fd, msg + off, len - off, MSG_DONTWAIT | MSG_NOSIGNAL);
            err = errno;
        }
        pthread_mutex_unlock(&g_event_fd_lock);

        if (fd < 0) {
            return;
        }
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && err == EINTR) {
            continue;
        }
        if (n < 0 && (err == EAGAIN || err == EWOULDBLOCK)) {
            struct pollfd pfd = { fd, POLLOUT, 0 };
            poll(&pfd, 1, 200);
            continue;
        }
        return;     /* peer gone */
    }
}

static void* output_queue_writer_thread(void* arg) {
    OutputQueue* q = (OutputQueue*)arg;
    int is_event = (q == &g_event_q);
    hook_mark_agent_thread(); // Agent threads are never hooked (native.c)

    for (;;) {
        pthread_mutex_lock(&q->lock);
        while (q->entry_count == 0) {
            pthread_cond_wait(&q->not_empty, &q->lock);
        }

        size_t len = q->lengths[q->entry_head];
        char* msg = outq_read_bytes_locked(q, len);

        q->entry_head = (q->entry_head + 1) % OUTQ_MAX_ENTRIES;
        q->entry_count--;
        q->byte_head = (q->byte_head + len) % OUTQ_CAPACITY_BYTES;
        q->byte_used -= len;

        unsigned long dropped = q->drop_count;
        q->drop_count = 0;

        pthread_mutex_unlock(&q->lock);

        /* All socket I/O below happens with NO lock held that producers
         * need -- neither this queue's lock nor (crucially) g_lua_mutex,
         * which this thread never touches at all. A slow/stalled host only
         * blocks this one writer thread. */

        char notice[128];
        int notice_len = 0;
        if (dropped > 0) {
            notice_len = snprintf(notice, sizeof(notice),
                                  "[dropped %lu messages, output queue full]\n",
                                  dropped);
        }

        if (is_event) {
            if (notice_len > 0) event_write(notice, (size_t)notice_len);
            if (msg) event_write(msg, len);
        } else {
            if (notice_len > 0 && g_output_client_fd >= 0) {
                write(g_output_client_fd, notice, (size_t)notice_len);
            }
            if (msg && g_output_client_fd >= 0) {
                write(g_output_client_fd, msg, len);
            }
        }
        /* msg is the queue's static read_buf, nothing to free. */

        /* Only now - after the bytes are on the socket - does this
         * message count as consumed for output_queue_flush(). */
        pthread_mutex_lock(&q->lock);
        q->consumed_seq++;
        pthread_cond_broadcast(&q->consumed);
        pthread_mutex_unlock(&q->lock);
    }

    return NULL;
}

static pthread_once_t g_outq_once = PTHREAD_ONCE_INIT;

static void output_queue_do_init(void) {
    OutputQueue* queues[2] = { &g_reply_q, &g_event_q };
    for (int i = 0; i < 2; i++) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, output_queue_writer_thread, queues[i]) == 0) {
            pthread_detach(thread);
            queues[i]->started = 1;
        } else {
            OQ_LOGE("Failed to start output queue writer thread %d", i);
        }
    }
    OQ_LOGI("Output queue writer threads started (capacity=%d bytes, %d entries each)",
            OUTQ_CAPACITY_BYTES, OUTQ_MAX_ENTRIES);
}

void output_queue_init(void) {
    pthread_once(&g_outq_once, output_queue_do_init);
}
