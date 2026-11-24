#ifndef AGENT_OUTPUT_QUEUE_H
#define AGENT_OUTPUT_QUEUE_H

#include <stddef.h>

/*
 * Bounded, thread-safe output queue for agent -> host text output.
 *
 * Why this exists: send_to_cli() (four copies: engine.c, api_memory.c,
 * api_strace.c, api_kcov.c) used to call write(g_output_client_fd, ...)
 * directly, from inside a hook callback, while the caller held
 * g_lua_mutex (see native.c). The socket fd is blocking (no O_NONBLOCK),
 * so if the host is slow or stalled reading, that write() blocks -- and
 * since g_lua_mutex is held, EVERY thread in the target process that
 * calls into a hooked function blocks too, because they all need the
 * same mutex to run their onEnter/onLeave Lua callback. One slow host
 * read can hang the whole target app.
 *
 * Fix: producers (send_to_cli() and friends) only ever push bytes into
 * this in-memory ring buffer under a short, non-blocking-ish lock -- no
 * socket I/O happens while holding g_lua_mutex. A single dedicated
 * writer thread drains the ring buffer and performs the real (possibly
 * blocking) write() to the socket, entirely outside of g_lua_mutex.
 *
 * The ring buffer has a fixed byte capacity. If a push would overflow
 * it, the oldest queued bytes are dropped (drop-oldest policy) to make
 * room, and a drop counter is incremented so the host can be told how
 * much output it lost ("[dropped N messages, output queue full]").
 *
 * Out of scope (deliberately): no length-prefixed message framing here.
 * This module only moves raw bytes from producers to the socket writer;
 * the wire format on the socket is unchanged.
 */

/* Must be called once, before any output_queue_push() call, typically
 * from the agent's constructor/init path. Starts the writer thread.
 * Safe to call more than once (subsequent calls are no-ops). */
void output_queue_init(void);

/* Enqueues `len` bytes of `data` for later delivery to the CLI socket.
 * Never blocks on socket I/O. Safe to call from any thread, including
 * from inside a hook callback while g_lua_mutex is held.
 *
 * If the queue is full, the oldest queued bytes are dropped to make
 * room for this message and the internal drop counter is incremented.
 * If `len` alone exceeds the queue's total capacity, the message itself
 * is dropped (counted as 1 dropped message) rather than partially
 * queued. */
void output_queue_push(const char* data, size_t len);

/* --- Event channel -------------------------------------------------
 *
 * Output is of two kinds: what the command being executed prints (its
 * reply), and what happens on its own - hook callbacks, the syscall
 * tracer. With only one socket the second kind ended up inside whatever
 * reply was read next. A server that knows about it opens a second
 * connection for events; output_queue_push() then routes by caller:
 * the command thread's output goes to the command socket, everything
 * else to the event socket. Without that connection nothing changes.
 */

/* Marks the calling thread as the one that executes commands. */
void output_queue_set_command_thread(void);

/* Installs `fd` as the event socket (-1: none). The previous one is
 * closed; with -1 the events still queued are discarded. */
void output_queue_set_event_fd(int fd);

/* 1 if an event socket is connected. */
int output_queue_has_event_channel(void);

/* 1 if output of the calling thread belongs on the event socket right
 * now (there is one, and this is not the command thread). For the few
 * producers that write to the command socket directly instead of going
 * through output_queue_push(). */
int output_queue_is_event_context(void);

/* Waits (up to timeout_ms) until everything queued before the call has
 * been written to the socket or dropped. Returns 1 if reached, 0 on
 * timeout. See output_queue.c. */
int output_queue_flush(int timeout_ms);

#endif /* AGENT_OUTPUT_QUEUE_H */
