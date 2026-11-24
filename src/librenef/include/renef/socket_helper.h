#pragma once
#include <sys/types.h>
#include <string>
#include <memory>
#include <functional>
#include <renef/framing.h>

class ITransport;

/**
 * Socket helper class for managing agent connections
 * Now uses ITransport for platform-agnostic communication
 */
class SocketHelper {
private:
    std::unique_ptr<ITransport> transport;
    int current_pid;
    std::string session_key;

    // Request framing towards the agent.
    unsigned long next_request_id = 1;
    renef_framing::ResponseReader response_reader;

    // Event channel: a second connection to the agent that carries what
    // hook callbacks and the syscall tracer print, so that it is not mixed
    // into command replies (agent/output_queue.h). -1 with agents that do
    // not know it; everything then arrives on the command socket as before.
    int event_fd = -1;
    std::string event_buf;              // complete and partial lines, oldest first
    size_t event_lines = 0;             // '\n' count in event_buf
    unsigned long event_lines_dropped = 0;

    int open_event_channel(int pid);
    void close_event_channel();

public:
    SocketHelper();
    ~SocketHelper();

    /**
     * Ensure connection to agent in target process
     * @param pid Target process PID
     * @return socket fd or -1 on error
     */
    int ensure_connection(int pid);

    /**
     * Send data to agent
     * @param data Data to send
     * @param size Size of data
     * @param prefix_key Prepend session key (default: true)
     * @return bytes sent or -1 on error
     */
    ssize_t send_data(const void* data, size_t size, bool prefix_key = true);

    /**
     * Receive data from agent
     * @param buffer Buffer to receive into
     * @param size Buffer size
     * @return bytes received or -1 on error
     */
    ssize_t receive_data(void* buffer, size_t size);

    enum class RecvResult { Done, Timeout, Closed };

    /**
     * Send a command to the agent as a framed request (session key is
     * prepended automatically). The agent answers with everything the
     * command wrote followed by a completion marker carrying the same id.
     * @return request id (> 0), or 0 on send failure
     */
    unsigned long send_request(const std::string& cmd);

    /**
     * Read the response of request `id` until its completion marker.
     * Output that belongs to an older, abandoned request is skipped, so a
     * late reply can never be mistaken for this request's reply.
     * @param silence_timeout_ms give up after this long without any data
     * @param on_data called with each piece of this request's output
     * @param busy_with_older set to true on Timeout if the agent was still
     *        working on an earlier request the whole time
     */
    RecvResult recv_response(unsigned long id, int silence_timeout_ms,
                             const std::function<void(const std::string&)>& on_data,
                             bool* busy_with_older = nullptr);

    /**
     * Collect output the agent produced on its own, outside of any request
     * (hook callbacks calling print()/send() between commands). Waits up to
     * wait_ms for the first byte, then until the socket has been quiet for
     * a short moment. Completion markers of abandoned requests are removed.
     */
    std::string read_pending(int wait_ms);

    /** True if the agent sends hook/trace output on its own connection. */
    bool has_event_channel() const { return event_fd >= 0; }

    /** Descriptor to poll() for new events, -1 without an event channel. */
    int get_event_fd() const { return event_fd; }

    /**
     * Moves what the agent has sent on the event channel into the event
     * buffer (never blocks). The buffer is bounded: when it is full the
     * oldest lines go and are counted.
     */
    void pump_events();

    /** Lines waiting in the event buffer (after the last pump_events()). */
    size_t pending_event_lines() const { return event_lines; }

    /**
     * Removes and returns buffered events, whole lines only, at most
     * max_bytes (0 = everything). Starts with a notice line if older
     * lines had to be dropped.
     */
    std::string take_events(size_t max_bytes = 0);

    /**
     * Drain any pending data from agent socket buffer
     * Useful after streaming commands (strace, watch) to clear stale output
     */
    void drain_buffer();

    /**
     * Close connection to agent
     */
    void close_connection();

    /**
     * Check if connected to agent
     * @return true if connected
     */
    bool is_connected() const;

    /**
     * Get socket file descriptor
     * @return Current socket fd
     */
    int get_socket_fd() const;

    /**
     * Set session authentication key
     * @param key Session key
     */
    void set_session_key(std::string key);

    /**
     * Get current session key
     * @return Session key
     */
    std::string get_session_key();
};
