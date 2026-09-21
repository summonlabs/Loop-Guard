// Loop Guard - loopback transport.
//
// The transport is a bounded, framed, TCP loopback connection. It is deliberately
// small: framed bytes in, framed bytes out, with an explicit deadline on every wait so
// that shutdown always completes and no thread can block forever.
//
// Trust boundary: Loop Guard does not implement authentication or encryption. A peer
// that can reach the listening socket can attempt a handshake. What the runtime does
// guarantee is that a session cannot act under another session's identity, boot or
// epoch: the session record is bound to the socket at handshake time and every frame
// is checked against it.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "loop_guard/digest.hpp"
#include "loop_guard/enums.hpp"
#include "loop_guard/limits.hpp"
#include "loop_guard/result.hpp"
#include "loop_guard/wire.hpp"

namespace loop_guard {

/// The sentinel that means "no socket handle". It is a namespace constant rather than a
/// class member so that Socket and Listener share exactly one definition of it.
inline constexpr std::uintptr_t kNoSocketHandle = ~static_cast<std::uintptr_t>(0);

/// Process-wide socket subsystem lifetime. Constructing one before using any socket
/// and destroying it afterwards is required on Windows.
class SocketSubsystem {
 public:
  SocketSubsystem();
  ~SocketSubsystem();
  SocketSubsystem(const SocketSubsystem&) = delete;
  SocketSubsystem& operator=(const SocketSubsystem&) = delete;
  [[nodiscard]] bool ok() const noexcept { return ok_; }

 private:
  bool ok_ = false;
};

/// RAII socket handle. Movable, never copyable, and safe to close twice.
class Socket {
 public:
  Socket() = default;
  ~Socket();
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  [[nodiscard]] bool valid() const noexcept { return handle_ != kNoSocketHandle; }

  /// Connects to 127.0.0.1:\p port with an explicit connect deadline.
  [[nodiscard]] static Result<Socket> connect_loopback(std::uint16_t port,
                                                       std::uint32_t deadline_ms);

  /// Sends all bytes or fails. Writes are bounded by \p deadline_ms.
  [[nodiscard]] Status send_all(std::span<const std::uint8_t> bytes, std::uint32_t deadline_ms);
  /// Receives at least one byte, or reports a closed peer / deadline expiry.
  [[nodiscard]] Result<std::size_t> recv_some(std::span<std::uint8_t> buffer,
                                              std::uint32_t deadline_ms);

  /// Releases any blocked call in another thread. Idempotent.
  [[nodiscard]] Status shutdown_both();
  /// Closes the handle. Idempotent; a second close is a no-op, not a double close.
  void close() noexcept;

  [[nodiscard]] std::uintptr_t raw_handle() const noexcept { return handle_; }

 private:
  explicit Socket(std::uintptr_t handle) : handle_(handle) {}

  std::uintptr_t handle_ = kNoSocketHandle;

  friend class Listener;
};

/// Listening socket bound to 127.0.0.1.
class Listener {
 public:
  Listener() = default;
  ~Listener();
  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;
  Listener(Listener&& other) noexcept;
  Listener& operator=(Listener&& other) noexcept;

  /// Binds to 127.0.0.1:\p port (0 chooses an ephemeral port).
  [[nodiscard]] static Result<Listener> listen_loopback(std::uint16_t port,
                                                        const Limits& limits);
  [[nodiscard]] static Result<Listener> listen_loopback(std::uint16_t port,
                                                        std::uint32_t backlog);

  [[nodiscard]] bool valid() const noexcept { return handle_ != kNoSocketHandle; }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }

  /// Accepts one connection, waiting at most \p deadline_ms. Closing the listener
  /// from another thread releases a blocked accept immediately.
  [[nodiscard]] Result<Socket> accept(std::uint32_t deadline_ms);

  [[nodiscard]] Status close() noexcept;

 private:
  std::uintptr_t handle_ = kNoSocketHandle;
  std::uint16_t port_ = 0;
};

/// A framed connection with an explicit, caller-supplied deadline on every wait.
class FramedConnection {
 public:
  FramedConnection() = default;
  explicit FramedConnection(Socket socket, const Limits& limits = default_limits());
  ~FramedConnection();
  FramedConnection(const FramedConnection&) = delete;
  FramedConnection& operator=(const FramedConnection&) = delete;
  FramedConnection(FramedConnection&& other) noexcept;
  FramedConnection& operator=(FramedConnection&& other) noexcept;

  [[nodiscard]] bool valid() const noexcept { return socket_.valid(); }

  [[nodiscard]] Status send_frame(MessageType type, SessionId session, std::uint64_t sequence,
                                  std::span<const std::uint8_t> payload, std::uint32_t deadline_ms,
                                  std::uint32_t flags = 0);

  /// Receives one frame, waiting at most \p deadline_ms. A deadline expiry returns
  /// Outcome::Indeterminate with the connection left usable; a protocol violation
  /// fails the decoder permanently and returns Outcome::IntegrityFailure.
  [[nodiscard]] Result<DecodedFrame> receive_frame(std::uint32_t deadline_ms);

  /// Releases a blocked receive in another thread and closes the socket.
  [[nodiscard]] Status close() noexcept;

  [[nodiscard]] const std::string& peer() const noexcept { return peer_; }

 private:
  Socket socket_;
  FrameDecoder decoder_;
  /// Frames decoded but not yet returned. A single read can complete several frames, and
  /// dropping the extras would silently lose protocol progress.
  std::deque<DecodedFrame> pending_;
  std::vector<std::uint8_t> scratch_;
  std::string peer_ = "127.0.0.1";
  bool decoder_failed_ = false;
};

/// Formats an IPv4 loopback endpoint for diagnostics. Never used for security checks.
[[nodiscard]] std::string loopback_endpoint(std::uint16_t port);

}  // namespace loop_guard
