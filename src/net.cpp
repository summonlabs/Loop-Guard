#include "loop_guard/net.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
// C6101 is reported inside the Windows SDK header for an inline helper this runtime never
// calls. It is a third-party header finding, not a finding in this runtime, and it is
// suppressed only around the include.
#pragma warning(push)
#pragma warning(disable : 6101)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma warning(pop)
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace loop_guard {
namespace {

#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket kNoSocketHandleSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kNoSocketHandleSocket = -1;
#endif

NativeSocket to_native(std::uintptr_t handle) { return static_cast<NativeSocket>(handle); }

std::uintptr_t from_native(NativeSocket socket) { return static_cast<std::uintptr_t>(socket); }

std::uint64_t now_millis() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

bool would_block() {
#if defined(_WIN32)
  const int error = WSAGetLastError();
  return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
  return errno == EWOULDBLOCK || errno == EAGAIN || errno == EINPROGRESS;
#endif
}

bool in_progress() {
#if defined(_WIN32)
  const int error = WSAGetLastError();
  return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS || error == WSAEALREADY;
#else
  return errno == EINPROGRESS || errno == EALREADY || errno == EWOULDBLOCK;
#endif
}

void close_native(NativeSocket socket) {
  if (socket == kNoSocketHandleSocket) {
    return;
  }
#if defined(_WIN32)
  ::closesocket(socket);
#else
  ::close(socket);
#endif
}

/// Waits until the socket is readable, writable, or the deadline expires.
/// Returns 1 ready, 0 timed out, -1 error.
int wait_for(NativeSocket socket, bool want_write, std::uint32_t deadline_ms) {
  fd_set read_set;
  fd_set write_set;
  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  if (want_write) {
    FD_SET(socket, &write_set);
  } else {
    FD_SET(socket, &read_set);
  }
  timeval timeout;
  timeout.tv_sec = static_cast<long>(deadline_ms / 1000U);
  timeout.tv_usec = static_cast<long>((deadline_ms % 1000U) * 1000U);
#if defined(_WIN32)
  const int result = ::select(0, want_write ? nullptr : &read_set, want_write ? &write_set : nullptr,
                              nullptr, &timeout);
#else
  const int result =
      ::select(static_cast<int>(socket) + 1, want_write ? nullptr : &read_set,
               want_write ? &write_set : nullptr, nullptr, &timeout);
#endif
  return result;
}

bool set_non_blocking(NativeSocket socket) {
#if defined(_WIN32)
  u_long mode = 1;
  return ::ioctlsocket(socket, FIONBIO, &mode) == 0;
#else
  const int flags = ::fcntl(socket, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  return ::fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

}  // namespace

// ---------------------------------------------------------------------------
// SocketSubsystem.
// ---------------------------------------------------------------------------
SocketSubsystem::SocketSubsystem() {
#if defined(_WIN32)
  WSADATA data{};
  const int status = WSAStartup(MAKEWORD(2, 2), &data);
  ok_ = status == 0;
#else
  ok_ = true;
#endif
}

SocketSubsystem::~SocketSubsystem() {
#if defined(_WIN32)
  if (ok_) {
    WSACleanup();
  }
#endif
  ok_ = false;
}

// ---------------------------------------------------------------------------
// Socket.
// ---------------------------------------------------------------------------
Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = kNoSocketHandle; }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = kNoSocketHandle;
  }
  return *this;
}

void Socket::close() noexcept {
  if (handle_ == kNoSocketHandle) {
    return;
  }
  close_native(to_native(handle_));
  handle_ = kNoSocketHandle;
}

Status Socket::shutdown_both() {
  if (handle_ == kNoSocketHandle) {
    return Status::ok();
  }
#if defined(_WIN32)
  ::shutdown(to_native(handle_), SD_BOTH);
#else
  ::shutdown(to_native(handle_), SHUT_RDWR);
#endif
  return Status::ok();
}

Result<Socket> Socket::connect_loopback(std::uint16_t port, std::uint32_t deadline_ms) {
  NativeSocket native = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (native == kNoSocketHandleSocket) {
    return Result<Socket>::failure(Outcome::IoFailure, "socket creation failed");
  }
  if (!set_non_blocking(native)) {
    close_native(native);
    return Result<Socket>::failure(Outcome::IoFailure, "cannot switch the socket to non-blocking mode");
  }

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  const std::uint64_t started = now_millis();
  int status = ::connect(native, reinterpret_cast<sockaddr*>(&address), sizeof(address));
  if (status != 0) {
    if (!in_progress()) {
      close_native(native);
      return Result<Socket>::failure(Outcome::IoFailure, "connect failed immediately");
    }
    const std::uint64_t elapsed = now_millis() - started;
    const std::uint32_t remaining = elapsed >= deadline_ms ? 0U : deadline_ms - static_cast<std::uint32_t>(elapsed);
    const int ready = wait_for(native, true, remaining);
    if (ready == 0) {
      close_native(native);
      return Result<Socket>::failure(Outcome::Indeterminate, "connect deadline expired");
    }
    if (ready < 0) {
      close_native(native);
      return Result<Socket>::failure(Outcome::IoFailure, "connect wait failed");
    }
    int error = 0;
#if defined(_WIN32)
    int length = sizeof(error);
    if (::getsockopt(native, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) != 0) {
      close_native(native);
      return Result<Socket>::failure(Outcome::IoFailure, "connect status could not be read");
    }
#else
    socklen_t length = sizeof(error);
    if (::getsockopt(native, SOL_SOCKET, SO_ERROR, &error, &length) != 0) {
      close_native(native);
      return Result<Socket>::failure(Outcome::IoFailure, "connect status could not be read");
    }
#endif
    if (error != 0) {
      close_native(native);
      return Result<Socket>::failure(Outcome::IoFailure, "connect was refused");
    }
  }
  return Result<Socket>::ok(Socket(from_native(native)));
}

Status Socket::send_all(std::span<const std::uint8_t> bytes, std::uint32_t deadline_ms) {
  if (handle_ == kNoSocketHandle) {
    return Status::failure(Outcome::Invalid, "socket is not open");
  }
  const NativeSocket native = to_native(handle_);
  std::size_t sent = 0;
  const std::uint64_t started = now_millis();
  while (sent < bytes.size()) {
#if defined(_WIN32)
    const int chunk = ::send(native, reinterpret_cast<const char*>(bytes.data() + sent),
                             static_cast<int>(bytes.size() - sent), 0);
#else
    const ssize_t chunk = ::send(native, bytes.data() + sent, bytes.size() - sent, MSG_NOSIGNAL);
#endif
    if (chunk > 0) {
      sent += static_cast<std::size_t>(chunk);
      continue;
    }
    if (!would_block()) {
      return Status::failure(Outcome::IoFailure, "send failed");
    }
    const std::uint64_t elapsed = now_millis() - started;
    if (elapsed >= deadline_ms) {
      return Status::failure(Outcome::Indeterminate, "send deadline expired");
    }
    const int ready = wait_for(native, true, static_cast<std::uint32_t>(deadline_ms - elapsed));
    if (ready == 0) {
      return Status::failure(Outcome::Indeterminate, "send deadline expired");
    }
    if (ready < 0) {
      return Status::failure(Outcome::IoFailure, "send wait failed");
    }
  }
  return Status::ok();
}

Result<std::size_t> Socket::recv_some(std::span<std::uint8_t> buffer, std::uint32_t deadline_ms) {
  if (handle_ == kNoSocketHandle) {
    return Result<std::size_t>::failure(Outcome::Invalid, "socket is not open");
  }
  const NativeSocket native = to_native(handle_);
  const std::uint64_t started = now_millis();
  for (;;) {
#if defined(_WIN32)
    const int chunk = ::recv(native, reinterpret_cast<char*>(buffer.data()),
                             static_cast<int>(buffer.size()), 0);
#else
    const ssize_t chunk = ::recv(native, buffer.data(), buffer.size(), 0);
#endif
    if (chunk > 0) {
      return Result<std::size_t>::ok(static_cast<std::size_t>(chunk));
    }
    if (chunk == 0) {
      return Result<std::size_t>::failure(Outcome::Interrupted, "peer closed the connection");
    }
    if (!would_block()) {
      return Result<std::size_t>::failure(Outcome::IoFailure, "receive failed");
    }
    const std::uint64_t elapsed = now_millis() - started;
    if (elapsed >= deadline_ms) {
      return Result<std::size_t>::failure(Outcome::Indeterminate, "receive deadline expired");
    }
    const int ready = wait_for(native, false, static_cast<std::uint32_t>(deadline_ms - elapsed));
    if (ready == 0) {
      return Result<std::size_t>::failure(Outcome::Indeterminate, "receive deadline expired");
    }
    if (ready < 0) {
      return Result<std::size_t>::failure(Outcome::IoFailure, "receive wait failed");
    }
  }
}

// ---------------------------------------------------------------------------
// Listener.
// ---------------------------------------------------------------------------
Listener::~Listener() { (void)close(); }

Listener::Listener(Listener&& other) noexcept : handle_(other.handle_), port_(other.port_) {
  other.handle_ = kNoSocketHandle;
  other.port_ = 0;
}

Listener& Listener::operator=(Listener&& other) noexcept {
  if (this != &other) {
    (void)close();
    handle_ = other.handle_;
    port_ = other.port_;
    other.handle_ = kNoSocketHandle;
    other.port_ = 0;
  }
  return *this;
}

Result<Listener> Listener::listen_loopback(std::uint16_t port, const Limits& limits) {
  return listen_loopback(port, limits.max_backlog);
}

Result<Listener> Listener::listen_loopback(std::uint16_t port, std::uint32_t backlog) {
  NativeSocket native = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (native == kNoSocketHandleSocket) {
    return Result<Listener>::failure(Outcome::IoFailure, "listener socket creation failed");
  }
  const int reuse = 1;
#if defined(_WIN32)
  ::setsockopt(native, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#else
  ::setsockopt(native, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(native, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close_native(native);
    return Result<Listener>::failure(Outcome::IoFailure, "listener bind failed");
  }
  if (::listen(native, static_cast<int>(backlog)) != 0) {
    close_native(native);
    return Result<Listener>::failure(Outcome::IoFailure, "listener listen failed");
  }
  if (!set_non_blocking(native)) {
    close_native(native);
    return Result<Listener>::failure(Outcome::IoFailure, "listener could not be made non-blocking");
  }
  sockaddr_in bound{};
#if defined(_WIN32)
  int length = sizeof(bound);
#else
  socklen_t length = sizeof(bound);
#endif
  if (::getsockname(native, reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
    close_native(native);
    return Result<Listener>::failure(Outcome::IoFailure, "listener address could not be read");
  }
  Listener listener;
  listener.handle_ = from_native(native);
  listener.port_ = ntohs(bound.sin_port);
  return Result<Listener>::ok(std::move(listener));
}

Result<Socket> Listener::accept(std::uint32_t deadline_ms) {
  if (handle_ == kNoSocketHandle) {
    return Result<Socket>::failure(Outcome::Invalid, "listener is not open");
  }
  const NativeSocket native = to_native(handle_);
  const std::uint64_t started = now_millis();
  for (;;) {
    sockaddr_in peer{};
#if defined(_WIN32)
    int length = sizeof(peer);
#else
    socklen_t length = sizeof(peer);
#endif
    NativeSocket accepted = ::accept(native, reinterpret_cast<sockaddr*>(&peer), &length);
    if (accepted != kNoSocketHandleSocket) {
      if (!set_non_blocking(accepted)) {
        close_native(accepted);
        return Result<Socket>::failure(Outcome::IoFailure, "accepted socket could not be configured");
      }
      return Result<Socket>::ok(Socket(from_native(accepted)));
    }
    if (!would_block()) {
      return Result<Socket>::failure(Outcome::Interrupted, "accept failed or the listener was closed");
    }
    const std::uint64_t elapsed = now_millis() - started;
    if (elapsed >= deadline_ms) {
      return Result<Socket>::failure(Outcome::Indeterminate, "accept deadline expired");
    }
    const int ready = wait_for(native, false, static_cast<std::uint32_t>(deadline_ms - elapsed));
    if (ready == 0) {
      return Result<Socket>::failure(Outcome::Indeterminate, "accept deadline expired");
    }
    if (ready < 0) {
      return Result<Socket>::failure(Outcome::Interrupted, "accept wait failed or was released");
    }
  }
}

Status Listener::close() noexcept {
  if (handle_ == kNoSocketHandle) {
    return Status::ok();
  }
  // Closing the handle releases any blocked accept in another thread immediately.
  close_native(to_native(handle_));
  handle_ = kNoSocketHandle;
  return Status::ok();
}

// ---------------------------------------------------------------------------
// FramedConnection.
// ---------------------------------------------------------------------------
FramedConnection::FramedConnection(Socket socket, const Limits& limits)
    : socket_(std::move(socket)), decoder_(limits) {
  scratch_.resize(64U * 1024U);
}

FramedConnection::~FramedConnection() { (void)close(); }

FramedConnection::FramedConnection(FramedConnection&& other) noexcept
    : socket_(std::move(other.socket_)),
      decoder_(other.decoder_),
      pending_(std::move(other.pending_)),
      scratch_(std::move(other.scratch_)),
      peer_(std::move(other.peer_)),
      decoder_failed_(other.decoder_failed_) {}

FramedConnection& FramedConnection::operator=(FramedConnection&& other) noexcept {
  if (this != &other) {
    socket_ = std::move(other.socket_);
    decoder_ = other.decoder_;
    pending_ = std::move(other.pending_);
    scratch_ = std::move(other.scratch_);
    peer_ = std::move(other.peer_);
    decoder_failed_ = other.decoder_failed_;
  }
  return *this;
}

Status FramedConnection::send_frame(MessageType type, SessionId session, std::uint64_t sequence,
                                    std::span<const std::uint8_t> payload, std::uint32_t deadline_ms,
                                    std::uint32_t flags) {
  auto frame = encode_frame(type, session, sequence, payload, flags);
  if (!frame.has_value()) {
    return Status::failure(frame.outcome(), frame.detail());
  }
  return socket_.send_all(frame.value(), deadline_ms);
}

Result<DecodedFrame> FramedConnection::receive_frame(std::uint32_t deadline_ms) {
  if (decoder_failed_) {
    return Result<DecodedFrame>::failure(Outcome::IntegrityFailure,
                                         "the decoder already failed permanently");
  }
  if (!pending_.empty()) {
    DecodedFrame frame = std::move(pending_.front());
    pending_.pop_front();
    return Result<DecodedFrame>::ok(std::move(frame));
  }
  std::vector<DecodedFrame> frames;
  const std::uint64_t started = now_millis();
  for (;;) {
    const std::uint64_t elapsed = now_millis() - started;
    if (elapsed >= deadline_ms) {
      return Result<DecodedFrame>::failure(Outcome::Indeterminate, "receive deadline expired");
    }
    const std::uint32_t remaining = static_cast<std::uint32_t>(deadline_ms - elapsed);
    auto received = socket_.recv_some(scratch_, remaining);
    if (!received.has_value()) {
      return Result<DecodedFrame>::failure(received.outcome(), received.detail());
    }
    const Status fed =
        decoder_.feed(std::span<const std::uint8_t>(scratch_.data(), received.value()), frames);
    if (!fed.is_ok()) {
      decoder_failed_ = true;
      return Result<DecodedFrame>::failure(fed.outcome(), fed.detail());
    }
    if (frames.empty()) {
      continue;
    }
    for (DecodedFrame& frame : frames) {
      pending_.push_back(std::move(frame));
    }
    frames.clear();
    DecodedFrame frame = std::move(pending_.front());
    pending_.pop_front();
    return Result<DecodedFrame>::ok(std::move(frame));
  }
}

Status FramedConnection::close() noexcept {
  (void)socket_.shutdown_both();
  socket_.close();
  return Status::ok();
}

std::string loopback_endpoint(std::uint16_t port) {
  return "127.0.0.1:" + std::to_string(port);
}

}  // namespace loop_guard
