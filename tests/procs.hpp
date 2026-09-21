// Loop Guard - real process helpers for the restart and multiprocess suites.
//
// These helpers launch real operating-system processes. Threads are never a substitute
// for a process boundary in these proofs. Every wait is bounded and fails explicitly;
// no watchdog hides a hang.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lg_test {

/// Absolute path of a built tool, taken from the build system. Empty when the tool was
/// not built, in which case the dependent suite reports UNSUPPORTED rather than passing.
[[nodiscard]] std::string tool_path(const std::string& name);

/// Starts the executable detached with the given arguments, redirecting stdout and stderr
/// to the log file of the named run. The executable and arguments are passed straight to
/// the platform process API, so no shell quoting can go wrong. Returns true on success.
bool spawn_process(const std::string& name, const std::string& executable,
                   const std::vector<std::string>& arguments);

/// Path of the log file a spawned process writes to.
[[nodiscard]] std::string process_log(const std::string& name);

/// Repeatedly reads the file until it contains the marker or the deadline elapses.
/// Returns true when the marker appeared. The caller decides what a timeout means.
[[nodiscard]] bool wait_for_marker(const std::string& path, const std::string& marker,
                                   std::uint64_t deadline_ms);

/// Waits, bounded, until no process with the given image name is running.
[[nodiscard]] bool wait_until_gone(const std::string& image, std::uint64_t deadline_ms);

/// Reads a whole text file, or returns an empty string.
[[nodiscard]] std::string read_text(const std::string& path);

/// Reads the first "key=value" line's value, or an empty string.
[[nodiscard]] std::string read_value(const std::string& path, const std::string& key);

/// Terminates every process whose image name matches, and waits for it to disappear.
/// Returns true when at least one process was terminated.
bool kill_image(const std::string& image);

/// True when a process with the given image name is currently running.
[[nodiscard]] bool image_running(const std::string& image);

/// Runs a command synchronously and returns its exit status.
int run_sync(const std::string& command);

/// Runs a built tool synchronously with the given arguments, capturing its output to
/// the output path. Returns the exit code, or -1 when the tool is missing.
int run_tool(const std::string& name, const std::vector<std::string>& arguments,
             const std::string& output_path);

/// Removes a file if it exists.
void remove_file(const std::string& path);

}  // namespace lg_test
