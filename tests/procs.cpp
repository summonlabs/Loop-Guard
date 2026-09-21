#include "procs.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

#include "fixtures.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace lg_test {
namespace {

std::uint64_t now_millis() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

/// Quotes one command line token for the platform process API. That API takes a single
/// command line string, so quoting is explicit here and no shell is involved.
std::string quote_argument(const std::string& value) {
  std::string quoted = "\"";
  for (const char character : value) {
    if (character == '"') {
      quoted += "\\\"";
    } else {
      quoted.push_back(character);
    }
  }
  quoted.push_back('"');
  return quoted;
}

}  // namespace

std::string tool_path(const std::string& name) {
  std::string configured;
  if (name == "lg_coordinator") {
#ifdef LG_COORDINATOR_EXE
    configured = LG_COORDINATOR_EXE;
#endif
  } else if (name == "lg_worker") {
#ifdef LG_WORKER_EXE
    configured = LG_WORKER_EXE;
#endif
  } else if (name == "lgctl") {
#ifdef LGCTL_EXE
    configured = LGCTL_EXE;
#endif
  }
  if (!configured.empty() && std::filesystem::exists(configured)) {
    return configured;
  }
  return {};
}

std::string process_log(const std::string& name) { return scratch_path(name + ".out"); }

bool spawn_process(const std::string& name, const std::string& executable,
                   const std::vector<std::string>& arguments) {
  if (executable.empty()) {
    return false;
  }
  const std::string log = process_log(name);
  remove_file(log);
#if defined(_WIN32)
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  HANDLE handle = CreateFileA(log.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return false;
  }
  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = handle;
  startup.hStdError = handle;
  startup.hStdInput = nullptr;
  std::string command = quote_argument(executable);
  for (const std::string& argument : arguments) {
    command.push_back(' ');
    command += quote_argument(argument);
  }
  std::vector<char> mutable_command(command.begin(), command.end());
  mutable_command.push_back('\0');
  PROCESS_INFORMATION process{};
  const BOOL started = CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
  CloseHandle(handle);
  if (started == 0) {
    return false;
  }
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return true;
#else
  const int log_descriptor = ::open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (log_descriptor < 0) {
    return false;
  }
  std::vector<std::string> storage;
  storage.push_back(executable);
  for (const std::string& argument : arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  for (std::string& token : storage) {
    argv.push_back(token.data());
  }
  argv.push_back(nullptr);
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, log_descriptor, STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, log_descriptor, STDERR_FILENO);
  pid_t child = 0;
  const int status =
      posix_spawn(&child, executable.c_str(), &actions, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  ::close(log_descriptor);
  return status == 0;
#endif
}

bool wait_for_marker(const std::string& path, const std::string& marker, std::uint64_t deadline_ms) {
  const std::uint64_t started = now_millis();
  while (now_millis() - started < deadline_ms) {
    if (read_text(path).find(marker) != std::string::npos) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return read_text(path).find(marker) != std::string::npos;
}

bool wait_until_gone(const std::string& image, std::uint64_t deadline_ms) {
  const std::uint64_t started = now_millis();
  while (now_millis() - started < deadline_ms) {
    if (!image_running(image)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return !image_running(image);
}

std::string read_text(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

std::string read_value(const std::string& path, const std::string& key) {
  const std::string text = read_text(path);
  const std::string prefix = key + "=";
  std::size_t position = 0;
  while (position < text.size()) {
    const std::size_t end = text.find('\n', position);
    const std::string line =
        text.substr(position, end == std::string::npos ? std::string::npos : end - position);
    if (line.rfind(prefix, 0) == 0) {
      std::string value = line.substr(prefix.size());
      while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) {
        value.pop_back();
      }
      return value;
    }
    if (end == std::string::npos) {
      break;
    }
    position = end + 1U;
  }
  return {};
}

bool image_running(const std::string& image) {
#if defined(_WIN32)
  const std::string command = "tasklist /FI \"IMAGENAME eq " + image + ".exe\" /NH";
  std::FILE* pipe = _popen(command.c_str(), "r");
  if (pipe == nullptr) {
    return false;
  }
  std::string output;
  char buffer[512];
  while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    output += buffer;
  }
  _pclose(pipe);
  return output.find(image + ".exe") != std::string::npos;
#else
  const std::string command = "pgrep -f " + image + " > /dev/null 2>&1";
  return std::system(command.c_str()) == 0;
#endif
}

bool kill_image(const std::string& image) {
  if (!image_running(image)) {
    return false;
  }
#if defined(_WIN32)
  const std::string command = "taskkill /IM " + image + ".exe /F > nul 2>&1";
#else
  const std::string command = "pkill -9 -f " + image + " > /dev/null 2>&1";
#endif
  (void)std::system(command.c_str());
  return wait_until_gone(image, 15000U);
}

int run_sync(const std::string& command) { return std::system(command.c_str()); }

int run_tool(const std::string& name, const std::vector<std::string>& arguments,
             const std::string& output_path) {
  const std::string executable = tool_path(name);
  if (executable.empty()) {
    return -1;
  }
  // The tool is started through the platform process API, not a shell, so a path with
  // spaces can never be split. The call waits, bounded, for the process to exit.
#if defined(_WIN32)
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  HANDLE handle = CreateFileA(output_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return -1;
  }
  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = handle;
  startup.hStdError = handle;
  startup.hStdInput = nullptr;
  std::string command = quote_argument(executable);
  for (const std::string& argument : arguments) {
    command.push_back(' ');
    command += quote_argument(argument);
  }
  std::vector<char> mutable_command(command.begin(), command.end());
  mutable_command.push_back('\0');
  PROCESS_INFORMATION process{};
  const BOOL started = CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
  CloseHandle(handle);
  if (started == 0) {
    return -1;
  }
  CloseHandle(process.hThread);
  const DWORD waited = WaitForSingleObject(process.hProcess, 300000U);
  DWORD exit_code = 1U;
  if (waited == WAIT_OBJECT_0) {
    (void)GetExitCodeProcess(process.hProcess, &exit_code);
  }
  CloseHandle(process.hProcess);
  return static_cast<int>(exit_code);
#else
  const int log_descriptor = ::open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (log_descriptor < 0) {
    return -1;
  }
  std::vector<std::string> storage;
  storage.push_back(executable);
  for (const std::string& argument : arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  for (std::string& token : storage) {
    argv.push_back(token.data());
  }
  argv.push_back(nullptr);
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, log_descriptor, STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, log_descriptor, STDERR_FILENO);
  pid_t child = 0;
  const int spawned =
      posix_spawn(&child, executable.c_str(), &actions, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  ::close(log_descriptor);
  if (spawned != 0) {
    return -1;
  }
  int status = 0;
  if (waitpid(child, &status, 0) < 0) {
    return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
#endif
}

void remove_file(const std::string& path) {
  std::error_code error;
  std::filesystem::remove(path, error);
}

}  // namespace lg_test
