#include "AMClient/AMCore.hpp"
#include "AMCommonTools.hpp"
#include <atomic>
#include <thread>
#pragma comment(lib, "libssh2.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "zlib.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "fmt.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "libcurl.lib")

// static auto bar = ProgressBar(0);
void total_cb([[maybe_unused]] int64_t total_size) {}
std::optional<TransferControl>
progress_cb([[maybe_unused]] const ProgressCBInfo &info) {
  // bar.update(info.this_size);
  return std::nullopt;
}
void error_cb(const ErrorCBInfo &info) {
  std::cerr << "Error: " << info.ecm.second << std::endl;
}

int main() {
#ifdef _WIN32
  WSADATA wsaData;
  int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (result != 0) {
    throw std::runtime_error("WSAStartup failed");
  }
  is_wsa_initialized.store(true);
#endif
  auto wsl_con = ConRequst("wsl", "172.26.36.83", "am", 22, "1984");
  auto wsl = std::make_shared<AMSFTPClient>(wsl_con);

  auto rcm = wsl->Connect();
  if (rcm.first != EC::Success) {
    std::cerr << "Connect failed: " << rcm.second << std::endl;
    return 1;
  }

  TerminalWindowInfo win;
  win.cols = 120;
  win.rows = 30;

  auto term_rcm = wsl->TerminalInit(
      win, [](const std::string &chunk) { std::cout << chunk; });
  if (term_rcm.first != EC::Success) {
    std::cerr << "Terminal init failed: " << term_rcm.second << std::endl;
    return 1;
  }

  std::atomic<bool> running{true};
  std::thread reader([&] {
    while (running.load()) {
      auto [rcm_read, _] = wsl->TerminalRead(nullptr, 50, -1, true);
      if (rcm_read.first == EC::OperationTimeout) {
        continue;
      }
      if (rcm_read.first != EC::Success) {
        std::cerr << "Terminal read failed: " << rcm_read.second << std::endl;
        break;
      }
    }
  });

  std::string cmd;
  while (true) {
    if (!std::getline(std::cin, cmd)) {
      break;
    }
    if (cmd == "exit" || cmd == "quit") {
      break;
    }
    cmd += "\n";
    auto wrc = wsl->TerminalWrite(cmd);
    if (wrc.first != EC::Success) {
      std::cerr << "Terminal write failed: " << wrc.second << std::endl;
      break;
    }
  }

  running.store(false);
  if (reader.joinable()) {
    reader.join();
  }

  wsl->TerminalClose();
  return 0;
}
