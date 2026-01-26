#include "AMClient/AMCore.hpp"
#include "AMCommonTools.hpp"
#include <atomic>

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
int main() { return 0; }

int main2() {
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
  return 1;
}
