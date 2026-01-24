#include "AMCommonTools.hpp"
#include "AMCore.hpp"
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
  std::cout << GenerateUID() << std::endl;
  auto wsl_con = ConRequst("wsl", "172.26.36.83", "am", 22, "1984");

  auto wsl = std::make_shared<AMSFTPClient>(wsl_con);

  auto rcm = wsl->Connect();

  auto me_con = ConRequst("me", "10.163.174.210", "am", 21, "1984");
  auto me = std::make_shared<AMFTPClient>(me_con);
  rcm = me->Connect();

  auto host_m = std::make_shared<ClientMaintainer>();
  host_m->add_client("wsl", wsl);
  host_m->add_client("me", me);
  auto cb_set = TransferCallback(total_cb, error_cb, progress_cb);
  auto worker = AMWorkManager();
  auto [ecm, tasks] =
      worker.load_tasks("/home/am/250414/250414.mp4", "/yes.mp4", host_m, "wsl",
                        "me", true, true, true);

  for (auto &task : tasks) {
    print(AMStr::amfmt("src: {}, dst: {}, size: {}", task.src, task.dst,
                       std::to_string(task.size)));
  }
  auto id = worker.transfer(tasks, host_m, cb_set, 32 * AMMB);

  while (true) {
    auto status = worker.get_status(id);
    if (status && (*status) == TaskStatus::Finished) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  auto result2 = worker.get_result(id);
  if (result2) {

  } else {
  }
}
