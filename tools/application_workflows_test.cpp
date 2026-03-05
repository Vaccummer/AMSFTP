#include "application/client/ClientSessionWorkflows.hpp"
#include "application/config/ConfigWorkflows.hpp"
#include "application/config/HostProfileWorkflows.hpp"
#include "application/transfer/TransferWorkflows.hpp"
#include "domain/transfer/TransferPorts.hpp"
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {
/**
 * @brief Simple assertion helper for boolean checks.
 */
void ExpectTrue(bool condition, const std::string &message, int *failures) {
  if (condition) {
    return;
  }
  if (failures) {
    ++(*failures);
  }
  std::cerr << "[FAIL] " << message << std::endl;
}

/**
 * @brief Assertion helper for enum/primitive equality.
 */
template <typename T>
void ExpectEq(const T &lhs, const T &rhs, const std::string &message,
              int *failures) {
  ExpectTrue(lhs == rhs, message, failures);
}

/**
 * @brief Fake client-session gateway used for application workflow tests.
 */
class FakeClientSessionGateway
    : public AMApplication::ClientWorkflow::IClientSessionGateway {
public:
  ECM ConnectNickname(const std::string &nickname, bool force, bool switch_client,
                      amf interrupt_flag) override {
    (void)interrupt_flag;
    connect_nickname_calls++;
    last_nickname = nickname;
    last_force = force;
    last_switch_client = switch_client;
    return connect_nickname_result;
  }

  ECM ChangeCurrentClient(const std::string &nickname,
                          amf interrupt_flag) override {
    (void)interrupt_flag;
    change_client_calls++;
    last_change_nickname = nickname;
    return change_client_result;
  }

  ECM ConnectSftp(const std::string &nickname, const std::string &user_at_host,
                  int64_t port, const std::string &password,
                  const std::string &keyfile, amf interrupt_flag) override {
    (void)interrupt_flag;
    connect_sftp_calls++;
    last_nickname = nickname;
    last_user_at_host = user_at_host;
    last_port = port;
    last_password = password;
    last_keyfile = keyfile;
    return connect_protocol_result;
  }

  ECM ConnectFtp(const std::string &nickname, const std::string &user_at_host,
                 int64_t port, const std::string &password,
                 const std::string &keyfile, amf interrupt_flag) override {
    (void)interrupt_flag;
    connect_ftp_calls++;
    last_nickname = nickname;
    last_user_at_host = user_at_host;
    last_port = port;
    last_password = password;
    last_keyfile = keyfile;
    return connect_protocol_result;
  }

  ECM ListClients(bool detail, amf interrupt_flag) override {
    (void)interrupt_flag;
    list_clients_calls++;
    last_detail = detail;
    return list_clients_result;
  }

  ECM DisconnectClients(const std::vector<std::string> &nicknames) override {
    disconnect_clients_calls++;
    disconnected = nicknames;
    return disconnect_clients_result;
  }

  ECM StatPaths(const std::vector<std::string> &paths,
                amf interrupt_flag) override {
    (void)interrupt_flag;
    stat_paths_calls++;
    last_paths = paths;
    return stat_paths_result;
  }

  ECM ListPath(const std::string &path, bool list_like, bool show_all,
               amf interrupt_flag) override {
    (void)interrupt_flag;
    list_path_calls++;
    last_path = path;
    last_list_like = list_like;
    last_show_all = show_all;
    return list_path_result;
  }

  ECM connect_nickname_result = Ok();
  ECM change_client_result = Ok();
  ECM connect_protocol_result = Ok();
  ECM list_clients_result = Ok();
  ECM disconnect_clients_result = Ok();
  ECM stat_paths_result = Ok();
  ECM list_path_result = Ok();

  int connect_nickname_calls = 0;
  int change_client_calls = 0;
  int connect_sftp_calls = 0;
  int connect_ftp_calls = 0;
  int list_clients_calls = 0;
  int disconnect_clients_calls = 0;
  int stat_paths_calls = 0;
  int list_path_calls = 0;

  std::string last_nickname = "";
  std::string last_change_nickname = "";
  std::string last_user_at_host = "";
  std::string last_password = "";
  std::string last_keyfile = "";
  std::string last_path = "";
  int64_t last_port = 0;
  bool last_force = false;
  bool last_switch_client = false;
  bool last_detail = false;
  bool last_list_like = false;
  bool last_show_all = false;
  std::vector<std::string> disconnected = {};
  std::vector<std::string> last_paths = {};
};

/**
 * @brief Fake path substitution port that returns values unchanged.
 */
class PassthroughSubstitutor
    : public AMApplication::TransferWorkflow::IPathSubstitutionPort {
public:
  std::string SubstitutePathLike(const std::string &raw) const override {
    return raw;
  }

  std::vector<std::string>
  SubstitutePathLike(const std::vector<std::string> &raw) const override {
    return raw;
  }
};

/**
 * @brief Fake transfer executor that records sync/async calls.
 */
class FakeTransferExecutor : public AMDomain::transfer::ITransferExecutorPort {
public:
  ECM Transfer(const std::vector<UserTransferSet> &transfer_sets, bool quiet,
               amf interrupt_flag) override {
    (void)interrupt_flag;
    transfer_calls++;
    last_sets = transfer_sets;
    last_quiet = quiet;
    return transfer_result;
  }

  ECM TransferAsync(const std::vector<UserTransferSet> &transfer_sets, bool quiet,
                    amf interrupt_flag) override {
    (void)interrupt_flag;
    transfer_async_calls++;
    last_sets = transfer_sets;
    last_quiet = quiet;
    return transfer_async_result;
  }

  ECM transfer_result = Ok();
  ECM transfer_async_result = Ok();
  int transfer_calls = 0;
  int transfer_async_calls = 0;
  bool last_quiet = false;
  std::vector<UserTransferSet> last_sets = {};
};

/**
 * @brief Fake config saver for save-order checks.
 */
class FakeHostSaver : public AMApplication::ConfigWorkflow::IHostConfigSaver {
public:
  explicit FakeHostSaver(std::vector<std::string> *order) : order_(order) {}

  ECM SaveHostConfig() override {
    if (order_) {
      order_->push_back("host");
    }
    return result;
  }

  ECM result = Ok();

private:
  std::vector<std::string> *order_ = nullptr;
};

/**
 * @brief Fake var config saver for save-order checks.
 */
class FakeVarSaver : public AMApplication::ConfigWorkflow::IVarConfigSaver {
public:
  explicit FakeVarSaver(std::vector<std::string> *order) : order_(order) {}

  ECM SaveVarConfig(bool dump_now) override {
    if (order_) {
      order_->push_back(dump_now ? "var_dump" : "var_lazy");
    }
    return result;
  }

  ECM result = Ok();

private:
  std::vector<std::string> *order_ = nullptr;
};

/**
 * @brief Fake prompt config saver for save-order checks.
 */
class FakePromptSaver
    : public AMApplication::ConfigWorkflow::IPromptConfigSaver {
public:
  explicit FakePromptSaver(std::vector<std::string> *order) : order_(order) {}

  ECM SavePromptConfig(bool dump_now) override {
    if (order_) {
      order_->push_back(dump_now ? "prompt_dump" : "prompt_lazy");
    }
    return result;
  }

  ECM result = Ok();

private:
  std::vector<std::string> *order_ = nullptr;
};

/**
 * @brief Validate protocol-connect workflow routing.
 */
void TestConnectProtocolClient(int *failures) {
  FakeClientSessionGateway gateway;
  const auto result = AMApplication::ClientWorkflow::ConnectProtocolClient(
      gateway, ClientProtocol::SFTP, {"demo", "user@host"}, 22, "pw", "key",
      nullptr);
  ExpectEq(result.rcm.first, EC::Success, "connect protocol should succeed",
           failures);
  ExpectTrue(result.enter_interactive, "connect should request interactive mode",
             failures);
  ExpectEq(gateway.connect_sftp_calls, 1, "sftp gateway should be called once",
           failures);
  ExpectEq(gateway.last_nickname, std::string("demo"),
           "nickname should pass through protocol workflow", failures);
}

/**
 * @brief Validate new client utility workflows used by CLI handlers.
 */
void TestClientUtilityWorkflows(int *failures) {
  FakeClientSessionGateway gateway;
  const ECM list_rcm =
      AMApplication::ClientWorkflow::ExecuteClientList(gateway, true, nullptr);
  const ECM stat_rcm = AMApplication::ClientWorkflow::ExecuteStatPaths(
      gateway, {"a", "b"}, nullptr);
  const ECM ls_rcm = AMApplication::ClientWorkflow::ExecuteListPath(
      gateway, "/tmp", true, false, nullptr);
  const ECM disconnect_rcm = AMApplication::ClientWorkflow::ExecuteClientDisconnect(
      gateway, {"c1", "c2"});
  ExpectEq(list_rcm.first, EC::Success, "list workflow should succeed", failures);
  ExpectEq(stat_rcm.first, EC::Success, "stat workflow should succeed", failures);
  ExpectEq(ls_rcm.first, EC::Success, "ls workflow should succeed", failures);
  ExpectEq(disconnect_rcm.first, EC::Success,
           "disconnect workflow should succeed", failures);
  ExpectEq(gateway.list_clients_calls, 1, "list workflow should call gateway",
           failures);
  ExpectEq(gateway.stat_paths_calls, 1, "stat workflow should call gateway",
           failures);
  ExpectEq(gateway.list_path_calls, 1, "ls workflow should call gateway",
           failures);
  ExpectEq(gateway.disconnect_clients_calls, 1,
           "disconnect workflow should call gateway", failures);
}

/**
 * @brief Validate transfer workflow async-suffix orchestration.
 */
void TestTransferExecutionWorkflow(int *failures) {
  const AMApplication::TransferWorkflow::TransferBuildArgs args{
      {"src.txt", "dst.txt", "&"}, "", false, false, false, false, false};
  AMApplication::TransferWorkflow::TransferExecutionOptions options{};
  options.run_async_from_context = false;
  options.quiet = true;
  options.accept_ampersand_suffix = true;

  PassthroughSubstitutor substitutor;
  FakeTransferExecutor executor;
  const auto result = AMApplication::TransferWorkflow::ExecuteTransfer(
      args, options, substitutor, executor, nullptr);
  ExpectEq(result.rcm.first, EC::Success, "transfer workflow should succeed",
           failures);
  ExpectTrue(result.run_async, "transfer workflow should switch to async", failures);
  ExpectEq(executor.transfer_async_calls, 1,
           "transfer async executor should be called once", failures);
  ExpectEq(executor.transfer_calls, 0,
           "sync transfer executor should not be called", failures);
  ExpectEq(result.transfer_set.srcs.size(), static_cast<size_t>(1),
           "transfer set should normalize one source", failures);
  ExpectEq(result.transfer_set.dst, std::string("dst.txt"),
           "transfer set should normalize destination", failures);
}

/**
 * @brief Validate config save workflow order and short-circuit behavior.
 */
void TestConfigSaveWorkflow(int *failures) {
  std::vector<std::string> order;
  FakeHostSaver host_saver(&order);
  FakeVarSaver var_saver(&order);
  FakePromptSaver prompt_saver(&order);

  ECM rcm = AMApplication::ConfigWorkflow::SaveAllFromCli(
      host_saver, var_saver, prompt_saver);
  ExpectEq(rcm.first, EC::Success, "config save workflow should succeed",
           failures);
  ExpectEq(order.size(), static_cast<size_t>(3),
           "config save workflow should call 3 savers", failures);
  ExpectEq(order[0], std::string("host"), "host saver should run first", failures);
  ExpectEq(order[1], std::string("var_dump"),
           "var saver should run second with dump_now", failures);
  ExpectEq(order[2], std::string("prompt_dump"),
           "prompt saver should run third with dump_now", failures);

  order.clear();
  var_saver.result = Err(EC::CommonFailure, "var save failed");
  rcm = AMApplication::ConfigWorkflow::SaveAllFromCli(host_saver, var_saver,
                                                      prompt_saver);
  ExpectEq(rcm.first, EC::CommonFailure,
           "config save should short-circuit on var failure", failures);
  ExpectEq(order.size(), static_cast<size_t>(2),
           "prompt saver should not run after var failure", failures);
}
} // namespace

/**
 * @brief Run dedicated application workflow tests.
 */
int main() {
  int failures = 0;
  TestConnectProtocolClient(&failures);
  TestClientUtilityWorkflows(&failures);
  TestTransferExecutionWorkflow(&failures);
  TestConfigSaveWorkflow(&failures);
  if (failures == 0) {
    std::cout << "[PASS] application workflow tests" << std::endl;
    return 0;
  }
  std::cerr << "[FAIL] application workflow tests: " << failures
            << " failure(s)" << std::endl;
  return 1;
}
