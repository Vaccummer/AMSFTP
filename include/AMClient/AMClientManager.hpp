#pragma once

#include "AMClient/AMCore.hpp"
#include "AMConfigManager.hpp"
#include <optional>
#include <utility>
#include <variant>

class AMClientManager {
public:
  enum class PoolKind { Transfer, Operation };
  using ClientMaintainerRef = ClientMaintainer;
  using PasswordCallback = AuthCallback;
  using DisconnectCallback =
      std::function<void(PoolKind, const std::shared_ptr<BaseClient> &,
                         const ECM &)>;

  explicit AMClientManager(AMConfigManager &cfg)
      : config_(cfg),
        transfer_clients_(ResolveHeartbeatInterval(cfg),
                          [this](const auto &client, const ECM &ecm) {
                            OnDisconnect(PoolKind::Transfer, client, ecm);
                          }),
        op_clients_(ResolveHeartbeatInterval(cfg),
                    [this](const auto &client, const ECM &ecm) {
                      OnDisconnect(PoolKind::Operation, client, ecm);
                    }) {
    LOCAL = transfer_clients_.GetHost("");
    CLIENT = LOCAL;
  }

  std::shared_ptr<BaseClient> CLIENT;
  std::shared_ptr<BaseClient> LOCAL;

  void SetPasswordCallback(PasswordCallback cb = {}) {
    password_cb_ = std::move(cb);
  }

  void SetDisconnectCallback(DisconnectCallback cb = {}) {
    disconnect_cb_ = std::move(cb);
  }

  ClientMaintainerRef &TransferClients() { return transfer_clients_; }
  ClientMaintainerRef &OperationClients() { return op_clients_; }

  std::vector<std::string> GetClientNames(PoolKind pool) {
    return ClientPool(pool).get_nicknames();
  }

  std::vector<AMCilent> GetClients(PoolKind pool) {
    return ClientPool(pool).get_clients();
  }

  std::pair<ECM, std::shared_ptr<BaseClient>>
  AddClient(const std::string &nickname, PoolKind pool, bool overwrite = false,
            bool connect = true, bool use_compression = false,
            ssize_t trace_num = 10, TraceCallback trace_cb = {}) {
    if (nickname.empty() || nickname == "local") {
      return {ECM{EC::Success, ""}, ClientPool(pool).GetHost("")};
    }

    if (!overwrite) {
      auto existing = ClientPool(pool).GetHost(nickname);
      if (existing) {
        return {ECM{EC::Success, ""}, existing};
      }
    }

    auto client_config = config_.GetClientConfig(nickname, use_compression);
    if (client_config.first.second != 0) {
      EC ec = static_cast<EC>(client_config.first.second);
      return {ECM{ec, client_config.first.first}, nullptr};
    }

    auto keys_result = config_.PrivateKeys(false);
    if (keys_result.first.second != 0) {
      EC ec = static_cast<EC>(keys_result.first.second);
      return {ECM{ec, keys_result.first.first}, nullptr};
    }

    auto created = CreateClient(client_config.second.request,
                                client_config.second.protocol, trace_num,
                                std::move(trace_cb),
                                client_config.second.buffer_size,
                                keys_result.second, password_cb_);
    if (!created.has_value()) {
      return {ECM{EC::OperationUnsupported, "Unsupported protocol"}, nullptr};
    }

    auto base_client = ToBaseClient(*created);
    if (!base_client) {
      return {ECM{EC::UnknownError, "Failed to create client"}, nullptr};
    }

    if (connect) {
      ECM rcm = base_client->Connect();
      if (rcm.first != EC::Success) {
        return {rcm, base_client};
      }
    }

    ClientPool(pool).add_client(nickname, base_client, true);
    return {ECM{EC::Success, ""}, base_client};
  }

  ECM RemoveClient(const std::string &nickname, PoolKind pool) {
    if (nickname.empty() || nickname == "local") {
      return {EC::InvalidArg, "Local client cannot be removed"};
    }
    auto existing = ClientPool(pool).GetHost(nickname);
    if (!existing) {
      return {EC::ClientNotFound, "Client not found"};
    }
    ClientPool(pool).remove_client(nickname);
    return {EC::Success, ""};
  }

  std::pair<ECM, std::shared_ptr<BaseClient>>
  CheckClient(const std::string &nickname, PoolKind pool, bool update = false,
              amf interrupt_flag = nullptr, int timeout_ms = -1,
              int64_t start_time = -1) {
    auto result =
        ClientPool(pool).test_client(nickname, update, interrupt_flag,
                                     timeout_ms, start_time);
    return result;
  }

private:
  AMConfigManager &config_;
  ClientMaintainerRef transfer_clients_;
  ClientMaintainerRef op_clients_;
  PasswordCallback password_cb_ = {};
  DisconnectCallback disconnect_cb_ = {};

  static int ResolveHeartbeatInterval(AMConfigManager &cfg) {
    int value = cfg.GetSettingInt({"client_manager", "heartbeat_interval_s"}, 60);
    if (value <= 0) {
      value = cfg.GetSettingInt({"ClientManager", "heartbeat_interval_s"}, 60);
    }
    return value > 0 ? value : 60;
  }

  ClientMaintainerRef &ClientPool(PoolKind pool) {
    return pool == PoolKind::Transfer ? transfer_clients_ : op_clients_;
  }

  static std::shared_ptr<BaseClient> ToBaseClient(const AMCilent &client) {
    return std::visit(
        [](const auto &ptr) -> std::shared_ptr<BaseClient> {
          return std::static_pointer_cast<BaseClient>(ptr);
        },
        client);
  }

  void OnDisconnect(PoolKind pool, const std::shared_ptr<BaseClient> &client,
                    const ECM &ecm) {
    if (disconnect_cb_) {
      CallCallbackSafe(disconnect_cb_, pool, client, ecm);
    }
  }
};
