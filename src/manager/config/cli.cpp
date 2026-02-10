#include "internal_func.hpp"

using namespace AMConfigInternal;

/**
 * @brief Construct an empty CLI adapter without callbacks.
 */
AMConfigCLIAdapter::AMConfigCLIAdapter() = default;

/**
 * @brief Bind the list callback used by CLI.
 */
void AMConfigCLIAdapter::SetListCallback(SimpleCallback cb) {
  list_cb_ = std::move(cb);
}

/**
 * @brief Bind the list-name callback used by CLI.
 */
void AMConfigCLIAdapter::SetListNameCallback(SimpleCallback cb) {
  list_name_cb_ = std::move(cb);
}

/**
 * @brief Bind the add callback used by CLI.
 */
void AMConfigCLIAdapter::SetAddCallback(SimpleCallback cb) {
  add_cb_ = std::move(cb);
}

/**
 * @brief Bind the modify callback used by CLI.
 */
void AMConfigCLIAdapter::SetModifyCallback(StringCallback cb) {
  modify_cb_ = std::move(cb);
}

/**
 * @brief Bind the delete callback used by CLI.
 */
void AMConfigCLIAdapter::SetDeleteCallback(StringCallback cb) {
  delete_cb_ = std::move(cb);
}

/**
 * @brief Bind the delete-list callback used by CLI.
 */
void AMConfigCLIAdapter::SetDeleteListCallback(StringsCallback cb) {
  delete_list_cb_ = std::move(cb);
}

/**
 * @brief Bind the query callback used by CLI.
 */
void AMConfigCLIAdapter::SetQueryCallback(StringCallback cb) {
  query_cb_ = std::move(cb);
}

/**
 * @brief Bind the query-list callback used by CLI.
 */
void AMConfigCLIAdapter::SetQueryListCallback(StringsCallback cb) {
  query_list_cb_ = std::move(cb);
}

/**
 * @brief Bind the rename callback used by CLI.
 */
void AMConfigCLIAdapter::SetRenameCallback(RenameCallback cb) {
  rename_cb_ = std::move(cb);
}

/**
 * @brief Bind the src callback used by CLI.
 */
void AMConfigCLIAdapter::SetSrcCallback(SimpleCallback cb) {
  src_cb_ = std::move(cb);
}

/**
 * @brief List configuration entries for CLI output.
 */
ECM AMConfigCLIAdapter::List() const {
  return list_cb_ ? list_cb_() : MissingCallback_("List");
}

/**
 * @brief List configuration entry names for CLI output.
 */
ECM AMConfigCLIAdapter::ListName() const {
  return list_name_cb_ ? list_name_cb_() : MissingCallback_("ListName");
}

/**
 * @brief Add a configuration entry for CLI output.
 */
ECM AMConfigCLIAdapter::Add() const {
  return add_cb_ ? add_cb_() : MissingCallback_("Add");
}

/**
 * @brief Modify a configuration entry.
 */
ECM AMConfigCLIAdapter::Modify(const std::string &nickname) const {
  return modify_cb_ ? modify_cb_(nickname) : MissingCallback_("Modify");
}

/**
 * @brief Delete a configuration entry.
 */
ECM AMConfigCLIAdapter::Delete(const std::string &nickname) const {
  return delete_cb_ ? delete_cb_(nickname) : MissingCallback_("Delete");
}

/**
 * @brief Delete configuration entries by list.
 */
ECM AMConfigCLIAdapter::Delete(const std::vector<std::string> &targets) const {
  return delete_list_cb_ ? delete_list_cb_(targets)
                         : MissingCallback_("DeleteList");
}

/**
 * @brief Query a configuration entry.
 */
ECM AMConfigCLIAdapter::Query(const std::string &nickname) const {
  return query_cb_ ? query_cb_(nickname) : MissingCallback_("Query");
}

/**
 * @brief Query configuration entries by list.
 */
ECM AMConfigCLIAdapter::Query(const std::vector<std::string> &targets) const {
  return query_list_cb_ ? query_list_cb_(targets)
                        : MissingCallback_("QueryList");
}

/**
 * @brief Rename a configuration entry.
 */
ECM AMConfigCLIAdapter::Rename(const std::string &old_nickname,
                               const std::string &new_nickname) {
  return rename_cb_ ? rename_cb_(old_nickname, new_nickname)
                    : MissingCallback_("Rename");
}

/**
 * @brief Print configuration source file locations for CLI.
 */
ECM AMConfigCLIAdapter::Src() const {
  return src_cb_ ? src_cb_() : MissingCallback_("Src");
}

/**
 * @brief Build a standardized error response for missing callbacks.
 */
ECM AMConfigCLIAdapter::MissingCallback_(const std::string &action) const {
  return Err(EC::ConfigNotInitialized,
             AMStr::amfmt("ConfigCLIAdapter missing callback: {}", action));
}
