#include "internal_func.hpp"

using namespace AMConfigInternal;
using cls = AMConfigCLIAdapter;

/**
 * @brief Construct an empty CLI adapter without callbacks.
 */
cls::AMConfigCLIAdapter() = default;

/**
 * @brief Bind the list callback used by CLI.
 */
void cls::SetListCallback(SimpleCallback cb) { list_cb_ = std::move(cb); }

/**
 * @brief Bind the list-name callback used by CLI.
 */
void cls::SetListNameCallback(SimpleCallback cb) {
  list_name_cb_ = std::move(cb);
}

/**
 * @brief Bind the add callback used by CLI.
 */
void cls::SetAddCallback(SimpleCallback cb) { add_cb_ = std::move(cb); }

/**
 * @brief Bind the modify callback used by CLI.
 */
void cls::SetModifyCallback(StringCallback cb) { modify_cb_ = std::move(cb); }

/**
 * @brief Bind the delete callback used by CLI.
 */
void cls::SetDeleteCallback(StringCallback cb) { delete_cb_ = std::move(cb); }

/**
 * @brief Bind the delete-list callback used by CLI.
 */
void cls::SetDeleteListCallback(StringsCallback cb) {
  delete_list_cb_ = std::move(cb);
}

/**
 * @brief Bind the query callback used by CLI.
 */
void cls::SetQueryCallback(StringCallback cb) { query_cb_ = std::move(cb); }

/**
 * @brief Bind the query-list callback used by CLI.
 */
void cls::SetQueryListCallback(StringsCallback cb) {
  query_list_cb_ = std::move(cb);
}

/**
 * @brief Bind the rename callback used by CLI.
 */
void cls::SetRenameCallback(RenameCallback cb) { rename_cb_ = std::move(cb); }

/**
 * @brief Bind the src callback used by CLI.
 */
void cls::SetSrcCallback(SimpleCallback cb) { src_cb_ = std::move(cb); }

/**
 * @brief List configuration entries for CLI output.
 */
ECM cls::List() const {
  return list_cb_ ? list_cb_() : MissingCallback_("List");
}

/**
 * @brief List configuration entry names for CLI output.
 */
ECM cls::ListName() const {
  return list_name_cb_ ? list_name_cb_() : MissingCallback_("ListName");
}

/**
 * @brief Add a configuration entry for CLI output.
 */
ECM cls::Add() const { return add_cb_ ? add_cb_() : MissingCallback_("Add"); }

/**
 * @brief Modify a configuration entry.
 */
ECM cls::Modify(const std::string &nickname) const {
  return modify_cb_ ? modify_cb_(nickname) : MissingCallback_("Modify");
}

/**
 * @brief Delete a configuration entry.
 */
ECM cls::Delete(const std::string &nickname) const {
  return delete_cb_ ? delete_cb_(nickname) : MissingCallback_("Delete");
}

/**
 * @brief Delete configuration entries by list.
 */
ECM cls::Delete(const std::vector<std::string> &targets) const {
  return delete_list_cb_ ? delete_list_cb_(targets)
                         : MissingCallback_("DeleteList");
}

/**
 * @brief Query a configuration entry.
 */
ECM cls::Query(const std::string &nickname) const {
  return query_cb_ ? query_cb_(nickname) : MissingCallback_("Query");
}

/**
 * @brief Query configuration entries by list.
 */
ECM cls::Query(const std::vector<std::string> &targets) const {
  return query_list_cb_ ? query_list_cb_(targets)
                        : MissingCallback_("QueryList");
}

/**
 * @brief Rename a configuration entry.
 */
ECM cls::Rename(const std::string &old_nickname,
                const std::string &new_nickname) {
  return rename_cb_ ? rename_cb_(old_nickname, new_nickname)
                    : MissingCallback_("Rename");
}

/**
 * @brief Print configuration source file locations for CLI.
 */
ECM cls::Src() const { return src_cb_ ? src_cb_() : MissingCallback_("Src"); }

/**
 * @brief Build a standardized error response for missing callbacks.
 */
ECM cls::MissingCallback_(const std::string &action) const {
  return Err(EC::ConfigNotInitialized,
             AMStr::amfmt("ConfigCLIAdapter missing callback: {}", action));
}
