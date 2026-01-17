#include "AMBindingTools.hpp"
#include "AMCore.hpp"
#include "AMDataClass.hpp"
#include "AMEnum.hpp"
#include "AMPath.hpp"

namespace AMBIDINGS {
void BindEnum(py::module &m) {
  bind_enum_auto<ErrorCode>(m, "ErrorCode");
  bind_enum_auto<OS_TYPE>(m, "OS_TYPE");
  bind_enum_auto<PathType>(m, "PathType");

  bind_enum_auto<TraceLevel>(m, "TraceLevel");
  bind_enum_auto<TransferControl>(m, "TransferControl");
  bind_enum_auto<AMFS::SepType>(m, "SepType");
  bind_enum_auto<AMFS::SearchType>(m, "SearchType");
}
void BindConRequest(py::module &m) {
  auto cls = py::class_<ConRequst, std::shared_ptr<ConRequst>>(m, "ConRequst")
                 .def_readwrite("nickname", &ConRequst::nickname,
                                "Unique nickname for the host and connection")
                 .def_readwrite("hostname", &ConRequst::hostname,
                                "Hostname or IP address of the remote server")
                 .def_readwrite("username", &ConRequst::username)
                 .def_readwrite("port", &ConRequst::port)
                 .def_readwrite("password", &ConRequst::password)
                 .def_readwrite("keyfile", &ConRequst::keyfile,
                                "Dedicated key file for this authentication")
                 .def_readwrite("compression", &ConRequst::compression,
                                "Enable compression")
                 .def_readwrite("timeout_s", &ConRequst::timeout_s)
                 .def_readwrite("trash_dir", &ConRequst::trash_dir,
                                "Trash directory for saferm function");
  cls.def(py::init<const std::string &, const std::string &, const std::string &,
                   int, std::string, std::string, bool, size_t, std::string>(),
          py::arg("nickname") = "", py::arg("hostname") = "",
          py::arg("username") = "", py::arg("port") = 22,
          py::arg("password") = "", py::arg("keyfile") = "",
          py::arg("compression") = false, py::arg("timeout_s") = 3,
          py::arg("trash_dir") = "");
}
void BindTransferCallback(py::module &m) {
  auto cls =
      py::class_<TransferCallback, std::shared_ptr<TransferCallback>>(
          m, "TransferCallback", "Callback function Gather")
          .def(py::init<py::object, py::object, py::object>(),
               py::arg("total_size") = py::none(),
               py::arg("error") = py::none(), py::arg("progress") = py::none())
          .def("SetErrorCB", &TransferCallback::SetErrorCB,
               py::arg("error") = py::none())
          .def("SetProgressCB", &TransferCallback::SetProgressCB,
               py::arg("progress") = py::none())
          .def("SetTotalSizeCB", &TransferCallback::SetTotalSizeCB,
               py::arg("total_size") = py::none());
}
void BindProgressCBInfo(py::module &m) {
  auto cls =
      py::class_<ProgressCBInfo, std::shared_ptr<ProgressCBInfo>>(
          m, "ProgressCBInfo", "Progress Callback Information")
          .def_readwrite("src", &ProgressCBInfo::src, "Source path")
          .def_readwrite("dst", &ProgressCBInfo::dst, "Destination path")
          .def_readwrite("src_host", &ProgressCBInfo::src_host, "Source host")
          .def_readwrite("dst_host", &ProgressCBInfo::dst_host,
                         "Destination host")
          .def_readwrite("this_size", &ProgressCBInfo::this_size,
                         "Size of the current file transfered")
          .def_readwrite("file_size", &ProgressCBInfo::file_size,
                         "This file size")
          .def_readwrite("accumulated_size", &ProgressCBInfo::accumulated_size,
                         "Size of the total files transfered")
          .def_readwrite("total_size", &ProgressCBInfo::total_size,
                         "Total size of the transfer");
  cls.def(py::init<const std::string &, const std::string &, const std::string &,
                   const std::string &, uint64_t, uint64_t, const uint64_t &,
                   const uint64_t &>(),
          py::arg("src") = "", py::arg("dst") = "", py::arg("src_host") = "",
          py::arg("dst_host") = "", py::arg("this_size") = 0,
          py::arg("file_size") = 0, py::arg("accumulated_size") = 0,
          py::arg("total_size") = 0);
}
void BindErrorCBInfo(py::module &m) {
  auto cls =
      py::class_<ErrorCBInfo, std::shared_ptr<ErrorCBInfo>>(
          m, "ErrorCBInfo", "Error Callback Information")
          .def_readwrite("ecm", &ErrorCBInfo::ecm, "Error Code and Message")
          .def_readwrite("src", &ErrorCBInfo::src, "Source path")
          .def_readwrite("dst", &ErrorCBInfo::dst, "Destination path")
          .def_readwrite("src_host", &ErrorCBInfo::src_host, "Source host")
          .def_readwrite("dst_host", &ErrorCBInfo::dst_host,
                         "Destination host");
  cls.def(py::init<std::pair<ErrorCode, std::string>, std::string, std::string,
                   std::string, std::string>(),
          py::arg("ecm") = ECM(EC::Success, ""), py::arg("src") = "",
          py::arg("dst") = "", py::arg("src_host") = "",
          py::arg("dst_host") = "");
}
void BindAuthCBInfo(py::module &m) {
  auto cls =
      py::class_<AuthCBInfo, std::shared_ptr<AuthCBInfo>>(
          m, "AuthCBInfo", "Authentication Callback Information")
          .def_readwrite("NeedPassword", &AuthCBInfo::NeedPassword,
                         "If true, python password callback need to return "
                         "password, if false, callback function just "
                         "tells you the password is wrong")
          .def_readwrite("request", &AuthCBInfo::request)
          .def_readwrite("trial_times", &AuthCBInfo::trial_times,
                         "Number of times the password has been tried");
  cls.def(py::init<bool, ConRequst, int>(), py::arg("NeedPassword") = false,
          py::arg("request") = ConRequst(), py::arg("trial_times") = 0);
}
void BindTransferTask(py::module &m) {
  auto cls =
      py::class_<TransferTask, std::shared_ptr<TransferTask>>(m, "TransferTask",
                                                              "Transfer Task")
          .def_readwrite("src", &TransferTask::src, "Source path")
          .def_readwrite("dst", &TransferTask::dst, "Destination path")
          .def_readwrite("src_host", &TransferTask::src_host, "Source host")
          .def_readwrite("dst_host", &TransferTask::dst_host,
                         "Destination host")
          .def_readwrite("size", &TransferTask::size, "Size of the src");
  cls.def(py::init<const std::string &, const std::string &, const std::string &,
                   const std::string &, uint64_t, PathType>(),
          py::arg("src"), py::arg("dst"), py::arg("src_host"),
          py::arg("dst_host"), py::arg("size"),
          py::arg("path_type") = PathType::FILE);
}
void BindTraceInfo(py::module &m) {
  auto cls = py::class_<TraceInfo, std::shared_ptr<TraceInfo>>(
                 m, "TraceInfo", "Trace Information")
                 .def_readwrite("level", &TraceInfo::level)
                 .def_readwrite("error_code", &TraceInfo::error_code)
                 .def_readwrite("nickname", &TraceInfo::nickname,
                                "Nickname of the connection client")
                 .def_readwrite("target", &TraceInfo::target,
                                "Target of the operation")
                 .def_readwrite("action", &TraceInfo::action,
                                "Name of the action function")
                 .def_readwrite("message", &TraceInfo::message,
                                "Inform message or Error message");
  cls.def(py::init<TraceLevel, ErrorCode, std::string, std::string, std::string,
                   std::string>(),
          py::arg("level"), py::arg("error_code"), py::arg("nickname"),
          py::arg("target"), py::arg("action"), py::arg("message"));
}
void BindPathInfo(py::module &m) {
  auto cls =
      py::class_<PathInfo, std::shared_ptr<PathInfo>>(
          m, "PathInfo", "Path Information DataClass")
          .def_readwrite("name", &PathInfo::name, "Basename of the path")
          .def_readwrite("path", &PathInfo::path, "Full path")
          .def_readwrite("dir", &PathInfo::dir, "Parent directory of the path")
          .def_readwrite("owner", &PathInfo::owner, "Owner of the path")
          .def_readwrite("size", &PathInfo::size, "Size of the path")
          .def_readwrite("create_time", &PathInfo::create_time,
                         "Create time of the path")
          .def_readwrite("access_time", &PathInfo::access_time,
                         "Access time of the path")
          .def_readwrite("modify_time", &PathInfo::modify_time,
                         "Modify time of the path")
          .def_readwrite("mode_int", &PathInfo::mode_int,
                         "Mode of the path as integer")
          .def_readwrite("mode_str", &PathInfo::mode_str,
                         "Mode of the path as string")
          .def_readwrite("type", &PathInfo::type, "Type of the path");
  cls.def(py::init<std::string, std::string, std::string, std::string, uint64_t,
                   double, double, double, PathType, uint64_t, std::string>(),
          py::arg("name"), py::arg("path"), py::arg("dir"), py::arg("owner"),
          py::arg("size"), py::arg("create_time"), py::arg("access_time"),
          py::arg("modify_time"), py::arg("type"), py::arg("mode_int"),
          py::arg("mode_str"));
}

void BindAMTracer(py::module &m) {
  auto cls = py::class_<AMTracer, std::shared_ptr<AMTracer>>(
      m, "AMTracer", "Base of the Client, Manage Trace action and record");
  cls.def(py::init<ConRequst, int, py::object>(), py::arg("request"),
          py::arg("buffer_capacity") = 10, py::arg("trace_cb") = py::none());
  cls.def("SetPublicVar", &AMTracer::SetPublicVar, py::arg("key"),
          py::arg("value"), py::arg("overwrite") = false);
  cls.def("GetPublicVar", &AMTracer::GetPublicVar, py::arg("key"),
          py::arg("default_value") = py::none());
  auto_def(cls, "DelPublicVar", &AMTracer::DelPublicVar).arg("key");
  auto_def(cls, "ClearPublicVar", &AMTracer::ClearPublicVar);
  auto_def(cls, "GetAllPublicVars", &AMTracer::GetAllPublicVars);
  auto_def(cls, "GetTraceNum", &AMTracer::GetTraceNum);
  auto_def(cls, "LastTrace", &AMTracer::LastTrace);
  auto_def(cls, "GetAllTraces", &AMTracer::GetAllTraces);
  auto_def(cls, "ClearTracer", &AMTracer::ClearTracer);
  auto_def(cls, "TracerCapacity", &AMTracer::TracerCapacity)
      .arg("size", -1)
      .doc("Give Negative Number to Get Capacity, Give Positive Number to Set "
           "Capacity");
  auto_def(
      cls, "trace",
      py::overload_cast<const TraceLevel &, const EC &, const std::string &,
                        const std::string &, const std::string &>(
          &AMTracer::trace))
      .arg("level")
      .arg("error_code")
      .arg("target")
      .arg("action")
      .arg("msg");
  auto_def(cls, "trace", py::overload_cast<const TraceInfo &>(&AMTracer::trace))
      .arg("trace_info");
  auto_def(cls, "SetTraceState", &AMTracer::SetTraceState).arg("is_pause");
  cls.def("SetPyTrace", &AMTracer::SetPyTrace, py::arg("trace_cb") = py::none(),
          "callable[TraceInfo, None], if none, disable py trace");
  auto_def(cls, "GetNickname", &AMTracer::GetNickname);
  auto_def(cls, "GetRequest", &AMTracer::GetRequest);
}

void BindBaseClient(py::module &m) {
  auto cls = py::class_<BaseClient, std::shared_ptr<BaseClient>, AMTracer,
                        AMFS::BasePathMatch>(
      m, "BaseClient",
      "Abstract Base Client Class, Implement by FTP, SFTP Client");
  auto_def(cls, "GetProtocol", &BaseClient::GetProtocol)
      .doc("Get the protocol of the client, Base and Unknown are not valid");
  auto_def(cls, "GetProtocolName", &BaseClient::GetProtocolName)
      .doc("Get the string name of the protocol of the client");
  auto_def(cls, "BufferSize", &BaseClient::TransferRingBufferSize)
      .arg("size", -1,
           "Give Negative Number to Get Buffer Size, Give Positive Number to "
           "Set Buffer Size")
      .doc(fmt::format("Buffer Size is restricted between {} and {}",
                       AMMinBufferSize, AMMaxBufferSize)
               .c_str());
}

void BindAMSession(py::module &m) {
  auto cls = py::class_<AMSession, std::shared_ptr<AMSession>, BaseClient>(
      m, "AMSession",
      "An intermediate class between BaseClient and SFTP Client, Manage SSH "
      "Connection and Session");
  cls.def(py::init<const ConRequst &, const std::vector<std::string> &,
                   unsigned int, py::object, py::object>(),
          py::arg("request"), py::arg("keys"), py::arg("tracer_capacity") = 10,
          py::arg("trace_cb") = py::none(), py::arg("auth_cb") = py::none());
  auto_def(cls, "GetLibssh2Version", &AMSession::GetLibssh2Version)
      .doc("Get the version of the libssh2 library");
  auto_def(cls, "IsValidKey", &AMSession::IsValidKey)
      .arg("key")
      .doc("Check if the keyfile is valid");
  auto_def(cls, "GetKeys", &AMSession::GetKeys).doc("Get the list of the keys");
  auto_def(cls, "SetKeys", &AMSession::SetKeys)
      .arg("keys")
      .doc("Set the list of the keys");
  auto_def(cls, "GetState", &AMSession::GetState)
      .doc("Get the cached state of the session");
  auto_def(cls, "BaseCheck", &AMSession::BaseCheck)
      .doc("Attemp to stat home path to test the connection");
  auto_def(cls, "BaseConnect", &AMSession::BaseConnect)
      .doc("Establish ssh ssesion and sftp");
  auto_def(cls, "GetLastEC", &AMSession::GetLastEC)
      .doc("Get the last error code of the session");
  auto_def(cls, "GetLastErrorMsg", &AMSession::GetLastErrorMsg)
      .doc("Get the last error message of the session");
  cls.def("SetAuthCallback", &AMSession::SetAuthCallback,
          py::arg("auth_cb") = py::none());
}

void BindAMSFTPClient(py::module &m) {
  auto cls = py::class_<AMSFTPClient, std::shared_ptr<AMSFTPClient>, AMSession>(
      m, "AMSFTPClient", "An SFTP Client Class Based on libssh2");
  cls.def(py::init<const ConRequst &, const std::vector<std::string> &,
                   unsigned int, py::object, py::object>(),
          py::arg("request"), py::arg("keys"), py::arg("tracer_capacity") = 10,
          py::arg("trace_cb") = py::none(), py::arg("auth_cb") = py::none());
  auto_def(cls, "GetOSType", &AMSFTPClient::GetOSType)
      .doc("Get the OS type of the server");
  auto_def(cls, "GetHomeDir", &AMSFTPClient::GetHomeDir);
  auto_def(cls, "Check", &AMSFTPClient::Check)
      .arg("need_trace", false)
      .doc("Check will force to update state, use GetState to get the cached "
           "state");
  auto_def(cls, "Connect", &AMSFTPClient::Connect)
      .arg("force", false)
      .doc("if force=True, will disconnect and reconnect, else will check "
           "first, if wrong then reconnect");
  auto_def(cls, "GetTrashDir", &AMSFTPClient::GetTrashDir);
  auto_def(cls, "SetTrashDir", &AMSFTPClient::SetTrashDir)
      .arg("trash_dir", "")
      .doc("Set the trash directory and create it if it doesn't exist, if "
           "wrong, will return error");

  auto_def(cls, "EnsureTrashDir", &AMSFTPClient::EnsureTrashDir)
      .doc("Ensure the trash directory exists, if not, create it. If path is "
           "empty, will use default trash directory");
  auto_def(cls, "realpath", &AMSFTPClient::realpath)
      .arg("path", "")
      .doc("Use server to parse the path, ~ parsed in local, symlink parsed in "
           "server");
  auto_def(cls, "chmod", &AMSFTPClient::chmod)
      .arg("path", "")
      .arg("mode")
      .doc("Recursive change the mode of the file");
  auto_def(cls, "stat", &AMSFTPClient::stat)
      .arg("path")
      .doc("Get the detailed information about the file");
  auto_def(cls, "listdir", &AMSFTPClient::listdir)
      .arg("path")
      .arg("max_time_ms", -1)
      .doc("List directory contents");
  auto_def(cls, "exists", &AMSFTPClient::exists)
      .arg("path")
      .doc("Check if path exists");
  auto_def(cls, "is_regular", &AMSFTPClient::is_regular)
      .arg("path")
      .doc("Check if path is a regular file");
  auto_def(cls, "is_dir", &AMSFTPClient::is_dir)
      .arg("path")
      .doc("Check if path is a directory");
  auto_def(cls, "is_symlink", &AMSFTPClient::is_symlink)
      .arg("path")
      .doc("Check if path is a symlink");
  auto_def(cls, "get_path_type", &AMSFTPClient::get_path_type)
      .arg("path")
      .doc("Get the type of the path");
  auto_def(cls, "mkdir", &AMSFTPClient::mkdir)
      .arg("path")
      .doc("Create a directory");
  auto_def(cls, "mkdirs", &AMSFTPClient::mkdirs)
      .arg("path")
      .doc("Create directories recursively");
  auto_def(cls, "rmdir", &AMSFTPClient::rmdir)
      .arg("path")
      .doc("Remove an empty directory");
  auto_def(cls, "rmfile", &AMSFTPClient::rmfile)
      .arg("path")
      .doc("Remove a file permanently");
  auto_def(cls, "remove", &AMSFTPClient::remove)
      .arg("path")
      .doc("Remove file or directory recursively");
  auto_def(cls, "saferm", &AMSFTPClient::saferm)
      .arg("path")
      .doc("Safely remove by moving to trash");
  auto_def(cls, "rename", &AMSFTPClient::rename)
      .arg("src")
      .arg("dst")
      .arg("overwrite", false)
      .doc("Rename file/directory");
  auto_def(cls, "move", &AMSFTPClient::move)
      .arg("src")
      .arg("dst")
      .arg("need_mkdir", false)
      .arg("force_write", false)
      .doc("Move file/directory to destination folder");
  auto_def(cls, "copy", &AMSFTPClient::copy)
      .arg("src")
      .arg("dst")
      .arg("need_mkdir", false)
      .doc("Copy file/directory on remote server using shell command");
  auto_def(cls, "getsize", &AMSFTPClient::getsize)
      .arg("path")
      .arg("ignore_special_file", true)
      .doc("Get total size of file or directory");
  auto_def(cls, "walk", &AMSFTPClient::walk)
      .arg("path")
      .arg("max_depth", -1)
      .arg("ignore_special_file", true)
      .doc("Walk directory tree, returns list of (dirpath, files) tuples");
  auto_def(cls, "iwalk", &AMSFTPClient::iwalk)
      .arg("path")
      .arg("ignore_special_file", true)
      .doc("Deep walk to get all leaf paths");
  auto_def(cls, "ConductCmd", &AMSFTPClient::ConductCmd)
      .arg("cmd")
      .arg("max_time_s", -1)
      .doc("Execute shell command on remote server");
  auto_def(cls, "TerminateCmd", &AMSFTPClient::TerminateCmd)
      .doc("Terminate currently running command");
  auto_def(cls, "GetRTT", &AMSFTPClient::GetRTT)
      .arg("times", 5)
      .doc("Get round-trip time to server");
}

void BindAMFTPClient(py::module &m) {
  auto cls = py::class_<AMFTPClient, std::shared_ptr<AMFTPClient>, BaseClient>(
      m, "AMFTPClient", "An FTP Client Class Based on libcurl");
  cls.def(py::init<ConRequst, size_t, py::object>(), py::arg("request"),
          py::arg("buffer_capacity") = 10, py::arg("trace_cb") = py::none());

  auto_def(cls, "Check", &AMFTPClient::Check)
      .arg("need_trace", false)
      .doc("Check FTP connection status");
  auto_def(cls, "Connect", &AMFTPClient::Connect)
      .arg("force", false)
      .doc("Connect to FTP server");
  auto_def(cls, "listdir", &AMFTPClient::listdir)
      .arg("path")
      .arg("max_time_ms", -1)
      .doc("List directory contents");
  auto_def(cls, "stat", &AMFTPClient::stat)
      .arg("path")
      .doc("Get file information");
  auto_def(cls, "exists", &AMFTPClient::exists)
      .arg("path")
      .doc("Check if path exists");
  auto_def(cls, "is_dir", &AMFTPClient::is_dir)
      .arg("path")
      .doc("Check if path is a directory");
  auto_def(cls, "mkdir", &AMFTPClient::mkdir)
      .arg("path")
      .doc("Create a directory");
  auto_def(cls, "mkdirs", &AMFTPClient::mkdirs)
      .arg("path")
      .doc("Create directories recursively");
  auto_def(cls, "rmdir", &AMFTPClient::rmdir)
      .arg("path")
      .doc("Remove an empty directory");
}

void BindHostMaintainer(py::module &m) {
  auto cls = py::class_<HostMaintainer, std::shared_ptr<HostMaintainer>>(
      m, "HostMaintainer", "Host Connection Manager with Heartbeat");
  cls.def(py::init<int, py::object>(), py::arg("heartbeat_interval_s") = 60,
          py::arg("disconnect_cb") = py::none(),
          "Create host maintainer with heartbeat monitoring");

  cls.def("get_hosts", &HostMaintainer::get_hosts,
          "Get list of all registered host nicknames");
  cls.def("get_clients", &HostMaintainer::get_clients,
          "Get list of all registered clients");
  cls.def("add_host", &HostMaintainer::add_host, py::arg("nickname"),
          py::arg("client"), py::arg("overwrite") = false,
          "Add a host client to the maintainer");
  cls.def("remove_host", &HostMaintainer::remove_host, py::arg("nickname"),
          "Remove a host from the maintainer");
  cls.def("get_host", &HostMaintainer::get_host, py::arg("nickname"),
          "Get a host client by nickname");
  cls.def("test_host", &HostMaintainer::test_host, py::arg("nickname"),
          py::arg("update") = false, "Test host connection status");
}

void BindAMSFTPWorker(py::module &m) {
  auto cls = py::class_<AMSFTPWorker, std::shared_ptr<AMSFTPWorker>>(
      m, "AMSFTPWorker", "High-performance file transfer worker");
  cls.def(py::init<const TransferCallback &, float>(), py::arg("callback"),
          py::arg("cb_interval_s") = 0.2f,
          "Create transfer worker with callback");

  cls.def("SetState", &AMSFTPWorker::SetState, py::arg("state"),
          "Set transfer state");
  cls.def("GetState", &AMSFTPWorker::GetState, "Get current transfer state");
  cls.def("EraseOverlapTasks", &AMSFTPWorker::EraseOverlapTasks,
          py::arg("tasks"), "Remove duplicate tasks from list");
  cls.def("transfer", &AMSFTPWorker::transfer, py::arg("tasks"),
          py::arg("hostm"), py::arg("buffer_size") = -1,
          "Execute batch file transfers");

  // Public members
  cls.def_readwrite("callback", &AMSFTPWorker::callback,
                    "Transfer callback object");
  // pd is not bound because ProgressData cannot be copied
}

} // namespace AMBIDINGS
PYBIND11_MODULE(AMSFTP, m) {
  m.doc() = "A SFTP Client Module Based on libssh2";
  auto em = m.def_submodule("AMEnum", "Enum Classes");
  auto data = m.def_submodule("AMData", "Data Classes");
  // auto fs = m.def_submodule("AMFS", "Local Filesystem Operations");
  AMBIDINGS::BindEnum(em);
  AMBIDINGS::BindConRequest(data);
  AMBIDINGS::BindTransferCallback(data);
  AMBIDINGS::BindProgressCBInfo(data);
  AMBIDINGS::BindErrorCBInfo(data);
  AMBIDINGS::BindAuthCBInfo(data);
  AMBIDINGS::BindTransferTask(data);
  AMBIDINGS::BindTraceInfo(data);
  AMBIDINGS::BindPathInfo(data);
  AMBIDINGS::BindAMTracer(m);
  AMBIDINGS::BindBaseClient(m);
  AMBIDINGS::BindAMSession(m);
  AMBIDINGS::BindAMSFTPClient(m);
  AMBIDINGS::BindAMFTPClient(m);
  AMBIDINGS::BindHostMaintainer(m);
  AMBIDINGS::BindAMSFTPWorker(m);
}
