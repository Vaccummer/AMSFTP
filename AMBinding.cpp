#include "AMCore.hpp"
#include "AMDataClass.hpp"
#include "AMEnum.hpp"
#include "AMPath.hpp"

PYBIND11_MODULE(AMSFTP, m) {
  m.doc() = "A SFTP Client Module Based on libssh2";
  auto em = m.def_submodule("AMEnum", "Enum Classes");
  auto data = m.def_submodule("AMData", "Data Classes");
  auto fs = m.def_submodule("AMFS", "Local Filesystem Operations");

  bool expected = false;
  if (std::atomic_compare_exchange_strong(&is_wsa_initialized, &expected,
                                          true)) {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
      throw std::runtime_error("WSAStartup failed");
    }
    is_wsa_initialized = true;
    m.add_object("_cleanup", py::capsule(cleanup_wsa));
  }

  py::enum_<ErrorCode>(em, "ErrorCode",
                       "Uniform Error Code for the whole module")
      .value("Success", ErrorCode::Success)
      .value("SessionCreateError", ErrorCode::SessionGenericError,
             "Negative code represent libssh2 session error")
      .value("NoBannerRecv", ErrorCode::NoBannerRecv)
      .value("BannerSendError", ErrorCode::BannerSendError)
      .value("InvalidMacAdress", ErrorCode::InvalidMacAdress)
      .value("KeyExchangeMethodNegotiationFailed",
             ErrorCode::KeyExchangeMethodNegotiationFailed)
      .value("MemAllocError", ErrorCode::MemAllocError)
      .value("SocketSendError", ErrorCode::SocketSendError)
      .value("KeyExchangeFailed", ErrorCode::KeyExchangeFailed)
      .value("OperationTimeout", ErrorCode::OperationTimeout)
      .value("HostkeyInitFailed", ErrorCode::HostkeyInitFailed)
      .value("HostkeySignFailed", ErrorCode::HostkeySignFailed)
      .value("DataDecryptError", ErrorCode::DataDecryptError)
      .value("SocketDisconnect", ErrorCode::SocketDisconnect)
      .value("SSHProtocolError", ErrorCode::SSHProtocolError)
      .value("PasswordExpired", ErrorCode::PasswordExpired)
      .value("LocalFileError", ErrorCode::LocalFileError)
      .value("NoAuthMethod", ErrorCode::NoAuthMethod)
      .value("AuthFailed", ErrorCode::AuthFailed)
      .value("PublickeyAuthFailed", ErrorCode::PublickeyAuthFailed)
      .value("ChannelOrderError", ErrorCode::ChannelOrderError)
      .value("ChannelOperationError", ErrorCode::ChannelOperationError)
      .value("ChannelRequestDenied", ErrorCode::ChannelRequestDenied)
      .value("ChannelWindowExceeded", ErrorCode::ChannelWindowExceeded)
      .value("ChannelPacketOversize", ErrorCode::ChannelPacketOversize)
      .value("ChannelClosed", ErrorCode::ChannelClosed)
      .value("ChannelAlreadySendEOF", ErrorCode::ChannelAlreadySendEOF)
      .value("SCPProtocolError", ErrorCode::SCPProtocolError)
      .value("ZlibCompressError", ErrorCode::ZlibCompressError)
      .value("SocketOperationTimeout", ErrorCode::SocketOperationTimeout)
      .value("SftpProtocolError", ErrorCode::SftpProtocolError)
      .value("RequestDenied", ErrorCode::RequestDenied)
      .value("InvalidArg", ErrorCode::InvalidArg)
      .value("InvalidPollType", ErrorCode::InvalidPollType)
      .value("PublicKeyProtocolError", ErrorCode::PublicKeyProtocolError)
      .value("SSHEAGAIN", ErrorCode::SSHEAGAIN)
      .value("BufferTooSmall", ErrorCode::BufferTooSmall)
      .value("BadOperationOrder", ErrorCode::BadOperationOrder)
      .value("CompressionError", ErrorCode::CompressionError)
      .value("PointerOverflow", ErrorCode::PointerOverflow)
      .value("SSHAgentProtocolError", ErrorCode::SSHAgentProtocolError)
      .value("SocketRecvError", ErrorCode::SocketRecvError)
      .value("DataEncryptError", ErrorCode::DataEncryptError)
      .value("InvalidSocketType", ErrorCode::InvalidSocketType)
      .value("HostFingerprintMismatch", ErrorCode::HostFingerprintMismatch)
      .value("ChannelWindowFull", ErrorCode::ChannelWindowFull)
      .value("PrivateKeyAuthFailed", ErrorCode::PrivateKeyAuthFailed)
      .value("RandomGenError", ErrorCode::RandomGenError)
      .value("MissingUserAuthBanner", ErrorCode::MissingUserAuthBanner)
      .value("AlgorithmUnsupported", ErrorCode::AlgorithmUnsupported)
      .value("MacAuthFailed", ErrorCode::MacAuthFailed)
      .value("HashInitError", ErrorCode::HashInitError)
      .value("HashCalculateError", ErrorCode::HashCalculateError)
      // positive code represent libssh2 sftp error
      .value("EndOfFile", ErrorCode::EndOfFile,
             "Positive code represent libssh2 sftp error")
      .value("FileNotExist", ErrorCode::FileNotExist)
      .value("PermissionDenied", ErrorCode::PermissionDenied)
      .value("CommonFailure", ErrorCode::CommonFailure)
      .value("BadMessageFormat", ErrorCode::BadMessageFormat)
      .value("NoConnection", ErrorCode::NoConnection)
      .value("ConnectionLost", ErrorCode::ConnectionLost)
      .value("OperationUnsupported", ErrorCode::OperationUnsupported)
      .value("InvalidHandle", ErrorCode::InvalidHandle)
      .value("PathNotExist", ErrorCode::PathNotExist)
      .value("PathAlreadyExists", ErrorCode::PathAlreadyExists)
      .value("FileWriteProtected", ErrorCode::FileWriteProtected)
      .value("StorageMediaUnavailable", ErrorCode::StorageMediaUnavailable)
      .value("FilesystemNoSpace", ErrorCode::FilesystemNoSpace)
      .value("SpaceQuotaExceed", ErrorCode::SpaceQuotaExceed)
      .value("UsernameNotExists", ErrorCode::UsernameNotExists)
      .value("PathUsingByOthers", ErrorCode::PathUsingByOthers)
      .value("DirNotEmpty", ErrorCode::DirNotEmpty)
      .value("NotADirectory", ErrorCode::NotADirectory)
      .value("InvalidFilename", ErrorCode::InvalidFilename)
      .value("SymlinkLoop", ErrorCode::SymlinkLoop)
      // following codes are AM Custom Error
      .value("UnknownError", ErrorCode::UnknownError,
             "Code greater than 22 are AM Custom Error")
      .value("SocketCreateError", ErrorCode::SocketCreateError)
      .value("SocketConnectTimeout", ErrorCode::SocketConnectTimeout)
      .value("SocketConnectFailed", ErrorCode::SocketConnectFailed)
      .value("SessionCreateFailed", ErrorCode::SessionCreateFailed)
      .value("SessionHandshakeFailed", ErrorCode::SessionHandshakeFailed)
      .value("NoSession", ErrorCode::NoSession)
      .value("NotAFile", ErrorCode::NotAFile)
      .value("ParentDirectoryNotExist", ErrorCode::ParentDirectoryNotExist)
      .value("InhostCopyFailed", ErrorCode::InhostCopyFailed)
      .value("LocalFileMapError", ErrorCode::LocalFileMapError)
      .value("UnexpectedEOF", ErrorCode::UnexpectedEOF)
      .value("Terminate", ErrorCode::Terminate)
      .value("UnImplentedMethod", ErrorCode::UnImplentedMethod)
      .value("NoPermissionAttribute", ErrorCode::NoPermissionAttribute)
      .value("LocalStatError", ErrorCode::LocalStatError)
      .value("TransferPause", ErrorCode::TransferPause)
      .value("DNSResolveError", ErrorCode::DNSResolveError)
      .value("ClientNotFound", ErrorCode::ClientNotFound)
      .value("DeepcopyFunctionNotAvailable",
             ErrorCode::DeepcopyFunctionNotAvailable)
      .value("KeyAlreadyExists", ErrorCode::KeyAlreadyExists)
      .value("DeepcopyFailed", ErrorCode::DeepcopyFailed);

  py::enum_<OS_TYPE>(em, "OS_TYPE", "System OS Type Enum")
      .value("Windows", OS_TYPE::Windows)
      .value("Linux", OS_TYPE::Linux)
      .value("MacOS", OS_TYPE::MacOS)
      .value("FreeBSD", OS_TYPE::FreeBSD)
      .value("Unix", OS_TYPE::Unix)
      .value("Unknown", OS_TYPE::Unknown)
      .value("Uncertain", OS_TYPE::Uncertain, "Set when get OS type failed");

  py::enum_<TraceLevel>(em, "TraceLevel")
      .value("Info", TraceLevel::Info)
      .value("Debug", TraceLevel::Debug)
      .value("Warning", TraceLevel::Warning)
      .value("Error", TraceLevel::Error)
      .value("Critical", TraceLevel::Critical);

  py::enum_<PathType>(em, "PathType")
      .value("DIR", PathType::DIR)
      .value("FILE", PathType::FILE)
      .value("SYMLINK", PathType::SYMLINK)
      .value("BLOCK_DEVICE", PathType::BlockDevice)
      .value("CHARACTER_DEVICE", PathType::CharacterDevice)
      .value("SOCKET", PathType::Socket)
      .value("FIFO", PathType::FIFO)
      .value("UNKNOWN", PathType::Unknown);

  py::enum_<TransferControl>(
      em, "TransferControl",
      "Using in progress callback to control the transfer task")
      .value("Pause", TransferControl::Pause)
      .value("Terminate", TransferControl::Terminate);

  py::enum_<AMFS::SearchType>(em, "SearchType", "Search Type Enum")
      .value("All", AMFS::SearchType::All)
      .value("File", AMFS::SearchType::File)
      .value("Directory", AMFS::SearchType::Directory);

  py::class_<ConRequst, std::shared_ptr<ConRequst>>(
      data, "ConRequst", "Connection Request DataClass")
      .def(py::init<std::string, std::string, std::string, int, std::string,
                    std::string, bool, size_t, std::string>(),
           py::arg("nickname"), py::arg("hostname"), py::arg("username"),
           py::arg("port"), py::arg("password") = "", py::arg("keyfile") = "",
           py::arg("compression") = false, py::arg("timeout_s") = 3,
           py::arg("trash_dir") = "")
      .def_readwrite("nickname", &ConRequst::nickname,
                     "Unique nickname for the host and connection")
      .def_readwrite("hostname", &ConRequst::hostname,
                     "Hostname or IP address of the remote server")
      .def_readwrite("username", &ConRequst::username,
                     "Username for authentication")
      .def_readwrite("password", &ConRequst::password,
                     "Password for authentication, if not provided, public key "
                     "authentication will be used")
      .def_readwrite("port", &ConRequst::port,
                     "Port number of the remote server, default is 22")
      .def_readwrite("compression", &ConRequst::compression,
                     "Whether to use compression, default is false")
      .def_readwrite("timeout_s", &ConRequst::timeout_s,
                     "Timeout in seconds, default is 3")
      .def_readwrite("trash_dir", &ConRequst::trash_dir,
                     "Trash directory for failed transfers, default is empty")
      .def_readwrite("keyfile", &ConRequst::keyfile,
                     "Dedicated key file for this host");

  py::class_<TransferCallback, std::shared_ptr<TransferCallback>>(
      data, "TransferCallback", "Callback function Gather")
      .def(py::init<py::object, py::object, py::object>(),
           py::arg("total_size") = py::none(), py::arg("error") = py::none(),
           py::arg("progress") = py::none())
      .def("SetErrorCB", &TransferCallback::SetErrorCB,
           py::arg("error") = py::none(), "callable[[ErrorCBInfo], None]")
      .def("SetProgressCB", &TransferCallback::SetProgressCB,
           py::arg("progress") = py::none(),
           "callable[[ProgressCBInfo], Optional[TransferControl]]")
      .def("SetTotalSizeCB", &TransferCallback::SetTotalSizeCB,
           py::arg("total_size") = py::none(), "callable[[int], None]");

  py::class_<ProgressCBInfo, std::shared_ptr<ProgressCBInfo>>(
      data, "ProgressCBInfo", "Progress Callback Info DataClass")
      .def(py::init<std::string, std::string, std::string, std::string,
                    uint64_t, uint64_t, uint64_t, uint64_t>(),
           py::arg("src"), py::arg("dst"), py::arg("src_host"),
           py::arg("dst_host"), py::arg("this_size"), py::arg("file_size"),
           py::arg("accumulated_size"), py::arg("total_size"))
      .def_readwrite("src", &ProgressCBInfo::src)
      .def_readwrite("dst", &ProgressCBInfo::dst)
      .def_readwrite("src_host", &ProgressCBInfo::src_host)
      .def_readwrite("dst_host", &ProgressCBInfo::dst_host)
      .def_readwrite("this_size", &ProgressCBInfo::this_size,
                     "Size of the current file transfered")
      .def_readwrite("file_size", &ProgressCBInfo::file_size)
      .def_readwrite("accumulated_size", &ProgressCBInfo::accumulated_size,
                     "Size of the total files transfered")
      .def_readwrite("total_size", &ProgressCBInfo::total_size);

  py::class_<ErrorCBInfo, std::shared_ptr<ErrorCBInfo>>(data, "ErrorCBInfo")
      .def(py::init<ECM, std::string, std::string, std::string, std::string>(),
           py::arg("ecm"), py::arg("src"), py::arg("dst"), py::arg("src_host"),
           py::arg("dst_host"))
      .def_readwrite("ecm", &ErrorCBInfo::ecm)
      .def_readwrite("src", &ErrorCBInfo::src)
      .def_readwrite("dst", &ErrorCBInfo::dst)
      .def_readwrite("src_host", &ErrorCBInfo::src_host)
      .def_readwrite("dst_host", &ErrorCBInfo::dst_host);

  py::class_<AuthCBInfo, std::shared_ptr<AuthCBInfo>>(data, "AuthCBInfo")
      .def(py::init<bool, ConRequst, int>(), py::arg("NeedPassword"),
           py::arg("request"), py::arg("trial_times"))
      .def_readwrite(
          "NeedPassword", &AuthCBInfo::NeedPassword,
          "If true, python password callback need to return password, if "
          "false, callback function just tells you the password is wrong")
      .def_readwrite("request", &AuthCBInfo::request, "Connection request data")
      .def_readwrite("trial_times", &AuthCBInfo::trial_times,
                     "Number of times the password has been tried");

  py::class_<TransferTask, std::shared_ptr<TransferTask>>(data, "TransferTask")
      .def(py::init<std::string, std::string, std::string, std::string,
                    uint64_t, PathType, bool>(),
           py::arg("src"), py::arg("src_host"), py::arg("dst"),
           py::arg("dst_host"), py::arg("size"),
           py::arg("path_type") = PathType::FILE, py::arg("overwrite") = false)
      .def_readwrite("src", &TransferTask::src)
      .def_readwrite("src_host", &TransferTask::src_host)
      .def_readwrite("dst", &TransferTask::dst)
      .def_readwrite("dst_host", &TransferTask::dst_host)
      .def_readwrite("size", &TransferTask::size)
      .def_readwrite("path_type", &TransferTask::path_type)
      .def_readwrite("IsSuccess", &TransferTask::IsSuccess)
      .def_readwrite("rc", &TransferTask::rc)
      .def_readwrite("overwrite", &TransferTask::overwrite);

  py::class_<TraceInfo, std::shared_ptr<TraceInfo>>(
      data, "TraceInfo", "Trace Information DataClass")
      .def(py::init<TraceLevel, ErrorCode, std::string, std::string,
                    std::string, std::string>(),
           py::arg("level"), py::arg("error_code"), py::arg("nickname"),
           py::arg("target"), py::arg("action"), py::arg("message"))
      .def_readwrite("level", &TraceInfo::level)
      .def_readwrite("error_code", &TraceInfo::error_code)
      .def_readwrite("nickname", &TraceInfo::nickname)
      .def_readwrite("target", &TraceInfo::target)
      .def_readwrite("action", &TraceInfo::action)
      .def_readwrite("message", &TraceInfo::message)
      .def_readwrite("timestamp", &TraceInfo::timestamp);

  py::class_<PathInfo, std::shared_ptr<PathInfo>>(data, "PathInfo",
                                                  "Path Information DataClass")
      .def(
          py::init<std::string, std::string, std::string, std::string, uint64_t,
                   double, double, double, PathType, uint64_t, std::string>(),
          py::arg("name"), py::arg("path"), py::arg("dir"), py::arg("owner"),
          py::arg("size"), py::arg("create_time"), py::arg("access_time"),
          py::arg("modify_time"), py::arg("path_type") = PathType::FILE,
          py::arg("mode_int") = 0777, py::arg("mode_str") = "rwxrwxrwx")
      .def_readwrite("name", &PathInfo::name)
      .def_readwrite("path", &PathInfo::path)
      .def_readwrite("dir", &PathInfo::dir)
      .def_readwrite("owner", &PathInfo::owner)
      .def_readwrite("size", &PathInfo::size)
      .def_readwrite("create_time", &PathInfo::create_time,
                     "Only Windows and MacOS has this attribute")
      .def_readwrite("access_time", &PathInfo::access_time)
      .def_readwrite("modify_time", &PathInfo::modify_time)
      .def_readwrite("type", &PathInfo::type)
      .def_readwrite("mode_int", &PathInfo::mode_int)
      .def_readwrite(
          "mode_str", &PathInfo::mode_str,
          "The mode of the path, like [rwxrwxrwx], [onwer、group、others]");

  py::class_<AMTracer, std::shared_ptr<AMTracer>>(data, "AMTracer",
                                                  "Trace Buffer Class")
      .def(py::init<unsigned int, py::object, std::string>(),
           py::arg("buffer_capacity") = 10, py::arg("trace_cb") = py::none(),
           py::arg("nickname") = "")
      .def("GetTracerSize", &AMTracer::GetTracerSize,
           "Get the size of the tracer")
      .def("GetTracerCapacity", &AMTracer::GetTracerCapacity,
           "Get the capacity of the tracer")
      .def("LastTrace", &AMTracer::LastTrace,
           "Get the last trace error, return Optional[TraceInfo]")
      .def("GetAllTraces", &AMTracer::GetAllTraces,
           "Get all trace errors, return list[TraceInfo]")
      .def("IsTracerEmpty", &AMTracer::IsTracerEmpty,
           "Check if the tracer is empty")
      .def("ClearTracer", &AMTracer::ClearTracer, "Clear the tracer")
      .def("SetTracerCapacity", &AMTracer::SetTracerCapacity,
           py::arg("capacity"), "Set the capacity of the tracer")
      .def("trace",
           py::overload_cast<const TraceLevel &, const ErrorCode &,
                             const std::string &, const std::string &,
                             const std::string &>(&AMTracer::trace),
           py::arg("trace_info"), py::arg("error_code"), py::arg("target"),
           py::arg("action"), py::arg("msg"), "Trace a message")
      .def("trace", py::overload_cast<const TraceInfo &>(&AMTracer::trace),
           py::arg("trace_info"), "Trace a message")
      .def("PauseTrace", &AMTracer::PauseTrace, "Pause the trace")
      .def("ResumeTrace", &AMTracer::ResumeTrace, "Resume the trace")
      .def("SetPyTrace", &AMTracer::SetPyTrace,
           py::arg("trace_cb") = py::none(),
           "Set the python trace callback, callable[TraceInfo, None]");

  py::class_<AMSession, std::shared_ptr<AMSession>, AMTracer>(m, "AMSession",
                                                              "Session Class")
      .def(py::init<ConRequst, std::vector<std::string>, unsigned int,
                    py::object, py::object>(),
           py::arg("request"), py::arg("keys"), py::arg("error_num") = 10,
           py::arg("trace_cb") = py::none(), py::arg("auth_cb") = py::none())
      .def("GetNickname", &AMSession::GetNickname,
           "Get the nickname of the session")
      .def("GetRequest", &AMSession::GetRequest, "Get the request data")
      .def("IsValidKey", &AMSession::IsValidKey, py::arg("key"),
           "Check whether a file is a valid private key file")
      .def("GetKeys", &AMSession::GetKeys,
           "Get all shared private keys of the session")
      .def("SetKeys", &AMSession::SetKeys, py::arg("keys"),
           "Set shared private keys")
      .def("GetState", &AMSession::GetState,
           "Get the current state of the session")
      .def("Check", &AMSession::Check, py::arg("need_trace") = false,
           "Realtime check the session status and update the state")
      .def("BaseConnect", &AMSession::BaseConnect, py::arg("force") = false,
           "Connect to the session, force will force to reconnect even if the "
           "session is already connected")
      .def("GetLastEC", &AMSession::GetLastEC,
           "Get the last error code of the session")
      .def("GetLastErrorMsg", &AMSession::GetLastErrorMsg,
           "Get the last error message of the session")
      .def("Disconnect", &AMSession::Disconnect, "Disconnect the session")
      .def("SetAuthCallback", &AMSession::SetAuthCallback,
           py::arg("auth_cb") = py::none(),
           "When password authentication is needed, this callback will be "
           "called, callable[[AuthCBInfo], bool]");

  py::class_<BaseSFTPClient, std::shared_ptr<BaseSFTPClient>, AMSession>(
      m, "BaseSFTPClient")
      .def(py::init<ConRequst, std::vector<std::string>, unsigned int,
                    py::object, py::object>(),
           py::arg("request"), py::arg("keys"), py::arg("error_num") = 10,
           py::arg("trace_cb") = py::none(), py::arg("auth_cb") = py::none())
      .def("GetRTT", &BaseSFTPClient::GetRTT, py::arg("times") = 5,
           "Get the round-trip time of the session")
      .def("ConductCmd", &BaseSFTPClient::ConductCmd, py::arg("cmd"),
           "Conduct a command and return the result")
      .def("GetOSType", &BaseSFTPClient::GetOSType, py::arg("update") = false,
           "Update will force to re-detect the OS type");

  py::class_<AMFS::BasePathMatch, std::shared_ptr<AMFS::BasePathMatch>>(
      fs, "BasePathMatch", "Base Path Match Class")
      .def("str_match", &AMFS::BasePathMatch::str_match, py::arg("name"),
           py::arg("pattern"))
      .def("name_match", &AMFS::BasePathMatch::name_match, py::arg("name"),
           py::arg("pattern"))
      .def("walk_match", &AMFS::BasePathMatch::walk_match, py::arg("parts"),
           py::arg("match_parts"))
      .def("find", &AMFS::BasePathMatch::find, py::arg("path"),
           py::arg("type") = AMFS::SearchType::All);

  py::class_<AMFS::PathMatch, std::shared_ptr<AMFS::PathMatch>,
             AMFS::BasePathMatch>(fs, "PathMatch", "Path Match Class")
      .def(py::init<>());

  py::class_<AMSFTPClient, std::shared_ptr<AMSFTPClient>, BaseSFTPClient,
             AMFS::BasePathMatch>(m, "AMSFTPClient", "Core SFTP Client Class")
      .def(py::init<ConRequst, std::vector<std::string>, unsigned int,
                    py::object, py::object>(),
           py::arg("request"), py::arg("keys"), py::arg("error_num") = 10,
           py::arg("trace_cb") = py::none(), py::arg("auth_cb") = py::none())
      .def(
          "SetPublicVar", &AMSFTPClient::SetPublicVar, py::arg("key"),
          py::arg("value"), py::arg("overwrite") = false,
          "Store a Python object in C++ side with deep copy, C++ owns the copy")
      .def("GetPublicVar", &AMSFTPClient::GetPublicVar, py::arg("key"),
           py::arg("default") = py::none(),
           "Get a stored Python object, returns a deep copy")
      .def("DelPublicVar", &AMSFTPClient::DelPublicVar, py::arg("key"),
           "Delete a stored Python object, returns True if deleted")
      .def("HasPublicVar", &AMSFTPClient::HasPublicVar, py::arg("key"),
           "Check if a key exists in the public variable dictionary")
      .def("ClearPublicVar", &AMSFTPClient::ClearPublicVar,
           "Clear all stored Python objects")
      .def("GetAllPublicVars", &AMSFTPClient::GetAllPublicVars,
           "Get all stored Python objects as a dictionary with deep copies")
      .def("StrUid", &AMSFTPClient::StrUid, py::arg("uid"),
           "Convert a uid to a string")
      .def("GetHomeDir", &AMSFTPClient::GetHomeDir, "Get the home directory")
      .def("Connect", &AMSFTPClient::Connect, py::arg("force") = false,
           "Wrapper of BaseConnect, will get OS type and home directory if "
           "conducted the first time")
      .def("GetTrashDir", &AMSFTPClient::GetTrashDir, "Get the trash directory")
      .def("SetTrashDir", &AMSFTPClient::SetTrashDir, py::arg("trash_dir") = "",
           "Set the trash directory and create it if it doesn't exist")
      .def("EnsureTrashDir", &AMSFTPClient::EnsureTrashDir)
      .def("realpath", &AMSFTPClient::realpath, py::arg("path"),
           "Parse and return the absolute path, ~ in client will be parsed, .. "
           "and . will be parsed by server, if there are these symbols, the "
           "path must exist")
      .def("chmod", &AMSFTPClient::chmod, py::arg("path"), py::arg("mode"),
           py::arg("recursive") = false)
      .def("stat", &AMSFTPClient::stat, py::arg("path"))
      .def("get_path_type", &AMSFTPClient::get_path_type, py::arg("path"))
      .def("exists", &AMSFTPClient::exists, py::arg("path"))
      .def("is_regular", &AMSFTPClient::is_regular, py::arg("path"))
      .def("is_dir", &AMSFTPClient::is_dir, py::arg("path"))
      .def("is_symlink", &AMSFTPClient::is_symlink, py::arg("path"))
      .def("listdir", &AMSFTPClient::listdir, py::arg("path"),
           py::arg("max_time_ms") = -1)
      .def("mkdir", &AMSFTPClient::mkdir, py::arg("path"))
      .def("mkdirs", &AMSFTPClient::mkdirs, py::arg("path"))
      .def("rmfile", &AMSFTPClient::rmfile, py::arg("path"))
      .def("rmdir", &AMSFTPClient::rmdir, py::arg("path"))
      .def("remove", &AMSFTPClient::remove, py::arg("path"),
           "Permanently remove a file or directory, if return (ErrorCode, "
           "str), the whole operation failed, otherwise return list[tuple[str, "
           "tuple[ErrorCode, str]]], means some paths failed to remove")
      .def("rename", &AMSFTPClient::rename, py::arg("src"), py::arg("dst"),
           py::arg("overwrite") = false,
           "Turn src_path into dst_path, if overwrite is true, the dst_path "
           "will be overwritten")
      .def("saferm", &AMSFTPClient::saferm, py::arg("path"),
           "Not real remove, just move it to "
           "{trash_dir}/{year-month-day-hour-minute-second}/{pathname}")
      .def("move", &AMSFTPClient::move, py::arg("src"), py::arg("dst"),
           py::arg("need_mkdir") = false, py::arg("force_write") = false,
           "Move source path src to Destination Directory dst")
      .def("copy", &AMSFTPClient::copy, py::arg("src"), py::arg("dst"),
           py::arg("need_mkdir") = false,
           "Unstable, using shell command to copy")
      .def("iwalk", &AMSFTPClient::iwalk, py::arg("path"),
           py::arg("ignore_sepcial_file") = true,
           "Recursive walk the path, ignore path structure, just return "
           "list[PathInfo]")
      .def("walk", &AMSFTPClient::walk, py::arg("path"),
           py::arg("max_depth") = -1, py::arg("ignore_sepcial_file") = true,
           "Recursive walk the path, record parent dir, return "
           "list[tuple[list[str],PathInfo]]")
      .def("getsize", &AMSFTPClient::getsize, py::arg("path"),
           py::arg("ignore_sepcial_file") = true);

  py::class_<HostMaintainer, std::shared_ptr<HostMaintainer>>(
      m, "HostMaintainer",
      "The Client Maintainer Class, Check clients status all the time")
      .def(py::init<int, py::object>(), py::arg("heartbeat_interval_s") = 60,
           py::arg("disconnect_cb") = py::none(),
           "callable[[AMSFTPClient, tuple[ErrorCode, str]], None], default "
           "None means no callback")
      .def("add_host", &HostMaintainer::add_host, py::arg("nickname"),
           py::arg("client"), py::arg("overwrite") = false)
      .def("remove_host", &HostMaintainer::remove_host, py::arg("nickname"))
      .def("get_host", &HostMaintainer::get_host, py::arg("nickname"))
      .def("get_hosts", &HostMaintainer::get_hosts,
           "Just return all hostnames, return list[str]")
      .def("get_clients", &HostMaintainer::get_clients,
           "Just return all clients, list[AMSFTPClient]")
      .def("test_host", &HostMaintainer::test_host, py::arg("nickname"),
           py::arg("update") = false,
           "Test the host connection, return (ErrorCode, str)");

  py::class_<AMSFTPWorker, std::shared_ptr<AMSFTPWorker>>(
      m, "AMSFTPWorker", "A worker for transferring files")
      .def(py::init<TransferCallback, float>(),
           py::arg("callback") = TransferCallback(),
           py::arg("cb_interval_s") = 0.1)
      .def("terminate", &AMSFTPWorker::terminate)
      .def("pause", &AMSFTPWorker::pause)
      .def("resume", &AMSFTPWorker::resume)
      .def("IsTerminate", &AMSFTPWorker::IsTerminate)
      .def("IsPause", &AMSFTPWorker::IsPause)
      .def("IsRunning", &AMSFTPWorker::IsRunning)
      .def("reset", &AMSFTPWorker::reset,
           "Rset Internal Status like is_terminate, is_pause, current_size, "
           "total_size")
      .def("set_cb_interval", &AMSFTPWorker::set_cb_interval,
           py::arg("interval_s"),
           "Set the interval of the callback in seconds, default is 0.1s")
      .def("load_tasks", &AMSFTPWorker::load_tasks, py::arg("src"),
           py::arg("dst"), py::arg("hostd"), py::arg("src_hostname") = "",
           py::arg("dst_hostname") = "", py::arg("overwrite") = false,
           py::arg("mkdir") = true, py::arg("ignore_sepcial_file") = true)
      .def("transfer", &AMSFTPWorker::transfer, py::arg("tasks"),
           py::arg("hostd"), py::arg("chunk_large") = 16 * AMMB,
           py::arg("chunk_middle") = 2 * AMMB,
           py::arg("chunk_small") = 256 * AMKB);

  fs.def("IsAbs", &AMFS::IsAbs, py::arg("path"), py::arg("sep") = "")
      .def("HomePath", &AMFS::HomePath)
      .def("extname", &AMFS::extname, py::arg("path"))
      .def("split_basename", &AMFS::split_basename, py::arg("basename"),
           "return tuple[str, str], the first is the basename without "
           "extension, the second is the extension(no .)")
      .def("CWD", &AMFS::CWD)
      .def("FormatTime", &AMFS::FormatTime, py::arg("time"),
           py::arg("format") = "%Y-%m-%d %H:%M:%S")
      .def("UnifyPathSep", &AMFS::UnifyPathSep, py::arg("path"),
           py::arg("sep") = "")
      .def("split", &AMFS::split, py::arg("path"),
           "return list[str], the path is split by separator")
      .def("abspath", &AMFS::abspath, py::arg("path"),
           py::arg("parsing_home") = true, py::arg("home") = "",
           py::arg("cwd") = "", py::arg("sep") = "")
      .def("dirname", &AMFS::dirname, py::arg("path"))
      .def("basename", &AMFS::basename, py::arg("path"))
      .def("mkdirs", &AMFS::mkdirs, py::arg("path"))
      .def("stat", &AMFS::stat, py::arg("path"), py::arg("trace_link") = false)
      .def("listdir", &AMFS::listdir, py::arg("path"))
      .def("iwalk", &AMFS::iwalk, py::arg("path"),
           py::arg("ignore_sepcial_file") = true)
      .def("walk", &AMFS::walk, py::arg("path"), py::arg("max_depth") = -1,
           py::arg("ignore_sepcial_file") = true)
      .def("getsize", &AMFS::getsize, py::arg("path"),
           py::arg("trace_link") = false);
};
