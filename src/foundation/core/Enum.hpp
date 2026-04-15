#pragma once
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <optional>
#include <string>
#include <utility>

inline static constexpr ssize_t AMKB = 1024;
inline static constexpr ssize_t AMMB = 1024 * 1024;
inline static constexpr ssize_t AMGB = 1024 * 1024 * 1024;

enum class ErrorCode {
  Success = 0,
  // negative code represent libssh2 session error
  SessionGenericError = -1,
  NoBannerRecv = -2,
  BannerSendError = -3,
  InvalidMacAdress = -4,
  KeyExchangeMethodNegotiationFailed = -5,
  MemAllocError = -6,
  SocketSendError = -7,
  KeyExchangeFailed = -8,
  OperationTimeout = -9,
  HostkeyInitFailed = -10,
  HostkeySignFailed = -11,
  DataDecryptError = -12,
  SocketDisconnect = -13,
  SSHProtocolError = -14,
  PasswordExpired = -15,
  LocalFileError = -16,
  NoAuthMethod = -17,
  AuthFailed = -18,
  PublickeyAuthFailed = -19,
  ChannelOrderError = -20,
  ChannelOperationError = -21,
  ChannelRequestDenied = -22,
  ChannelWindowExceeded = -24,
  ChannelPacketOversize = -25,
  ChannelClosed = -26,
  ChannelAlreadySendEOF = -27,
  SCPProtocolError = -28,
  ZlibCompressError = -29,
  SocketOperationTimeout = -30,
  SftpProtocolError = -31,
  RequestDenied = -32,
  InvalidArg = -34,
  InvalidPollType = -35,
  PublicKeyProtocolError = -36,
  SSHEAGAIN = LIBSSH2_ERROR_EAGAIN,
  BufferTooSmall = -38,
  BadOperationOrder = -39,
  CompressionError = -40,
  PointerOverflow = -41,
  SSHAgentProtocolError = -42,
  SocketRecvError = -43,
  DataEncryptError = -44,
  InvalidSocketType = -45,
  HostFingerprintMismatch = -46,
  ChannelWindowFull = -47,
  PrivateKeyAuthFailed = -48,
  RandomGenError = -49,
  MissingUserAuthBanner = -50,
  AlgorithmUnsupported = -51,
  MacAuthFailed = -52,
  HashInitError = -53,
  HashCalculateError = -54,
  // positive code represent libssh2 sftp error
  EndOfFile = 1,
  FileNotExist = 2,
  PermissionDenied = 3,
  CommonFailure = 4,
  BadMessageFormat = 5,
  NotInitialized = 89,
  NoConnection = 6,
  ConnectionLost = 7,
  OperationUnsupported = 8,
  InvalidHandle = 9,
  PathNotExist = 10,
  PathAlreadyExists = 11,
  FileWriteProtected = 12,
  StorageMediaUnavailable = 13,
  FilesystemNoSpace = 14,
  SpaceQuotaExceed = 15,
  UsernameNotExists = 16,
  PathUsingByOthers = 17,
  DirNotEmpty = 18,
  NotADirectory = LIBSSH2_FX_NOT_A_DIRECTORY,
  InvalidFilename = 20,
  SymlinkLoop = 21,

  // FTP Server Error
  UnsupportFTPProtocol = 47,
  IllegealURLFormat = 81,
  NetworkError = 82,
  FTPConnectFailed = 48,
  FTPWriteError = 81,
  FTPReadError = 96,
  FTPSendError = 91,
  FTPRecvError = 92,
  IllegealSeverReply = 93,
  FTPMkdirFailed = 49,
  FTPRenameFailed = 50,
  FTPUploadFailed = 51,
  FTPDownloadFailed = 52,
  FTPListFailed = 53,

  // following codes are AM Custom Error
  ParentDirectoryNotExist = 21,
  UnknownError = 22,
  SocketCreateError = 23,
  SocketConnectTimeout = 24,
  SocketConnectFailed = 25,
  SessionCreateFailed = 26,
  SessionHandshakeFailed = 27,
  NoSession = 28,
  NotAFile = 29,
  InhostCopyFailed = 31,
  LocalFileMapError = 32,
  LocalFileOpenError = 33,
  LocalFileReadError = 34,
  LocalFileWriteError = 35,
  UnexpectedEOF = 36,
  Terminate = 37,
  UnImplentedMethod = 38,
  NoPermissionAttribute = 39,
  LocalStatError = 40,
  TransferPause = 41,
  DNSResolveError = 42,
  ClientNotFound = 43,
  ConnectionAlreadyExists = 44,
  DeepcopyFunctionNotAvailable = 45,
  KeyAlreadyExists = 46,
  DeepcopyFailed = 47,
  BufferWriteError = 70,
  BufferReadError = 71,
  PyCBError = 72,
  HostConfigNotFound = 100,
  ConfigNotInitialized = 101,
  ConfigLoadFailed = 102,
  ConfigDumpFailed = 103,
  ConfigInvalid = 104,
  ConfigCanceled = 105,
  TaskNotFound = 106,
  IndexOutOfRange = 107,
  InvalidOffset = 108,
  ProgrammInitializeFailed = 109,
  TargetAlreadyExists = 110,
};

enum class WaitResult {
  Ready,       // Socket is ready for read/write
  ReadReady,   // Socket is ready for read (ReadOrWrite mode only)
  WriteReady,  // Socket is ready for write (ReadOrWrite mode only)
  Timeout,     // Operation timed out
  Interrupted, // Operation was interrupted by flag
  Error        // Socket error occurred
};

inline ErrorCode wait_result_to_error_code(WaitResult wr) {
  switch (wr) {
  case WaitResult::Ready:
  case WaitResult::ReadReady:
  case WaitResult::WriteReady:
    return ErrorCode::Success;
  case WaitResult::Timeout:
    return ErrorCode::OperationTimeout;
  case WaitResult::Interrupted:
    return ErrorCode::Terminate;
  case WaitResult::Error:
    return ErrorCode::SocketRecvError;
  default:
    return ErrorCode::UnknownError;
  }
}

enum class PathType {
  BlockDevice = -1,
  CharacterDevice = -2,
  Socket = -3,
  FIFO = -4,
  Unknown = -5,
  DIR = 0,
  FILE = 1,
  SYMLINK = 2
};

enum class SearchType { All = 0, File = 1, Directory = 2 };

enum class SepType { Unix = 0, Windows = 1 };

enum class MapType { Read = 0, Write = 1 };

enum class TaskAssignType { Affinity, Public };

enum class BufferStatus {
  is_writing = 0,
  is_reading = 1,
  read_done = 2,
  write_done = 3
};

enum class TransferControl { Running = 1, Pause = 0, Terminate = -1 };

enum class AMTokenType {
  Unset = -1,
  Common = 0,
  Module = 1,
  Command = 2,
  VarName = 3,
  VarNameMissing = 11,
  VarValue = 4,
  Nickname = 5,
  String = 6,
  Option = 7,
  AtSign = 8,
  DollarSign = 9,
  EqualSign = 10,
  EscapeSign = 12,
  Path = 13,
  Nonexistentpath = 14,
  File = 15,
  Dir = 16,
  Symlink = 17,
  Special = 18,
  BangSign = 19,
  ShellCmd = 20,
  IllegalCommand = 21,
  UnestablishedNickname = 22,
  NonexistentNickname = 23,
  BuiltinArg = 24,
  LeftBraceSign = 25,
  RightBraceSign = 26,
  ColonSign = 27,
  ValidValue = 28,
  InvalidValue = 29,
  NonexistentBuiltinArg = 30,
  ValidNewNickname = 31,
  InvalidNewNickname = 32,
  DisconnectedNickname = 33,
  TerminalName = 34,
  DisconnectedTerminalName = 35,
  UnestablishedTerminalName = 36,
  NonexistentTerminalName = 37,
  ChannelName = 38,
  DisconnectedChannelName = 39,
  NonexistentChannelName = 40,
  ValidNewChannelName = 41,
  InvalidNewChannelName = 42
};

enum class TraceSource { Client = 0, Programm = 1 };

using EC = ErrorCode;

enum class RawErrorSource {
  Unknown = 0,
  Libssh2 = 1,
  Curl = 2,
  Filesystem = 3,
  WindowsAPI = 4,
};

struct RawError {
  RawErrorSource source = RawErrorSource::Unknown;
  int code = 0;
};

[[nodiscard]] inline const char *RawErrorSourceName(RawErrorSource source) {
  switch (source) {
  case RawErrorSource::Libssh2:
    return "Libssh2";
  case RawErrorSource::Curl:
    return "Curl";
  case RawErrorSource::Filesystem:
    return "Filesystem";
  case RawErrorSource::WindowsAPI:
    return "WindowsAPI";
  case RawErrorSource::Unknown:
  default:
    return "Unknown";
  }
}

struct AMError {
  ErrorCode code = EC::Success;
  std::string operation = "";
  std::string target = "";
  std::string error = "";
  std::optional<RawError> raw_error = std::nullopt;

  AMError() = default;

  AMError(EC ec, std::string err)
      : code(ec), operation(""), target(""), error(std::move(err)) {
    if (code != EC::Success) {
      if (operation.empty()) {
        operation = "";
      }
      if (target.empty()) {
        target = "";
      }
    }
  }

  AMError(EC ec, std::string op, std::string tgt, std::string err)
      : code(ec), operation(std::move(op)), target(std::move(tgt)),
        error(std::move(err)) {
    if (code != EC::Success) {
      if (operation.empty()) {
        operation = "";
      }
      if (target.empty()) {
        target = "";
      }
    }
  }

  AMError(EC ec, std::string err, RawError raw)
      : code(ec), operation(""), target(""), error(std::move(err)),
        raw_error(raw) {
    if (code != EC::Success) {
      if (operation.empty()) {
        operation = "";
      }
      if (target.empty()) {
        target = "";
      }
    }
  }

  AMError(EC ec, std::string op, std::string tgt, std::string err,
          std::optional<RawError> raw)
      : code(ec), operation(std::move(op)), target(std::move(tgt)),
        error(std::move(err)), raw_error(raw) {
    if (code != EC::Success) {
      if (operation.empty()) {
        operation = "";
      }
      if (target.empty()) {
        target = "";
      }
    }
  }

  operator bool() const { return code == EC::Success; }

  [[nodiscard]] std::string msg() const {
    const bool has_operation = !operation.empty();
    const bool has_target = !target.empty();
    const bool has_error = !error.empty();

    if (has_operation && has_target && has_error) {
      return operation + " on " + target + " error: " + error;
    }
    if (has_operation && has_error) {
      return operation + " error: " + error;
    }
    if (has_target && has_error) {
      return target + " error: " + error;
    }
    if (has_error) {
      return error;
    }
    if (has_operation && has_target) {
      return operation + " on " + target;
    }
    if (has_operation) {
      return operation;
    }
    if (has_target) {
      return target;
    }
    return std::string(magic_enum::enum_name(code));
  }
};

static const AMError OK = AMError{};
using Err = AMError;
using ECM = AMError;
