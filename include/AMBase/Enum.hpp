#pragma once
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>

constexpr ssize_t AMKB = 1024;
constexpr ssize_t AMMB = 1024 * 1024;
constexpr ssize_t AMGB = 1024 * 1024 * 1024;
constexpr ssize_t AMDefaultLocalBufferSize = 1024 * 1024 * 16;
constexpr ssize_t AMDefaultRemoteBufferSize = 1024 * 1024 * 8;
constexpr ssize_t AMMinBufferSize = 1024 * 512;
constexpr ssize_t AMMaxBufferSize = 1024 * 1024 * 512;

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
  SSHEAGAIN = -37,
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
  NotADirectory = 19,
  InvalidFilename = 20,
  SymlinkLoop = 21,
  // following codes are AM Custom Error
  UnknownError = 22,
  SocketCreateError = 23,
  SocketConnectTimeout = 24,
  SocketConnectFailed = 25,
  SessionCreateFailed = 26,
  SessionHandshakeFailed = 27,
  NoSession = 28,
  NotAFile = 29,
  ParentDirectoryNotExist = 30,
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

  // FTP Server Error
  UnsupportFTPProtocol = 47,
  IllegealURLFormat = 81,
  NetworkError = 82,
  FTPConnectFailed = 48,
  FTPWriteError = 81,
  FTPReadError = 96,

  FTPSendError = 91,
  FTPRecvError = 92,
  IllegealSeverReply,
  FTPMkdirFailed = 49,
  FTPRenameFailed = 50,
  FTPUploadFailed = 51,
  FTPDownloadFailed = 52,
  FTPListFailed = 53,
};

enum class WaitResult {
  Ready,       // Socket is ready for read/write
  ReadReady,   // Socket is ready for read (仅 ReadOrWrite 模式)
  WriteReady,  // Socket is ready for write (仅 ReadOrWrite 模式)
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

enum class TaskStatus { Pending, Conducting, Paused, Finished };

enum class MapType { Read = 0, Write = 1 };

enum class TaskAssignType { Affinity, Public };

enum class OS_TYPE {
  Windows = -1,
  Unknown = -2,
  Uncertain = 0,
  Linux = 1,
  MacOS = 2,
  FreeBSD = 3,
  Unix = 4
};

enum class ClientProtocol {
  Unknown = -1,
  Base = 0,
  SFTP = 1,
  FTP = 2,
  LOCAL = 3
};

enum class BufferStatus {
  is_writing = 0,
  is_reading = 1,
  read_done = 2,
  write_done = 3
};

enum class TransferControl { Running = 1, Pause = 0, Terminate = -1 };

enum class TraceLevel {
  Critical = 0,
  Error = 1,
  Warning = 2,
  Info = 3,
  Debug = 4
};

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
  IllegalCommand = 21

};

enum class TraceSource { Client = 0, Programm = 1 };
