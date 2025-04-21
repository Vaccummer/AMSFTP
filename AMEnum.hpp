#pragma once
#include <libssh2.h>
#include <unordered_map>
#include <string>

// 常量定义
constexpr uint64_t AMKB = 1024;
constexpr uint64_t AMMB = 1024 * 1024;
constexpr uint64_t AMGB = 1024 * 1024 * 1024;

constexpr char *AMLEVEL = "LEVEL";
constexpr char *AMERRORCODE = "ERRORCODE";
constexpr char *AMERRORNAME = "ERRORNAME";
constexpr char *AMTARGET = "TARGET";
constexpr char *AMACTION = "ACTION";
constexpr char *AMMESSAGE = "MESSAGE";
constexpr char *AMCRITICAL = "CRITICAL";
constexpr char *AMERROR = "ERROR";
constexpr char *AMWARNING = "WARNING";
constexpr char *AMDEBUG = "DEBUG";
constexpr char *AMINFO = "INFO";

// 枚举类定义
enum class TransferErrorCode
{
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
    PrivateKeyFileError = -48,
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
    FileAlreadyExists = 11,
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
};

enum class PathType
{
    DIR = 0,
    FILE = 1,
    SYMLINK = 2
};

enum class MapType
{
    Read = 0,
    Write = 1
};

enum class OS_TYPE
{
    Windows = 0,
    Linux = 1,
    MacOS = 2,
    Unknown = 3
};

enum class BufferStatus
{
    is_writing = 0,
    is_reading = 1,
    read_done = 2,
    write_done = 3
};

// 外部声明
extern const std::unordered_map<int, std::string> SFTPMessage;
extern const std::unordered_map<int, TransferErrorCode> Int2EC;

std::string GetECName(TransferErrorCode ec);
