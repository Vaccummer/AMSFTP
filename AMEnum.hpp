#pragma once
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <string>
#include <unordered_map>

constexpr uint64_t AMKB = 1024;
constexpr uint64_t AMMB = 1024 * 1024;
constexpr uint64_t AMGB = 1024 * 1024 * 1024;

enum class ErrorCode
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
    UnexpectedEOF = 33,
    Terminate = 34,
    UnImplentedMethod = 35,
    NoPermissionAttribute = 36,
    LocalStatError = 37,
    TransferPause = 38,
    DNSResolveError = 39,
    ClientNotFound = 40,
    ConnectionAlreadyExists = 41,
    DeepcopyFunctionNotAvailable = 42,
    KeyAlreadyExists = 43,
    DeepcopyFailed = 44,

};

enum class MapType
{
    Read = 0,
    Write = 1
};

enum class OS_TYPE
{
    Windows = -1,
    Unknown = -2,
    Uncertain = 0,
    Linux = 1,
    MacOS = 2,
    FreeBSD = 3,
    Unix = 4
};

enum class BufferStatus
{
    is_writing = 0,
    is_reading = 1,
    read_done = 2,
    write_done = 3
};

enum class TransferControl
{
    Pause = 0,
    Terminate = 1
};

enum class TraceLevel
{
    Debug = 2,
    Info = 1,
    Warning = 0,
    Error = -1,
    Critical = -2,

};

// 将libssh2错误码映射为错误消息
const std::unordered_map<int, std::string> SFTPMessage = {
    {LIBSSH2_FX_EOF, "End of file"},
    {LIBSSH2_FX_NO_SUCH_FILE, "File does not exist"},
    {LIBSSH2_FX_PERMISSION_DENIED, "Permission denied"},
    {LIBSSH2_FX_FAILURE, "Generic failure"},
    {LIBSSH2_FX_BAD_MESSAGE, "Bad message format"},
    {LIBSSH2_FX_NO_CONNECTION, "No connection exists"},
    {LIBSSH2_FX_CONNECTION_LOST, "Connection lost"},
    {LIBSSH2_FX_OP_UNSUPPORTED, "Operation not supported"},
    {LIBSSH2_FX_INVALID_HANDLE, "Invalid handle"},
    {LIBSSH2_FX_NO_SUCH_PATH, "No such path"},
    {LIBSSH2_FX_FILE_ALREADY_EXISTS, "File already exists"},
    {LIBSSH2_FX_WRITE_PROTECT, "Target is write protected"},
    {LIBSSH2_FX_NO_MEDIA, "Target Storage Media is not available"},
    {LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM, "No space on filesystem"},
    {LIBSSH2_FX_QUOTA_EXCEEDED, "Space quota exceeded"},
    {LIBSSH2_FX_UNKNOWN_PRINCIPAL, "User not found in host"},
    {LIBSSH2_FX_LOCK_CONFLICT, "Path is locked by another process"},
    {LIBSSH2_FX_DIR_NOT_EMPTY, "Directory is not empty"},
    {LIBSSH2_FX_NOT_A_DIRECTORY, "Target is not a directory"},
    {LIBSSH2_FX_INVALID_FILENAME, "Filename is invalid"},
    {LIBSSH2_FX_LINK_LOOP, "Symbolic link loop"}};

// 将ErrorCode枚举值映射为int
const std::unordered_map<int, ErrorCode> Int2EC = []
{
    std::unordered_map<int, ErrorCode> map;
    for (auto [val, name] : magic_enum::enum_entries<ErrorCode>())
    {
        map[static_cast<int>(val)] = val;
    }
    return map;
}();

inline std::string GetECName(ErrorCode ec)
{
    return std::string(magic_enum::enum_name(ec));
}
