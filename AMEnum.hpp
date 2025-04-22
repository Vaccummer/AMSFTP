#pragma once
#include <libssh2.h>
#include <string>
#include <unordered_map>

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

enum class ErrorCode2
{
    Success = 0,
    SessionCreateError = -1,
    SftpCreateError = -2,
    SessionEstablishError = -3,
    SftpEstablishError = -4,
    ConnectionAuthorizeError = -5,
    LocalFileMapError = -6,
    RemoteFileOpenError = -7,
    RemoteFileStatError = -8,
    LocalFileCreateError = -9,
    LocalFileAllocError = -10,
    NetworkError = -11,
    NetworkDisconnect = -12,
    NetworkTimeout = -13,
    LocalFileFlushError = -14,
    SegmentationFault = -15,
    SessionBroken = -16,
    SftpBroken = -17,
    ChannelCreateError = -18,
    ConnectionCheckFailed = -19,
    RemoteFileWriteError = -20,
    RemoteFileReadError = -21,
    Terminate = -22,
    LocalFileExists = -23,
    RemoteFileExists = -24,
    PathNotExist = -25,
    PermissionDenied = -26,
    RemotePathOpenError = -27,
    NotDirectory = -28,
    ParentDirectoryNotExist = -29,
    TargetNotAFile = -30,
    RemoteFileDeleteError = -31,
    RemoteDirDeleteError = -32,
    UnknownError = -33,
    DirNotEmpty = -34,
    EmptyDirRemoveError = -35,
    TargetNotADirectory = -36,
    InvalidTrashDir = -37,
    MoveError = -38,
    TargetExists = -39,
    CopyError = -40,
    EndOfFile = -41,
    EAgain = -42,
    SocketNone = -43,
    SocketSend = -44,
    SocketTimeout = -45,
    SocketRecv = -46,
    SocketAccept = -47,
    WriteProtected = -48,
    UnenoughSpace = -49,
    UserSpaceQuotaExceeded = -50,
    BannerRecvError = -51,
    BannerSendError = -52,
    SocketSendError = -53,
    SocketDisconnect = -54,
    AuthFailed = -55,
    PublicKeyAuthFailed = -56,
    PasswordExpired = -57,
    KeyfileAuthFailed = -58,
    ChannelFailure = -59,
    ChannelWindowFull = -60,
    ChannelWindowExceeded = -61,
    MACAuthFailed = -62,
    KexFailure = -63,
    AlgoUnsupported = -64,
    MemoryAllocError = -65,
    FileOperationError = -66,
    ScpProtocolError = -67,
    SftpProtocolError = -68,
    KnownHostAuthFailed = -69,
    InvalidParameter = -70,
    NoSFTPConnection = -71,
    SFTPConnectionLost = -72,
    SFTPBadMessage = -73,
    InvalidHandle = -74,
    SFTPLockConflict = -75,
    SymlinkLoop = -76,
    InvalidFilename = -77,
    UnsupportedSFTPOperation = -78,
    MediaUnavailable = -79,
    SftpNotInitialized = -80,
    SessionNotInitialized = -81,
    DirAlreadyExists = -82,
    SocketCreateError = -83,
    PathAlreadyExists = -84,
    UnexpectedEOF = -85,
};

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
};

enum class PathType
{
    BlockDevice = -1,
    CharacterDevice = -2,
    Socket = -3,
    FIFO = -4,
    Unknown = -5,
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

extern const std::unordered_map<int, std::string> SFTPMessage;
extern const std::unordered_map<int, ErrorCode> Int2EC;
extern const std::vector<std::pair<uint64_t, size_t>> GLOBAL_PERMISSIONS_MASK;

std::string GetECName(ErrorCode ec);
