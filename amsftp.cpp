#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <fmt/core.h>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
#include <windows.h>
#include <time.h>
#include <fcntl.h>
#include <atomic>
#include <string>
#include <stdio.h>
#include <vector>
#include <iostream>
#include <time.h>
#include <unordered_map>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <filesystem>
#include <algorithm>
#include <chrono>
#include <numeric>
#include <memory>
#include <cstdint>

namespace py = pybind11;
namespace fs = std::filesystem;
static std::atomic<bool> is_wsa_initialized(false);
static void cleanup_wsa()
{
    if (is_wsa_initialized)
    {
        WSACleanup();
        is_wsa_initialized = false;
    }
}

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

std::vector<std::string> make_py_error(std::string errorname, std::string tar, std::string act)
{
    return {errorname, tar, act};
}

std::vector<std::string> split_path(const std::string &path_f)
{
    std::vector<std::string> result;
    fs::path path(path_f);
    for (auto &part : path)
    {
        if (part.string().empty())
        {
            continue;
        }
        result.push_back(part.string());
    }
    return result;
}

std::wstring Wstring(const std::string &narrowStr)
{
    int length = MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, nullptr, 0);
    std::wstring wideStr(length, 0);
    MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, &wideStr[0], length);
    for (auto &c : wideStr)
    {
        if (c == L'/')
        {
            c = L'\\';
        }
    }
    return wideStr;
}

std::string dirname(const std::string &path)
{
    fs::path p(path);
    if (p.parent_path().empty())
    {
        return "";
    }
    return p.parent_path().string();
}

std::string basename(const std::string &path)
{
    fs::path p(path);
    return p.filename().string();
}

std::string local_realpath(const std::string &path)
{
    fs::path p(path);
    return p.lexically_normal().generic_string();
}

void lmkdirs(const std::string &path)
{
    try
    {
        fs::path p(path);
        fs::create_directories(p);
    }
    catch (const fs::filesystem_error)
    {
        return;
    }
}

double timenow()
{
    return std::chrono::duration<double>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

template <typename... Args>
std::string join_path(Args &&...args)
{
    std::vector<std::string> segments;
    fs::path combined;

    auto process_arg = [&](auto &&arg)
    {
        // 检测arg是否为std::filesystem::path类型
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::filesystem::path>)
        {
            segments.push_back(arg.string());
        }
        else
        {
            std::string s = std::forward<decltype(arg)>(arg);
            if (s.empty())
            {
                return;
            }
            segments.push_back(s);
        }
    };

    (process_arg(std::forward<Args>(args)), ...);

    if (segments.empty())
        return "";

    for (auto &seg : segments)
    {
        if (combined.empty())
        {
            combined = seg;
        }
        else
        {
            combined /= seg;
        }
    }
    return combined.lexically_normal().generic_string();
}

enum class TransferErrorCode2
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
    SYMLINK = 2,
};

enum class MapType
{
    Read = 0,
    Write = 1,
};

enum class OS_TYPE
{
    Windows = 0,
    Linux = 1,
    MacOS = 2,
    Unknown = 3,
};

enum class BufferStatus
{
    is_writing = 0,
    is_reading = 1,
    read_done = 2,
    write_done = 3
};

struct ConRequst
{
    std::string nickname;
    std::string hostname;
    std::string username;
    std::string password;
    std::string keyfile;
    bool compression;
    int port;
    size_t timeout_s;
    std::string trash_dir = "";
    ConRequst()
        : nickname(""), hostname(""), username(""), password(""), port(22), compression(false), timeout_s(3), trash_dir("") {}
    ConRequst(std::string nickname,
              std::string hostname,
              std::string username,
              int port,
              std::string password = "",
              std::string keyfile = "",
              bool compression = false,
              size_t timeout_s = 3,
              std::string trash_dir = "")
        : nickname(nickname), hostname(hostname), username(username), password(password), keyfile(keyfile), compression(compression), port(port), timeout_s(timeout_s), trash_dir(trash_dir)
    {
    }
};

struct TransferCallback
{
    float cb_interval_s;
    bool need_error_cb;
    bool need_progress_cb;
    bool need_total_size_cb;
    py::function error_cb;      // Callable[[EC, str, str, str], None] error_code, msg, src, dst
    py::function progress_cb;   // Callable[[str, str, int, int, int, int], None] src, dst, this_size, file_size, accumulated_size, total_size
    py::function total_size_cb; // Callable[[int], None]
    TransferCallback()
        : cb_interval_s(0.5), need_error_cb(false), need_progress_cb(false), need_total_size_cb(false), error_cb(py::function()), progress_cb(py::function()), total_size_cb(py::function()) {}
    TransferCallback(
        float interval,
        py::object total_size = py::none(),
        py::object error = py::none(),
        py::object progress = py::none()) : cb_interval_s(interval)
    {
        if (total_size.is_none())
        {
            need_total_size_cb = false;
            total_size_cb = py::function();
        }
        else
        {
            need_total_size_cb = true;
            total_size_cb = py::cast<py::function>(total_size);
        }

        if (error.is_none())
        {
            need_error_cb = false;
            error_cb = py::function();
        }
        else
        {
            need_error_cb = true;
            error_cb = error.cast<py::function>();
        }

        if (progress.is_none())
        {
            need_progress_cb = false;
            progress_cb = py::function();
        }
        else
        {
            need_progress_cb = true;
            progress_cb = progress.cast<py::function>();
        }
    }
};

struct TransferTask
{
    std::string src;
    std::string dst;
    uint64_t size;
    PathType path_type = PathType::FILE;
    TransferTask(std::string src, std::string dst, uint64_t size, PathType path_type = PathType::FILE)
        : src(src), dst(dst), size(size), path_type(path_type) {}
};

struct PathInfo
{
    std::string name;
    std::string path;
    std::string dir;
    std::string uname;
    uint64_t size = -1;
    uint64_t atime = -1;
    uint64_t mtime = -1;
    PathType path_type = PathType::FILE;
    uint64_t permission = 777;
    PathInfo()
        : name(""), path(""), dir(""), uname(""), size(-1), atime(-1), mtime(-1), path_type(PathType::FILE), permission(0) {}
    PathInfo(std::string name, std::string path, std::string dir, std::string uname, uint64_t size, uint64_t atime, uint64_t mtime, PathType path_type = PathType::FILE, uint64_t permission = 777)
        : name(name), path(path), dir(dir), uname(uname), size(size), atime(atime), mtime(mtime), path_type(path_type), permission(permission) {}
};

class FileMapper
{
private:
    HANDLE hFile;
    HANDLE hMap;
    LPVOID addr;
    LARGE_INTEGER file_size_ptr;

public:
    char *file_ptr;
    uint64_t file_size;
    ~FileMapper()
    {

        UnmapViewOfFile(addr);

        CloseHandle(hMap);

        CloseHandle(hFile);
        file_ptr = nullptr;
    }
    FileMapper()
    {
        this->hFile = nullptr;
        this->hMap = nullptr;
        this->addr = nullptr;
        this->file_ptr = nullptr;
    }

    FileMapper(std::wstring &file_path, MapType map_type, std::string &error_msg, uint64_t file_size = 0)
    {
        LARGE_INTEGER li;
        li.QuadPart = file_size;
        bool is_ok = false;

        if (map_type == MapType::Read)
        {
            this->hFile = CreateFileW(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (this->hFile == INVALID_HANDLE_VALUE)
            {
                goto DONE;
            }

            GetFileSizeEx(this->hFile, &file_size_ptr);
            this->file_size = file_size_ptr.QuadPart;
            this->hMap = CreateFileMapping(this->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
            if (!this->hMap)
            {
                goto DONE;
            }
            this->addr = MapViewOfFile(this->hMap, FILE_MAP_READ, 0, 0, 0);
            if (!this->addr)
            {
                goto DONE;
            }
            this->file_ptr = (char *)this->addr;
            is_ok = true;
            goto DONE;
        }

        this->hFile = CreateFileW(file_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (this->hFile == INVALID_HANDLE_VALUE)
        {
            goto DONE;
        }

        if (!SetFilePointerEx(this->hFile, li, NULL, FILE_BEGIN))
        {
            goto DONE;
        }

        if (!SetEndOfFile(this->hFile))
        {
            goto DONE;
        }
        this->hMap = CreateFileMapping(this->hFile, NULL, PAGE_READWRITE, li.HighPart, li.LowPart, NULL);

        if (!this->hMap)
        {
            goto DONE;
        }
        this->addr = MapViewOfFile(this->hMap, FILE_MAP_WRITE, 0, 0, 0);

        if (!this->addr)
        {
            goto DONE;
        }
        this->file_ptr = (char *)this->addr;
        is_ok = true;
    DONE:
        if (!is_ok)
        {
            DWORD err = GetLastError();
            LPSTR errMsg = nullptr;
            FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&errMsg, 0, NULL);
            error_msg = errMsg;
            LocalFree(errMsg);
            this->file_ptr = nullptr;
            return;
        }
    }
};

struct ErrorInfo2
{
    TransferErrorCode error_code;
    std::string src;
    std::string dst;
    std::string function_name;
    std::string msg;

    ErrorInfo2()
        : error_code(TransferErrorCode::UnknownError), src(""), dst(""), function_name(""), msg("") {}

    ErrorInfo2(TransferErrorCode error_code, std::string src, std::string dst, std::string function_name, std::string msg)
        : error_code(error_code), src(src), dst(dst), function_name(function_name), msg(msg) {}

    std::string toString()
    {
        return "ErrorInfo(error_code=" + std::to_string(static_cast<int>(error_code)) + ", src=" + src + ", dst=" + dst + ", function_name=" + function_name + ", msg=" + msg + ")";
    }
};

struct SingleBuffer
{
    std::shared_ptr<char[]> bufferptr_origin;
    char *bufferptr = nullptr;
    BufferStatus status = BufferStatus::write_done;
    uint64_t written = 0;
    uint64_t read = 0;
    uint64_t write_order = 0;
    uint64_t read_order = 0;
    SingleBuffer() {}
    SingleBuffer(size_t buffer_size) : bufferptr_origin(new char[buffer_size], std::default_delete<char[]>()),
                                       bufferptr(bufferptr_origin.get()) {}
};

struct TransferContext
{
    std::unordered_map<int, SingleBuffer> bufferd;
    TransferContext(size_t buffer_size)
    {
        bufferd[0] = SingleBuffer(buffer_size);
        bufferd[1] = SingleBuffer(buffer_size);
    }

    int get_write_buffer()
    {
        if (bufferd[0].status == BufferStatus::is_writing)
        {
            return 0;
        }
        else if (bufferd[1].status == BufferStatus::is_writing)
        {
            return 1;
        }
        else if (bufferd[0].status == BufferStatus::read_done)
        {
            if (bufferd[1].status == BufferStatus::read_done && bufferd[0].read_order > bufferd[1].read_order)
            {
                bufferd[1].status = BufferStatus::is_writing;
                return 1;
            }
            else
            {
                bufferd[0].status = BufferStatus::is_writing;
                return 0;
            }
        }

        else if (bufferd[1].status == BufferStatus::read_done)
        {
            bufferd[1].status = BufferStatus::is_writing;
            return 1;
        }
        else
        {
            return -1;
        }
    }

    int get_read_buffer()
    {
        if (bufferd[0].status == BufferStatus::is_reading)
        {
            return 0;
        }
        else if (bufferd[1].status == BufferStatus::is_reading)
        {
            return 1;
        }
        else if (bufferd[0].status == BufferStatus::write_done)
        {
            if (bufferd[1].status == BufferStatus::write_done && bufferd[0].write_order > bufferd[1].write_order)
            {
                bufferd[1].status = BufferStatus::is_reading;
                return 1;
            }
            else
            {
                bufferd[0].status = BufferStatus::is_reading;
                return 0;
            }
        }
        else if (bufferd[1].status == BufferStatus::write_done)
        {
            bufferd[1].status = BufferStatus::is_reading;
            return 1;
        }
        else
        {
            return -1;
        }
    }

    void finish_write(int buffer_name, uint64_t order)
    {
        bufferd[buffer_name].status = BufferStatus::write_done;
        bufferd[buffer_name].written = 0;
        bufferd[buffer_name].read = 0;
        bufferd[buffer_name].write_order = order;
    }

    void finish_read(int buffer_name, uint64_t order)
    {
        bufferd[buffer_name].status = BufferStatus::read_done;
        bufferd[buffer_name].written = 0;
        bufferd[buffer_name].read_order = order;
    }
};

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

const std::unordered_map<int, EC> Int2EC = []
{
    std::unordered_map<int, EC> map;
    for (auto [val, name] : magic_enum::enum_entries<EC>())
    {
        map[static_cast<int>(val)] = val;
    }
    return map;
}();

using EC = TransferErrorCode;
using result_map = std::unordered_map<std::string, TransferErrorCode>;
using TASKS = std::vector<TransferTask>;
using int_ptr = std::shared_ptr<uint64_t>;
using safe_int_ptr = std::shared_ptr<std::atomic<uint64_t>>;
using ECM = std::pair<EC, std::string>;
using RMR = std::vector<std::pair<std::string, ECM>>;
using TRM = std::vector<std::pair<std::pair<std::string, std::string>, ECM>>;
using RR = std::variant<std::string, ECM>;
using TR = std::variant<TRM, ECM>;
using BR = std::variant<bool, ECM>;
using SR = std::variant<PathInfo, ECM>;
using LR = std::variant<std::vector<PathInfo>, ECM>;
using WRV = std::vector<PathInfo>;
using WR = std::variant<WRV, ECM>;
using ED = std::pair<EC, std::string>;
using SIZER = std::variant<uint64_t, ECM>;
using ErrorInfo = std::unordered_map<std::string, std::variant<std::string, EC>>;

void _local_walk(std::string path, WRV &result)
{
    fs::path p(path);
    fs::file_status status;
    if (!fs::exists(p))
    {
        return;
    }
    try
    {
        status = fs::status(p);
    }
    catch (const std::exception)
    {
        return;
    }
    std::string filename = p.filename().string();
    std::string dir = p.parent_path().string();
    auto ftime = fs::last_write_time(p);
    auto duration = ftime.time_since_epoch();
    uint64_t atime = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    uint64_t mtime = atime;
    bool end_dir = true;

    switch (status.type())
    {
    case fs::file_type::directory:
        for (const auto &entry : fs::directory_iterator(p))
        {
            if (fs::is_directory(entry.status()))
            {
                end_dir = false;
            }
            _local_walk(entry.path().string(), result);
        }
        if (end_dir)
        {
            result.push_back(PathInfo(filename, path, dir, "", 0, atime, mtime, PathType::DIR));
        }
        break;
    case fs::file_type::symlink:
        result.push_back(PathInfo(filename, path, dir, "", 0, atime, mtime, PathType::SYMLINK));
        break;
    default:
        result.push_back(PathInfo(filename, path, dir, "", fs::file_size(p), atime, mtime, PathType::FILE));
        break;
    }
}

bool isok(ECM &ecm)
{
    return ecm.first == EC::Success;
}

WRV local_walk(std::string path)
{
    WRV result = {};

    _local_walk(path, result);

    return result;
}

class CircularBuffer
{
private:
    std::vector<ErrorInfo> buffer = {};
    size_t capacity = 10;

public:
    CircularBuffer() {}

    CircularBuffer(size_t size) : capacity(size)
    {
        if (size > 0)
        {
            capacity = size;
        }
    }

    void push(const ErrorInfo value)
    {
        if (buffer.size() < capacity)
        {
            buffer.push_back(value);
        }
        else
        {
            buffer.erase(buffer.begin());
            buffer.push_back(value);
        }
    }

    size_t size() const { return buffer.size(); }

    size_t getCapacity() const { return capacity; }

    std::variant<py::object, ErrorInfo> back()
    {
        if (buffer.size() == 0)
        {
            return py::none();
        }
        return buffer[buffer.size() - 1];
    }

    std::vector<ErrorInfo> GetAllErrors()
    {
        std::vector<ErrorInfo> result;
        for (auto &item : buffer)
        {
            result.push_back(item);
        }
        return result;
    }

    bool isEmpty() const { return buffer.size() == 0; }

    void clear()
    {
        buffer.clear();
    }

    void setCapacity(int size)
    {
        if (size <= 0)
        {
            return;
        }
        if (size > capacity)
        {
            capacity = size;
        }
        else
        {
            buffer.resize(size);
            capacity = size;
        }
    }
};

class AMTracer
{
private:
    py::function trace_cb;
    std::atomic<bool> is_py_trace = false;
    CircularBuffer ErrorBuffer;
    std::atomic<bool> is_pause = false;

public:
    AMTracer(int size = 10, py::object trace_cb = py::none())
    {
        size = size > 0 ? size : 10;
        this->ErrorBuffer = CircularBuffer(size);
        if (!trace_cb.is_none())
        {
            this->trace_cb = py::cast<py::function>(trace_cb);
            this->is_py_trace = true;
        }
        else
        {
            this->is_py_trace = false;
        }
    }

    void trace(std::string level, EC error_code, std::string target = "", std::string action = "", std::string msg = "")
    {
        if (is_pause.load())
        {
            return;
        }
        ErrorInfo level_map = {
            {AMLEVEL, level},
            {AMERRORCODE, error_code},
            {AMTARGET, target},
            {AMACTION, action},
            {AMMESSAGE, msg},
        };
        if (is_py_trace.load())
        {
            py::gil_scoped_acquire acquire;
            trace_cb(level_map);
        }
        ErrorBuffer.push(level_map);
    }

    void pause()
    {
        is_pause.store(true);
    }

    void resume()
    {
        is_pause.store(false);
    }

    void Clear()
    {
        ErrorBuffer.clear();
    }

    void SetCapacity(int size)
    {
        if (size > 0)
        {
            ErrorBuffer.setCapacity(size);
        }
    }

    void SetPyTrace(py::object pytrace = py::none())
    {
        if (pytrace.is_none())
        {
            is_py_trace.store(false);
            trace_cb = py::function();
        }
        else
        {
            trace_cb = py::cast<py::function>(pytrace);
            is_py_trace.store(true);
        }
    }

    std::vector<ErrorInfo> AllErrors()
    {
        return ErrorBuffer.GetAllErrors();
    }

    std::variant<py::object, ErrorInfo> LastTraceError()
    {
        return ErrorBuffer.back();
    }

    bool IsEmpty()
    {
        return ErrorBuffer.isEmpty();
    }
};

class AMSession
{
public:
    LIBSSH2_SESSION *session = nullptr;
    LIBSSH2_SFTP *sftp = nullptr;
    SOCKET sock = INVALID_SOCKET;
    std::vector<std::string> private_keys;
    std::shared_ptr<AMTracer> amtracer;
    ConRequst request;
    std::string cwd = "";
    py::function auth_cb = py::function(); // Callable[[int, ConRequst, int], str]
    bool password_auth_cb = false;

    bool IsValidKey(std::string key)
    {
        FILE *fp = fopen(key.c_str(), "r");
        if (!fp)
            return false;

        RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);

        if (rsa)
        {
            RSA_free(rsa);
            return true;
        }
        return false;
    }

    void LoadPrivateKeys()
    {
        std::vector<std::string> keys;
        for (auto &key : this->private_keys)
        {
            if (IsValidKey(key))
            {
                keys.push_back(key);
            }
        }
        if (!keys.empty())
        {
            this->private_keys = keys;
            return;
        }
        std::string default_key_dir = local_realpath("~/.ssh");
        for (auto &entry : fs::directory_iterator(default_key_dir))
        {
            if (fs::is_regular_file(entry))
            {
                if (IsValidKey(entry.path().string()))
                {
                    keys.push_back(entry.path().string());
                }
            }
        }
        this->private_keys = keys;
    }

    ECM Connect()
    {
        std::string msg = "";
        EC rc = EC::Success;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            trace(AMCRITICAL, EC::SocketCreateError, request.nickname, "CreateSocket", "Create but get invalid socket");
            return {EC::SocketCreateError, "Create but get invalid socket"};
        }

        unsigned long nonblocking = 1;
        ioctlsocket(sock, FIONBIO, &nonblocking);

        sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(request.port);
        inet_pton(AF_INET, request.hostname.c_str(), &sin.sin_addr);
        int rcr = connect(sock, (sockaddr *)&sin, sizeof(sin));

        timeval timeout;
        timeout.tv_sec = request.timeout_s;
        timeout.tv_usec = 0;

        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(sock, &writeSet);
        int selectRet = select(sock + 1, nullptr, &writeSet, nullptr, &timeout);
        if (selectRet <= 0)
        {
            if (selectRet == 0)
            {
                trace(AMCRITICAL, EC::NetworkTimeout, request.nickname, "ConnectSocket", "Connect Timeout");
                return {EC::NetworkTimeout, "Connection Establish Timeout"};
            }
            else
            {
                trace(AMCRITICAL, EC::NetworkError, request.nickname, "ConnectSocket", "Connect Failed");
                return {EC::NetworkError, "Connection Establish Failed"};
            }

            session = libssh2_session_init();

            if (!session)
            {
                trace(AMCRITICAL, EC::SessionCreateError, request.nickname, "SessionInit", "Session initialization failed");
                return {EC::SessionCreateError, "Libssh2 Session initialization failed"};
            }

            libssh2_session_set_blocking(session, 1);

            if (request.compression)
            {
                libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
                libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS, "zlib@openssh.com,zlib,none");
            }

            int rc_handshake = libssh2_session_handshake(session, sock);

            if (rc_handshake != 0)
            {
                trace(AMCRITICAL, EC::SessionEstablishError, request.nickname, "SessionHandshake", "Session handshake failed");
                return {EC::SessionEstablishError, "Session handshake failed"};
            }
            const char *auth_list = libssh2_userauth_list(session, request.username.c_str(), request.username.length());
            if (auth_list == nullptr)
            {
                trace(AMCRITICAL, EC::ConnectionAuthorizeError, request.nickname, "SessionHandshake", "Fail to negotiate authentication method");
                return {EC::ConnectionAuthorizeError, "Fail to negotiate authentication method"};
            }

            bool password_auth = false;
            if (strstr(auth_list, "password") != NULL)
            {
                password_auth = true;
            }

            rc = EC::ConnectionAuthorizeError;
            int rca = 0;
            int trial_times = 0;
            std::string password_tmp;
            if (!request.keyfile.empty())
            {
                rca = libssh2_userauth_publickey_fromfile(session, request.username.c_str(), nullptr, request.keyfile.c_str(), nullptr);
                if (rca == 0)
                {
                    rc = EC::Success;
                    msg = "";
                    trace(AMINFO, EC::Success, request.nickname, "PublicKeyAuthorize", fmt::format("Public key \"{}\" authorize success", request.keyfile));
                    goto OK;
                }
            }

            if (!request.password.empty())
            {
                rca = libssh2_userauth_password(session, request.username.c_str(), request.password.c_str());
                if (rca == 0)
                {
                    rc = EC::Success;
                    msg = "";
                    trace(AMINFO, EC::Success, request.nickname, "PasswordAuthorize", "Password authorize success");
                    goto OK;
                }
            }

            if (password_auth_cb)
            {
                while (trial_times < 2)
                {
                    password_tmp = py::cast<std::string>(auth_cb(0, request, trial_times)); // 0 means password demand
                    if (password_tmp.empty())
                    {
                        break;
                    }
                    rca = libssh2_userauth_password(session, request.username.c_str(), password_tmp.c_str());
                    trial_times++;
                    if (rca == 0)
                    {
                        rc = EC::Success;
                        msg = "";
                        trace(AMINFO, EC::Success, request.nickname, "PasswordAuthorize", "Password authorize success");
                        goto OK;
                    }
                    else
                    {
                        auth_cb(1, request, trial_times); // 1 means info, false means failed
                    }
                }
            }

            for (auto &private_key : private_keys)
            {
                rca = libssh2_userauth_publickey_fromfile(session, request.username.c_str(), nullptr, private_key.c_str(), nullptr);

                if (rca == 0)
                {
                    msg = fmt::format("Public key \"{}\" authorize success", private_key);
                    trace(AMINFO, EC::Success, request.nickname, "PublicKeyAuthorize", msg);
                    rc = EC::Success;
                    goto OK;
                }
                else
                {
                    msg = fmt::format("Public key \"{}\" authorize failed", private_key);
                    trace(AMWARNING, EC::PublicKeyAuthFailed, request.nickname, "PublicKeyAuthorize", msg);
                }
            }
        OK:
            if (rc != TransferErrorCode::Success)
            {
                trace(AMCRITICAL, EC::AuthFailed, request.nickname, "FinalAuthorizeState", "All authorize methods failed");
                return {rc, "All authorize methods failed"};
            }

            sftp = libssh2_sftp_init(session);

            if (!sftp)
            {
                trace(AMCRITICAL, EC::SftpCreateError, request.nickname, "SFTPInitialization", "SFTP initialization failed");
                return {EC::SftpCreateError, "SFTP initialization failed"};
            }

            return {EC::Success, ""};
        }
    }

    ECM Check()
    {
        if (!sftp)
        {
            trace(AMCRITICAL, EC::SftpNotInitialized, "Sftp", "SFTPCheck", "SFTP not initialized");
            return {EC::SftpNotInitialized, "SFTP not initialized"};
        }

        if (!session)
        {
            trace(AMCRITICAL, EC::SessionNotInitialized, "Session", "SessionCheck", "Session not initialized");
            return {EC::SessionNotInitialized, "Session not initialized"};
        }

        LIBSSH2_SFTP_ATTRIBUTES attrs;
        std::string test_path = "amtrial";
        int rct;

        rct = libssh2_sftp_stat(sftp, test_path.c_str(), &attrs);

        if (rct != 0)
        {
            EC rc;
            rc = cast_libssh2_error(libssh2_sftp_last_error(sftp));

            if (rc == EC::PathNotExist)
            {
                return {EC::Success, ""};
            }
            std::string msg = StrSftpEC(libssh2_sftp_last_error(sftp));
            trace(AMCRITICAL, rc, fmt::format("{}@{}", request.nickname, request.port), "TrialPathStatCheck", msg);
            return {rc, msg};
        }

        trace(AMINFO, EC::Success, fmt::format("{}@{}", request.nickname, "SSHSeesion"), "Check", "");
        return {EC::Success, ""};
    }

    void clean()
    {
        if (sftp)
        {
            libssh2_sftp_shutdown(sftp);
        }
        if (session)
        {
            libssh2_session_disconnect(session, "Normal Shutdown");
            libssh2_session_free(session);
        }
        if (sock != INVALID_SOCKET)
        {
            closesocket(sock);
        }
    }

    ECM Reconnect()
    {
        clean();
        return Connect();
    }

    AMSession()
    {
        this->session = nullptr;
        this->sftp = nullptr;
        this->private_keys = {};
        this->sock = INVALID_SOCKET;
        this->request = ConRequst();
        this->private_keys = {};
        this->amtracer = nullptr;
    }

    AMSession(ConRequst request, std::vector<std::string> private_keys, std::shared_ptr<AMTracer> amtracer = nullptr, py::object auth_cb = py::none())
        : request(request), private_keys(private_keys), amtracer(amtracer)
    {
        if (!auth_cb.is_none())
        {
            this->auth_cb = py::cast<py::function>(auth_cb);
            this->password_auth_cb = true;
        }
    }

    ~AMSession()
    {
        clean();
    }

    void trace(std::string level, EC error_code, std::string target = "", std::string action = "", std::string msg = "")
    {
        amtracer->trace(level, error_code, target, action, msg);
    }
};

class SafeChannel
{
public:
    LIBSSH2_CHANNEL *channel = nullptr;
    std::string error_msg = "";
    ~SafeChannel()
    {
        if (channel)
        {
            libssh2_channel_close(channel);
            libssh2_channel_free(channel);
        }
    }

    SafeChannel(std::shared_ptr<AMSession> amsession)
    {
        this->channel = libssh2_channel_open_ex(amsession->session,
                                                "session",
                                                sizeof("session") - 1,
                                                4 * AMMB,
                                                32 * AMKB,
                                                nullptr,
                                                0);
        if (!channel)
        {
            error_msg = "Channel creation failed";
        }
    }
};

class BaseSFTPClient
{
public:
    std::string trash_dir;
    std::vector<std::string> private_keys;
    ConRequst request;
    std::shared_ptr<AMSession> amsession;
    std::shared_ptr<AMTracer> amtracer;

    BaseSFTPClient()
    {
        this->trash_dir = "";
        this->private_keys = {};
        this->request = ConRequst();
        this->amtracer = nullptr;
    }

    BaseSFTPClient(ConRequst request, std::vector<std::string> private_keys, size_t error_num = 10, py::object trace_cb = py::none())
    {
        this->trash_dir = "";
        this->private_keys = private_keys;
        this->request = request;
        this->amtracer = std::make_shared<AMTracer>(error_num, trace_cb);
        this->amsession = std::make_shared<AMSession>(request, private_keys, amtracer, trace_cb);
    }

    PathInfo FormatStat(std::string path, LIBSSH2_SFTP_ATTRIBUTES &attrs)
    {
        PathInfo info;
        info.path = path;
        info.name = basename(path);
        info.dir = dirname(path);
        long uid = attrs.uid;
        std::string user_name = StrUid(uid);
        if (user_name.empty())
        {
            info.uname = std::to_string(uid);
        }
        else
        {
            info.uname = user_name;
        }

        if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE)
        {
            info.size = attrs.filesize;
        }

        if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME)
        {
            info.atime = attrs.atime;
            info.mtime = attrs.mtime;
        }

        if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)
        {
            const uint32_t mode = attrs.permissions;
            const uint32_t file_type = mode & LIBSSH2_SFTP_S_IFMT;
            switch (file_type)
            {
            case LIBSSH2_SFTP_S_IFDIR:
                info.path_type = PathType::DIR;
                break;
            case LIBSSH2_SFTP_S_IFLNK:
                info.path_type = PathType::SYMLINK;
                break;
            }
            info.permission = attrs.permissions & 0777;
        }
        return info;
    }

    void trace(std::string level, EC error_code, std::string target = "", std::string action = "", std::string msg = "")
    {
        amtracer->trace(level, error_code, target, action, msg);
    }

    std::variant<py::object, ErrorInfo> LastTraceError()
    {
        return amtracer->LastTraceError();
    }

    std::vector<ErrorInfo> GetAllErrors()
    {
        return amtracer->AllErrors();
    }

    std::string GetTrashDir()
    {
        return this->trash_dir;
    }

    std::string Nickname()
    {
        return this->request.nickname;
    }

    void SetPyTrace(py::object trace_cb = py::none())
    {
        amtracer->SetPyTrace(trace_cb);
    }

    EC SessionEC()
    {
        return cast_libssh2_error(libssh2_session_last_errno(amsession->session));
    }

    EC SftpEC()
    {
        return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
    }

    EC LibsshEC()
    {
        int session_err = libssh2_session_last_errno(amsession->session);
        if (session_err == LIBSSH2_ERROR_SFTP_PROTOCOL)
        {
            session_err = libssh2_sftp_last_error(amsession->sftp);
        }
        if (Int2EC.find(session_err) != Int2EC.end())
        {
            return Int2EC.at(session_err);
        }
        return EC::UnknownError;
    }
    std::string LibsshErrorMsg()
    {
        int session_err = libssh2_session_last_errno(amsession->session);
        if (session_err == LIBSSH2_ERROR_EAGAIN)
        {
            return "";
        }
        else if (session_err == LIBSSH2_ERROR_SFTP_PROTOCOL)
        {
            int sftp_err = libssh2_sftp_last_error(amsession->sftp);
            // 检查sftp_err是否在SFTPMessage中
            if (SFTPMessage.find(sftp_err) != SFTPMessage.end())
            {
                return SFTPMessage.at(sftp_err);
            }
            return "Unknown SFTP error";
        }
        char *errmsg = NULL;
        int errmsg_len;
        int errcode = libssh2_session_last_error(amsession->session, &errmsg, &errmsg_len, 0);
        return std::string(errmsg);
    }

    ECM Check()
    {
        EC rc = EC::Success;
        std::string msg = "";
        if (!amsession)
        {
            rc = EC::SessionNotInitialized;
            msg = "Session is not initialized";
            trace(AMCRITICAL, rc, "AMSFTPClient", "Check", msg);
            return {rc, msg};
        }
        else
        {
            ECM ecm = amsession->Check();
            if (!isok(ecm))
            {
                return ecm;
            }
        }
        return {rc, msg};
    }

    ECM Reconnect()
    {
        ECM ecm = amsession->Reconnect();
        if (!isok(ecm))
        {
            return ecm;
        }
        return {EC::Success, ""};
    }

    ECM Ensure()
    {
        ECM ecm = Check();
        if (!isok(ecm))
        {
            ecm = Reconnect();
            if (!isok(ecm))
            {

                return ecm;
            }
        }
        return {EC::Success, ""};
    }

    OS_TYPE OS_NAME()
    {
        SafeChannel channel(amsession);
        if (!channel.channel)
        {
            return OS_TYPE::Unknown;
        }
        std::string cmd = "uname -s";
        int out = libssh2_channel_exec(channel.channel, cmd.c_str());
        if (out < 0)
        {
            return OS_TYPE::Unknown;
        }
        char buf[1024];
        int nbytes = libssh2_channel_read(channel.channel, buf, sizeof(buf) - 1);
        if (nbytes > 0)
        {
            buf[nbytes] = '\0';
            if (std::string(buf) == "Linux")
            {
                return OS_TYPE::Linux;
            }
            else if (std::string(buf) == "Darwin")
            {
                return OS_TYPE::MacOS;
            }
            else if (std::string(buf) == "Windows")
            {
                return OS_TYPE::Windows;
            }
        }
        return OS_TYPE::Unknown;
    }

    virtual std::string StrUid(long uid) { return ""; };
};

class AMSFTPClient : public BaseSFTPClient
{
private:
    std::map<long, std::string> user_id_map;
    bool is_trash_dir_ensure = false;

    void _walk(std::string path, WRV &result)
    {
        SR info = stat(path);
        if (!std::holds_alternative<PathInfo>(info))
        {
            return;
        }
        PathInfo info_path = std::get<PathInfo>(info);
        if (info_path.path_type != PathType::DIR)
        {
            result.push_back(info_path);
            return;
        }
        LR list = listdir(path);
        std::vector<PathInfo> list_info = {};
        if (!std::holds_alternative<std::vector<PathInfo>>(list))
        {
            return;
        }
        list_info = std::get<std::vector<PathInfo>>(list);
        if (list_info.empty())
        {
            SR info = stat(path);
            if (!std::holds_alternative<PathInfo>(info))
            {
                return;
            }
            result.push_back(std::get<PathInfo>(info));
            return;
        }
        bool all_file = true;
        for (auto &info : list_info)
        {
            if (info.path_type == PathType::DIR)
            {
                _walk(info.path, result);
                all_file = false;
            }
            else
            {
                result.push_back(info);
            }
        }
        if (all_file)
        {
            SR info = stat(path);
            if (!std::holds_alternative<PathInfo>(info))
            {
                return;
            }
            result.push_back(std::get<PathInfo>(info));
            return;
        }
    }

    void _GetSize(std::string path, uint64_t &size)
    {
        SR info = stat(path);
        if (!std::holds_alternative<PathInfo>(info))
        {
            return;
        }
        PathInfo path_info = std::get<PathInfo>(info);
        switch (path_info.path_type)
        {
        case PathType::FILE:
            size = path_info.size;
            return;
        case PathType::SYMLINK:
            return;
        case PathType::DIR:
            break;
        default:
            return;
        }

        LR list = listdir(path);
        if (!std::holds_alternative<WRV>(list))
        {
            return;
        }

        for (auto &item : std::get<WRV>(list))
        {
            _GetSize(item.path, size);
        }
    }

    void _rm(std::string path, RMR &errors)
    {
        BR rc = is_dir(path);
        bool is_dir;
        if (std::holds_alternative<bool>(rc))
        {
            is_dir = std::get<bool>(rc);
        }
        else
        {
            errors.push_back(std::make_pair(path, std::get<ECM>(rc)));
            return;
        }

        if (!is_dir)
        {
            ECM ecm = rmfile(path);
            if (!isok(ecm))
            {
                errors.push_back(std::make_pair(path, ecm));
            }
            return;
        }

        LR file_list = listdir(path);
        if (std::holds_alternative<std::vector<PathInfo>>(file_list))
        {
            std::vector<PathInfo> file_list_f = std::get<std::vector<PathInfo>>(file_list);
            for (auto &file : file_list_f)
            {
                _rm(file.path, errors);
            }
            ECM ecm = rmdir(path);
            if (!isok(ecm))
            {
                errors.push_back(std::make_pair(path, ecm));
            }
            return;
        }
        else
        {
            errors.push_back(std::make_pair(path, std::get<ECM>(file_list)));
        }
    }

public:
    ~AMSFTPClient()
    {
    }

    AMSFTPClient(ConRequst request, std::vector<std::string> private_keys, size_t error_info_buffer_size = 10) : BaseSFTPClient(request, private_keys, error_info_buffer_size)
    {
    }

    ECM Connect()
    {
        ECM ecm = amsession->Connect();
        if (!isok(ecm))
        {
            return ecm;
        }
        trash_dir = this->request.trash_dir;

        ecm = Check();
        if (!isok(ecm))
        {
            return ecm;
        }
        EnsureTrashDir();
        return {EC::Success, ""};
    }

    void SetAuthCallback(py::object auth_cb = py::none())
    {
        if (auth_cb.is_none())
        {
            this->amsession->password_auth_cb = false;
            this->amsession->auth_cb = py::function();
        }
        else
        {
            this->amsession->auth_cb = py::cast<py::function>(auth_cb);
            this->amsession->password_auth_cb = true;
        }
    }

    std::string StrUid(long uid)
    {
        if (user_id_map.find(uid) != user_id_map.end())
        {
            return user_id_map[uid];
        }
        char uname[64];
        SafeChannel channel(amsession);
        if (!channel.channel)
        {
            return "";
        }
        std::string cmd = fmt::format("id -un {}", uid);
        int out = libssh2_channel_exec(channel.channel, cmd.c_str());
        if (out < 0)
        {
            return "";
        }
        int nbytes = libssh2_channel_read(channel.channel, uname, sizeof(uname) - 1);
        if (nbytes > 0)
        {
            uname[nbytes] = '\0';
            user_id_map[uid] = std::string(uname);
            return std::string(uname);
        }
        else
        {
            return "";
        }
    }

    ECM SetTrashDir(std::string trash_dir_f = "")
    {
        if (!trash_dir_f.empty())
        {
            ECM res = mkdirs(trash_dir_f);
            if (!isok(res))
            {
                return res;
            }
            this->trash_dir = trash_dir_f;
            return {EC::Success, ""};
        }
        if (!request.trash_dir.empty())
        {
            ECM res = mkdirs(request.trash_dir);
            if (!isok(res))
            {
                return res;
            }
            this->trash_dir = request.trash_dir;
            return {EC::Success, ""};
        }
        char path_t[1024];
        std::string trash_dir_t = "";
        std::string cwd = "";
        int rcr = libssh2_sftp_realpath(amsession->sftp, ".", path_t, sizeof(path_t));
        if (rcr > 0)
        {
            cwd = std::string(path_t);
        }
        else
        {
            trace(AMERROR, EC::UnknownError, fmt::format("{}@{}", request.nickname, "CWD"), "SetTrashDir", "Can't get current working directory");
        }

        if (cwd.empty())
        {
            this->trash_dir = ".amsftp_trash";
        }
        else
        {
            this->trash_dir = join_path(cwd, ".amsftp_trash");
        }
        pytrace(AMINFO, "", "TrashDir", "DefaultTrashDir", fmt::format("Trash directory set to default: \"{}\"", this->trash_dir));
        ECM res = mkdirs(this->trash_dir);
        if (!isok(res))
        {
            return res;
        }
        return {EC::Success, ""};
    }

    ECM EnsureTrashDir()
    {
        ECM res = mkdirs(this->trash_dir);
        if (!isok(res))
        {
            is_trash_dir_ensure = true;
            return res;
        }
        std::string trash_dir_t = "./.AMSFTP_Trash";
        ECM res2 = mkdirs(trash_dir_t);
        if (!isok(res2))
        {
            is_trash_dir_ensure = false;
            return res2;
        }
        is_trash_dir_ensure = true;
        this->trash_dir = trash_dir_t;
        trace(AMINFO, EC::Success, fmt::format("{}@{}", request.nickname, "TrashDir"), "EnsureTrashDir", fmt::format("Trash directory was set to default: \"{}\"", this->trash_dir));
        return {EC::Success, ""};
    }

    ECM chmod(std::string path, std::string mode, bool recursive = false)
    {
        ECM ecm = amsession->chmod(path, mode);
        if (!isok(ecm))
        {
            return ecm;
        }
    }

    RR realpath(std::string path)
    {
        char path_t[1024];
        int rcr = libssh2_sftp_realpath(amsession->sftp, path.c_str(), path_t, sizeof(path_t));
        if (rcr < 0)
        {
            EC rc = SftpEC();
            pytrace(AMERROR, "RealpathFailed", fmt::format("{}@{}", request.nickname, path), "Realpath", "realpath failed");
            return std::make_pair(rc, fmt::format("realpath {} failed", path));
        }
        else
        {
            return std::string(path_t);
        }
    }

    SR stat(std::string path)
    {
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        EC rc;
        std::string msg = "";
        int rct;
        {
            rct = libssh2_sftp_stat(amsession->sftp, path.c_str(), &attrs);
        }
        if (rct != 0)
        {
            rc = SftpEC();
            msg = LibsshErrorMsg();
            trace(AMWARNING, rc, fmt::format("{}@{}", request.nickname, path), "Stat", msg);
            return std::make_pair(rc, fmt::format("stat {} failed: {}", path, msg));
        }
        return FormatStat(path, attrs);
    }

    BR exists(std::string path)
    {
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        EC rc;
        int rct;
        {
            rct = libssh2_sftp_stat(amsession->sftp, path.c_str(), &attrs);
        }
        if (rct != 0)
        {
            rc = SftpEC();
            std::string msg = LibsshErrorMsg();
            switch (rc)
            {
            case EC::PathNotExist:
                return false;
            case EC::PermissionDenied:
                return std::make_pair(rc, fmt::format("No Permission to access path: {}", path));
            default:
                pytrace(AMERROR, "ExistsFailed", fmt::format("{}@{}", request.nickname, path), "Exists", fmt::format("exists check {} failed: {}", path, msg));
                return std::make_pair(rc, fmt::format("exists check {} failed: {}", path, msg));
            }
        }
        return true;
    }

    BR is_file(std::string path)
    {
        SR info = stat(path);
        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).path_type == PathType::FILE ? true : false;
        }
        else
        {
            return std::get<ECM>(info);
        }
    }

    BR is_dir(std::string path)
    {

        SR info = stat(path);

        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).path_type == PathType::DIR ? true : false;
        }
        else
        {
            return std::get<ECM>(info);
        }
    }

    BR is_symlink(std::string path)
    {

        SR info = stat(path);

        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).path_type == PathType::SYMLINK ? true : false;
        }
        else
        {
            return std::get<ECM>(info);
        }
    }

    LR listdir(std::string path, long max_num = -1)
    {

        std::string msg = "";
        std::vector<PathInfo> file_list = {};
        BR br = is_dir(path);

        if (std::holds_alternative<bool>(br))
        {
            if (!std::get<bool>(br))
            {
                return std::make_pair(EC::NotDirectory, fmt::format("Path is not a directory: {}", path));
            }
        }
        else
        {
            return std::get<ECM>(br);
        }

        std::string normalized_path = path;
        LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        std::string name;
        std::string path_i;
        const size_t buffer_size = 4096;
        std::vector<char> filename_buffer(buffer_size);
        EC rc;
        int rct;
        PathInfo info;
        bool is_sucess = false;

        sftp_handle = libssh2_sftp_open_ex(
            amsession->sftp,
            normalized_path.c_str(),
            normalized_path.size(),
            0,
            LIBSSH2_SFTP_OPENDIR,
            LIBSSH2_FXF_READ);

        if (!sftp_handle)
        {
            std::string tmp_msg = LibsshErrorMsg();
            pytrace(AMWARNING, "HandleOpenFailed", fmt::format("{}@{}", request.nickname, path), "ListDir", tmp_msg);
            msg = fmt::format("Path: {} handle open failed: {}", path, tmp_msg);
            rc = EC::InvalidHandle;
            goto clean;
        }

        while (true)
        {
            rct = libssh2_sftp_readdir_ex(
                sftp_handle,
                filename_buffer.data(),
                buffer_size,
                nullptr, 0,
                &attrs);

            if (rct < 0)
            {
                rc = SftpEC();
                std::string tmp_msg = LibsshErrorMsg();
                pytrace(AMWARNING, "ReadDirFailed", fmt::format("{}@{}", request.nickname, path), "ListDir", tmp_msg);
                msg = fmt::format("Path: {} readdir failed: {}", path, tmp_msg);
                goto clean;
            }
            else if (rct == 0)
            {
                is_sucess = true;
                break;
            }
            else if (max_num > 0 && file_list.size() >= max_num)
            {
                is_sucess = true;
                break;
            }
            name.assign(filename_buffer.data(), rct);

            if (name == "." || name == "..")
            {
                continue;
            }

            path_i = join_path(normalized_path, name);
            info = FormatStat(path_i, attrs);
            file_list.push_back(info);
        }

    clean:
        if (sftp_handle)
        {
            libssh2_sftp_close_handle(sftp_handle);
        }
        if (is_sucess)
        {
            return file_list;
        }
        else
        {
            return std::make_pair(rc, msg);
        }
    }

    ECM mkdir(std::string path)
    {
        std::string msg = "";
        BR br = is_dir(path);
        if (std::holds_alternative<ECM>(br))
        {
            ECM ecm = std::get<ECM>(br);
            if (ecm.first != EC::PathNotExist)
            {
                return ecm;
            }
        }
        else
        {
            if (!std::get<bool>(br))
            {
                return {EC::PathAlreadyExists, fmt::format("Path exists and is not a directory: {}", path)};
            }
            else
            {
                return {EC::Success, ""};
            }
        }

        int rcr = libssh2_sftp_mkdir_ex(amsession->sftp, path.c_str(), path.size(), 0740);

        if (rcr != 0)
        {
            EC rc = SftpEC();
            std::string msg_tmp = LibsshErrorMsg();
            msg = fmt::format("Path: {} mkdir failed: {}", path, msg_tmp);
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::mkdir", msg_tmp));
            pytrace(AMWARNING, "MkdirFailed", fmt::format("{}@{}", request.nickname, path), "Mkdir", msg_tmp);
            return {rc, msg};
        }
        return {EC::Success, ""};
    }

    ECM mkdirs(std::string path)
    {
        if (path.empty())
        {
            return {EC::InvalidParameter, "path parameter can't be an empty string"};
        }

        std::replace(path.begin(), path.end(), '\\', '/');
        std::vector<std::string> parts = split_path(path);
        std::string root = ".";
        if (parts[0] == "/")
        {
            root = "/";
            parts.erase(parts.begin());
        }
        else if (parts.size() == 2 && parts[0][1] == ':')
        {
            root = parts[0];
            parts.erase(parts.begin());
        }

        std::string current_path = root;
        for (const auto &part : parts)
        {
            current_path = join_path(current_path, part);

            ECM rc = mkdir(current_path);
            if (isok(rc))
            {
                continue;
            }
            else
            {
                return rc;
            }
        }
        return {EC::Success, ""};
    }

    ECM rmfile(std::string path)
    {
        SR info = stat(path);
        ECM ecm;
        EC rc;
        std::string msg = "";
        if (std::holds_alternative<ECM>(info))
        {
            return std::get<ECM>(info);
        }
        else
        {
            if (std::get<PathInfo>(info).path_type == PathType::DIR)
            {
                msg = fmt::format("Path is not a file: {}", path);
                record_error(ErrorInfo(EC::TargetNotAFile, path, "", "AMSFTPClient::rmfile", "Path is not a file"));
                return {EC::TargetNotAFile, msg};
            }
        }

        int rcr = libssh2_sftp_unlink(amsession->sftp, path.c_str());

        if (rcr != 0)
        {
            rc = SftpEC();
            std::string tmp_msg = LibsshErrorMsg();
            msg = fmt::format("rmfile {} failed: {}", path, tmp_msg);
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::rmfile", tmp_msg));
            pytrace(AMWARNING, "RmfileFailed", fmt::format("{}@{}", request.nickname, path), "Rmfile", tmp_msg);
            return {rc, msg};
        }
        return {EC::Success, ""};
    }

    ECM rmdir(std::string path)
    {
        LR lr = listdir(path, 1);
        std::string msg = "";
        EC rc;
        if (std::holds_alternative<std::vector<PathInfo>>(lr))
        {
            std::vector<PathInfo> file_list = std::get<std::vector<PathInfo>>(lr);
            if (!file_list.empty())
            {
                msg = fmt::format("Directory is not empty: {}", path);
                return {EC::DirNotEmpty, msg};
            }
        }
        else
        {
            return std::get<ECM>(lr);
        }

        int rcr;
        {

            rcr = libssh2_sftp_rmdir(amsession->sftp, path.c_str());
        }
        if (rcr < 0)
        {
            rc = SftpEC();
            std::string tmp_msg = LibsshErrorMsg();
            msg = fmt::format("Path: {} rmdir failed: {}", path, tmp_msg);
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::rmdir", tmp_msg));
            pytrace(AMWARNING, "RmdirFailed", fmt::format("{}@{}", request.nickname, path), "Rmdir", tmp_msg);
            return {rc, msg};
        }
        return {EC::Success, ""};
    }

    ECM rename(std::string src, std::string newname)
    {
        std::string src_dir = dirname(src);
        std::string dst_path = join_path(src_dir, newname);
        return move(src, dst_path);
    }

    ECM move(std::string src, std::string dst, bool need_mkdir = false, bool force_write = false)
    {
        SR sr = stat(src);
        ECM ecm;

        if (std::holds_alternative<ECM>(sr))
        {
            return std::get<ECM>(sr);
        }
        PathInfo src_stat = std::get<PathInfo>(sr);

        std::string src_base = basename(src);
        std::string dst_dir = dst;
        std::string dst_path = join_path(dst_dir, src_base);
        BR br = is_dir(dst_dir);
        if (std::holds_alternative<ECM>(br))
        {
            ecm = std::get<ECM>(br);
            if (ecm.first == EC::PathNotExist)
            {
                if (need_mkdir)
                {
                    ecm = mkdirs(dst_dir);
                    if (!isok(ecm))
                    {
                        return ecm;
                    }
                }
                else
                {
                    return {EC::ParentDirectoryNotExist, fmt::format("Dst dir not exists: {}", dst_dir)};
                }
            }
            else
            {
                return ecm;
            }
        }
        else
        {
            if (!std::get<bool>(br))
            {
                return {EC::PathAlreadyExists, fmt::format("Dst already exists: {} but not a directory", dst_dir)};
            }
        }

        SR dst_stat = stat(dst_path);
        if (std::holds_alternative<PathInfo>(dst_stat))
        {
            PathInfo dst_stat_info = std::get<PathInfo>(dst_stat);
            if (!force_write)
            {
                return {EC::TargetExists, fmt::format("Dst already exists: {}", dst_path)};
            }
            if ((dst_stat_info.path_type == PathType::DIR) != (src_stat.path_type == PathType::DIR))
            {
                return {EC::TargetExists, fmt::format("Dst already exists and has different type with src: {}", dst_path)};
            }
        }

        int rcr = libssh2_sftp_rename_ex(amsession->sftp, src.c_str(), src.size(), dst_path.c_str(), dst_path.size(), LIBSSH2_SFTP_RENAME_OVERWRITE);

        EC rc;
        std::string msg = "";
        if (rcr != 0)
        {
            rc = SftpEC();
            std::string msg_tmp = LibsshErrorMsg();
            msg = fmt::format("Move {} to {} failed: {}", src, dst_path, msg_tmp);
            record_error(ErrorInfo(rc, src, dst_path, "AMSFTPClient::move", msg_tmp));
            if (rc != EC::PermissionDenied && rc != EC::PathNotExist && rc != EC::TargetExists)
            {
                pytrace(AMWARNING, "MoveFailed", fmt::format("{}@{}->{}", request.nickname, src, dst_path), "Move", msg_tmp);
            }
            return {rc, msg};
        }

        return {EC::Success, ""};
    }

    ECM saferm(std::string path)
    {
        BR br = exists(path);
        if (std::holds_alternative<ECM>(br))
        {
            return std::get<ECM>(br);
        }
        else if (!std::get<bool>(br))
        {
            trace(AMWARNING, EC::PathNotExist, fmt::format("{}@{}", request.nickname, path), "saferm", fmt::format("Src path not exists: {}", path));
            return {EC::PathNotExist, fmt::format("Src path not exists: {}", path)};
        }

        if (!is_trash_dir_ensure)
        {
            return {EC::InvalidTrashDir, fmt::format("Trash dir not ready: {}", this->trash_dir)};
        }
        std::string base = basename(path);
        std::string target_path;
        std::string base_name = base;
        std::string base_ext = "";
        size_t dot_pos = base.find_last_of('.');
        if (dot_pos != std::string::npos)
        {
            base_name = base.substr(0, dot_pos);
            base_ext = base.substr(dot_pos);
        }

        target_path = join_path(trash_dir, base);
        size_t i = 1;
        br = exists(target_path);
        if (std::holds_alternative<ECM>(br))
        {
            return std::get<ECM>(br);
        }
        while (std::holds_alternative<bool>(br) && std::get<bool>(br))
        {
            target_path = join_path(trash_dir, base_name + std::string("_") + std::to_string(i) + base_ext);
            i++;
            br = exists(target_path);
        }
        int rcr;
        {
            rcr = libssh2_sftp_rename(amsession->sftp, path.c_str(), target_path.c_str());
        }
        EC rc;
        if (rcr != 0)
        {
            rc = SftpEC();
            std::string msg = LibsshErrorMsg();
            record_error(ErrorInfo(rc, path, trash_dir, "AMSFTPClient::saferm", msg));
            return {rc, fmt::format("Rename {} to {} failed: {}", path, target_path, msg)};
        }
        return {EC::Success, ""};
    }

    ECM copy(std::string src, std::string dst, bool need_mkdir = false)
    {
        BR br = exists(src);
        if (std::holds_alternative<ECM>(br))
        {
            return std::get<ECM>(br);
        }
        else if (!std::get<bool>(br))
        {
            record_error(ErrorInfo(EC::PathNotExist, src, dst, "AMSFTPClient::copy", "Src not exists"));
            return {EC::PathNotExist, fmt::format("Src not exists: {}", src)};
        }

        br = is_dir(dst);
        if (std::holds_alternative<ECM>(br))
        {
            if (std::get<ECM>(br).first == EC::PathNotExist)
            {
                if (need_mkdir)
                {
                    ECM ecm = mkdirs(dst);
                    if (!isok(ecm))
                    {
                        return ecm;
                    }
                }
                else
                {
                    record_error(ErrorInfo(EC::ParentDirectoryNotExist, src, dst, "AMSFTPClient::copy", "Dst parent dir not exists"));
                    return {EC::ParentDirectoryNotExist, fmt::format("Dst dir not exists: {}", dst)};
                }
            }
        }
        else if (!std::get<bool>(br))
        {
            record_error(ErrorInfo(EC::PathNotExist, dst, "", "AMSFTPClient::copy", "Dst not exists"));
            return {EC::PathNotExist, fmt::format("Dst exists but not a directory: {}", dst)};
        }

        std::string command = "cp -r \"" + src + "\" \"" + dst + "\"";
        SafeChannel channel(amsession);
        if (!channel.channel)
        {
            pytrace(AMCRITICAL, "ChannelCreationFailed", request.nickname, "Copy", "Channel creation failed");
            record_error(ErrorInfo(SessionEC(), src, dst, "AMSFTPClient::copy", "Channel creation failed"));
            return {SessionEC(), "Channel creation failed"};
        }
        int rcr;
        {
            rcr = libssh2_channel_exec(channel.channel, command.c_str());
        }

        if (rcr != 0)
        {
            int exit_code;
            {
                exit_code = libssh2_channel_get_exit_status(channel.channel);
            }
            if (exit_code != 0)
            {
                pytrace(AMWARNING, "CopyFailed", fmt::format("{}@{}->{}", request.nickname, src, dst), "Copy", "Copy cmd conducted failed");
                record_error(ErrorInfo(SessionEC(), src, dst, "AMSFTPClient::copy", "Cmd exec failed"));
                return {SessionEC(), "copy cmd conducted failed"};
            }
        }
        return {EC::Success, ""};
    }

    WRV walk(std::string path)
    {
        // get all files and deepest folders
        WRV result = {};
        _walk(path, result);
        return result;
    }

    RMR rm(std::string path)
    {
        RMR errors = {};
        _rm(path, errors);
        return errors;
    }

    SIZER GetSize(std::string path)
    {
        BR br = exists(path);
        if (std::holds_alternative<ECM>(br))
        {
            return std::get<ECM>(br);
        }
        else if (!std::get<bool>(br))
        {
            return ECM{EC::PathNotExist, fmt::format("Path not exists: {}", path)};
        }
        uint64_t size = 0;
        _GetSize(path, size);
        return size;
    }
};

class AMSFTPWorker : public AMSFTPClient
{
private:
    TransferCallback callback;
    std::atomic<bool> is_terminate = false;
    std::atomic<bool> is_pause = false;
    uint64_t current_size = 0;
    long long total_size = 0;
    std::string current_filename = "";
    double cb_time = timenow();

    void reset()
    {
        cb_time = timenow();
        current_size = 0;
        total_size = 0;
        current_filename = "";
        is_terminate = false;
        is_pause = false;
    }

    double getRTT(uint64_t times = 5)
    {
        double total_time = 0;
        double time_start;
        double time_end;
        int rc;
        for (uint64_t i = 0; i < times; i++)
        {
            SafeChannel channel(amsession);
            if (!channel.channel)
            {
                return -1;
            }

            time_start = timenow();
            rc = libssh2_channel_exec(channel.channel, "echo amsftp");
            if (rc != 0)
            {
                return -1;
            }
            time_end = timenow();
            total_time += (time_end - time_start);
        }
        return total_time / times;
    }

    ECM Local2Remote(const std::string &src, const std::string &dst, uint64_t &chunk_size)
    {
        TransferErrorCode rc_r = EC::Success;
        long rct;
        LIBSSH2_SFTP_HANDLE *sftpFile;
        std::string error_msg = "Error to create FileMapper";

        sftpFile = libssh2_sftp_open(amsession->sftp, dst.c_str(), LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0744);
        if (!sftpFile)
        {
            rct = libssh2_sftp_last_error(amsession->sftp);
            if (rct == LIBSSH2_FX_NO_SUCH_FILE)
            {
                mkdirs(dirname(dst));
                sftpFile = libssh2_sftp_open(amsession->sftp, dst.c_str(), LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0744);
                if (!sftpFile)
                {
                    pytrace(AMERROR, "RemoteFileOpenError", fmt::format("{}@{}", request.nickname, dst), "Remote2Local", LibsshErrorMsg());
                    return {SftpEC(), fmt::format("Failed to open remote file: {}, cause {}", dst, LibsshErrorMsg())};
                }
            }
            else
            {
                pytrace(AMERROR, "RemoteFileOpenError", fmt::format("{}@{}", request.nickname, dst), "Remote2Local", LibsshErrorMsg());
                return {SftpEC(), fmt::format("Failed to open remote file: {}, cause {}", dst, LibsshErrorMsg())};
            }
        }

        FileMapper l_file_m(Wstring(src), MapType::Read, error_msg);
        if (!l_file_m.file_ptr)
        {
            libssh2_sftp_close_handle(sftpFile);
            pytrace(AMERROR, "LocalFileMapError", fmt::format("Local@{}", src), "Local2Remote", error_msg);
            record_error(ErrorInfo(EC::LocalFileMapError, src, "", "FileMapper", error_msg));
            return {EC::LocalFileMapError, fmt::format("Failed to map local file: {}, cause {}", src, error_msg)};
        }

        uint64_t offset = 0;
        uint64_t remaining = l_file_m.file_size;
        uint64_t buffer_size;
        uint64_t local_size = 0;

        long rc;
        double time_end = timenow();

        while (remaining > 0)
        {
            local_size = 0;
            buffer_size = std::min<uint64_t>(chunk_size, remaining);

            while (local_size < buffer_size)
            {

                rc = libssh2_sftp_write(sftpFile, l_file_m.file_ptr + offset + local_size, buffer_size - local_size);

                if (rc > 0)
                {
                    local_size += rc;
                }
                else if (rc == 0)
                {
                    if (local_size < buffer_size)
                    {
                        rc_r = EC::UnexpectedEOF;
                    }
                    goto clean;
                }
                else
                {
                    rc_r = EC::NetworkDisconnect;
                    error_msg = fmt::format("Sftp write error: {}", LibsshErrorMsg());
                    goto clean;
                }
            }

            remaining -= buffer_size;
            offset += buffer_size;
            current_size += buffer_size;
            time_end = timenow();

            if (callback.need_progress_cb && ((time_end - cb_time) > callback.cb_interval_s))
            {
                cb_time = time_end;
                {
                    py::gil_scoped_acquire acquire;
                    callback.progress_cb(src, dst, offset, l_file_m.file_size, current_size, total_size);
                }
            }

            if (is_terminate.load())
            {
                rc_r = EC::Terminate;
                error_msg = "Transfer cancelled";
                goto clean;
            }

            while (is_pause.load() && !is_terminate.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
        }

    clean:
        if (callback.need_progress_cb)
        {
            py::gil_scoped_acquire acquire;
            callback.progress_cb(src, dst, offset, l_file_m.file_size, current_size, total_size);
        }

        if (sftpFile)
        {
            libssh2_sftp_close_handle(sftpFile);
        }

        switch (rc_r)
        {
        case EC::Success:
            error_msg = "";
            break;
        case EC::Terminate:
            pytrace(AMINFO, "", fmt::format("Local@{}->{}@{}", src, request.nickname, dst), "Local2Remote", "Transfer cancelled");
            break;
        case EC::UnexpectedEOF:
            pytrace(AMERROR, "UnexpectedEOF", fmt::format("Local@{}->{}@{}", src, request.nickname, dst), "Local2Remote", "File was unexpectedly truncated");
            break;
        default:
            pytrace(AMERROR, "TransferError", fmt::format("Local@{}->{}@{}", src, request.nickname, dst), "Local2Remote", LibsshErrorMsg());
            break;
        }

        return {rc_r, error_msg};
    }

    ECM Remote2Local(const std::string &src, const std::string &dst, uint64_t &chunk_size)
    {
        TransferErrorCode rc_r = EC::Success;
        LIBSSH2_SFTP_HANDLE *sftpFile;
        std::string error_msg = "";

        sftpFile = libssh2_sftp_open(amsession->sftp, src.c_str(), LIBSSH2_FXF_READ, 0400);
        if (!sftpFile)
        {
            pytrace(AMERROR, "RemoteFileOpenError", fmt::format("{}@{}", request.nickname, src), "Remote2Local", LibsshErrorMsg());
            return ECM{EC::RemoteFileOpenError, fmt::format("Failed to open remote file: {}, cause {}", src, LibsshErrorMsg())};
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(sftpFile, &attrs);
        uint64_t file_size = attrs.filesize;
        if (file_size == 0)
        {
            libssh2_sftp_close_handle(sftpFile);
            pytrace(AMERROR, "RemoteFileStatError", fmt::format("{}@{}", request.nickname, src), "Remote2Local", LibsshErrorMsg());
            return ECM{EC::PathNotExist, fmt::format("Failed to get remote file size: {}, cause {}", src, LibsshErrorMsg())};
        }

        lmkdirs(dirname(dst));
        FileMapper l_file_m(Wstring(dst), MapType::Write, error_msg, file_size);

        if (!l_file_m.file_ptr)
        {
            libssh2_sftp_close_handle(sftpFile);
            pytrace(AMERROR, "LocalFileMapError", fmt::format("Local@{}", dst), "Remote2Local", error_msg);
            record_error(ErrorInfo(EC::LocalFileMapError, dst, "", "FileMapper", error_msg));
            return ECM{EC::LocalFileMapError, fmt::format("Failed to map local file: {}, cause {}", dst, error_msg)};
        }

        uint64_t buffer_size;
        uint64_t offset = 0;
        uint64_t local_size = 0;
        double time_end = timenow();
        long rc;

        while (offset < file_size)
        {
            buffer_size = std::min<uint64_t>(chunk_size, file_size - offset);
            local_size = 0;
            while (local_size < buffer_size)
            {
                rc = libssh2_sftp_read(sftpFile, l_file_m.file_ptr + offset + local_size, buffer_size - local_size);
                if (rc > 0)
                {
                    local_size += rc;
                }

                else if (rc == 0)
                {
                    if (offset < file_size)
                    {
                        rc_r = EC::UnexpectedEOF;
                    }
                    goto clean;
                }
                else
                {
                    rc_r = EC::NetworkDisconnect;
                    error_msg = fmt::format("Sftp read error: {}", LibsshErrorMsg());
                    goto clean;
                }
            }
            offset += buffer_size;
            current_size += buffer_size;
            time_end = timenow();

            if (callback.need_progress_cb && ((time_end - cb_time) > callback.cb_interval_s))
            {
                cb_time = time_end;
                {
                    py::gil_scoped_acquire acquire;
                    callback.progress_cb(src, dst, offset, file_size, current_size, total_size);
                }
            }

            if (is_terminate.load())
            {
                rc_r = EC::Terminate;
                error_msg = "Transfer cancelled";
                goto clean;
            }

            while (is_pause.load() && !is_terminate.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }

    clean:
        if (callback.need_progress_cb)
        {
            py::gil_scoped_acquire acquire;
            callback.progress_cb(src, dst, offset, file_size, current_size, total_size);
        }
        if (sftpFile)
        {
            libssh2_sftp_close_handle(sftpFile);
        }
        switch (rc_r)
        {
        case EC::Success:
            error_msg = "";
            break;
        case EC::Terminate:
            pytrace(AMINFO, "", fmt::format("{}@{}->Local@{}", request.nickname, src, dst), "Remote2Local", "Transfer cancelled");
            break;
        case EC::UnexpectedEOF:
            pytrace(AMERROR, "UnexpectedEOF", fmt::format("{}@{}->Local@{}", request.nickname, src, dst), "Remote2Local", "File was unexpectedly truncated");
            break;
        default:
            pytrace(AMERROR, "TransferError", fmt::format("{}@{}->Local@{}", request.nickname, src, dst), "Remote2Local", LibsshErrorMsg());
            break;
        }
        return {rc_r, error_msg};
    }

    ECM Remote2Remote(const std::string &src, const std::string &dst, std::shared_ptr<AMSFTPWorker> another_worker, uint64_t &chunk_size)
    {
        TransferErrorCode rc_final = EC::Success;
        std::string error_msg = "";
        long rct;
        LIBSSH2_SFTP_HANDLE *srcFile;
        LIBSSH2_SFTP_HANDLE *dstFile;
        srcFile = libssh2_sftp_open(amsession->sftp, src.c_str(), LIBSSH2_FXF_READ, 0400);

        dstFile = libssh2_sftp_open(another_worker->amsession->sftp, dst.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);

        if (!srcFile)
        {
            pytrace(AMERROR, "RemoteSrcOpenError", fmt::format("{}@{}", request.nickname, src), "Remote2Remote", LibsshErrorMsg());
            record_error(ErrorInfo(EC::RemoteFileOpenError, src, "", "Remote2Remote", LibsshErrorMsg()));
            return ECM{EC::RemoteFileOpenError, fmt::format("Failed to open src remote file: {}, cause {}", src, LibsshErrorMsg())};
        }

        if (!dstFile)
        {
            rct = libssh2_sftp_last_error(another_worker->amsession->sftp);
            if (rct == LIBSSH2_FX_NO_SUCH_FILE)
            {
                another_worker->mkdirs(dirname(dst));
                dstFile = libssh2_sftp_open(another_worker->amsession->sftp, dst.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);
                if (!dstFile)
                {
                    pytrace(AMERROR, "RemoteDstOpenError", fmt::format("{}@{}", request.nickname, dst), "Remote2Remote", LibsshErrorMsg());
                    record_error(ErrorInfo(EC::RemoteFileOpenError, dst, "", "Remote2Remote", LibsshErrorMsg()));
                    return ECM{another_worker->SftpEC(), fmt::format("Failed to open dst remote file: {}, cause {}", dst, LibsshErrorMsg())};
                }
            }
            else
            {
                pytrace(AMERROR, "RemoteDstOpenError", fmt::format("{}@{}", request.nickname, dst), "Remote2Remote", LibsshErrorMsg());
                return ECM{another_worker->SftpEC(), fmt::format("Failed to open dst remote file: {}, cause {}", dst, LibsshErrorMsg())};
            }
        }

        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(srcFile, &attrs);
        uint64_t file_size = attrs.filesize;

        // uint64_t buffer_size_ori = calculate_buffer_size(file_size, 32 * AMGB);
        TransferContext ctx(chunk_size);
        uint64_t offset = 0;

        long rc_read = 0;
        long rc_write = 0;

        uint64_t rchunk_size = std::min<uint64_t>(chunk_size, file_size);
        uint64_t all_read = 0;
        uint64_t all_write = 0;
        int wbuffer = -1;
        int rbuffer = -1;
        double time_end = timenow();

        uint64_t read_order = 0;
        uint64_t write_order = 0;

        libssh2_session_set_blocking(amsession->session, 0);
        libssh2_session_set_blocking(another_worker->amsession->session, 0);
        uint64_t read_eagain_count = 0;
        uint64_t write_eagain_count = 0;

        while (all_write < file_size)
        {
            rbuffer = ctx.get_read_buffer();

            if (rbuffer != -1 && all_read < file_size)
            {
                do
                {
                    rc_read = libssh2_sftp_read(srcFile, ctx.bufferd[rbuffer].bufferptr + ctx.bufferd[rbuffer].read, rchunk_size - ctx.bufferd[rbuffer].read);
                    if (rc_read > 0)
                    {
                        read_eagain_count = 0;
                        all_read += rc_read;
                        ctx.bufferd[rbuffer].read += rc_read;
                    }
                    else if (rc_read == LIBSSH2_ERROR_EAGAIN)
                    {
                        read_eagain_count++;
                        if (read_eagain_count > 1000 && read_eagain_count % 100 == 0)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(200));
                        }
                        break;
                    }
                    else if (rc_read < 0)
                    {
                        rc_final = another_worker->SftpEC();
                        error_msg = fmt::format("Sftp read error: {}", LibsshErrorMsg());
                        goto clean;
                    }
                } while (rc_read > 0 && ctx.bufferd[rbuffer].read < rchunk_size);
                if (ctx.bufferd[rbuffer].read == rchunk_size)
                {
                    ctx.finish_read(rbuffer, read_order++);
                    rchunk_size = std::min<uint64_t>(chunk_size, file_size - all_read);
                }
            }

            wbuffer = ctx.get_write_buffer();

            if (wbuffer != -1 && all_write < file_size)
            {
                do
                {
                    rc_write = libssh2_sftp_write(dstFile, ctx.bufferd[wbuffer].bufferptr + ctx.bufferd[wbuffer].written, ctx.bufferd[wbuffer].read - ctx.bufferd[wbuffer].written);
                    if (rc_write > 0)
                    {
                        write_eagain_count = 0;
                        ctx.bufferd[wbuffer].written += rc_write;
                        all_write += rc_write;
                    }
                    else if (rc_write == LIBSSH2_ERROR_EAGAIN)
                    {
                        write_eagain_count++;
                        if (write_eagain_count > 1000 && write_eagain_count % 100 == 0)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(200));
                        }
                        break;
                    }
                    else if (rc_write < 0)
                    {
                        rc_final = cast_libssh2_error(libssh2_sftp_last_error(another_worker->amsession->sftp));
                        error_msg = fmt::format("Sftp write error: {}", LibsshErrorMsg());
                        goto clean;
                    }
                } while (rc_write > 0 && ctx.bufferd[wbuffer].written < ctx.bufferd[wbuffer].read);
                if (ctx.bufferd[wbuffer].written == ctx.bufferd[wbuffer].read)
                {
                    time_end = timenow();
                    current_size += ctx.bufferd[wbuffer].written;
                    if (callback.need_progress_cb && time_end - cb_time > callback.cb_interval_s)
                    {
                        cb_time = time_end;
                        {
                            py::gil_scoped_acquire acquire;
                            callback.progress_cb(src, dst, all_write, file_size, current_size, total_size);
                        }
                    }
                    ctx.finish_write(wbuffer, write_order++);
                    break;
                }
            }

            if (is_terminate.load())
            {
                rc_final = EC::Terminate;
                error_msg = "Transfer cancelled";
                goto clean;
            }

            while (is_pause.load() && !is_terminate.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
        }

    clean:
        libssh2_session_set_blocking(amsession->session, 1);
        libssh2_session_set_blocking(another_worker->amsession->session, 1);

        if (callback.need_progress_cb)
        {
            py::gil_scoped_acquire acquire;
            callback.progress_cb(src, dst, all_write, file_size, current_size, total_size);
        }

        if (srcFile)
        {
            libssh2_sftp_close_handle(srcFile);
        }

        if (dstFile)
        {
            libssh2_sftp_close_handle(dstFile);
        }

        return {rc_final, error_msg};
    }

public:
    ~AMSFTPWorker()
    {
    }

    AMSFTPWorker(ConRequst request, std::vector<std::string> private_keys, uint64_t error_info_buffer_size = 16)
        : AMSFTPClient(request, private_keys, error_info_buffer_size)
    {
    }

    void terminate()
    {
        is_terminate.store(true, std::memory_order_release);
    }

    void pause()
    {
        is_pause.store(true, std::memory_order_relaxed);
    }

    void resume()
    {
        is_pause.store(false, std::memory_order_release);
    }

    bool IsRunning()
    {
        return !is_terminate.load(std::memory_order_acquire);
    }

    std::variant<TASKS, ECM> load_tasks(std::string src, std::string dst, bool ignore_link, bool is_src_remote = true)
    {
        WRV result;
        TASKS tasks;
        std::string dst_i;

        if (!is_src_remote)
        {
            result = local_walk(src);
        }
        else
        {
            WR res = walk(src);
            if (std::holds_alternative<ECM>(res))
            {
                return std::get<ECM>(res);
            }
            result = std::get<WRV>(res);
        }

        std::cout << "result size: " << result.size() << std::endl;
        for (auto &item : result)
        {
            if (ignore_link && (item.path_type == PathType::SYMLINK))
            {
                continue;
            }
            dst_i = join_path(dst, fs::relative(item.path, dirname(src)));
            tasks.push_back(TransferTask(item.path, dst_i, item.size, item.path_type));
        }
        return tasks;
    }

    TR upload(TASKS &tasks, TransferCallback cb_set = TransferCallback(), uint64_t chunk_size = 2 * AMMB)
    {

        ECM rc = check();
        if (rc.first != EC::Success)
        {
            return rc;
        }
        reset();
        this->callback = cb_set;
        for (auto &task : tasks)
        {
            total_size += task.size;
        }
        if (cb_set.need_total_size_cb)
        {
            cb_set.total_size_cb(total_size);
        }

        TRM result = {};

        for (auto &task : tasks)
        {
            current_filename = task.src;
            if (is_terminate.load())
            {
                rc = {EC::Terminate, "Transfer cancelled"};
            }
            else
            {
                if (task.path_type == PathType::DIR)
                {
                    rc = mkdir(task.dst);
                }
                else
                {
                    rc = Local2Remote(task.src, task.dst, chunk_size);
                }
            }
            result.push_back(std::pair(std::pair(task.src, task.dst), rc));

            if (rc.first != EC::Success && rc.first != EC::Terminate && callback.need_error_cb)
            {
                py::gil_scoped_acquire acquire;
                callback.error_cb(rc.first, rc.second, current_filename, task.dst);
            }
        }

        return result;
    }

    TR download(TASKS &tasks, TransferCallback cb_set = TransferCallback(), uint64_t chunk_size = 2 * AMMB)
    {
        reset();
        ECM rc = check();
        if (!isok(rc))
        {
            return rc;
        }
        this->callback = cb_set;
        this->total_size = std::accumulate(tasks.begin(), tasks.end(), 0, [](uint64_t sum, const TransferTask &task)
                                           { return sum + task.size; });
        if (cb_set.need_total_size_cb)
        {
            cb_set.total_size_cb(total_size);
        }

        TRM result = {};

        for (auto &task : tasks)
        {
            current_filename = task.src;
            if (is_terminate.load())
            {
                rc = {EC::Terminate, "Transfer cancelled"};
            }
            else
            {
                rc = Remote2Local(task.src, task.dst, chunk_size);
            }
            result.push_back(std::pair(std::pair(task.src, task.dst), rc));
            if (rc.first != EC::Success && rc.first != EC::Terminate && callback.need_error_cb)
            {
                py::gil_scoped_acquire acquire;
                callback.error_cb(rc.first, rc.second, task.src, task.dst);
            }
        }

        return result;
    }

    TR toAnotherHost(TASKS &tasks, std::shared_ptr<AMSFTPWorker> another_worker, TransferCallback cb_set = TransferCallback(), uint64_t chunk_size = 256 * AMKB)
    {
        ECM rc = check();
        if (rc.first != EC::Success)
        {
            return ECM{rc.first, fmt::format("Src Client Check failed: {}", rc.second)};
        }
        ECM rc_another = another_worker->check();
        if (rc_another.first != EC::Success)
        {
            return ECM{rc_another.first, fmt::format("Dst Client Check failed: {}", rc_another.second)};
        }
        reset();
        another_worker->reset();

        this->callback = cb_set;
        TRM result = {};
        total_size = std::accumulate(tasks.begin(), tasks.end(), 0, [](uint64_t sum, const TransferTask &task)
                                     { return sum + task.size; });

        for (auto &task : tasks)
        {
            current_filename = task.src;
            if (is_terminate.load())
            {
                rc = {EC::Terminate, "Transfer cancelled"};
            }
            else
            {
                rc = Remote2Remote(task.src, task.dst, another_worker, chunk_size);
            }
            result.push_back(std::pair(std::pair(task.src, task.dst), rc));

            if (rc.first != EC::Success && rc.first != EC::Terminate && callback.need_error_cb)
            {
                py::gil_scoped_acquire acquire;
                callback.error_cb(rc.first, rc.second, task.src, task.dst);
            }
        }

        return result;
    }

    TR get(std::string src, std::string dst, TransferCallback cb_set = TransferCallback(), bool ignore_link = true, uint64_t chunk_size = 2 * AMMB)
    {
        RR res = realpath(src);
        if (std::holds_alternative<ECM>(res))
        {
            return std::get<ECM>(res);
        }
        src = std::get<std::string>(res);
        auto tasks_ori = load_tasks(src, dst, ignore_link, true);
        if (std::holds_alternative<ECM>(tasks_ori))
        {
            return std::get<ECM>(tasks_ori);
        }
        auto tasks = std::get<TASKS>(tasks_ori);
        return download(tasks, cb_set, chunk_size);
    }

    TR put(std::string src, std::string dst, TransferCallback cb_set = TransferCallback(), bool ignore_link = true, uint64_t chunk_size = 2 * AMMB)
    {
        RR res = local_realpath(src);
        if (std::holds_alternative<ECM>(res))
        {
            return std::get<ECM>(res);
        }
        src = std::get<std::string>(res);
        auto tasks_ori = load_tasks(src, dst, ignore_link, false);
        if (std::holds_alternative<ECM>(tasks_ori))
        {
            return std::get<ECM>(tasks_ori);
        }
        auto tasks = std::get<TASKS>(tasks_ori);
        return upload(tasks, cb_set, chunk_size);
    }

    TR transmit(std::string src, std::string dst, std::shared_ptr<AMSFTPWorker> woker2, TransferCallback cb_set = TransferCallback(), bool ignore_link = true, uint64_t chunk_size = 256 * AMKB)
    {
        RR res = realpath(src);
        if (std::holds_alternative<ECM>(res))
        {
            return std::get<ECM>(res);
        }
        src = std::get<std::string>(res);
        auto tasks_ori = load_tasks(src, dst, ignore_link, true);
        if (std::holds_alternative<ECM>(tasks_ori))
        {
            return std::get<ECM>(tasks_ori);
        }
        auto tasks = std::get<TASKS>(tasks_ori);
        return toAnotherHost(tasks, woker2, cb_set, chunk_size);
    }
};

PYBIND11_MODULE(AMSFTP, m)
{
    bool expected = false;
    if (std::atomic_compare_exchange_strong(&is_wsa_initialized, &expected, true))
    {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0)
        {
            throw std::runtime_error("WSAStartup failed");
        }
        is_wsa_initialized = true;
        m.add_object("_cleanup", py::capsule(cleanup_wsa));
    }

    py::enum_<TransferErrorCode>(m, "TransferErrorCode")
        .value("Success", TransferErrorCode::Success)
        .value("PassCheck", TransferErrorCode::PassCheck)
        .value("FailedCheck", TransferErrorCode::FailedCheck)
        .value("SessionCreateError", TransferErrorCode::SessionCreateError)
        .value("SftpCreateError", TransferErrorCode::SftpCreateError)
        .value("SessionEstablishError", TransferErrorCode::SessionEstablishError)
        .value("SftpEstablishError", TransferErrorCode::SftpEstablishError)
        .value("ConnectionAuthorizeError", TransferErrorCode::ConnectionAuthorizeError)
        .value("LocalFileMapError", TransferErrorCode::LocalFileMapError)
        .value("RemoteFileOpenError", TransferErrorCode::RemoteFileOpenError)
        .value("RemoteFileStatError", TransferErrorCode::RemoteFileStatError)
        .value("LocalFileCreateError", TransferErrorCode::LocalFileCreateError)
        .value("LocalFileAllocError", TransferErrorCode::LocalFileAllocError)
        .value("NetworkError", TransferErrorCode::NetworkError)
        .value("NetworkDisconnect", TransferErrorCode::NetworkDisconnect)
        .value("NetworkTimeout", TransferErrorCode::NetworkTimeout)
        .value("LocalFileFlushError", TransferErrorCode::LocalFileFlushError)
        .value("SegmentationFault", TransferErrorCode::SegmentationFault)
        .value("SessionBroken", TransferErrorCode::SessionBroken)
        .value("SftpBroken", TransferErrorCode::SftpBroken)
        .value("ChannelCreateError", TransferErrorCode::ChannelCreateError)
        .value("ConnectionCheckFailed", TransferErrorCode::ConnectionCheckFailed)
        .value("RemoteFileWriteError", TransferErrorCode::RemoteFileWriteError)
        .value("RemoteFileReadError", TransferErrorCode::RemoteFileReadError)
        .value("Terminate", TransferErrorCode::Terminate)
        .value("LocalFileExists", TransferErrorCode::LocalFileExists)
        .value("RemoteFileExists", TransferErrorCode::RemoteFileExists)
        .value("PathNotExist", TransferErrorCode::PathNotExist)
        .value("PermissionDenied", TransferErrorCode::PermissionDenied)
        .value("RemotePathOpenError", TransferErrorCode::RemotePathOpenError)
        .value("NotDirectory", TransferErrorCode::NotDirectory)
        .value("ParentDirectoryNotExist", TransferErrorCode::ParentDirectoryNotExist)
        .value("TargetNotAFile", TransferErrorCode::TargetNotAFile)
        .value("RemoteFileDeleteError", TransferErrorCode::RemoteFileDeleteError)
        .value("RemoteDirDeleteError", TransferErrorCode::RemoteDirDeleteError)
        .value("UnknownError", TransferErrorCode::UnknownError)
        .value("DirNotEmpty", TransferErrorCode::DirNotEmpty)
        .value("EmptyDirRemoveError", TransferErrorCode::EmptyDirRemoveError)
        .value("TargetNotADirectory", TransferErrorCode::TargetNotADirectory)
        .value("InvalidTrashDir", TransferErrorCode::InvalidTrashDir)
        .value("MoveError", TransferErrorCode::MoveError)
        .value("TargetExists", TransferErrorCode::TargetExists)
        .value("CopyError", TransferErrorCode::CopyError)
        .value("EndOfFile", TransferErrorCode::EndOfFile)
        .value("EAgain", TransferErrorCode::EAgain)
        .value("SocketNone", TransferErrorCode::SocketNone)
        .value("SocketSend", TransferErrorCode::SocketSend)
        .value("SocketTimeout", TransferErrorCode::SocketTimeout)
        .value("SocketRecv", TransferErrorCode::SocketRecv)
        .value("SocketAccept", TransferErrorCode::SocketAccept)
        .value("WriteProtected", TransferErrorCode::WriteProtected)
        .value("UnenoughSpace", TransferErrorCode::UnenoughSpace)
        .value("UserSpaceQuotaExceeded", TransferErrorCode::UserSpaceQuotaExceeded)
        .value("BannerRecvError", TransferErrorCode::BannerRecvError)
        .value("BannerSendError", TransferErrorCode::BannerSendError)
        .value("SocketSendError", TransferErrorCode::SocketSendError)
        .value("SocketDisconnect", TransferErrorCode::SocketDisconnect)
        .value("AuthFailed", TransferErrorCode::AuthFailed)
        .value("PublicKeyAuthFailed", TransferErrorCode::PublicKeyAuthFailed)
        .value("PasswordExpired", TransferErrorCode::PasswordExpired)
        .value("KeyfileAuthFailed", TransferErrorCode::KeyfileAuthFailed)
        .value("ChannelFailure", TransferErrorCode::ChannelFailure)
        .value("ChannelWindowFull", TransferErrorCode::ChannelWindowFull)
        .value("ChannelWindowExceeded", TransferErrorCode::ChannelWindowExceeded)
        .value("MACAuthFailed", TransferErrorCode::MACAuthFailed)
        .value("KexFailure", TransferErrorCode::KexFailure)
        .value("AlgoUnsupported", TransferErrorCode::AlgoUnsupported)
        .value("MemoryAllocError", TransferErrorCode::MemoryAllocError)
        .value("FileOperationError", TransferErrorCode::FileOperationError)
        .value("ScpProtocolError", TransferErrorCode::ScpProtocolError)
        .value("SftpProtocolError", TransferErrorCode::SftpProtocolError)
        .value("KnownHostAuthFailed", TransferErrorCode::KnownHostAuthFailed)
        .value("InvalidParameter", TransferErrorCode::InvalidParameter)
        .value("NoSFTPConnection", TransferErrorCode::NoSFTPConnection)
        .value("SFTPConnectionLost", TransferErrorCode::SFTPConnectionLost)
        .value("SFTPBadMessage", TransferErrorCode::SFTPBadMessage)
        .value("SFTPLockConflict", TransferErrorCode::SFTPLockConflict)
        .value("SymlinkLoop", TransferErrorCode::SymlinkLoop)
        .value("InvalidFilename", TransferErrorCode::InvalidFilename)
        .value("UnsupportedSFTPOperation", TransferErrorCode::UnsupportedSFTPOperation)
        .value("MediaUnavailable", TransferErrorCode::MediaUnavailable)
        .value("SftpNotInitialized", TransferErrorCode::SftpNotInitialized)
        .value("SessionNotInitialized", TransferErrorCode::SessionNotInitialized)
        .value("DirAlreadyExists", TransferErrorCode::DirAlreadyExists)
        .value("PathAlreadyExists", TransferErrorCode::PathAlreadyExists)
        .value("UnexpectedEOF", TransferErrorCode::UnexpectedEOF);

    py::enum_<PathType>(m, "PathType")
        .value("DIR", PathType::DIR)
        .value("FILE", PathType::FILE)
        .value("SYMLINK", PathType::SYMLINK);

    py::class_<ConRequst>(m, "ConRequst")
        .def(py::init<std::string, std::string, std::string, int, std::string, std::string, bool, size_t, std::string>(), py::arg("nickname"), py::arg("hostname"), py::arg("username"), py::arg("port"), py::arg("password") = "", py::arg("keyfile") = "", py::arg("compression") = false, py::arg("timeout_s") = 3, py::arg("trash_dir") = "")
        .def_readwrite("nickname", &ConRequst::nickname)
        .def_readwrite("hostname", &ConRequst::hostname)
        .def_readwrite("username", &ConRequst::username)
        .def_readwrite("password", &ConRequst::password)
        .def_readwrite("port", &ConRequst::port)
        .def_readwrite("compression", &ConRequst::compression)
        .def_readwrite("timeout_s", &ConRequst::timeout_s)
        .def_readwrite("trash_dir", &ConRequst::trash_dir)
        .def_readwrite("keyfile", &ConRequst::keyfile);

    py::class_<TransferCallback>(m, "TransferCallback")
        .def(py::init<float, py::object, py::object, py::object>(),
             py::arg("interval"),
             py::arg("total_size") = py::none(),
             py::arg("error") = py::none(),
             py::arg("progress") = py::none());

    py::class_<TransferTask>(m, "TransferTask")
        .def(py::init<std::string, std::string, uint64_t, PathType>(), py::arg("src"), py::arg("dst"), py::arg("size"), py::arg("path_type") = PathType::FILE)
        .def_readwrite("src", &TransferTask::src)
        .def_readwrite("dst", &TransferTask::dst)
        .def_readwrite("size", &TransferTask::size)
        .def_readwrite("path_type", &TransferTask::path_type);

    py::class_<PathInfo>(m, "PathInfo")
        .def(py::init<std::string, std::string, std::string, std::string, uint64_t, uint64_t, uint64_t, PathType, uint64_t>(), py::arg("name"), py::arg("path"), py::arg("dir"), py::arg("uname"), py::arg("size"), py::arg("atime"), py::arg("mtime"), py::arg("path_type") = PathType::FILE, py::arg("permission") = 0)
        .def_readwrite("name", &PathInfo::name)
        .def_readwrite("path", &PathInfo::path)
        .def_readwrite("dir", &PathInfo::dir)
        .def_readwrite("uname", &PathInfo::uname)
        .def_readwrite("size", &PathInfo::size)
        .def_readwrite("atime", &PathInfo::atime)
        .def_readwrite("mtime", &PathInfo::mtime)
        .def_readwrite("path_type", &PathInfo::path_type)
        .def_readwrite("permission", &PathInfo::permission);

    py::class_<ErrorInfo>(m, "ErrorInfo")
        .def(py::init<TransferErrorCode, std::string, std::string, std::string, std::string>(), py::arg("error_code"), py::arg("src"), py::arg("dst"), py::arg("function_name"), py::arg("msg"))
        .def_readwrite("error_code", &ErrorInfo::error_code)
        .def_readwrite("src", &ErrorInfo::src)
        .def_readwrite("dst", &ErrorInfo::dst)
        .def_readwrite("function_name", &ErrorInfo::function_name)
        .def_readwrite("msg", &ErrorInfo::msg);

    py::class_<AMSFTPWorker, std::shared_ptr<AMSFTPWorker>>(m, "AMSFTPWorker")
        .def(py::init<ConRequst, std::vector<std::string>, uint64_t>(), py::arg("request"), py::arg("private_keys"), py::arg("error_info_buffer_size") = 10)
        .def("setAuthCallback", &AMSFTPWorker::setAuthCallback, py::arg("auth_cb") = py::none())
        .def("SetPyTrace", &AMSFTPWorker::SetPyTrace, py::arg("trace_cb") = py::none())
        .def("SetWorkerPyTrace", &AMSFTPWorker::SetWorkerPyTrace, py::arg("trace_cb") = py::none())
        .def("SetSessionPyTrace", &AMSFTPWorker::SetSessionPyTrace, py::arg("trace_cb") = py::none())
        .def("check", &AMSFTPClient::check)
        .def("reconnect", &AMSFTPClient::reconnect)
        .def("ensure", &AMSFTPClient::ensure)
        .def("ensure_trash_dir", &AMSFTPClient::ensure_trash_dir)
        .def("init", &AMSFTPClient::init, py::arg("pycb") = py::none())
        .def("GetSize", &AMSFTPClient::GetSize, py::arg("path"))
        .def("realpath", &AMSFTPClient::realpath, py::arg("path"))
        .def("stat", &AMSFTPClient::stat, py::arg("path"))
        .def("exists", &AMSFTPClient::exists, py::arg("path"))
        .def("is_file", &AMSFTPClient::is_file, py::arg("path"))
        .def("is_dir", &AMSFTPClient::is_dir, py::arg("path"))
        .def("is_symlink", &AMSFTPClient::is_symlink, py::arg("path"))
        .def("listdir", &AMSFTPClient::listdir, py::arg("path"), py::arg("max_num") = -1)
        .def("mkdir", &AMSFTPClient::mkdir, py::arg("path"))
        .def("mkdirs", &AMSFTPClient::mkdirs, py::arg("path"))
        .def("rmfile", &AMSFTPClient::rmfile, py::arg("path"))
        .def("rmdir", &AMSFTPClient::rmdir, py::arg("path"))
        .def("rm", &AMSFTPClient::rm, py::arg("path"))
        .def("saferm", &AMSFTPClient::saferm, py::arg("path"))
        .def("move", &AMSFTPClient::move, py::arg("src"), py::arg("dst"), py::arg("need_mkdir") = false, py::arg("force_write") = false)
        .def("copy", &AMSFTPClient::copy, py::arg("src"), py::arg("dst"), py::arg("need_mkdir") = false)
        .def("rename", &AMSFTPClient::rename, py::arg("src"), py::arg("newname"))
        .def("walk", &AMSFTPClient::walk, py::arg("path"))
        .def("LastTraceError", &AMSFTPClient::LastTraceError)
        .def("GetAllErrors", &AMSFTPClient::GetAllErrors)
        .def("set_trash_dir", &AMSFTPClient::set_trash_dir, py::arg("trash_dir_f") = "")
        .def("get_trash_dir", &AMSFTPClient::get_trash_dir)
        .def("Nickname", &AMSFTPClient::Nickname)
        .def("terminate", &AMSFTPWorker::terminate)
        .def("pause", &AMSFTPWorker::pause)
        .def("resume", &AMSFTPWorker::resume)
        .def("is_running", &AMSFTPWorker::IsRunning)
        .def("upload", &AMSFTPWorker::upload, py::arg("tasks"), py::arg("cb_set") = TransferCallback(), py::arg("chunk_size") = 256 * AMKB)
        .def("download", &AMSFTPWorker::download, py::arg("tasks"), py::arg("cb_set") = TransferCallback(), py::arg("chunk_size") = 256 * AMKB)
        .def("toAnotherHost", &AMSFTPWorker::toAnotherHost, py::arg("tasks"), py::arg("another_worker"), py::arg("cb_set") = TransferCallback(), py::arg("chunk_size") = 256 * AMKB)
        .def("put", &AMSFTPWorker::put, py::arg("src"), py::arg("dst"), py::arg("cb_set") = TransferCallback(), py::arg("ignore_link") = true, py::arg("chunk_size") = 256 * AMKB)
        .def("get", &AMSFTPWorker::get, py::arg("src"), py::arg("dst"), py::arg("cb_set") = TransferCallback(), py::arg("ignore_link") = true, py::arg("chunk_size") = 256 * AMKB)
        .def("transmit", &AMSFTPWorker::transmit, py::arg("src"), py::arg("dst"), py::arg("another_worker"), py::arg("cb_set") = TransferCallback(), py::arg("ignore_link") = true, py::arg("chunk_size") = 256 * AMKB)
        .def("load_tasks", &AMSFTPWorker::load_tasks, py::arg("src"), py::arg("dst"), py::arg("ignore_link") = true, py::arg("is_src_remote") = true);
}
