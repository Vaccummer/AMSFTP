#include <libssh2.h>
#include <sddl.h> // ConvertSidToStringSid
#include <fmt/core.h>
#include <libssh2_sftp.h>
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
using f_ptr = std::shared_ptr<py::function>;
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
constexpr char *AMERRORNAME = "ERRORNAME";
constexpr char *AMTARGET = "TARGET";
constexpr char *AMACTION = "ACTION";
constexpr char *AMMESSAGE = "MESSAGE";

constexpr char *AMCRITICAL = "CRITICAL";
constexpr char *AMERROR = "ERROR";
constexpr char *AMWARNING = "WARNING";
constexpr char *AMDEBUG = "DEBUG";
constexpr char *AMINFO = "INFO";

std::string sftp_error_code_cast(unsigned long errcode)
{
    switch (errcode)
    {
    case LIBSSH2_FX_OK:
        return "Success";
    case LIBSSH2_FX_EOF:
        return "End of file";
    case LIBSSH2_FX_NO_SUCH_FILE:
        return "File does not exist";
    case LIBSSH2_FX_PERMISSION_DENIED:
        return "Permission denied";
    case LIBSSH2_FX_FAILURE:
        return "Generic failure";
    case LIBSSH2_FX_BAD_MESSAGE:
        return "Bad protocol message";
    case LIBSSH2_FX_NO_CONNECTION:
        return "No connection";
    case LIBSSH2_FX_CONNECTION_LOST:
        return "Connection lost";
    case LIBSSH2_FX_OP_UNSUPPORTED:
        return "Operation not supported";
    case LIBSSH2_FX_INVALID_HANDLE:
        return "Invalid handle";
    case LIBSSH2_FX_NO_SUCH_PATH:
        return "No such path";
    case LIBSSH2_FX_FILE_ALREADY_EXISTS:
        return "File already exists";
    case LIBSSH2_FX_WRITE_PROTECT:
        return "Write protected filesystem";
    case LIBSSH2_FX_NO_MEDIA:
        return "No media in drive";
    default:
        return "Unknown error";
    }
}

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
    catch (const fs::filesystem_error &e)
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
    namespace fs = std::filesystem;

    std::vector<std::string> segments;
    fs::path combined;

    auto process_arg = [&](auto &&arg)
    {
        std::string s = std::forward<decltype(arg)>(arg);
        if (s.empty())
        {
            return;
        }
        segments.push_back(s);
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

enum class TransferErrorCode
{
    Success = 0,
    PassCheck = 1,
    FailedCheck = 2,
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
    ConRequst(std::string nickname, std::string hostname, std::string username, std::string password, int port, bool compression, size_t timeout_s = 3, std::string trash_dir = "")
        : nickname(nickname), hostname(hostname), username(username), password(password), port(port), compression(compression), timeout_s(timeout_s), trash_dir(trash_dir) {}
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

    TransferCallback(
        py::object total_size = py::none(),
        py::object error = py::none(),
        py::object progress = py::none(),
        float interval = 0.5) : cb_interval_s(interval)
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
    uint64_t permissions = 777;
    PathInfo()
        : name(""), path(""), dir(""), uname(""), size(-1), atime(-1), mtime(-1), path_type(PathType::FILE), permissions(0) {}
    PathInfo(std::string name, std::string path, std::string dir, std::string uname, uint64_t size, uint64_t atime, uint64_t mtime, PathType path_type = PathType::FILE, uint64_t permissions = 777)
        : name(name), path(path), dir(dir), uname(uname), size(size), atime(atime), mtime(mtime), path_type(path_type), permissions(permissions) {}
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

struct ErrorInfo
{
    TransferErrorCode error_code;
    std::string src;
    std::string dst;
    std::string function_name;
    std::string msg;

    ErrorInfo()
        : error_code(TransferErrorCode::UnknownError), src(""), dst(""), function_name(""), msg("") {}

    ErrorInfo(TransferErrorCode error_code, std::string src, std::string dst, std::string function_name, std::string msg)
        : error_code(error_code), src(src), dst(dst), function_name(function_name), msg(msg) {}

    std::string toString()
    {
        return "ErrorInfo(error_code=" + std::to_string(static_cast<int>(error_code)) + ", src=" + src + ", dst=" + dst + ", function_name=" + function_name + ", msg=" + msg + ")";
    }
};

enum class BufferStatus
{
    is_writing = 0,
    is_reading = 1,
    read_done = 2,
    write_done = 3
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
    catch (const std::exception &e)
    {
        return;
    }
    std::string filename = p.filename().string();
    std::string dir = p.parent_path().string();
    uint64_t size = fs::file_size(p);
    auto ftime = fs::last_write_time(p);
    auto duration = ftime.time_since_epoch();
    uint64_t atime = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    uint64_t mtime = atime;
    std::vector<std::string> subdirs = {};
    std::vector<std::string> files = {};
    switch (status.type())
    {
    case fs::file_type::directory:
        for (const auto &entry : fs::directory_iterator(p))
        {
            if (fs::is_directory(entry.status()))
            {
                subdirs.push_back(entry.path().string());
            }
            else
            {
                files.push_back(entry.path().string());
            }
            if (subdirs.empty())
            {
                result.push_back(PathInfo(filename, path, dir, "", size, atime, mtime, PathType::DIR));
            }
            for (const auto &subdir : subdirs)
            {
                _local_walk(subdir, result);
            }
            for (const auto &file : files)
            {
                _local_walk(file, result);
            }
        }
    case fs::file_type::symlink:
        result.push_back(PathInfo(filename, path, dir, "", size, atime, mtime, PathType::SYMLINK));
        break;
    default:
        result.push_back(PathInfo(filename, path, dir, "", size, atime, mtime, PathType::FILE));
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

EC cast_libssh2_error(int error_code)
{
    switch (error_code)
    {
    case LIBSSH2_ERROR_SOCKET_NONE:
        return EC::SocketNone;
    case LIBSSH2_ERROR_BANNER_RECV:
        return EC::BannerRecvError;
    case LIBSSH2_ERROR_BANNER_SEND:
        return EC::BannerSendError;
    case LIBSSH2_ERROR_SOCKET_SEND:
        return EC::SocketSendError;
    case LIBSSH2_ERROR_SOCKET_DISCONNECT:
        return EC::SocketDisconnect;
    case LIBSSH2_ERROR_AUTHENTICATION_FAILED:
        return EC::AuthFailed;
    case LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED:
        return EC::PublicKeyAuthFailed;
    case LIBSSH2_ERROR_PASSWORD_EXPIRED:
        return EC::PasswordExpired;
    case LIBSSH2_ERROR_KEYFILE_AUTH_FAILED:
        return EC::KeyfileAuthFailed;
    case LIBSSH2_ERROR_CHANNEL_FAILURE:
        return EC::ChannelFailure;
    case LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED:
        return EC::ChannelFailure;
    case LIBSSH2_ERROR_CHANNEL_WINDOW_FULL:
        return EC::ChannelWindowFull;
    case LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED:
        return EC::ChannelWindowExceeded;
    case LIBSSH2_ERROR_INVALID_MAC:
        return EC::MACAuthFailed;
    case LIBSSH2_ERROR_KEX_FAILURE:
        return EC::KexFailure;
    case LIBSSH2_ERROR_ALGO_UNSUPPORTED:
        return EC::AlgoUnsupported;
    case LIBSSH2_ERROR_ALLOC:
        return EC::MemoryAllocError;
    case LIBSSH2_ERROR_FILE:
        return EC::FileOperationError;

    case LIBSSH2_ERROR_SCP_PROTOCOL:
        return EC::ScpProtocolError;
    case LIBSSH2_ERROR_SFTP_PROTOCOL:
        return EC::SftpProtocolError;
    case LIBSSH2_ERROR_KNOWN_HOSTS:
        return EC::KnownHostAuthFailed;
    case LIBSSH2_ERROR_INVAL:
        return EC::InvalidParameter;
    case LIBSSH2_ERROR_MAC_FAILURE:
        return EC::MACAuthFailed;

    case LIBSSH2_FX_EOF:
        return EC::EndOfFile;
    case LIBSSH2_FX_NO_SUCH_FILE:
        return EC::PathNotExist;
    case LIBSSH2_FX_PERMISSION_DENIED:
        return EC::PermissionDenied;
    case LIBSSH2_FX_FILE_ALREADY_EXISTS:
        return EC::TargetExists;
    case LIBSSH2_FX_WRITE_PROTECT:
        return EC::WriteProtected;
    case LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM:
        return EC::UnenoughSpace;
    case LIBSSH2_FX_QUOTA_EXCEEDED:
        return EC::UserSpaceQuotaExceeded;
    case LIBSSH2_FX_DIR_NOT_EMPTY:
        return EC::DirNotEmpty;
    case LIBSSH2_FX_NOT_A_DIRECTORY:
        return EC::NotDirectory;
    case LIBSSH2_FX_NO_CONNECTION:
        return EC::NoSFTPConnection;
    case LIBSSH2_FX_CONNECTION_LOST:
        return EC::SFTPConnectionLost;
    case LIBSSH2_FX_BAD_MESSAGE:
        return EC::SFTPBadMessage;
    case LIBSSH2_FX_INVALID_HANDLE:
        return EC::InvalidHandle;
    case LIBSSH2_FX_LOCK_CONFLICT:
        return EC::SFTPLockConflict;
    case LIBSSH2_FX_LINK_LOOP:
        return EC::SymlinkLoop;
    case LIBSSH2_FX_NO_SUCH_PATH:
        return EC::PathNotExist;
    case LIBSSH2_FX_INVALID_FILENAME:
        return EC::InvalidFilename;
    case LIBSSH2_FX_OP_UNSUPPORTED:
        return EC::UnsupportedSFTPOperation;
    case LIBSSH2_FX_NO_MEDIA:
        return EC::MediaUnavailable;
    default:
        return EC::UnknownError;
    }
}

class CircularBuffer
{
private:
    std::vector<ErrorInfo> buffer = {};
    size_t capacity;
    size_t head = 0;
    size_t tail = 0;
    size_t count = 0;

public:
    CircularBuffer() : capacity(10) {}

    CircularBuffer(size_t size) : capacity(size)
    {
        buffer.resize(size);
    }

    void push(const ErrorInfo &value)
    {
        if (count == capacity)
        {
            head = (head + 1) % capacity;
            count--;
        }
        buffer[tail] = value;
        tail = (tail + 1) % capacity;
        count++;
    }

    size_t size() const { return count; }

    size_t getCapacity() const { return capacity; }

    ErrorInfo &back()
    {
        if (count == 0)
        {
            throw std::out_of_range("Buffer is empty");
        }
        return buffer[(tail - 1 + capacity) % capacity];
    }

    std::vector<ErrorInfo> toVector() const
    {
        std::vector<ErrorInfo> vec;
        vec.reserve(count);
        size_t current = head;
        for (size_t i = 0; i < count; ++i)
        {
            vec.push_back(buffer[current]);
            current = (current + 1) % capacity;
        }
        return vec;
    }

    bool empty() const { return count == 0; }
};

class AMSession
{
public:
    LIBSSH2_SESSION *session = nullptr;
    LIBSSH2_SFTP *sftp = nullptr;
    SOCKET sock = INVALID_SOCKET;
    std::vector<std::string> private_keys;
    ConRequst request;
    py::function trace_cb = py::function();
    std::atomic<bool> is_trace = false;
    std::string cwd = "";
    py::function auth_cb = py::function();
    bool password_auth_cb = false;
    ECM init()
    {
        std::string msg = "";
        EC rc = EC::Success;
        WSADATA wsaData;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            pytrace(AMCRITICAL, "SocketCreateError", request.nickname, "CreateSocket", "Create but get invalid socket");
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
                pytrace(AMCRITICAL, "SocketConnectError", request.nickname, "ConnectSocket", "Connect Timeout");
            }
            else
            {
                pytrace(AMCRITICAL, "SocketConnectError", request.nickname, "ConnectSocket", "Connect Failed");
            }

            return {EC::NetworkTimeout, "Connection Establish Timeout"};
        }

        session = libssh2_session_init();

        if (!session)
        {
            pytrace(AMCRITICAL, "SessionCreateError", request.nickname, "SessionInit", "Session initialization failed");
            return {EC::SessionCreateError, "Libssh2 Session initialization failed"};
        }

        libssh2_session_set_blocking(session, 1);

        if (request.compression)
        {
            libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
            libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS, "zlib@openssh.com,zlib,none");
        }

        int rc_handshake;
        {
            rc_handshake = libssh2_session_handshake(session, sock);
        }

        if (rc_handshake != 0)
        {
            pytrace(AMCRITICAL, "HandshakeEstablishError", request.nickname, "SessionHandshake", "Session handshake failed");
            return {EC::SessionEstablishError, "Session handshake failed"};
        }
        const char *auth_list = libssh2_userauth_list(session, request.username.c_str(), request.username.length());
        if (auth_list == nullptr)
        {
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
                pytrace(AMINFO, "AuthorizeSuccess", request.nickname, "PublicKeyAuthorize", "Public key authorize success");
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
                pytrace(AMINFO, "AuthorizeSuccess", request.nickname, "PasswordAuthorize", "Password authorize success");
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
                    pytrace(AMINFO, "AuthorizeSuccess", request.nickname, "PasswordAuthorize", "Password authorize success");
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
                pytrace(AMINFO, "", request.nickname, "PublicKeyAuthorize", msg);
                rc = TransferErrorCode::Success;
                goto OK;
            }
            else
            {
                msg = fmt::format("Public key \"{}\" authorize failed", private_key);
                pytrace(AMWARNING, "AuthorizeError", request.nickname, "PublicKeyAuthorize", msg);
            }
        }
    OK:
        if (rc != TransferErrorCode::Success)
        {
            pytrace(AMCRITICAL, "AuthorizeError", request.nickname, "FinalAuthorizeState", "Authorize failed");
            return {rc, "All authorize methods failed"};
        }

        sftp = libssh2_sftp_init(session);

        if (!sftp)
        {
            return {EC::SftpCreateError, "SFTP initialization failed"};
        }

        return {EC::Success, ""};
    }

    ECM check()
    {
        if (!sftp)
        {
            pytrace(AMCRITICAL, "SftpNotInitialized", "Sftp", "SFTPCheck", "SFTP not initialized");
            return {EC::SftpNotInitialized, "SFTP not initialized"};
        }

        if (!session)
        {
            pytrace(AMCRITICAL, "SessionNotInitialized", "Session", "SessionCheck", "Session not initialized");
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
            std::string msg = sftp_error_code_cast(libssh2_sftp_last_error(sftp));
            pytrace(AMCRITICAL, "SftpCheckFailed", fmt::format("{}@{}", request.nickname, request.port), "TrialPathStatCheck", msg);
            return {rc, msg};
        }

        pytrace(AMINFO, "", request.nickname, "SessionCheck", "Success");
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

    ECM reconnect()
    {
        clean();
        return init();
    }

    AMSession()
    {
        this->session = nullptr;
        this->sftp = nullptr;
        this->private_keys = {};
        this->sock = INVALID_SOCKET;
        this->request = ConRequst();
        this->private_keys = {};
    }

    AMSession(ConRequst request, std::vector<std::string> private_keys, py::object auth_cb = py::none())
        : request(request), private_keys(private_keys)
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

    void pytrace(std::string level, std::string error_name = "", std::string target = "", std::string action = "", std::string msg = "")
    {
        if (is_trace.load(std::memory_order_acquire))
        {
            std::unordered_map<std::string, std::string> level_map = {
                {AMLEVEL, level},
                {AMERRORNAME, error_name},
                {AMTARGET, target},
                {AMACTION, action},
                {AMMESSAGE, msg},
            };
            trace_cb(level_map);
        }
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
                                                512 * AMKB,
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
    CircularBuffer error_info_buffer;
    std::string nickname;
    ConRequst request;
    py::function trace_cb = py::function();
    std::atomic<bool> is_trace = false;
    std::shared_ptr<AMSession> amsession;

    BaseSFTPClient()
    {
        this->trash_dir = "";
        this->private_keys = {};
        this->nickname = "";
        this->request = ConRequst();
    }

    BaseSFTPClient(ConRequst request, std::vector<std::string> private_keys, size_t error_info_buffer_size = 10)
    {
        this->trash_dir = "";
        this->private_keys = private_keys;
        this->nickname = request.nickname;
        this->request = request;
        this->error_info_buffer = CircularBuffer(error_info_buffer_size);
        this->amsession = std::make_shared<AMSession>(request, private_keys);
    }

    PathInfo format_stat(std::string path, LIBSSH2_SFTP_ATTRIBUTES &attrs)
    {
        PathInfo info;
        info.path = path;
        info.name = basename(path);
        info.dir = dirname(path);
        long uid = attrs.uid;
        std::string user_name = get_user_name(uid);
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
            info.permissions = attrs.permissions & 0777;
        }
        return info;
    }

    void pytrace(std::string level, std::string error_name = "", std::string target = "", std::string action = "", std::string msg = "")
    {
        if (is_trace.load(std::memory_order_acquire))
        {
            std::unordered_map<std::string, std::string> level_map = {
                {AMLEVEL, level},
                {AMERRORNAME, error_name},
                {AMTARGET, target},
                {AMACTION, action},
                {AMMESSAGE, msg},
            };
            {
                py::gil_scoped_acquire acquire;
                trace_cb(level_map);
            }
            // trace_cb(error_info);
        }
    }

    void record_error(ErrorInfo error_info)
    {
        error_info_buffer.push(error_info);
    }

    ErrorInfo get_last_error_info()
    {
        if (error_info_buffer.empty())
        {
            return ErrorInfo(EC::Success, "", "", "", "");
        }
        return error_info_buffer.back();
    }

    std::vector<ErrorInfo> get_all_error_info()
    {

        return error_info_buffer.toVector();
    }

    std::string get_trash_dir()
    {

        return this->trash_dir;
    }

    std::string get_nickname()
    {
        return this->nickname;
    }

    void SetPyTrace(py::object trace_cb = py::none())
    {
        SetWorkerPyTrace(trace_cb);
        SetSessionPyTrace(trace_cb);
    }

    void SetWorkerPyTrace(py::object trace_cb = py::none())
    {
        if (trace_cb.is_none())
        {
            this->is_trace = false;
            this->trace_cb = py::function();
        }
        else
        {
            this->trace_cb = trace_cb.cast<py::function>();
            this->is_trace = true;
        }
    }

    void SetSessionPyTrace(py::object trace_cb = py::none())
    {
        if (trace_cb.is_none())
        {
            this->amsession->is_trace = false;
            this->amsession->trace_cb = py::function();
        }
        else
        {
            this->amsession->trace_cb = trace_cb.cast<py::function>();
            this->amsession->is_trace = true;
        }
    }

    EC get_session_last_error()
    {
        return cast_libssh2_error(libssh2_session_last_errno(amsession->session));
    }

    EC get_sftp_last_error()
    {
        return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
    }

    std::string get_session_error_msg()
    {
        char *errmsg = NULL;
        int errmsg_len;
        int errcode = libssh2_session_last_error(amsession->session, &errmsg, &errmsg_len, 0);
        return std::string(errmsg);
    }

    ECM init(py::object pycb = py::none())
    {
        SetPyTrace(pycb);
        ECM ecm = amsession->init();
        if (!isok(ecm))
        {
            record_error(ErrorInfo(ecm.first, "", "", "AMSFTPClient::init", ecm.second));
            return ecm;
        }
        trash_dir = amsession->request.trash_dir;

        ecm = check();
        if (!isok(ecm))
        {
            record_error(ErrorInfo(ecm.first, "", "", "AMSFTPClient::init", "Session check failed"));
            return ecm;
        }

        return {EC::Success, ""};
    }

    ECM check()
    {
        EC rc = EC::Success;
        std::string msg = "";
        if (!amsession)
        {
            rc = EC::SessionNotInitialized;
            msg = "Session is not initialized";
            pytrace(AMCRITICAL, "SessionBroken", "AMSFTPClient", "check", "Session is not initialized");
            record_error(ErrorInfo(TransferErrorCode::SessionNotInitialized, "", "", "AMSFTPClient::check", "Session is not initialized"));
            return {rc, msg};
        }
        else
        {
            ECM ecm = amsession->check();
            if (!isok(ecm))
            {
                record_error(ErrorInfo(ecm.first, "", "", "AMSFTPClient::check", ecm.second));
                return ecm;
            }
        }
        pytrace(AMINFO, "ClientCheckSuccess", request.nickname, "check", "");
        return {EC::Success, ""};
    }

    ECM reconnect()
    {
        ECM ecm = amsession->reconnect();
        if (!isok(ecm))
        {
            record_error(ErrorInfo(ecm.first, "", "", "AMSFTPClient::reconnect", ecm.second));
            return ecm;
        }
        return {EC::Success, ""};
    }

    ECM ensure()
    {
        ECM ecm = check();
        if (!isok(ecm))
        {
            ecm = reconnect();
            if (!isok(ecm))
            {
                record_error(ErrorInfo(ecm.first, "", "", "AMSFTPClient::ensure", "Session reconnect failed"));
                return ecm;
            }
        }
        return {EC::Success, ""};
    }

    virtual std::string get_user_name(long uid) {};
};

class AMSFTPClient : public BaseSFTPClient
{
private:
    std::map<long, std::string> user_id_map;

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

    void _get_size(std::string path, uint64_t &size)
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
            _get_size(item.path, size);
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

    AMSFTPClient(ConRequst request, std::vector<std::string> private_keys, size_t error_info_buffer_size = 10)
    {
        BaseSFTPClient(request, private_keys, error_info_buffer_size);
    }

    std::string get_user_name(long uid)
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

    ECM set_trash_dir(std::string trash_dir_f = "")
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
            pytrace(AMERROR, "WorkDirGetError", request.nickname, "CWD", "Can't get current working directory");
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

    ECM ensure_trash_dir()
    {
        BR res = is_dir(this->trash_dir);
        if (std::holds_alternative<ECM>(res))
        {
            return std::get<ECM>(res);
        }
        if (std::holds_alternative<bool>(res))
        {
            if (std::get<bool>(res))
            {
                return {EC::Success, ""};
            }
        }
        std::string trash_dir_t = "./.AMSFTP_Trash";
        ECM res2 = mkdirs(trash_dir_t);
        if (!isok(res2))
        {
            return res2;
        }
        this->trash_dir = trash_dir_t;
        return {EC::Success, ""};
    }

    RR realpath(std::string path)
    {
        char path_t[1024];
        int rcr = libssh2_sftp_realpath(amsession->sftp, path.c_str(), path_t, sizeof(path_t));
        if (rcr < 0)
        {
            EC rc = get_sftp_last_error();
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::realpath", "realpath failed"));
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
            rc = get_sftp_last_error();
            msg = get_session_error_msg();
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::stat", msg));
            if (rc != EC::PathNotExist && rc != EC::PermissionDenied)
            {
                pytrace(AMWARNING, "StatFailed", fmt::format("{}@{}", request.nickname, path), "Stat", msg);
            }
            return std::make_pair(rc, fmt::format("stat {} failed: {}", path, msg));
        }
        return format_stat(path, attrs);
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
            rc = get_sftp_last_error();
            std::string msg = get_session_error_msg();
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::stat", msg));
            switch (rc)
            {
            case EC::PathNotExist:
                return false;
            case EC::PermissionDenied:
                return std::make_pair(rc, fmt::format("No Permission to access path: {}", path));
            default:
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

    LR listdir(std::string path, uint64_t max_num = -1)
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
            std::string tmp_msg = get_session_error_msg();
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
                rc = get_sftp_last_error();
                std::string tmp_msg = get_session_error_msg();
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
            info = format_stat(path_i, attrs);
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
            EC rc = get_sftp_last_error();
            std::string msg_tmp = get_session_error_msg();
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
            rc = get_sftp_last_error();
            std::string tmp_msg = get_session_error_msg();
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
            rc = get_sftp_last_error();
            std::string tmp_msg = get_session_error_msg();
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
            rc = get_sftp_last_error();
            std::string msg_tmp = get_session_error_msg();
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
            record_error(ErrorInfo(EC::PathNotExist, path, trash_dir, "AMSFTPClient::saferm", "Src path not exists"));
            return {EC::PathNotExist, fmt::format("Src path not exists: {}", path)};
        }

        ECM ecm = ensure_trash_dir();
        if (!isok(ecm))
        {
            return {ecm.first, fmt::format("Trash dir not ready: {}", ecm.second)};
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
            target_path = join_path(trash_dir, base_name + "_" + std::to_string(i) + base_ext);
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
            rc = get_sftp_last_error();
            std::string msg = get_session_error_msg();
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
            record_error(ErrorInfo(get_session_last_error(), src, dst, "AMSFTPClient::copy", "Channel creation failed"));
            return {get_session_last_error(), "Channel creation failed"};
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
                record_error(ErrorInfo(get_session_last_error(), src, dst, "AMSFTPClient::copy", "Cmd exec failed"));
                return {get_session_last_error(), "copy cmd conducted failed"};
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

    SIZER get_size(std::string path)
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
        _get_size(path, size);
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
    uint64_t total_size = 100;
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
        LIBSSH2_CHANNEL *channel;
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
                    pytrace(AMERROR, "RemoteFileOpenError", fmt::format("{}@{}", request.nickname, dst), "Remote2Local", get_session_error_msg());
                    return {get_sftp_last_error(), fmt::format("Failed to open remote file: {}, cause {}", dst, get_session_error_msg())};
                }
            }
            else
            {
                pytrace(AMERROR, "RemoteFileOpenError", fmt::format("{}@{}", request.nickname, dst), "Remote2Local", get_session_error_msg());
                return {get_sftp_last_error(), fmt::format("Failed to open remote file: {}, cause {}", dst, get_session_error_msg())};
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
        std::cout << "chunk_size: " << chunk_size << std::endl;

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
                    error_msg = fmt::format("Sftp write error: {}", get_session_error_msg());
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
            pytrace(AMERROR, "TransferError", fmt::format("Local@{}->{}@{}", src, request.nickname, dst), "Local2Remote", get_session_error_msg());
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
            pytrace(AMERROR, "RemoteFileOpenError", fmt::format("{}@{}", request.nickname, src), "Remote2Local", get_session_error_msg());
            return ECM{EC::RemoteFileOpenError, fmt::format("Failed to open remote file: {}, cause {}", src, get_session_error_msg())};
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(sftpFile, &attrs);
        uint64_t file_size = attrs.filesize;
        if (file_size == 0)
        {
            libssh2_sftp_close_handle(sftpFile);
            pytrace(AMERROR, "RemoteFileStatError", fmt::format("{}@{}", request.nickname, src), "Remote2Local", get_session_error_msg());
            return ECM{EC::PathNotExist, fmt::format("Failed to get remote file size: {}, cause {}", src, get_session_error_msg())};
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
                    error_msg = fmt::format("Sftp read error: {}", get_session_error_msg());
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
            pytrace(AMERROR, "TransferError", fmt::format("{}@{}->Local@{}", request.nickname, src, dst), "Remote2Local", get_session_error_msg());
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
            pytrace(AMERROR, "RemoteSrcOpenError", fmt::format("{}@{}", request.nickname, src), "Remote2Remote", get_session_error_msg());
            record_error(ErrorInfo(EC::RemoteFileOpenError, src, "", "Remote2Remote", get_session_error_msg()));
            return ECM{EC::RemoteFileOpenError, fmt::format("Failed to open src remote file: {}, cause {}", src, get_session_error_msg())};
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
                    pytrace(AMERROR, "RemoteDstOpenError", fmt::format("{}@{}", request.nickname, dst), "Remote2Remote", get_session_error_msg());
                    record_error(ErrorInfo(EC::RemoteFileOpenError, dst, "", "Remote2Remote", get_session_error_msg()));
                    return ECM{another_worker->get_sftp_last_error(), fmt::format("Failed to open dst remote file: {}, cause {}", dst, get_session_error_msg())};
                }
            }
            else
            {
                pytrace(AMERROR, "RemoteDstOpenError", fmt::format("{}@{}", request.nickname, dst), "Remote2Remote", get_session_error_msg());
                return ECM{another_worker->get_sftp_last_error(), fmt::format("Failed to open dst remote file: {}, cause {}", dst, get_session_error_msg())};
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
                        rc_final = another_worker->get_sftp_last_error();
                        error_msg = fmt::format("Sftp read error: {}", get_session_error_msg());
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
                        error_msg = fmt::format("Sftp write error: {}", get_session_error_msg());
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

    AMSFTPWorker(std::vector<std::string> private_keys, ConRequst request, uint64_t error_info_buffer_size = 16)
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
        if (is_src_remote)
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
        for (auto &item : result)
        {
            if (ignore_link && (item.path_type == PathType::SYMLINK))
            {
                continue;
            }
            dst_i = join_path(dst, fs::relative(item.path, src));
            tasks.push_back(TransferTask(item.path, dst_i, item.size, item.path_type));
        }
        return tasks;
    }

    TR upload(TASKS &tasks, TransferCallback cb_set = TransferCallback(), uint64_t chunk_size = 256 * AMKB)
    {

        ECM rc = check();
        if (rc.first != EC::Success)
        {
            return rc;
        }
        reset();
        this->callback = cb_set;
        this->total_size = std::accumulate(tasks.begin(), tasks.end(), 0, [](uint64_t sum, const TransferTask &task)
                                           { return sum + task.size; });

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
                rc = Local2Remote(task.src, task.dst, chunk_size);
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

    TR download(TASKS &tasks, TransferCallback cb_set = TransferCallback(), uint64_t chunk_size = 256 * AMKB)
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

    TR get(std::string src, std::string dst, TransferCallback cb_set = TransferCallback(), bool ignore_link = true, uint64_t chunk_size = 256 * AMKB)
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

    TR put(std::string src, std::string dst, TransferCallback cb_set = TransferCallback(), bool ignore_link = true, uint64_t chunk_size = 256 * AMKB)
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
        .def(py::init<std::string, std::string, std::string, std::string, int, bool, size_t, std::string>(), py::arg("nickname"), py::arg("hostname"), py::arg("username"), py::arg("password"), py::arg("port"), py::arg("compression"), py::arg("timeout_s") = 3, py::arg("trash_dir") = "")
        .def_readwrite("nickname", &ConRequst::nickname)
        .def_readwrite("hostname", &ConRequst::hostname)
        .def_readwrite("username", &ConRequst::username)
        .def_readwrite("password", &ConRequst::password)
        .def_readwrite("port", &ConRequst::port)
        .def_readwrite("compression", &ConRequst::compression)
        .def_readwrite("timeout_s", &ConRequst::timeout_s)
        .def_readwrite("trash_dir", &ConRequst::trash_dir);

    py::class_<TransferCallback>(m, "TransferCallback")
        .def(py::init<float, py::object, py::object, py::object>(),
             py::arg("cb_interval_s") = 0.5,
             py::arg("error_cb") = py::none(),
             py::arg("progress_cb") = py::none(),
             py::arg("filename_cb") = py::none())
        .def_readwrite("error_cb", &TransferCallback::error_cb)
        .def_readwrite("progress_cb", &TransferCallback::progress_cb)
        .def_readwrite("filename_cb", &TransferCallback::filename_cb)
        .def_readwrite("cb_interval_s", &TransferCallback::cb_interval_s)
        .def_readwrite("need_error_cb", &TransferCallback::need_error_cb)
        .def_readwrite("need_progress_cb", &TransferCallback::need_progress_cb)
        .def_readwrite("need_filename_cb", &TransferCallback::need_filename_cb);

    py::class_<TransferTask>(m, "TransferTask")
        .def(py::init<std::string, std::string, uint64_t>(), py::arg("src"), py::arg("dst"), py::arg("size"))
        .def_readwrite("src", &TransferTask::src)
        .def_readwrite("dst", &TransferTask::dst)
        .def_readwrite("size", &TransferTask::size);

    py::class_<PathInfo>(m, "PathInfo")
        .def(py::init<std::string, std::string, std::string, uint64_t, uint64_t, uint64_t, PathType>(), py::arg("name"), py::arg("path"), py::arg("dir"), py::arg("size"), py::arg("atime"), py::arg("mtime"), py::arg("path_type"))
        .def_readwrite("name", &PathInfo::name)
        .def_readwrite("path", &PathInfo::path)
        .def_readwrite("dir", &PathInfo::dir)
        .def_readwrite("size", &PathInfo::size)
        .def_readwrite("atime", &PathInfo::atime)
        .def_readwrite("mtime", &PathInfo::mtime)
        .def_readwrite("path_type", &PathInfo::path_type);

    // py::class_<BufferSizePair>(m, "BufferSizePair")
    //     .def(py::init<uint64_t, uint64_t>(), py::arg("threshold"), py::arg("buffer"))
    //     .def_readwrite("threshold", &BufferSizePair::threshold)
    //     .def_readwrite("buffer", &BufferSizePair::buffer);

    // py::class_<BufferSet>(m, "BufferSet")
    //     .def(py::init<std::vector<BufferSizePair>, uint64_t>(),
    //          py::arg("buffer_sizes") = std::vector<BufferSizePair>(),
    //          py::arg("min_buffer_size") = 64 * AMKB);

    py::class_<ErrorInfo>(m, "ErrorInfo")
        .def(py::init<TransferErrorCode, std::string, std::string, std::string, std::string>(), py::arg("error_code"), py::arg("src"), py::arg("dst"), py::arg("function_name"), py::arg("msg"))
        .def_readwrite("error_code", &ErrorInfo::error_code)
        .def_readwrite("src", &ErrorInfo::src)
        .def_readwrite("dst", &ErrorInfo::dst)
        .def_readwrite("function_name", &ErrorInfo::function_name)
        .def_readwrite("msg", &ErrorInfo::msg);

    py::class_<AMSFTPWorker, std::shared_ptr<AMSFTPWorker>>(m, "AMSFTPWorker")
        .def(py::init<std::vector<std::string>, ConRequst, uint64_t>(), py::arg("private_keys"), py::arg("request"), py::arg("error_info_buffer_size") = 10)
        .def("check", &AMSFTPClient::check)
        .def("reconnect", &AMSFTPClient::reconnect)
        .def("ensure", &AMSFTPClient::ensure)
        .def("ensure_trash_dir", &AMSFTPClient::ensure_trash_dir)
        .def("init", &AMSFTPClient::init, py::arg("pycb") = py::none())
        .def("get_size", &AMSFTPClient::get_size, py::arg("path"), py::arg("exclude_dir") = false, py::arg("exclude_symlink") = false)
        .def("stat", &AMSFTPClient::stat, py::arg("path"))
        .def("exists", &AMSFTPClient::exists, py::arg("path"))
        .def("is_file", &AMSFTPClient::is_file, py::arg("path"))
        .def("is_dir", &AMSFTPClient::is_dir, py::arg("path"))
        .def("is_symlink", &AMSFTPClient::is_symlink, py::arg("path"))
        .def("listdir", &AMSFTPClient::listdir, py::arg("path"))
        .def("mkdir", &AMSFTPClient::mkdir, py::arg("path"))
        .def("mkdirs", &AMSFTPClient::mkdirs, py::arg("path"))
        .def("rmfile", &AMSFTPClient::rmfile, py::arg("path"))
        .def("rmdir", &AMSFTPClient::rmdir, py::arg("path"))
        .def("rm", &AMSFTPClient::rm, py::arg("path"))
        .def("saferm", &AMSFTPClient::saferm, py::arg("path"))
        .def("move", &AMSFTPClient::move, py::arg("src"), py::arg("dst"), py::arg("need_mkdir") = false, py::arg("force_write") = false)
        .def("copy", &AMSFTPClient::copy, py::arg("src"), py::arg("dst"), py::arg("need_mkdir") = false)
        .def("rename", &AMSFTPClient::rename, py::arg("src"), py::arg("dst"), py::arg("need_mkdir") = false, py::arg("force_write") = false)
        .def("walk", &AMSFTPClient::walk, py::arg("path"))
        .def("get_last_error_info", &AMSFTPClient::get_last_error_info)
        .def("get_all_error_info", &AMSFTPClient::get_all_error_info)
        .def("set_trash_dir", &AMSFTPClient::set_trash_dir, py::arg("trash_dir"))
        .def("get_trash_dir", &AMSFTPClient::get_trash_dir)
        .def("get_nickname", &AMSFTPClient::get_nickname)
        .def("terminate", &AMSFTPWorker::terminate)
        .def("pause", &AMSFTPWorker::pause)
        .def("resume", &AMSFTPWorker::resume)
        .def("is_running", &AMSFTPWorker::IsRunning)
        .def("upload", &AMSFTPWorker::upload, py::arg("tasks"), py::arg("cb_set") = TransferCallback(), py::arg("chunk_size") = 256 * AMKB)
        .def("download", &AMSFTPWorker::download, py::arg("tasks"), py::arg("cb_set") = TransferCallback(), py::arg("chunk_size") = 256 * AMKB)
        .def("toAnotherHost", &AMSFTPWorker::toAnotherHost, py::arg("tasks"), py::arg("another_worker"), py::arg("cb_set") = TransferCallback(), py::arg("chunk_size") = 256 * AMKB)
        .def("SetPyTrace", &AMSFTPWorker::SetPyTrace)
        .def("SetWorkerPyTrace", &AMSFTPWorker::SetWorkerPyTrace)
        .def("SetSessionPyTrace", &AMSFTPWorker::SetSessionPyTrace);
}
