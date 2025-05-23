#include <libssh2.h>
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
#include <shared_mutex>
#include <filesystem>
#include <algorithm>
#include <chrono>
#include <numeric>
#include <memory>

namespace py = pybind11;
namespace fs = std::filesystem;
using f_ptr = std::shared_ptr<py::function>;

constexpr uint64_t AMKB = 1024;
constexpr uint64_t AMMB = 1024 * 1024;
constexpr uint64_t AMGB = 1024 * 1024 * 1024;

std::wstring Wstring(const std::string &narrowStr)
{
    int length = MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, nullptr, 0);
    std::wstring wideStr(length, 0);
    MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, &wideStr[0], length);
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

void mkdirs(const std::string &path)
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
};

enum class TarSystemType
{
    Unix = 0,
    Windows = 1,
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
    bool need_filename_cb;
    py::function progress_cb;
    py::function filename_cb;
    py::function error_cb;
    TransferCallback()
        : progress_cb(py::function()), filename_cb(py::function()), error_cb(py::function()), cb_interval_s(0.5), need_progress_cb(false), need_filename_cb(false), need_error_cb(false) {}
    TransferCallback(py::function error_cb, py::function progress_cb, py::function filename_cb, float cb_interval_s, bool need_error_cb, bool need_progress_cb, bool need_filename_cb)
        : progress_cb(progress_cb), filename_cb(filename_cb), error_cb(error_cb), cb_interval_s(cb_interval_s), need_progress_cb(need_progress_cb), need_filename_cb(need_filename_cb), need_error_cb(need_error_cb) {}
};

struct TransferTask
{
    std::string src;
    std::string dst;
    uint64_t size;
    TransferTask(std::string src, std::string dst, uint64_t size)
        : src(src), dst(dst), size(size) {}
};

struct PathInfo
{
    std::string name;
    std::string path;
    std::string dir;
    uint64_t size = -1;
    uint64_t atime = -1;
    uint64_t mtime = -1;
    PathType path_type = PathType::FILE;
    PathInfo()
        : name(""), path(""), dir(""), size(-1), atime(-1), mtime(-1), path_type(PathType::FILE) {}
    PathInfo(std::string name, std::string path, std::string dir, uint64_t size, uint64_t atime, uint64_t mtime, PathType path_type)
        : name(name), path(path), dir(dir), size(size), atime(atime), mtime(mtime), path_type(path_type) {}
};

struct BufferSizePair
{
    uint64_t threshold;
    uint64_t buffer;
    BufferSizePair(uint64_t threshold, uint64_t buffer)
        : threshold(threshold > 0 ? threshold : 0), buffer(buffer > 0 ? buffer : 0) {}
};

struct BufferSet
{
    std::vector<BufferSizePair> buffer_sizes;
    uint64_t min_buffer_size;
    BufferSet()
        : buffer_sizes({BufferSizePair{16 * AMGB, 16 * AMMB},
                        BufferSizePair{4 * AMGB, 8 * AMMB},
                        BufferSizePair{AMGB, 4 * AMMB},
                        BufferSizePair{512 * AMMB, AMMB},
                        BufferSizePair{50 * AMMB, 256 * AMKB},
                        BufferSizePair{10 * AMMB, 128 * AMKB},
                        BufferSizePair{0, 64 * AMKB}}),
          min_buffer_size(64 * AMKB) {}
    BufferSet(std::vector<BufferSizePair> buffer_sizes, uint64_t min_buffer_size = 64 * AMKB)
        : buffer_sizes(buffer_sizes), min_buffer_size(min_buffer_size)
    {
        this->buffer_sizes.push_back(BufferSizePair{0, min_buffer_size});
        std::sort(this->buffer_sizes.begin(), this->buffer_sizes.end(), [](BufferSizePair a, BufferSizePair b)
                  { return a.threshold > b.threshold; });
    }
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
        addr = nullptr;
        hMap = nullptr;
        hFile = nullptr;
        file_ptr = nullptr;
        file_size = 0;
    }
    FileMapper()
    {
        this->hFile = nullptr;
        this->hMap = nullptr;
        this->addr = nullptr;
        this->file_ptr = nullptr;
    }
    FileMapper(std::wstring &file_path, MapType map_type, uint64_t file_size = 0)
    {
        if (map_type == MapType::Read)
        {
            this->hFile = CreateFileW(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            GetFileSizeEx(hFile, &file_size_ptr);
            this->file_size = file_size_ptr.QuadPart;
            this->hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
            this->addr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
            this->file_ptr = (char *)addr;
            return;
        }
        this->hFile = CreateFileW(file_path.c_str(), GENERIC_WRITE | GENERIC_READ, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (this->hFile == nullptr)
        {
            this->file_ptr = nullptr;
            return;
        }
        LARGE_INTEGER li;
        li.QuadPart = file_size;
        if (!SetFilePointerEx(hFile, li, NULL, FILE_BEGIN))
        {
            this->file_ptr = nullptr;
            return;
        }
        if (!SetEndOfFile(hFile))
        {
            this->file_ptr = nullptr;
            return;
        }
        this->hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, li.HighPart, li.LowPart, NULL);
        if (!this->hMap)
        {
            this->file_ptr = nullptr;
            return;
        }
        this->addr = MapViewOfFile(this->hMap, FILE_MAP_WRITE, 0, 0, 0);
        this->file_ptr = (char *)addr;
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

struct TransferContext
{
    std::unique_ptr<char[]> buf_a;
    std::unique_ptr<char[]> buf_b;
    size_t buf_a_size = 0;
    size_t buf_b_size = 0;
    bool buf_a_ready = false;
    bool buf_b_ready = false;
    bool read_complete = false;
    bool write_complete = false;
    uint64_t total_written = 0;

    TransferContext(size_t buffer_size) : buf_a(std::make_unique<char[]>(buffer_size)),
                                          buf_b(std::make_unique<char[]>(buffer_size)) {}
};
using result_map = std::unordered_map<std::string, TransferErrorCode>;
using TASKS = std::vector<TransferTask>;
using int_ptr = std::shared_ptr<uint64_t>;
using safe_int_ptr = std::shared_ptr<std::atomic<uint64_t>>;
using EC = TransferErrorCode;
using TRM = std::unordered_map<std::string, TransferErrorCode>;
using TR = std::variant<TRM, EC>;
using SR = std::variant<PathInfo, EC>;
using LR = std::variant<std::vector<PathInfo>, EC>;
using WRV = std::vector<PathInfo>;
using WR = std::variant<WRV, EC>;
using ED = std::pair<EC, std::string>;
using SIZER = std::variant<uint64_t, EC>;

void _walk(std::string path, WRV &result)
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
                result.push_back(PathInfo(filename, path, dir, size, atime, mtime, PathType::DIR));
            }
            for (const auto &subdir : subdirs)
            {
                _walk(subdir, result);
            }
            for (const auto &file : files)
            {
                _walk(file, result);
            }
        }
    case fs::file_type::symlink:
        result.push_back(PathInfo(filename, path, dir, size, atime, mtime, PathType::SYMLINK));
        break;
    default:
        result.push_back(PathInfo(filename, path, dir, size, atime, mtime, PathType::FILE));
        break;
    }
}

WRV local_walk(std::string path)
{
    std::vector<PathInfo> result = {};

    _walk(path, result);

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
    std::vector<ErrorInfo> buffer;
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
    std::recursive_mutex r_mtx;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp;
    std::vector<std::string> private_keys;
    ConRequst request;
    SOCKET sock = INVALID_SOCKET;
    LIBSSH2_CHANNEL *channel = nullptr;
    EC init()
    {
        EC rc = TransferErrorCode::Success;
        WSADATA wsaData;

        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            return TransferErrorCode::NetworkError;
        }

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            return TransferErrorCode::SocketCreateError;
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
            return TransferErrorCode::NetworkTimeout;
        }

        session = libssh2_session_init();

        if (!session)
        {
            return TransferErrorCode::SessionCreateError;
        }

        libssh2_session_set_blocking(session, 1);

        if (request.compression)
        {
            libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
            libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS, "zlib@openssh.com,zlib,none");
        }

        int rc_handshake;
        {
            std::lock_guard<std::recursive_mutex> lock(r_mtx);
            rc_handshake = libssh2_session_handshake(session, sock);
        }

        if (rc_handshake != 0)
        {
            return TransferErrorCode::SessionEstablishError;
        }

        rc = TransferErrorCode::ConnectionAuthorizeError;
        int rca = 0;
        if (!request.password.empty())
        {
            {
                {
                    std::lock_guard<std::recursive_mutex> lock(r_mtx);
                    rca = libssh2_userauth_password(session, request.username.c_str(), request.password.c_str());
                }
                if (rca == 0)
                {
                    rc = TransferErrorCode::Success;
                    goto OK;
                }
            }
            for (auto &private_key : private_keys)
            {
                {
                    std::lock_guard<std::recursive_mutex> lock(r_mtx);
                    rca = libssh2_userauth_publickey_fromfile(session, request.username.c_str(), nullptr, private_key.c_str(), nullptr);
                }
                if (rca == 0)
                {
                    rc = TransferErrorCode::Success;
                    goto OK;
                }
            }
        OK:
            if (rc != TransferErrorCode::Success)
            {
                return rc;
            }
            {
                std::lock_guard<std::recursive_mutex> lock(r_mtx);
                sftp = libssh2_sftp_init(session);
            }
            if (!sftp)
            {
                return TransferErrorCode::SftpCreateError;
            }
            {
                std::lock_guard<std::recursive_mutex> lock(r_mtx);
                channel = libssh2_channel_open_ex(session,
                                                  "session",
                                                  sizeof("session") - 1,
                                                  4 * AMMB,
                                                  512 * AMKB,
                                                  nullptr,
                                                  0);
            }

            if (!channel)
            {
                return TransferErrorCode::ChannelCreateError;
            }
            char path_t[1024];
            std::string trash_dir_t = "";

            if (request.trash_dir.empty())
            {
                int rcr;
                {
                    std::lock_guard<std::recursive_mutex> lock(r_mtx);
                    rcr = libssh2_sftp_realpath(sftp, ".", path_t, sizeof(path_t));
                }
                if (rcr <= 0)
                {
                    trash_dir_t = ".amsftp_trash";
                }
                else
                {
                    trash_dir_t = join_path(std::string(path_t), ".amsftp_trash");
                }
                request.trash_dir = trash_dir_t;
            }
            return TransferErrorCode::Success;
        }
    }

    EC check()
    {
        if (!sftp)
        {
            return EC::SftpNotInitialized;
        }

        if (!session)
        {
            return EC::SessionNotInitialized;
        }

        LIBSSH2_SFTP_ATTRIBUTES attrs;
        std::string test_path = "/amsftp_test/sample";
        int rct;
        {
            std::lock_guard<std::recursive_mutex> lock(r_mtx);
            rct = libssh2_sftp_stat(sftp, test_path.c_str(), &attrs);
        }

        if (rct != 0)
        {
            EC rc;
            {
                std::lock_guard<std::recursive_mutex> lock(r_mtx);
                rc = cast_libssh2_error(libssh2_session_last_errno(session));
            }
            if (rc == EC::PathNotExist)
            {
                return EC::Success;
            }
            return rc;
        }
        return EC::Success;
    }

    void clean()
    {
        if (sftp)
        {
            libssh2_sftp_shutdown(sftp);
        }
        if (session)
        {
            libssh2_session_free(session);
        }
        if (sock != INVALID_SOCKET)
        {
            closesocket(sock);
            WSACleanup();
        }
        if (channel)
        {
            libssh2_channel_close(channel);
            libssh2_channel_free(channel);
        }
    }

    EC reconnect()
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

    AMSession(ConRequst request, std::vector<std::string> private_keys)
        : request(request), private_keys(private_keys)
    {
    }

    ~AMSession()
    {
        clean();
    }
};

class AMSFTPClient
{
private:
    std::vector<std::string> private_keys;
    CircularBuffer error_info_buffer;

    PathInfo format_stat(std::string path, LIBSSH2_SFTP_ATTRIBUTES &attrs)
    {
        PathInfo info;
        info.path = path;
        info.name = basename(path);
        info.dir = dirname(path);

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
            case LIBSSH2_SFTP_S_IFREG:
                info.path_type = PathType::FILE;
                break;
            case LIBSSH2_SFTP_S_IFLNK:
                info.path_type = PathType::SYMLINK;
            }
        }
        return info;
    }

    void _walk(std::string path, WRV &result)
    {
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

    void _get_size(std::string path, bool exclude_dir = false, bool exclude_symlink = false, uint64_t &size, EC &error)
    {
        SR info = stat(path);
        if (std::holds_alternative<EC>(info))
        {
            error = std::get<EC>(info);
            return;
        }
        if (!std::holds_alternative<PathInfo>(info))
        {
            error = EC::UnknownError;
            return;
        }
        PathInfo path_info = std::get<PathInfo>(info);
        switch (path_info.path_type)
        {
        case PathType::FILE:
            size = path_info.size;
            return;
        case PathType::SYMLINK:
            if (exclude_symlink)
            {
                size = 0;
            }
            else
            {
                size = path_info.size;
            }
        case PathType::DIR:
            break;
        default:
            error = EC::UnknownError;
            return;
        }

        if (!exclude_dir)
        {
            size += path_info.size;
        }
        LR list = listdir(path);
        if (std::holds_alternative<EC>(list))
        {
            error = std::get<EC>(list);
            return;
        }
        if (!std::holds_alternative<WRV>(list))
        {
            error = EC::UnknownError;
            return;
        }

        for (auto &item : std::get<WRV>(list))
        {
            _get_size(item.path, exclude_dir, exclude_symlink, size);
        }
    }

public:
    std::string nickname;
    ConRequst request;
    AMSession *amsession;
    std::string trash_dir;
    std::recursive_mutex r_mtx;

    void record_error(ErrorInfo error_info)
    {
        std::lock_guard<std::recursive_mutex> lock(r_mtx);
        error_info_buffer.push(error_info);
    }

    EC get_session_last_error()
    {
        std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
        return cast_libssh2_error(libssh2_session_last_errno(amsession->session));
    }

    EC get_sftp_last_error()
    {
        std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
        return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
    }

    ~AMSFTPClient()
    {
        delete amsession;
        amsession = nullptr;
    }

    AMSFTPClient(ConRequst request, std::vector<std::string> private_keys, size_t error_info_buffer_size = 10)
        : request(request), private_keys(private_keys)
    {
        this->amsession = new AMSession(request, private_keys);
        this->error_info_buffer = CircularBuffer(error_info_buffer_size);
        this->nickname = request.nickname;
    }

    EC check()
    {
        EC rc = EC::Success;
        if (!amsession)
        {
            rc = EC::SessionBroken;
            record_error(ErrorInfo(TransferErrorCode::SessionBroken, "", "", "AMSFTPClient::check", "Session is not initialized"));
            return rc;
        }
        else
        {

            rc = amsession->check();

            if (rc != EC::Success)
            {
                record_error(ErrorInfo(rc, "", "", "AMSFTPClient::check", "Session is broken"));
            }
        }
        return rc;
    }

    EC reconnect()
    {
        delete amsession;
        // AMSession amsession_f = AMSession(request, private_keys);
        amsession = new AMSession(request, private_keys);
        EC rc = amsession->init();
        if (rc != EC::Success)
        {
            record_error(ErrorInfo(rc, "", "", "AMSFTPClient::reconnect", "Session init failed"));
        }
        return rc;
    }

    EC ensure()
    {
        EC rc = check();
        if (rc != EC::Success)
        {
            rc = reconnect();
            if (rc != EC::Success)
            {
                record_error(ErrorInfo(rc, "", "", "AMSFTPClient::ensure", "Session reconnect failed"));
                return rc;
            }
        }
        return rc;
    }

    EC ensure_trash_dir()
    {
        SR info = stat(trash_dir);
        EC rc;
        if (std::holds_alternative<EC>(info))
        {
            rc = std::get<EC>(info);
            if (rc != EC::PathNotExist)
            {
                record_error(ErrorInfo(rc, "", "", "AMSFTPClient::ensure_trash_dir", "Trash dir initializes failed"));
                return rc;
            }
        }

        if (std::holds_alternative<PathInfo>(info))
        {
            if (std::get<PathInfo>(info).path_type == PathType::DIR)
            {
                return EC::Success;
            }
            else
            {
                record_error(ErrorInfo(EC::TargetNotADirectory, request.trash_dir, "", "AMSFTPClient::ensure_trash_dir", "trash_dir is not a directory"));
                return EC::TargetNotADirectory;
            }
        }
        rc = mkdirs(trash_dir);
        if (rc != EC::Success)
        {
            return rc;
        }
        return EC::Success;
    }

    EC init()
    {
        EC rc = amsession->init();
        if (rc != EC::Success)
        {
            record_error(ErrorInfo(rc, "", "", "AMSFTPClient::init", "Session init failed"));
            return rc;
        }
        trash_dir = amsession->request.trash_dir;
        rc = check();
        if (rc != EC::Success)
        {
            record_error(ErrorInfo(rc, "", "", "AMSFTPClient::init", "Session check failed"));
            return rc;
        }
        return rc;
    }

    SIZER get_size(std::string path, bool exclude_dir = false, bool exclude_symlink = false)
    {
        uint64_t size = 0;
        EC error = EC::Success;
        _get_size(path, exclude_dir, exclude_symlink, size, error);
        if (error != EC::Success)
        {
            record_error(ErrorInfo(error, path, "", "AMSFTPClient::get_size", "get size failed"));
            return error;
        }
        return size;
    }

    SR stat(std::string path)
    {

        LIBSSH2_SFTP_ATTRIBUTES attrs;
        EC rc;
        int rct;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rct = libssh2_sftp_stat(amsession->sftp, path.c_str(), &attrs);
        }
        if (rct != 0)
        {
            rc = get_sftp_last_error();
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::stat", "stat failed"));
            return rc;
        }
        return format_stat(path, attrs);
    }

    EC exists(std::string path)
    {

        SR info = stat(path);
        EC rc;
        if (std::holds_alternative<EC>(info))
        {
            rc = std::get<EC>(info);
            if (rc == EC::PathNotExist)
            {
                return EC::FailedCheck;
            }
            return rc;
        }
        if (std::holds_alternative<PathInfo>(info))
        {
            return EC::PassCheck;
        }
        record_error(ErrorInfo(EC::UnknownError, path, "", "AMSFTPClient::exists", "Value Type Error"));
        return EC::UnknownError;
    }

    EC is_file(std::string path)
    {

        SR info = stat(path);
        EC rc;
        if (std::holds_alternative<EC>(info))
        {
            rc = std::get<EC>(info);
            return rc;
        }
        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).path_type == PathType::FILE ? EC::PassCheck : EC::FailedCheck;
        }
        record_error(ErrorInfo(EC::UnknownError, path, "", "AMSFTPClient::is_file", "Value Type Error"));
        return EC::UnknownError;
    }

    EC is_dir(std::string path)
    {

        SR info = stat(path);
        EC rc;
        if (std::holds_alternative<EC>(info))
        {
            rc = std::get<EC>(info);
            return rc;
        }
        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).path_type == PathType::DIR ? EC::PassCheck : EC::FailedCheck;
        }
        record_error(ErrorInfo(EC::UnknownError, path, "", "AMSFTPClient::is_dir", "Value Type Error"));
        return EC::UnknownError;
    }

    EC is_symlink(std::string path)
    {

        SR info = stat(path);
        EC rc;
        if (std::holds_alternative<EC>(info))
        {
            rc = std::get<EC>(info);
            return rc;
        }
        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).path_type == PathType::SYMLINK ? EC::PassCheck : EC::FailedCheck;
        }
        record_error(ErrorInfo(EC::UnknownError, path, "", "AMSFTPClient::is_symlink", "Value Type Error"));
        return EC::UnknownError;
    }

    LR listdir(std::string path)
    {

        std::vector<PathInfo> file_list = {};
        EC rc = is_dir(path);
        std::string normalized_path = path;
        LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        std::string name;
        std::string path_i;
        const size_t buffer_size = 4096;
        std::vector<char> filename_buffer(buffer_size);
        int rct;
        PathInfo info;
        bool is_sucess = false;

        switch (rc)
        {
        case EC::PassCheck:
            break;
        case EC::FailedCheck:
            record_error(ErrorInfo(EC::NotDirectory, path, "", "AMSFTPClient::listdir", "Path is not a directory"));
            return EC::NotDirectory;
        default:
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::listdir", "Path check failed"));
            return rc;
        }

        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            sftp_handle = libssh2_sftp_open_ex(
                amsession->sftp,
                normalized_path.c_str(),
                normalized_path.size(),
                0,
                LIBSSH2_SFTP_OPENDIR,
                LIBSSH2_FXF_READ);

            if (!sftp_handle)
            {
                goto clean;
            }

            // Use a reasonably sized buffer for filenames

            // Read directory entries
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
                    goto clean;
                }
                else if (rct == 0)
                {
                    is_sucess = true;
                    break;
                }

                // Process the entry
                name.assign(filename_buffer.data(), rct);

                // Skip "." and ".." entries
                if (name == "." || name == "..")
                {
                    continue;
                }

                // Construct the full path based on target system
                path_i = join_path(normalized_path, name);
                // Create PathInfo object and add to list
                info = format_stat(path_i, attrs);
                file_list.push_back(info);
            }
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
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rc = get_sftp_last_error();
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::listdir", "Handle open failed"));
            return rc;
        }
    }

    EC mkdir(std::string path)
    {

        EC rc = is_dir(path);

        switch (rc)
        {
        case EC::PassCheck:
            return EC::Success;
        case EC::FailedCheck:
            record_error(ErrorInfo(EC::RemoteFileExists, path, "", "AMSFTPClient::mkdir", "Path exists and is not a directory"));
            return EC::RemoteFileExists;
        case EC::PathNotExist:
            break;
        default:
            return rc;
        }

        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rcr = libssh2_sftp_mkdir_ex(amsession->sftp, path.c_str(), path.size(), 0740);
        }
        if (rcr != 0)
        {
            rc = get_sftp_last_error();
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::mkdir", "Mkdir failed"));
            return rc;
        }
        return EC::Success;
    }

    EC mkdirs(std::string path)
    {

        if (path.empty())
        {
            return EC::InvalidParameter;
        }

        std::replace(path.begin(), path.end(), '\\', '/');

        std::vector<std::string> parts;
        size_t start = 0;
        size_t end = 0;

        bool is_absolute = (path[0] == '/');
        std::string root;

        if (is_absolute)
        {
            root = "/";
            start = 1;
        }
        else if (path.size() >= 2 && path[1] == ':')
        {
            root = path.substr(0, 3);
            start = 3;
            path = root + path.substr(3);
        }

        while (start < path.size())
        {
            end = path.find('/', start);
            if (end == std::string::npos)
            {
                end = path.size();
            }
            if (end != start)
            {
                std::string part = path.substr(start, end - start);
                parts.push_back(part);
            }
            start = end + 1;
        }

        std::string current_path = root;
        for (const auto &part : parts)
        {
            if (current_path.empty())
            {
                current_path = part;
            }
            else
            {
                if (current_path.back() != '/')
                    current_path += '/';
                current_path += part;
            }

            EC rc = mkdir(current_path);
            if (rc == EC::Success || rc == EC::DirAlreadyExists)
            {
                continue;
            }
            else
            {
                return rc;
            }
        }
        return EC::Success;
    }

    EC rmfile(std::string path)
    {

        SR info = stat(path);
        EC rc;
        if (std::holds_alternative<EC>(info))
        {
            return std::get<EC>(info);
        }
        if (std::holds_alternative<PathInfo>(info))
        {
            if (std::get<PathInfo>(info).path_type == PathType::FILE || std::get<PathInfo>(info).path_type == PathType::SYMLINK)
            {
            }
            else
            {
                record_error(ErrorInfo(EC::TargetNotAFile, path, "", "AMSFTPClient::rmfile", "Path is not a file"));
                return EC::TargetNotAFile;
            }
        }
        else
        {
            record_error(ErrorInfo(EC::UnknownError, path, "", "AMSFTPClient::rmfile", "Value Type Error"));
            return EC::UnknownError;
        }

        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rcr = libssh2_sftp_unlink(amsession->sftp, path.c_str());
        }
        if (rcr != 0)
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rc = get_sftp_last_error();
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::rmfile", "Rmfile failed"));
            return rc;
        }
        return EC::Success;
    }

    EC rmdir(std::string path)
    {
        EC rc = is_dir(path);
        switch (rc)
        {
        case EC::PassCheck:
            break;
        case EC::FailedCheck:
            return EC::TargetNotADirectory;
        default:
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::rmdir", "Path check failed"));
            return rc;
        }

        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rcr = libssh2_sftp_rmdir(amsession->sftp, path.c_str());
        }
        if (rcr < 0)
        {
            rc = get_sftp_last_error();
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::rmdir", "Rmdir failed"));
            return rc;
        }
        return EC::Success;
    }

    EC rm(std::string path)
    {

        EC rc = is_dir(path);
        int path_type = 0;
        switch (rc)
        {
        case EC::PassCheck:
            path_type = 1;
            break;
        case EC::FailedCheck:
            path_type = 0;
            break;
        default:
            record_error(ErrorInfo(rc, path, "", "AMSFTPClient::rm", "path check failed"));
            return rc;
        }

        if (path_type == 0)
        {
            return rmfile(path);
        }

        LR file_list = listdir(path);
        if (std::holds_alternative<std::vector<PathInfo>>(file_list))
        {
            std::vector<PathInfo> file_list_f = std::get<std::vector<PathInfo>>(file_list);
            for (auto &file : file_list_f)
            {
                rm(file.path);
            }
            return rmdir(path);
        }
        else
        {
            if (std::holds_alternative<EC>(file_list))
            {
                return std::get<EC>(file_list);
            }
            else
            {
                return EC::UnknownError;
            }
        }
    }

    EC saferm(std::string path)
    {
        EC rc = exists(path);
        if (rc != EC::PassCheck)
        {
            record_error(ErrorInfo(rc, path, trash_dir, "AMSFTPClient::saferm", "Src path not exists"));
            return rc;
        }
        rc = is_dir(trash_dir);
        if (rc != EC::PassCheck)
        {
            rc = mkdirs(trash_dir);
            if (rc != EC::Success)
            {
                record_error(ErrorInfo(rc, path, trash_dir, "AMSFTPClient::saferm", "Trash dir mkdir failed"));
                return rc;
            }
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
        while (exists(target_path) == EC::PassCheck)
        {
            target_path = join_path(trash_dir, base_name + "_" + std::to_string(i) + base_ext);
            i++;
        }
        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rcr = libssh2_sftp_rename(amsession->sftp, path.c_str(), target_path.c_str());
        }
        if (rcr != 0)
        {
            rc = get_sftp_last_error();
            record_error(ErrorInfo(rc, path, trash_dir, "AMSFTPClient::saferm", "Rename failed"));
            return rc;
        }
        return EC::Success;
    }

    EC move(std::string src, std::string dst, bool need_mkdir = false, bool force_write = false)
    {
        EC rc = exists(src);
        if (rc != EC::PassCheck)
        {
            error_info_buffer.push(ErrorInfo(rc, src, dst, "AMSFTPClient::move", "Src not exists"));
            return rc;
        }

        std::string src_base = basename(src);
        std::string dst_dir = dst;
        std::string dst_path = join_path(dst_dir, src_base);
        rc = exists(dst_dir);
        if (rc != EC::PassCheck)
        {
            if (need_mkdir)
            {
                rc = mkdirs(dst_dir);
                if (rc != EC::Success)
                {
                    error_info_buffer.push(ErrorInfo(rc, src, dst_dir, "AMSFTPClient::move", "Dst dir mkdir failed"));
                    return rc;
                }
            }
            else
            {
                error_info_buffer.push(ErrorInfo(EC::ParentDirectoryNotExist, src, dst_dir, "AMSFTPClient::move", "Dst dir not exists"));
                return EC::ParentDirectoryNotExist;
            }
        }
        if (exists(dst_path) == EC::PassCheck)
        {
            if (!force_write)
            {
                error_info_buffer.push(ErrorInfo(EC::TargetExists, src, dst_path, "AMSFTPClient::move", "Dst path already exists"));
                return EC::TargetExists;
            }
        }

        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rcr = libssh2_sftp_rename_ex(amsession->sftp, src.c_str(), src.size(), dst_path.c_str(), dst_path.size(), force_write ? LIBSSH2_SFTP_RENAME_OVERWRITE : 0);
        }

        if (rcr != 0)
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rc = get_sftp_last_error();
            error_info_buffer.push(ErrorInfo(rc, src, dst_path, "AMSFTPClient::move", "Rename failed"));
            return rc;
        }

        return EC::Success;
    };

    EC copy(std::string src, std::string dst, bool need_mkdir = false)
    {
        EC rc = exists(src);
        switch (rc)
        {
        case EC::PassCheck:
            break;
        case EC::FailedCheck:
            error_info_buffer.push(ErrorInfo(rc, src, dst, "AMSFTPClient::copy", "Src not exists"));
            return EC::PathNotExist;
        default:
            error_info_buffer.push(ErrorInfo(rc, src, dst, "AMSFTPClient::copy", "Src check failed"));
            return rc;
        }

        rc = is_file(dst);
        if (rc == EC::PassCheck)
        {
            return EC::TargetExists;
        }

        rc = is_dir(dst);
        if (rc != EC::PassCheck)
        {
            if (need_mkdir)
            {
                rc = mkdirs(dst);
                if (rc != EC::Success)
                {
                    error_info_buffer.push(ErrorInfo(rc, src, dst, "AMSFTPClient::copy", "Dst dir mkdir failed"));
                    return rc;
                }
            }
            else
            {
                error_info_buffer.push(ErrorInfo(EC::ParentDirectoryNotExist, src, dst, "AMSFTPClient::copy", "Dst parent dir not exists"));
                return EC::ParentDirectoryNotExist;
            }
        }

        std::string command = "cp -r \"" + src + "\" \"" + dst + "\"";

        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rcr = libssh2_channel_exec(amsession->channel, command.c_str());
        }

        if (rcr != 0)
        {
            int exit_code;
            {
                std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
                exit_code = libssh2_channel_get_exit_status(amsession->channel);
            }
            if (exit_code != 0)
            {
                std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
                error_info_buffer.push(ErrorInfo(get_session_last_error(), src, dst, "AMSFTPClient::copy", "Cmd exec failed"));
                return EC::CopyError;
            }
        }
        return EC::Success;
    };

    EC rename(std::string src, std::string dst, bool need_mkdir = false, bool force_write = false)
    {
        EC rc = exists(src);
        std::string dst_dir;
        if (rc != EC::PassCheck)
        {
            std::lock_guard<std::recursive_mutex> lock(r_mtx);
            error_info_buffer.push(ErrorInfo(rc, src, dst, "AMSFTPClient::rename", "Src not exists"));
            return EC::PathNotExist;
        }
        rc = exists(dst);
        switch (rc)
        {
        case EC::PassCheck:
            if (!force_write)
            {
                std::lock_guard<std::recursive_mutex> lock(r_mtx);
                error_info_buffer.push(ErrorInfo(EC::TargetExists, src, dst, "AMSFTPClient::rename", "Dst exists"));
                return EC::TargetExists;
            }
            break;
        case EC::FailedCheck:
            break;
        default:
            std::lock_guard<std::recursive_mutex> lock(r_mtx);
            error_info_buffer.push(ErrorInfo(rc, src, dst, "AMSFTPClient::rename", "Dst check failed"));
            return rc;
        }
        dst_dir = dirname(dst);
        std::cout << "dst_dir: " << dst_dir << std::endl;
        rc = exists(dst_dir);
        if (rc != EC::PassCheck)
        {
            if (need_mkdir)
            {
                rc = mkdirs(dst_dir);
                if (rc != EC::Success)
                {
                    std::lock_guard<std::recursive_mutex> lock(r_mtx);
                    error_info_buffer.push(ErrorInfo(rc, src, dst_dir, "AMSFTPClient::rename", "Dst dir mkdir failed"));
                    return rc;
                }
            }
            else
            {
                std::lock_guard<std::recursive_mutex> lock(r_mtx);
                error_info_buffer.push(ErrorInfo(EC::ParentDirectoryNotExist, src, dst_dir, "AMSFTPClient::rename", "Dst dir not exists"));
                return EC::ParentDirectoryNotExist;
            }
        }
        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
            rcr = libssh2_sftp_rename_ex(amsession->sftp, src.c_str(), src.size(), dst.c_str(), dst.size(), force_write ? LIBSSH2_SFTP_RENAME_OVERWRITE : 0);
        }
        if (rcr != 0)
        {
            rc = get_sftp_last_error();
            {
                std::lock_guard<std::recursive_mutex> lock(r_mtx);
                error_info_buffer.push(ErrorInfo(rc, src, dst, "AMSFTPClient::rename", "Rename failed"));
            }
            return rc;
        }
        return EC::Success;
    }

    WR walk(std::string path)
    {
        // get all files and deepest folders
        WRV result = {};
        EC rc;
        rc = exists(path);
        if (rc != EC::PassCheck)
        {
            std::lock_guard<std::recursive_mutex> lock(r_mtx);
            error_info_buffer.push(ErrorInfo(rc, path, "", "AMSFTPClient::walk", "Path not exists"));
            return rc;
        }
        rc = is_dir(path);
        if (rc != EC::PassCheck)
        {
            std::lock_guard<std::recursive_mutex> lock(r_mtx);
            error_info_buffer.push(ErrorInfo(rc, path, "", "AMSFTPClient::walk", "Path is not a directory"));
            return rc;
        }
        _walk(path, result);
        return result;
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

    void set_trash_dir(std::string trash_dir)
    {

        this->trash_dir = trash_dir;
    }

    std::string get_trash_dir()
    {

        return this->trash_dir;
    }

    std::string GetNickname()
    {
        return this->nickname;
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
    double cb_time = std::chrono::duration<double>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    uint64_t calculate_buffer_size(uint64_t file_size, double speed)
    {
        double f_s = speed / 50;
        uint64_t speed_limit_uint = static_cast<uint64_t>(f_s);
        speed_limit_uint = (speed_limit_uint + 4096 - 1) / 4096 * 4096;
        uint64_t buffer_size_out = 64 * AMKB;
        for (auto &buffer_size : buffer_set.buffer_sizes)
        {
            if (file_size > buffer_size.threshold || file_size == buffer_size.threshold)
            {
                buffer_size_out = buffer_size.buffer;
                break;
            }
        }
        buffer_size_out = buffer_size_out > speed_limit_uint ? speed_limit_uint : buffer_size_out;
        buffer_size_out = buffer_size_out < buffer_set.min_buffer_size ? buffer_set.min_buffer_size : buffer_size_out;
        return buffer_size_out;
    }

    EC Local2Remote(std::string src, std::string dst)
    {
        std::lock_guard<std::recursive_mutex> lock(dst_client->amsession->r_mtx);
        TransferErrorCode rc_r = EC::Success;
        long rct;
        LIBSSH2_SFTP_HANDLE *sftpFile;

        sftpFile = libssh2_sftp_open(dst_client->amsession->sftp, dst.c_str(), LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0744);

        if (!sftpFile)
        {
            rct = libssh2_sftp_last_error(dst_client->amsession->sftp);
            if (rct == LIBSSH2_FX_NO_SUCH_FILE)
            {
                libssh2_sftp_mkdir(dst_client->amsession->sftp, dirname(dst).c_str(), 0744);
                sftpFile = libssh2_sftp_open(dst_client->amsession->sftp, dst.c_str(), LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0744);
                if (!sftpFile)
                {
                    return EC::RemoteFileOpenError;
                }
            }
            else
            {
                return EC::RemoteFileOpenError;
            }
        }

        FileMapper l_file_m(Wstring(src), MapType::Read);
        if (!l_file_m.file_ptr)
        {
            libssh2_sftp_close_handle(sftpFile);
            return dst_client->get_sftp_last_error();
        }
        double speed = AMGB * 1024;
        uint64_t buffer_size = calculate_buffer_size(l_file_m.file_size, speed);
        uint64_t offset = 0;
        uint64_t remaining = l_file_m.file_size;
        double time_start = std::chrono::duration<double>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
        double time_end = std::chrono::duration<double>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();
        uint64_t chunk_size = std::min<uint64_t>(buffer_size, remaining);
        uint64_t speed_interval_cout = 0;
        while (remaining > 0)
        {
            if (speed_interval_cout % adjust_interval == 0)
            {
                time_start = std::chrono::duration<double>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            }
            chunk_size = std::min<uint64_t>(buffer_size, remaining);
            long rc = libssh2_sftp_write(sftpFile, l_file_m.file_ptr + offset, chunk_size);
            if (is_terminate.load())
            {
                rc_r = EC::Terminate;
                goto clean;
            }
            while (is_pause.load() && !is_terminate.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
            if (rc > 0)
            {
                remaining -= rc;
                offset += rc;
                current_size += rc;
                time_end = std::chrono::duration<double>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();

                if (callback.need_progress_cb && ((time_end - cb_time) > callback.cb_interval_s))
                {
                    current_size += rc;
                    cb_time = time_end;
                    {
                        py::gil_scoped_acquire acquire;
                        callback.progress_cb(current_size, callback.total_bytes);
                    }
                }

                if (speed_interval_cout % adjust_interval == 0)
                {
                    speed = static_cast<double>(rc) / (time_end - time_start > 0 ? time_end - time_start : 1E-7);
                    buffer_size = calculate_buffer_size(remaining, speed);
                }
                speed_interval_cout++;
            }
            else if (rc == 0)
            {
                break;
            }
            else
            {
                rc_r = dst_client->get_sftp_last_error();
                goto clean;
            }
        }
    clean:
        if (sftpFile)
        {
            libssh2_sftp_close_handle(sftpFile);
        }
        return rc_r;
    }

    EC Remote2Local(std::string src, std::string dst)
    {
        std::lock_guard<std::recursive_mutex> lock(src_client->amsession->r_mtx);
        TransferErrorCode rc_r = EC::Success;
        LIBSSH2_SFTP_HANDLE *sftpFile;
        sftpFile = libssh2_sftp_open(src_client->amsession->sftp, src.c_str(), LIBSSH2_FXF_READ, 0400);
        if (!sftpFile)
        {
            return EC::RemoteFileOpenError;
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(sftpFile, &attrs);
        uint64_t file_size = attrs.filesize;

        mkdirs(dirname(dst));

        FileMapper l_file_m = FileMapper(Wstring(dst), MapType::Write, file_size);
        if (!l_file_m.file_ptr)
        {
            libssh2_sftp_close_handle(sftpFile);
            return EC::LocalFileMapError;
        }

        double speed = 32 * AMGB;
        uint64_t buffer_size = calculate_buffer_size(l_file_m.file_size, speed);
        uint64_t offset = 0;

        uint64_t chunk_size = 0;
        uint64_t speed_interval_cout = 0;
        double time_start = std::chrono::duration<double>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
        double time_end = std::chrono::duration<double>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();
        double interval_time = 0.001;
        while (offset < file_size)
        {
            if (speed_interval_cout % adjust_interval == 0)
            {
                time_start = std::chrono::duration<double>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            }

            chunk_size = std::min<uint64_t>(buffer_size, file_size - offset);
            long rc = libssh2_sftp_read(sftpFile, l_file_m.file_ptr + offset, chunk_size);
            if (is_terminate.load())
            {
                rc_r = EC::Terminate;
                goto clean;
            }
            while (is_pause.load() && !is_terminate.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            if (rc > 0)
            {
                offset += rc;
                current_size += rc;
                time_end = std::chrono::duration<double>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();

                if (speed_interval_cout % adjust_interval == 0)
                {
                    speed = static_cast<double>(rc) / (time_end - time_start > 0 ? time_end - time_start : 1E-7);
                    buffer_size = calculate_buffer_size(file_size - offset, speed);
                }

                if (callback.need_progress_cb && (time_end - cb_time > callback.cb_interval_s))
                {
                    cb_time = time_end;
                    current_size += chunk_size;
                    {
                        py::gil_scoped_acquire acquire;
                        callback.progress_cb(current_size, callback.total_bytes);
                    }
                }
                speed_interval_cout++;
            }
            else if (rc == 0)
            {
                break;
            }
            else
            {
                rc_r = src_client->get_sftp_last_error();
                goto clean;
            }
        }

    clean:
        if (sftpFile)
        {
            libssh2_sftp_close_handle(sftpFile);
        }
        return rc_r;
    }

    EC Remote2Remote(std::string src, std::string dst)
    {
        std::lock_guard<std::recursive_mutex> lock_src(src_client->amsession->r_mtx);
        std::lock_guard<std::recursive_mutex> lock_dst(dst_client->amsession->r_mtx);
        TransferErrorCode rc_final = EC::Success;
        long rct;
        LIBSSH2_SFTP_HANDLE *srcFile;
        LIBSSH2_SFTP_HANDLE *dstFile;
        char *buffer = nullptr;
        srcFile = libssh2_sftp_open(src_client->amsession->sftp, src.c_str(), LIBSSH2_FXF_READ, 0400);

        dstFile = libssh2_sftp_open(dst_client->amsession->sftp, dst.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);

        if (!srcFile)
        {
            return src_client->get_sftp_last_error();
        }
        if (!dstFile)
        {
            rct = libssh2_sftp_last_error(dst_client->amsession->sftp);
            if (rct == LIBSSH2_FX_NO_SUCH_FILE)
            {
                libssh2_sftp_mkdir(dst_client->amsession->sftp, dirname(dst).c_str(), 0744);
                dstFile = libssh2_sftp_open(dst_client->amsession->sftp, dst.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);
                if (!dstFile)
                {
                    return EC::RemoteFileOpenError;
                }
            }
            else
            {
                return EC::RemoteFileOpenError;
            }
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(srcFile, &attrs);
        uint64_t file_size = attrs.filesize;

        double speed = 32 * AMGB;
        double speed_ori = 64 * AMMB;

        uint64_t buffer_size_ori = calculate_buffer_size(file_size, speed);
        uint64_t buffer_size = buffer_size_ori;
        buffer = new char[buffer_size_ori];
        uint64_t write_buffer = 0;
        uint64_t offset = 0;

        long rc_read = 0;
        long rc_write = 0;

        double time_start = std::chrono::duration<double>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
        double time_middle = time_start;
        double time_end = std::chrono::duration<double>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();
        double interval_time = 0;

        uint64_t count = 0;
        uint64_t local_write = 0;
        uint64_t local_read = 0;
        uint64_t chunk_size = 0;

        while (offset < file_size)
        {
            if (count % adjust_interval == 0)
            {
                time_start = std::chrono::duration<double>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            }
            chunk_size = std::min<uint64_t>(AMMB, file_size - offset);
            local_read = 0;
            local_write = 0;

            while (local_read < chunk_size)
            {
                rc_read = libssh2_sftp_read(srcFile, buffer + local_read, chunk_size - local_read);
                if (rc_read > 0)
                {
                    local_read += rc_read;
                }
                else if (rc_read == 0)
                {
                    break;
                }
                else
                {
                    rc_final = cast_libssh2_error(libssh2_sftp_last_error(src_client->amsession->sftp));
                    goto clean;
                }
            }

            if (is_terminate.load())
            {
                rc_final = EC::Terminate;
                goto clean;
            }

            while (is_pause.load() && !is_terminate.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }

            if (count % adjust_interval == 0)
            {
                time_middle = std::chrono::duration<double>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count();
            }

            while (local_write < chunk_size)
            {
                rc_write = libssh2_sftp_write(dstFile, buffer + local_write, chunk_size - local_write);
                if (rc_write > 0)
                {
                    local_write += rc_write;
                }
                else if (rc_write == 0)
                {
                    break;
                }
                else
                {
                    rc_final = cast_libssh2_error(libssh2_sftp_last_error(dst_client->amsession->sftp));
                    goto clean;
                }
            }

            offset += chunk_size;
            current_size += chunk_size;
            time_end = std::chrono::duration<double>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
            if (count % adjust_interval == 0)
            {
                interval_time = std::max<double>(time_end - time_middle, time_middle - time_start);
                speed = (chunk_size / (interval_time > 0 ? interval_time : 1E-7) / AMMB) * 0.7 + speed_ori * 0.3;
                speed_ori = speed;
                buffer_size = calculate_buffer_size(file_size - offset, speed);
                buffer_size = buffer_size > buffer_size_ori ? buffer_size_ori : buffer_size;
            }
            count++;

            if (callback.need_progress_cb && (time_end - cb_time > callback.cb_interval_s))
            {
                cb_time = time_end;
                current_size += rc_write;
                {
                    py::gil_scoped_acquire acquire;
                    callback.progress_cb(current_size, callback.total_bytes);
                }
            }
        }
    clean:
        if (srcFile)
        {
            libssh2_sftp_close_handle(srcFile);
        }
        if (dstFile)
        {
            libssh2_sftp_close_handle(dstFile);
        }
        if (buffer)
        {
            delete[] buffer;
        }
        return rc_final;
    }

public:
    BufferSet buffer_set = BufferSet();
    uint64_t adjust_interval = 10;

    ~AMSFTPWorker()
    {
    }

    AMSFTPWorker(std::vector<std::string> private_keys, ConRequst request, uint64_t error_info_buffer_size = 16)
        : AMSFTPClient(request, private_keys, error_info_buffer_size)
    {
    }

    void terminate()
    {
        is_terminate = true;
    }

    void pause()
    {
        is_pause = true;
    }

    void resume()
    {
        is_pause = false;
    }

    EC uploads(TASKS tasks)
    {
        return _transfer_file(tasks);
    }
    EC downloads(TASKS tasks)
    {
        return _transfer_file(tasks);
    }

    EC _transfer_file(std::string src, std::string dst)
    {
    }

    TRM transfer(TASKS tasks)
    {
        EC rc = check_client();
        TRM result = {};
        total_size = std::accumulate(tasks.begin(), tasks.end(), 0, [](uint64_t sum, const TransferTask &task)
                                     { return sum + task.size; });
        if (rc != EC::Success)
        {
            result[""] = rc;
            return result;
        }

        if (!src_client && dst_client)
        {

            for (auto &task : tasks)
            {
                current_filename = task.src;
                if (callback.need_filename_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.filename_cb(current_filename);
                }
                EC our_i = Local2Remote(task.src, task.dst);
                result[task.dst] = our_i;
                if (our_i != EC::Success && callback.need_error_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.error_cb(current_filename, our_i);
                }
            }
        }
        else if (src_client && !dst_client)
        {
            for (auto &task : tasks)
            {
                current_filename = task.src;
                if (callback.need_filename_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.filename_cb(current_filename);
                }
                EC our_i = Remote2Local(task.src, task.dst);
                result[task.dst] = our_i;
                if (our_i != EC::Success && callback.need_error_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.error_cb(current_filename, our_i);
                }
            }
        }
        else if (src_client && dst_client)
        {
            for (auto &task : tasks)
            {
                current_filename = task.src;
                if (callback.need_filename_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.filename_cb(current_filename);
                }
                EC our_i = Remote2Remote(task.src, task.dst);
                result[task.dst] = our_i;
                if (our_i != EC::Success && callback.need_error_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.error_cb(current_filename, our_i);
                }
            }
        }

        return result;
    }

    void set_buffersize(BufferSet buffer_set)
    {
        std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
        this->buffer_set = buffer_set;
    }

    void set_callback(TransferCallback callback)
    {
        std::lock_guard<std::recursive_mutex> lock(amsession->r_mtx);
        this->callback = callback;
    }
};

PYBIND11_MODULE(AMSFTP, m)
{
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
        .value("DirAlreadyExists", TransferErrorCode::DirAlreadyExists);

    py::enum_<TarSystemType>(m, "TarSystemType")
        .value("Unix", TarSystemType::Unix)
        .value("Windows", TarSystemType::Windows);

    py::enum_<PathType>(m, "PathType")
        .value("DIR", PathType::DIR)
        .value("FILE", PathType::FILE)
        .value("SYMLINK", PathType::SYMLINK);

    py::class_<ConRequst>(m, "ConRequst")
        .def(py::init<std::string, std::string, std::string, int, bool, size_t, std::string>(), py::arg("hostname"), py::arg("username"), py::arg("password"), py::arg("port"), py::arg("compression"), py::arg("timeout_s") = 3, py::arg("trash_dir") = "")
        .def_readwrite("hostname", &ConRequst::hostname)
        .def_readwrite("username", &ConRequst::username)
        .def_readwrite("password", &ConRequst::password)
        .def_readwrite("port", &ConRequst::port)
        .def_readwrite("compression", &ConRequst::compression)
        .def_readwrite("timeout_s", &ConRequst::timeout_s)
        .def_readwrite("trash_dir", &ConRequst::trash_dir);

    py::class_<TransferCallback>(m, "TransferCallback")
        .def(py::init<py::function, py::function, py::function, float, uint64_t, bool, bool, bool>(), py::arg("error_cb"), py::arg("progress_cb"), py::arg("filename_cb"), py::arg("cb_interval_s"), py::arg("total_bytes"), py::arg("need_error_cb"), py::arg("need_progress_cb"), py::arg("need_filename_cb"))
        .def_readwrite("error_cb", &TransferCallback::error_cb)
        .def_readwrite("progress_cb", &TransferCallback::progress_cb)
        .def_readwrite("filename_cb", &TransferCallback::filename_cb)
        .def_readwrite("cb_interval_s", &TransferCallback::cb_interval_s)
        .def_readwrite("total_bytes", &TransferCallback::total_bytes)
        .def_readwrite("need_error_cb", &TransferCallback::need_error_cb)
        .def_readwrite("need_progress_cb", &TransferCallback::need_progress_cb)
        .def_readwrite("need_filename_cb", &TransferCallback::need_filename_cb);

    py::class_<TransferTask>(m, "TransferTask")
        .def(py::init<std::string, std::string>(), py::arg("src"), py::arg("dst"))
        .def_readwrite("src", &TransferTask::src)
        .def_readwrite("dst", &TransferTask::dst);

    py::class_<PathInfo>(m, "PathInfo")
        .def(py::init<std::string, std::string, std::string, uint64_t, uint64_t, uint64_t, PathType>(), py::arg("name"), py::arg("path"), py::arg("dir"), py::arg("size"), py::arg("atime"), py::arg("mtime"), py::arg("path_type"))
        .def_readwrite("name", &PathInfo::name)
        .def_readwrite("path", &PathInfo::path)
        .def_readwrite("dir", &PathInfo::dir)
        .def_readwrite("size", &PathInfo::size)
        .def_readwrite("atime", &PathInfo::atime)
        .def_readwrite("mtime", &PathInfo::mtime)
        .def_readwrite("path_type", &PathInfo::path_type);

    py::class_<BufferSizePair>(m, "BufferSizePair")
        .def(py::init<uint64_t, uint64_t>(), py::arg("threshold"), py::arg("buffer"))
        .def_readwrite("threshold", &BufferSizePair::threshold)
        .def_readwrite("buffer", &BufferSizePair::buffer);

    py::class_<BufferSet>(m, "BufferSet")
        .def(py::init<std::vector<BufferSizePair>, uint64_t>(), py::arg("buffer_sizes"), py::arg("min_buffer_size"));

    py::class_<AMSFTPWorker>(m, "AMSFTPWorker")
        .def(py::init<uint64_t, std::vector<std::string>, TransferCallback, TASKS, ConRequst, ConRequst>(), py::arg("ID"), py::arg("private_keys"), py::arg("callback"), py::arg("tasks"), py::arg("src_request") = ConRequst(), py::arg("dst_request") = ConRequst())
        .def("set_buffersize", &AMSFTPWorker::set_buffersize, py::arg("buffer_set"))
        .def("terminate", &AMSFTPWorker::terminate)
        .def("pause", &AMSFTPWorker::pause)
        .def("resume", &AMSFTPWorker::resume)
        .def("GetID", &AMSFTPWorker::GetID);

    py::class_<ErrorInfo>(m, "ErrorInfo")
        .def(py::init<TransferErrorCode, std::string, std::string, std::string, std::string>(), py::arg("error_code"), py::arg("src"), py::arg("dst"), py::arg("function_name"), py::arg("msg"))
        .def_readwrite("error_code", &ErrorInfo::error_code)
        .def_readwrite("src", &ErrorInfo::src)
        .def_readwrite("dst", &ErrorInfo::dst)
        .def_readwrite("function_name", &ErrorInfo::function_name)
        .def_readwrite("msg", &ErrorInfo::msg);

    py::class_<AMSFTPClient>(m, "AMSFTPClient")
        .def(py::init<ConRequst, std::vector<std::string>>(), py::arg("request"), py::arg("private_keys"))
        .def("check", &AMSFTPClient::check)
        .def("reconnect", &AMSFTPClient::reconnect)
        .def("ensure", &AMSFTPClient::ensure)
        .def("ensure_trash_dir", &AMSFTPClient::ensure_trash_dir)
        .def("init", &AMSFTPClient::init)
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
        .def("get_trash_dir", &AMSFTPClient::get_trash_dir);
}
