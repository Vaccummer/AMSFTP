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

namespace py = pybind11;
namespace fs = std::filesystem;
template <typename... Args>
using f_ptr = std::shared_ptr<py::function>;

constexpr uint64_t AMKB = 1024 * 1024;
constexpr uint64_t AMMB = 1024 * 1024 * 1024;
constexpr uint64_t AMGB = 1024 * 1024 * 1024 * 1024;

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

template <typename... Args>
std::string join_path(Args &&...args)
{
    namespace fs = std::filesystem;

    std::vector<std::string> segments;
    auto process_arg = [&](auto &&arg)
    {
        std::string s = std::forward<decltype(arg)>(arg);
        if (s.empty())
            return;

        size_t pos = 0;
        while (pos < s.size())
        {
            size_t next = s.find_first_of("/\\", pos);
            if (next == std::string::npos)
                next = s.size();

            std::string segment = s.substr(pos, next - pos);
            if (!segment.empty())
            {
                segments.push_back(std::move(segment));
            }
            pos = next + 1;
        }
    };

    (process_arg(std::forward<Args>(args)), ...);

    if (segments.empty())
        return "";

    fs::path combined;
    for (auto &seg : segments)
    {
        combined /= seg;
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
    DirAlreadyExists = -82
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

enum class TransferType
{
    RemoteToLocal = -1,
    LocalToRemote = 1,
    RemoteToRemote = 0,
};

enum class MapType
{
    Read = 0,
    Write = 1,
};

struct ConRequst
{
    std::string hostname;
    std::string username;
    std::string password;
    TarSystemType tar_system;
    bool compression;
    int port;
    std::string trash_dir;
    ConRequst()
        : hostname(""), username(""), password(""), port(22), tar_system(TarSystemType::Unix), compression(false), trash_dir("") {}
    ConRequst(std::string hostname, std::string username, std::string password, int port, TarSystemType tar_system, bool compression, std::string trash_dir)
        : hostname(hostname), username(username), password(password), port(port), tar_system(tar_system), compression(compression) {}
};

struct TransferSet
{
    TransferType transfer_type;
    bool force_write;
    TransferSet()
        : transfer_type(TransferType::LocalToRemote), force_write(false) {}
    TransferSet(TransferType transfer_type, bool force_write)
        : transfer_type(transfer_type), force_write(force_write) {}
};

struct TransferCallback
{
    int trace_level;
    int cb_interval_ms;
    uint64_t total_bytes;
    bool need_error_cb;
    bool need_progress_cb;
    bool need_filename_cb;
    py::function progress_cb;
    py::function filename_cb;
    py::function error_cb;
    TransferCallback()
        : trace_level(0), progress_cb(py::function()), filename_cb(py::function()), error_cb(py::function()), cb_interval_ms(10000), total_bytes(1000), need_progress_cb(false), need_filename_cb(false), need_error_cb(false) {}
    TransferCallback(py::function error_cb, py::function progress_cb, py::function filename_cb, int cb_interval_ms, uint64_t total_bytes, bool need_error_cb, bool need_progress_cb, bool need_filename_cb)
        : trace_level(0), progress_cb(progress_cb), filename_cb(filename_cb), error_cb(error_cb), cb_interval_ms(cb_interval_ms), total_bytes(total_bytes), need_progress_cb(need_progress_cb), need_filename_cb(need_filename_cb), need_error_cb(need_error_cb) {}
};

struct TransferTask
{
    std::string src;
    std::string dst;
    PathType path_type;
    uint64_t size;
    TransferTask(std::string &src, std::string &dst, PathType path_type, uint64_t size)
        : src(src), dst(dst), path_type(path_type), size(size) {}
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
        : name(name), path(path), size(size), atime(atime), mtime(mtime), path_type(path_type) {}
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
    BufferSet()
        : buffer_sizes({BufferSizePair{16 * AMGB, 16 * AMMB},
                        BufferSizePair{4 * AMGB, 8 * AMMB},
                        BufferSizePair{AMGB, 4 * AMMB},
                        BufferSizePair{512 * AMMB, AMMB},
                        BufferSizePair{50 * AMMB, 256 * AMKB},
                        BufferSizePair{10 * AMMB, 128 * AMKB},
                        BufferSizePair{0, 64 * AMKB}}) {}
    BufferSet(std::vector<BufferSizePair> buffer_sizes, uint64_t min_buffer_size = 64 * AMKB)
    {
        this->buffer_sizes = buffer_sizes;
        std::sort(this->buffer_sizes.begin(), this->buffer_sizes.end(), [](BufferSizePair a, BufferSizePair b)
                  { return a.threshold > b.threshold; });
        this->buffer_sizes.push_back(BufferSizePair{0, min_buffer_size});
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
    FileMapper(std::wstring &file_path, MapType map_type, bool force_write = false, uint64_t file_size = 0)
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
        if (force_write)
        {
            this->hFile = CreateFileW(file_path.c_str(), GENERIC_WRITE | GENERIC_READ, 0, NULL,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        }
        else
        {
            if (GetFileAttributesW(file_path.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                this->hFile = CreateFileW(file_path.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            }
            else
            {
                this->hFile = nullptr;
            }
        }
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

using result_map = std::unordered_map<std::string, TransferErrorCode>;
using TASKS = std::vector<TransferTask>;
using int_ptr = std::shared_ptr<uint64_t>;
using safe_int_ptr = std::shared_ptr<std::atomic<uint64_t>>;
using EC = TransferErrorCode;
using TRM = std::unordered_map<std::string, TransferErrorCode>;
using TR = std::variant<TRM, EC>;
using SR = std::variant<PathInfo, EC>;
using LR = std::variant<std::vector<PathInfo>, EC>;

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
    }
}

class AMSession
{
public:
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp;
    std::vector<std::string> private_keys;
    ConRequst request;
    SOCKET sock = INVALID_SOCKET;
    TarSystemType tar_system;
    EC init()
    {
        WSADATA wsaData;

        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            return TransferErrorCode::NetworkError;
        }

        tar_system = request.tar_system;
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(request.port);
        inet_pton(AF_INET, request.hostname.c_str(), &sin.sin_addr);
        connect(sock, (sockaddr *)&sin, sizeof(sin));
        session = libssh2_session_init();

        if (!session)
        {
            return TransferErrorCode::SessionCreateError;
        }

        if (request.compression)
        {
            libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
            libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS, "zlib@openssh.com,zlib,none");
        }

        int rc_handshake = libssh2_session_handshake(session, sock);

        if (rc_handshake != 0)
        {
            return TransferErrorCode::SessionEstablishError;
        }
        TransferErrorCode rc = TransferErrorCode::ConnectionAuthorizeError;
        int rca = 0;
        if (!request.password.empty())
        {
            rca = libssh2_userauth_password(session, request.username.c_str(), request.password.c_str());
            if (rca == 0)
            {
                rc = TransferErrorCode::Success;
                goto OK;
            }
        }
        for (auto &private_key : private_keys)
        {
            rca = libssh2_userauth_publickey_fromfile(session, request.username.c_str(), nullptr, private_key.c_str(), nullptr);
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
        sftp = libssh2_sftp_init(session);
        if (!sftp)
        {
            return TransferErrorCode::SftpCreateError;
        }

        LIBSSH2_CHANNEL *channel = libssh2_channel_open_ex(session,
                                                           "session",
                                                           sizeof("session") - 1,
                                                           2 * AMMB,
                                                           512 * AMKB,
                                                           nullptr,
                                                           0);

        if (!channel)
        {
            return TransferErrorCode::ChannelCreateError;
        }

        return rc;
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
        int rct;
        if (tar_system == TarSystemType::Windows)
        {
            rct = libssh2_sftp_stat(sftp, ("C:\\Users\\" + request.username).c_str(), &attrs);
        }
        else
        {
            rct = libssh2_sftp_stat(sftp, ("/home/" + request.username).c_str(), &attrs);
        }
        if (rct != 0)
        {
            return cast_libssh2_error(libssh2_session_last_errno(session));
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
        this->tar_system = TarSystemType::Unix;
        this->private_keys = {};
    }

    AMSession(ConRequst &request, std::vector<std::string> &private_keys)
        : request(request), private_keys(private_keys)
    {
    }

    ~AMSession()
    {
        clean();
    }
};

class AMSFTPWorker
{
private:
    TransferSet set;
    TransferCallback callback;
    ConRequst request;
    AMSession *amsession = nullptr;
    TASKS tasks;
    std::atomic<bool> is_terminate = false;
    std::atomic<bool> is_pause = false;
    uint64_t current_size = 0;
    std::string current_filename = "";
    long cb_time = clock();

    uint64_t calculate_buffer_size(uint64_t file_size, uint64_t speed)
    {
        float f_s = static_cast<float>(speed) / 5 + 1;
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
        return buffer_size_out;
    }

    EC Local2Remote(const TransferTask &task)
    {
        TransferErrorCode rc_r = EC::Success;
        LIBSSH2_SFTP_HANDLE *sftpFile;
        if (set.force_write)
        {
            sftpFile = libssh2_sftp_open(amsession->sftp, task.dst.c_str(), LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0740);
        }
        else
        {
            sftpFile = libssh2_sftp_open(amsession->sftp, task.dst.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0740);
        }
        if (!sftpFile)
        {
            return EC::RemoteFileOpenError;
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(sftpFile, &attrs);

        if (attrs.filesize != 0 && !set.force_write)
        {
            libssh2_sftp_close_handle(sftpFile);
            return EC::RemoteFileExists;
        }

        FileMapper l_file_m(Wstring(task.src), MapType::Read);
        if (!l_file_m.file_ptr)
        {
            libssh2_sftp_close_handle(sftpFile);
            return EC::LocalFileMapError;
        }
        uint64_t speed = AMGB * 1024;
        uint64_t buffer_size = calculate_buffer_size(l_file_m.file_size, speed);
        uint64_t offset = 0;
        uint64_t remaining = l_file_m.file_size;
        long time_start = 0;
        long time_end = 100;
        uint64_t chunk_size = std::min<uint64_t>(buffer_size, remaining);
        uint64_t speed_interval_cout = 0;
        while (remaining > 0)
        {
            if (speed_interval_cout % adjust_interval == 0)
            {
                time_start = clock();
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
                time_end = clock();
                if (callback.need_progress_cb && ((time_end - cb_time) > callback.cb_interval_ms))
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
                    speed = (chunk_size * CLOCKS_PER_SEC) / (time_end - time_start > 0 ? time_end - time_start : 1);
                    buffer_size = calculate_buffer_size(remaining, speed);
                }
                speed_interval_cout++;
            }
            else if (rc == 0)
            {
                std::cout << "rc == 0" << std::endl;
                break;
            }
            else
            {
                rc_r = cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
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

    EC Remote2Local(const TransferTask &task)
    {
        TransferErrorCode rc_r = EC::Success;
        LIBSSH2_SFTP_HANDLE *sftpFile;
        sftpFile = libssh2_sftp_open(amsession->sftp, task.src.c_str(), LIBSSH2_FXF_READ, 0400);
        if (!sftpFile)
        {
            return EC::RemoteFileOpenError;
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(sftpFile, &attrs);
        uint64_t file_size = attrs.filesize;

        if ((!set.force_write) && GetFileAttributesW(Wstring(task.dst).c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            libssh2_sftp_close_handle(sftpFile);
            return EC::LocalFileExists;
        }

        FileMapper l_file_m = FileMapper(Wstring(task.dst), MapType::Write, set.force_write, file_size);
        if (!l_file_m.file_ptr)
        {
            libssh2_sftp_close_handle(sftpFile);
            return EC::LocalFileMapError;
        }

        uint64_t speed = 9999999999;
        uint64_t buffer_size = calculate_buffer_size(l_file_m.file_size, speed);
        uint64_t offset = 0;

        uint64_t chunk_size = 0;
        uint64_t speed_interval_cout = 0;
        long time_start = 0;
        long time_end = 10;
        while (offset < file_size)
        {
            if (speed_interval_cout % adjust_interval == 0)
            {
                long time_start = clock();
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
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
            if (rc > 0)
            {
                offset += rc;
                current_size += rc;
                if (speed_interval_cout % adjust_interval == 0)
                {
                    long time_end = clock();
                    if (callback.need_progress_cb && (time_end - cb_time > callback.cb_interval_ms))
                    {
                        cb_time = time_end;
                        current_size += chunk_size;
                        {
                            py::gil_scoped_acquire acquire;
                            (*callback.progress_cb)(current_size, callback.total_bytes);
                        }
                    }
                    speed = (chunk_size * CLOCKS_PER_SEC) / (time_end - time_start);
                    buffer_size = calculate_buffer_size(file_size - offset, speed);
                }
                speed_interval_cout++;
            }
            else if (rc == 0)
            {
                break;
            }
            else
            {
                rc_r = cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
                goto clean;
            }
        }
    clean:
        if (sftpFile)
        {
            libssh2_sftp_close_handle(sftpFile);
        }
        if (rc_r != EC::Success && callback.need_error_cb)
        {
            py::gil_scoped_acquire acquire;
            (*callback.error_cb)(current_filename, rc_r);
        }
        return rc_r;
    }

    EC Remote2Remote(const TransferTask &task)
    {
        TransferErrorCode rc_final = EC::Success;
        LIBSSH2_SFTP_HANDLE *srcFile;
        LIBSSH2_SFTP_HANDLE *dstFile;
        srcFile = libssh2_sftp_open(amsession->sftp, task.src.c_str(), LIBSSH2_FXF_READ, 0400);
        if (set.force_write)
        {
            dstFile = libssh2_sftp_open(amsession->sftp, task.dst.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0740);
        }
        else
        {
            dstFile = libssh2_sftp_open(amsession->sftp, task.dst.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0740);
            LIBSSH2_SFTP_ATTRIBUTES attrd;
            if (!dstFile)
            {
                libssh2_sftp_close_handle(srcFile);
                return EC::RemoteFileOpenError;
            }
            libssh2_sftp_fstat(dstFile, &attrd);
            uint64_t file_size = attrd.filesize;
            if (file_size != 0)
            {
                libssh2_sftp_close_handle(dstFile);
                libssh2_sftp_close_handle(srcFile);
                return EC::RemoteFileExists;
            }
        }
        if (!srcFile || !dstFile)
        {
            rc_final = EC::RemoteFileOpenError;
            goto clean;
        }

        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(srcFile, &attrs);
        uint64_t file_size = attrs.filesize;

        uint64_t buffer_size = calculate_buffer_size(file_size, 9999999999);
        char *buffer = new char[buffer_size];
        uint64_t write_buffer = 0;
        uint64_t offset = 0;

        long rc_read = 0;
        long rc_write = 0;
        long time_end = clock();

        while (offset < file_size)
        {
            uint64_t chunk_size = std::min<uint64_t>(buffer_size, file_size - offset);
            libssh2_sftp_seek64(srcFile, offset);
            rc_read = libssh2_sftp_read(srcFile, buffer, chunk_size);
            if (is_terminate.load())
            {
                rc_final = EC::Terminate;
                goto clean;
            }
            while (is_pause.load() && !is_terminate.load())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }

            if (rc_read > 0)
            {
                libssh2_sftp_seek64(dstFile, offset);
                rc_write = libssh2_sftp_write(dstFile, buffer, rc_read);
                if (rc_write > 0)
                {
                    offset += rc_write;
                    current_size += rc_write;
                    time_end = clock();
                    if (callback.need_progress_cb && (time_end - cb_time > callback.cb_interval_ms))
                    {
                        cb_time = time_end;
                        current_size += rc_write;
                        {
                            py::gil_scoped_acquire acquire;
                            (*callback.progress_cb)(current_size, callback.total_bytes);
                        }
                    }
                }
                else
                {
                    rc_final = EC::RemoteFileWriteError;
                    goto clean;
                }
            }
            else if (rc_read == 0)
            {
                break;
            }
            else
            {
                rc_final = cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
                goto clean;
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
            free(buffer);
        }
        return rc_final;
    }

public:
    uint64_t ID;
    BufferSet buffer_set = BufferSet();
    uint64_t adjust_interval = 10;

    ~AMSFTPWorker()
    {
    }

    AMSFTPWorker(uint64_t ID, std::vector<std::string> private_keys, ConRequst request, TransferSet set, TransferCallback callback, TASKS tasks)
        : ID(ID), request(request), set(set), callback(callback), tasks(tasks)
    {
        this->amsession = new AMSession(request, private_keys);
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

    TR start()
    {
        EC init_code = amsession->init();

        if (init_code != EC::Success)
        {
            return init_code;
        }

        if (callback.trace_level > 0)
        {
            libssh2_trace(amsession->session, LIBSSH2_TRACE_ERROR);
        }
        std::unordered_map<std::string, TransferErrorCode> result;

        switch (set.transfer_type)
        {
        case TransferType::LocalToRemote:
            for (auto &task : tasks)
            {
                current_filename = task.src;
                if (callback.need_filename_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.filename_cb(current_filename);
                }
                EC our_i = Local2Remote(task);
                result[task.dst] = our_i;
                if (our_i != EC::Success && callback.need_error_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.error_cb(current_filename, our_i);
                }
            }
            break;
        case TransferType::RemoteToLocal:
            for (auto &task : tasks)
            {
                current_filename = task.src;
                if (callback.need_filename_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.filename_cb(current_filename);
                }
                EC our_i = Remote2Local(task);
                result[task.dst] = our_i;
                if (our_i != EC::Success && callback.need_error_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.error_cb(current_filename, our_i);
                }
            }
            break;
        case TransferType::RemoteToRemote:
            for (auto &task : tasks)
            {
                current_filename = task.src;
                if (callback.need_filename_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.filename_cb(current_filename);
                }
                EC our_i = Remote2Remote(task);
                result[task.dst] = our_i;
                if (our_i != EC::Success && callback.need_error_cb)
                {
                    py::gil_scoped_acquire acquire;
                    callback.error_cb(current_filename, our_i);
                }
            }
            break;
        }
        delete amsession;
        return result;
    }

    void set_buffersize(BufferSet buffer_set)
    {
        this->buffer_set = buffer_set;
    }
};

class AMSFTPClient
{
private:
    ConRequst request;
    std::vector<std::string> private_keys;
    AMSession *amsession;
    std::string trash_dir = "";
    LIBSSH2_CHANNEL *channel = nullptr;

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

public:
    ~AMSFTPClient()
    {
        delete amsession;
        amsession = nullptr;
        if (channel)
        {
            libssh2_channel_close(channel);
            libssh2_channel_free(channel);
            channel = nullptr;
        }
    }

    AMSFTPClient(ConRequst request, std::vector<std::string> private_keys)
        : request(request), private_keys(private_keys)
    {
        this->amsession = new AMSession(request, private_keys);
    }

    EC check()
    {
        if (!amsession)
        {
            return EC::SessionBroken;
        }
        return amsession->check();
    }

    EC reconnect()
    {
        delete amsession;
        amsession = new AMSession(request, private_keys);
        channel = libssh2_channel_open_session(amsession->session);
        return amsession->init();
    }

    EC ensure()
    {
        EC rc = check();
        if (rc != EC::Success)
        {
            return reconnect();
        }
        return EC::Success;
    }

    EC ensure_trash_dir()
    {
        SR info = stat(trash_dir);
        if (std::holds_alternative<EC>(info))
        {
            return std::get<EC>(info);
        }
        if (!std::holds_alternative<PathInfo>(info))
        {
            return EC::UnknownError;
        }
        if (std::get<PathInfo>(info).path_type == PathType::DIR)
        {
            return EC::Success;
        }
        EC rc = mkdirs(trash_dir);
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
            return rc;
        }
        rc = check();
        if (rc != EC::Success)
        {
            return rc;
        }
        trash_dir = request.trash_dir;
        channel = libssh2_channel_open_session(amsession->session);
        return rc;
    }

    SR stat(std::string path)
    {
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        EC rc;
        int rct = libssh2_sftp_stat(amsession->sftp, path.c_str(), &attrs);
        if (rct != 0)
        {
            return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
        }
        return format_stat(path, attrs);
    }

    EC exists(std::string path)
    {
        SR info = stat(path);
        if (std::holds_alternative<EC>(info))
        {
            return std::get<EC>(info);
        }
        if (std::holds_alternative<PathInfo>(info))
        {
            return EC::PassCheck;
        }
        return EC::FailedCheck;
    }

    EC is_file(std::string path)
    {
        SR info = stat(path);
        if (std::holds_alternative<EC>(info))
        {
            return std::get<EC>(info);
        }
        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).path_type == PathType::FILE ? EC::PassCheck : EC::FailedCheck;
        }
        return EC::UnknownError;
    }

    EC is_dir(std::string path)
    {
        SR info = stat(path);
        if (std::holds_alternative<EC>(info))
        {
            return std::get<EC>(info);
        }
        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).path_type == PathType::DIR ? EC::PassCheck : EC::FailedCheck;
        }
        return EC::UnknownError;
    }

    EC is_symlink(std::string path)
    {
        SR info = stat(path);
        if (std::holds_alternative<EC>(info))
        {
            return std::get<EC>(info);
        }
        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).path_type == PathType::SYMLINK ? EC::PassCheck : EC::FailedCheck;
        }
        return EC::UnknownError;
    }

    LR listdir(std::string path)
    {
        std::vector<PathInfo> file_list = {};
        EC rc = is_dir(path);

        switch (rc)
        {
        case EC::PassCheck:
            break;
        case EC::FailedCheck:
            return EC::NotDirectory;
        default:
            return rc;
        }

        // Ensure path ends with appropriate separator for the target system

        std::string normalized_path = path;

        LIBSSH2_SFTP_HANDLE *sftp_handle = libssh2_sftp_open_ex(
            amsession->sftp,
            normalized_path.c_str(),
            normalized_path.size(),
            0,
            LIBSSH2_SFTP_OPENDIR,
            LIBSSH2_FXF_READ);

        if (!sftp_handle)
        {
            return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
        }

        LIBSSH2_SFTP_ATTRIBUTES attrs;
        std::string name;
        std::string path_i;

        // Use a reasonably sized buffer for filenames
        const size_t buffer_size = 4096;
        std::vector<char> filename_buffer(buffer_size);

        // Read directory entries
        while (true)
        {
            int rc = libssh2_sftp_readdir_ex(
                sftp_handle,
                filename_buffer.data(),
                buffer_size,
                nullptr, 0,
                &attrs);

            if (rc < 0)
            {
                // Check if there was an error or just end of directory
                libssh2_sftp_close_handle(sftp_handle);
                return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
            }
            else if (rc == 0)
            {
                break;
            }

            // Process the entry
            name.assign(filename_buffer.data(), rc);

            // Skip "." and ".." entries
            if (name == "." || name == "..")
            {
                continue;
            }

            // Construct the full path based on target system
            path_i = join_path(normalized_path, name);

            // Create PathInfo object and add to list
            PathInfo info = format_stat(path_i, attrs);
            file_list.push_back(info);
        }

        libssh2_sftp_close_handle(sftp_handle);
        return file_list;
    }

    EC mkdir(std::string path)
    {
        EC rc = is_dir(path);

        switch (rc)
        {
        case EC::PassCheck:
            return EC::Success;
        case EC::FailedCheck:
            return EC::RemoteFileExists;
        case EC::PathNotExist:
            break;
        default:
            return rc;
        }

        int rcr = libssh2_sftp_mkdir_ex(amsession->sftp, path.c_str(), path.size(), 0740);
        if (rcr != 0)
        {
            return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
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
        EC rc = is_file(path);
        switch (rc)
        {
        case EC::PassCheck:
            break;
        case EC::FailedCheck:
            return EC::TargetNotAFile;
        default:
            return rc;
        }
        int rcr = libssh2_sftp_unlink(amsession->sftp, path.c_str());
        if (rcr != 0)
        {
            return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
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
            return rc;
        }
        int rcr = libssh2_sftp_rmdir(amsession->sftp, path.c_str());
        if (rcr != 0)
        {
            return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
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
            return rc;
        }
        rc = is_dir(trash_dir);
        if (rc != EC::PassCheck)
        {
            rc = mkdirs(trash_dir);
            if (rc != EC::Success)
            {
                return rc;
            }
        }
        std::string base = basename(path);
        std::string target_path;
        target_path = join_path(trash_dir, base);
        int i = 0;
        while (exists(target_path) == EC::PassCheck)
        {
            target_path = join_path(trash_dir, std::to_string(i) + "_" + base);
            i++;
        }
        int rcr = libssh2_sftp_rename(amsession->sftp, path.c_str(), target_path.c_str());
        if (rcr != 0)
        {
            return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
        }
        return EC::Success;
    }

    EC move(std::string src, std::string dst, bool need_mkdir = false, bool force_write = false)
    {
        EC rc = exists(src);
        if (rc != EC::PassCheck)
        {
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
                mkdirs(dst_dir);
            }
            else
            {
                return EC::ParentDirectoryNotExist;
            }
        }
        if (exists(dst_path) == EC::PassCheck)
        {
            return EC::RemoteFileExists;
        }

        int rcr = libssh2_sftp_rename_ex(amsession->sftp, src.c_str(), src.size(), dst_path.c_str(), dst_path.size(), force_write ? LIBSSH2_SFTP_RENAME_OVERWRITE : 0);

        if (rcr != 0)
        {
            return cast_libssh2_error(libssh2_sftp_last_error(amsession->sftp));
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
            return EC::PathNotExist;
        default:
            return rc;
        }

        rc = is_file(src);
        if (rc == EC::PassCheck)
        {
            return EC::TargetExists;
        }
        rc = is_dir(src);

        if (rc != EC::PassCheck)
        {
            rc = is_dir(dirname(src));
            if (rc != EC::PassCheck)
            {
                return rc;
            }
        }

        std::string command = "cp -r \"" + src + "\" \"" + dst + "\"";

        int rcr = libssh2_channel_exec(channel, command.c_str());

        if (rcr != 0)
        {
            return EC::CopyError;
        }
        int exit_code = libssh2_channel_get_exit_status(channel);
        if (exit_code != 0)
        {
            return EC::CopyError;
        }
        return EC::Success;
    };
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
        .value("NoSFTPConnection", TransferErrorCode::InvalidState)
        .value("SFTPConnectionLost", TransferErrorCode::InvalidArgument)
        .value("SFTPBadMessage", TransferErrorCode::InvalidOperation)
        .value("SFTPLockConflict", TransferErrorCode::InvalidCast)
        .value("SymlinkLoop", TransferErrorCode::InvalidConversion)
        .value("InvalidCast", TransferErrorCode::InvalidCast)
        .value("InvalidConversion", TransferErrorCode::InvalidConversion)

            py::enum_<TarSystemType>(m, "TarSystemType")
        .value("Unix", TarSystemType::Unix)
        .value("Windows", TarSystemType::Windows);

    py::enum_<PathType>(m, "PathType")
        .value("DIR", PathType::DIR)
        .value("FILE", PathType::FILE)
        .value("SYMLINK", PathType::SYMLINK);

    py::enum_<TransferType>(m, "TransferType")
        .value("LocalToRemote", TransferType::LocalToRemote)
        .value("RemoteToLocal", TransferType::RemoteToLocal)
        .value("RemoteToRemote", TransferType::RemoteToRemote);

    py::class_<ConRequst>(m, "ConRequst")
        .def(py::init<std::string, std::string, std::string, int, TarSystemType, bool>(), py::arg("hostname"), py::arg("username"), py::arg("password"), py::arg("port"), py::arg("tar_system"), py::arg("compression"))
        .def_readwrite("hostname", &ConRequst::hostname)
        .def_readwrite("username", &ConRequst::username)
        .def_readwrite("password", &ConRequst::password)
        .def_readwrite("port", &ConRequst::port)
        .def_readwrite("tar_system", &ConRequst::tar_system)
        .def_readwrite("compression", &ConRequst::compression);

    py::class_<TransferSet>(m, "TransferSet")
        .def(py::init<TransferType, bool>(), py::arg("transfer_type"), py::arg("force_write"))
        .def_readwrite("transfer_type", &TransferSet::transfer_type)
        .def_readwrite("force_write", &TransferSet::force_write);

    py::class_<TransferCallback>(m, "TransferCallback")
        .def(py::init<py::function, py::function, py::function, int, uint64_t, bool, bool, bool>(), py::arg("error_cb"), py::arg("progress_cb"), py::arg("filename_cb"), py::arg("cb_interval_ms"), py::arg("total_bytes"), py::arg("need_error_cb"), py::arg("need_progress_cb"), py::arg("need_filename_cb"))
        .def_readwrite("error_cb", &TransferCallback::error_cb)
        .def_readwrite("progress_cb", &TransferCallback::progress_cb)
        .def_readwrite("filename_cb", &TransferCallback::filename_cb)
        .def_readwrite("cb_interval_ms", &TransferCallback::cb_interval_ms)
        .def_readwrite("total_bytes", &TransferCallback::total_bytes);

    py::class_<TransferTask>(m, "TransferTask")
        .def(py::init<std::string, std::string, PathType, uint64_t>(), py::arg("src"), py::arg("dst"), py::arg("path_type"), py::arg("size"))
        .def_readwrite("src", &TransferTask::src)
        .def_readwrite("dst", &TransferTask::dst)
        .def_readwrite("path_type", &TransferTask::path_type)
        .def_readwrite("size", &TransferTask::size);

    py::class_<PathInfo>(m, "PathInfo")
        .def(py::init<std::string, std::string, uint64_t, uint64_t, uint64_t, PathType>(), py::arg("name"), py::arg("path"), py::arg("size"), py::arg("atime"), py::arg("mtime"), py::arg("path_type"))
        .def_readwrite("name", &PathInfo::name)
        .def_readwrite("path", &PathInfo::path)
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
        .def(py::init<uint64_t, std::vector<std::string>, ConRequst, TransferSet, TransferCallback, TASKS>(), py::arg("ID"), py::arg("private_keys"), py::arg("request"), py::arg("set"), py::arg("callback"), py::arg("tasks"))
        .def("set_buffersize", &AMSFTPWorker::set_buffersize, py::arg("buffer_set"))
        .def("terminate", &AMSFTPWorker::terminate)
        .def("pause", &AMSFTPWorker::pause)
        .def("resume", &AMSFTPWorker::resume)
        .def("start", &AMSFTPWorker::start);

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
        .def("listdir", [](AMSFTPClient &self, const std::string &path)
             {
            LR result = self.listdir(path);
            if (std::holds_alternative<std::vector<PathInfo>>(result)) {
                return std::get<std::vector<PathInfo>>(result);
            } else if (std::holds_alternative<EC>(result)) {
                throw py::value_error("Error listing directory: " + 
                    std::to_string(static_cast<int>(std::get<EC>(result))));
            }
            throw py::value_error("Unknown error in listdir"); }, py::arg("path"),
             R"pbdoc(
            List contents of a directory.

            Args:
                path (str): Path to the directory to list

            Returns:
                List[PathInfo]: List of PathInfo objects representing directory contents

            Raises:
                ValueError: If there is an error listing the directory
        )pbdoc")
        .def("mkdir", &AMSFTPClient::mkdir, py::arg("path"))
        .def("mkdirs", &AMSFTPClient::mkdirs, py::arg("path"))
        .def("rmfile", &AMSFTPClient::rmfile, py::arg("path"))
        .def("rmdir", &AMSFTPClient::rmdir, py::arg("path"))
        .def("rm", &AMSFTPClient::rm, py::arg("path"))
        .def("saferm", &AMSFTPClient::saferm, py::arg("path"))
        .def("move", &AMSFTPClient::move, py::arg("src"), py::arg("dst"), py::arg("need_mkdir") = false)
        .def("copy", &AMSFTPClient::copy, py::arg("src"), py::arg("dst"), py::arg("need_mkdir") = false);
}

// int TRIAL_Function()
// {
//     clock_t start_time = clock();
//     std::string host = "192.168.31.46";
//     std::string user = "am";
//     std::string password = "1984";
//     int port = 45;
//     std::string src = "F:\\Windows_Data\\Desktop_File\\voc2007.rar";
//     std::string dst = "d:\\Document\\Desktop\\trial\\voc2007.rar";
//     std::string private_key = "C:\\Users\\am\\.ssh\\id_rsa";
//     TransferSet AMset;
//     TransferCallback AMcallback;
//     TASKS AMtasks;
//     AMtasks.push_back(TransferTask(src, dst, PathType::FILE, 0));
//     ConRequst AMrequest(host, user, password, port, TarSystemType::Unix, true);
//     std::vector<std::string> AMprivate_keys;
//     AMprivate_keys.push_back(private_key);
//     AMSession AMsession(AMrequest, &AMprivate_keys, AMset);
//     AMSFTPWorker AMsfpt(0, AMsession, AMset, AMcallback, AMtasks);
//     AMsfpt.start();
// }