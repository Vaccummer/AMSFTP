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

namespace py = pybind11;
namespace fs = std::filesystem;
using f_ptr = std::shared_ptr<py::function>;

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
    UnknownError = -32,
    DirNotEmpty = -33,
    EmptyDirRemoveError = -34,
    TargetNotADirectory = -35,
    InvalidTrashDir = -36,
    MoveError = -37,
    TargetExists = -38,
    CopyError = -39,
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
    ConRequst()
        : hostname(""), username(""), password(""), port(22), tar_system(TarSystemType::Unix), compression(false) {}
    ConRequst(std::string hostname, std::string username, std::string password, int port, TarSystemType tar_system, bool compression)
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
    uint64_t size = -1;
    uint64_t atime = -1;
    uint64_t mtime = -1;
    PathType path_type = PathType::FILE;
};

struct BufferSizePair
{
    uint64_t threshold;
    uint64_t buffer;
    BufferSizePair(uint64_t threshold, uint64_t buffer)
        : threshold(threshold), buffer(buffer) {}
};

struct BufferSet
{
    std::vector<BufferSizePair> buffer_sizes;
    BufferSet()
        : buffer_sizes({BufferSizePair{16 * 1024 * 1024, 16 * 1024 * 1024 * 1024},
                        BufferSizePair{8 * 1024 * 1024, 4 * 1024 * 1024 * 1024},
                        BufferSizePair{4 * 1024 * 1024, 1024 * 1024 * 1024},
                        BufferSizePair{1024 * 1024, 512 * 1024 * 1024},
                        BufferSizePair{258 * 1024, 50 * 1024 * 1024},
                        BufferSizePair{128 * 1024, 10 * 1024 * 1024},
                        BufferSizePair{64 * 1024, 0}}) {}
    BufferSet(std::vector<uint64_t> buffer_sizes, std::vector<uint64_t> buffer_sizes_limit)
    {
        A_buffer = buffer_sizes[0];
        A_size = buffer_sizes_limit[0];
        B_buffer = buffer_sizes[1];
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
            char *error_msg;
            int error_code = libssh2_session_last_error(session, &error_msg, nullptr, 0);
            std::cerr << "libssh2 Error [" << error_code << "]: " << error_msg << std::endl;
            std::cout << "rc_handshake: " << rc_handshake << std::endl;
            std::cerr << "WinSock Error: " << WSAGetLastError() << std::endl;
            std::cerr << "Socket Errno: " << errno << std::endl;
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
        LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
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
            return EC::SftpBroken;
        }

        if (!session)
        {
            return EC::SessionBroken;
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
            return EC::ConnectionCheckFailed;
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
        uint64_t buffer_size_out = buffer_set.G_buffer;
        if (speed_limit_uint > buffer_set.A_size)
        {
            buffer_size_out = buffer_set.A_buffer;
        }
        else if (file_size > buffer_set.B_size)
        {
            buffer_size_out = buffer_set.B_buffer;
        }
        else if (file_size > buffer_set.C_size)
        {
            buffer_size_out = buffer_set.C_buffer;
        }
        else if (file_size > buffer_set.D_size)
        {
            buffer_size_out = buffer_set.D_buffer;
        }
        else if (file_size > buffer_set.E_size)
        {
            buffer_size_out = buffer_set.E_buffer;
        }
        else if (file_size > buffer_set.F_size)
        {
            buffer_size_out = buffer_set.F_buffer;
        }
        buffer_size_out = buffer_size_out > speed_limit_uint ? speed_limit_uint : buffer_size_out;
        return buffer_size_out;
    }

    EC Local2Remote(const TransferTask &task)
    {
        std::cout << "3" << std::endl;
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
            rc_r = EC::RemoteFileOpenError;
            return rc_r;
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(sftpFile, &attrs);

        if (attrs.filesize != 0 && !set.force_write)
        {
            libssh2_sftp_close_handle(sftpFile);
            rc_r = EC::RemoteFileExists;
            return rc_r;
        }
        std::cout << "4" << std::endl;
        FileMapper l_file_m(Wstring(task.src), MapType::Read);
        if (!l_file_m.file_ptr)
        {
            libssh2_sftp_close_handle(sftpFile);
            rc_r = EC::LocalFileMapError;
            return rc_r;
        }
        std::cout << "5" << std::endl;
        uint64_t speed = 1204 * 1024 * 1024 * 128;
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
                std::cout << "terminate" << std::endl;
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
                std::cout << "RemoteFileWriteError" << std::endl;
                rc_r = EC::RemoteFileWriteError;
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
            rc_r = EC::RemoteFileOpenError;
            return rc_r;
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(sftpFile, &attrs);
        uint64_t file_size = attrs.filesize;

        if ((!set.force_write) && GetFileAttributesW(Wstring(task.dst).c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            libssh2_sftp_close_handle(sftpFile);
            rc_r = EC::LocalFileExists;
            return rc_r;
        }

        FileMapper l_file_m = FileMapper(Wstring(task.dst), MapType::Write, set.force_write, file_size);
        if (!l_file_m.file_ptr)
        {
            libssh2_sftp_close_handle(sftpFile);
            rc_r = EC::LocalFileMapError;
            return rc_r;
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
                rc_r = EC::RemoteFileReadError;
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
                rc_final = EC::RemoteFileReadError;
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
        if (rc_final != EC::Success && callback.need_error_cb)
        {
            py::gil_scoped_acquire acquire;
            (*callback.error_cb)(current_filename, rc_final);
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
};

class AMSFTPClient
{
private:
    ConRequst request;
    std::vector<std::string> private_keys;
    AMSession *amsession;
    std::string trash_dir = "";
    LIBSSH2_CHANNEL *channel = nullptr;
    bool is_trash_dir_exists = false;
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

    PathInfo formatstat(std::string path, LIBSSH2_SFTP_ATTRIBUTES &attrs)
    {
        PathInfo info;
        info.path = path;
        if (path.find('\\') != std::string::npos)
        {
            info.name = path.substr(path.find_last_of('\\') + 1);
        }
        else
        {
            info.name = path.substr(path.find_last_of('/') + 1);
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
            const auto mode = attrs.permissions;
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
            is_trash_dir_exists = true;
            return EC::Success;
        }
        EC rc = mkdirs(trash_dir);
        if (rc != EC::Success)
        {
            return rc;
        }
        is_trash_dir_exists = true;
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
        switch (request.tar_system)
        {
        case TarSystemType::Windows:
            trash_dir = "C:\\Users\\" + request.username + "\\AMSFTP_Trash";
        default:
            trash_dir = "/home/" + request.username + "/.AMSFTP_Trash";
            break;
        }
        channel = libssh2_channel_open_session(amsession->session);
        return rc;
    }

    SR stat(std::string path, bool need_reconnect = false)
    {
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        EC rc;
        int rct = libssh2_sftp_stat(amsession->sftp, path.c_str(), &attrs);
        if (rct != 0)
        {
            unsigned long sftp_error = libssh2_sftp_last_error(amsession->sftp);
            switch (sftp_error)
            {
            case LIBSSH2_FX_NO_SUCH_FILE:
                return EC::PathNotExist;
            case LIBSSH2_FX_PERMISSION_DENIED:
                return EC::PermissionDenied;
            default:
                rc = ensure();
                if (rc != EC::Success)
                {
                    return rc;
                }
                if (need_reconnect)
                {
                    return stat(path, false);
                }
                else
                {
                    return EC::RemoteFileStatError;
                }
            }
        }

        return formatstat(path, attrs);
    }

    EC exists(std::string path)
    {
        SR info = stat(path, true);
        if (std::holds_alternative<EC>(info))
        {
            EC rc = std::get<EC>(info);
            return rc;
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

    LR listdir(std::string path, bool need_reconnect = false)
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

        LIBSSH2_SFTP_HANDLE *sftp_handle = libssh2_sftp_open_ex(amsession->sftp, path.c_str(), path.size(), 0, LIBSSH2_SFTP_OPENDIR, LIBSSH2_FXF_READ);

        if (!sftp_handle)
        {
            return EC::RemotePathOpenError;
        }

        LIBSSH2_SFTP_ATTRIBUTES attrs;
        std::string name;
        std::string path_i;
        std::shared_ptr<char> safe_filename_buffer = std::make_shared<char>(2048);
        char *filename_buffer = safe_filename_buffer.get();
        while (true)
        {
            int rc = libssh2_sftp_readdir_ex(
                sftp_handle,
                filename_buffer, sizeof(filename_buffer),
                nullptr, 0,
                &attrs);

            if (rc <= 0)
            {
                break;
            }

            name = *filename_buffer;
            if (name == "." || name == "..")
            {
                continue;
            }

            if (name.find('\\') != std::string::npos)
            {
                path_i = path + "\\" + name;
            }
            else
            {
                path_i = path + "/" + name;
            }
            PathInfo info = formatstat(path_i, attrs);
            file_list.push_back(info);
        }
        return file_list;
    }

    EC mkdir(std::string path, bool need_reconnect = false)
    {
        EC rc = exists(path);

        switch (rc)
        {
        case EC::PassCheck:
            return EC::RemoteFileExists;
        case EC::FailedCheck:
            break;
        default:
            return rc;
        }

        rc = is_dir(dirname(path));

        if (rc != EC::PassCheck)
        {
            return rc;
        }

        int rcr = libssh2_sftp_mkdir(amsession->sftp, path.c_str(), 0777);
        if (rcr != 0)
        {
            switch (rcr)
            {
            case LIBSSH2_FX_PERMISSION_DENIED:
                return EC::PermissionDenied;
            case LIBSSH2_FX_FILE_ALREADY_EXISTS:
                return EC::Success;
            case LIBSSH2_ERROR_SFTP_PROTOCOL:
                return EC::ParentDirectoryNotExist;
            default:
                rc = ensure();
                if (rc != EC::Success)
                {
                    return rc;
                }
                return mkdir(path, false);
            }
        }
    }

    EC mkdirs(std::string path, bool need_reconnect = false)
    {
        std::vector<std::string> parts;
        size_t pos = 0;
        if (path.find('\\') != std::string::npos)
        {
            while (pos != std::string::npos)
            {
                pos = path.find('\\', pos + 1);
                parts.push_back(path.substr(0, pos));
            }
        }
        else
        {
            while (pos != std::string::npos)
            {
                pos = path.find('/', pos + 1);
                parts.push_back(path.substr(0, pos));
            }
        }

        for (auto &part : parts)
        {
            EC rc = mkdir(part, need_reconnect);
            if (rc == EC::RemoteFileExists || rc == EC::Success)
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

    EC rmfile(std::string path, bool need_reconnect = false)
    {
        EC rc = is_file(path);
        if (rc != EC::PassCheck)
        {
            return rc;
        }
        int rcr = libssh2_sftp_unlink(amsession->sftp, path.c_str());
        if (rcr != 0)
        {
            return EC::RemoteFileDeleteError;
        }
        return EC::Success;
    }

    EC rmdir(std::string path, bool need_reconnect = false)
    {
        LR info = listdir(path, need_reconnect);
        if (std::holds_alternative<EC>(info))
        {
            return std::get<EC>(info);
        }
        if (!std::holds_alternative<std::vector<PathInfo>>(info))
        {
            return EC::UnknownError;
        }

        std::vector<PathInfo> file_list = std::get<std::vector<PathInfo>>(info);
        if (!file_list.empty())
        {
            return EC::DirNotEmpty;
        }
        int rcr = libssh2_sftp_rmdir(amsession->sftp, path.c_str());
        if (rcr != 0)
        {
            return EC::EmptyDirRemoveError;
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

    EC saferm(std::string path, bool need_reconnect = false)
    {
        EC rc = exists(path);
        if (rc != EC::PassCheck)
        {
            return rc;
        }
        rc = is_dir(trash_dir);
        if (rc != EC::PassCheck)
        {
            return EC::InvalidTrashDir;
        }
        std::string base = basename(path);
        std::string target_path;
        if (trash_dir.find('\\') != std::string::npos)
        {
            target_path = trash_dir + "\\" + base;
        }
        else
        {
            target_path = trash_dir + "/" + base;
        }
        int i = 0;
        while (exists(target_path) == EC::PassCheck)
        {
            if (trash_dir.find('\\') != std::string::npos)
            {
                target_path = trash_dir + "\\" + std::to_string(i) + "_" + base;
            }
            else
            {
                target_path = trash_dir + "/" + std::to_string(i) + "_" + base;
            }
            i++;
        }
        int rcr = libssh2_sftp_rename(amsession->sftp, path.c_str(), target_path.c_str());
        if (rcr != 0)
        {
            return EC::MoveError;
        }
        return EC::Success;
    }

    EC move(std::string src, std::string dst, bool need_mkdir = false)
    {
        EC rc = exists(src);
        if (rc != EC::PassCheck)
        {
            return rc;
        }

        std::string src_base = basename(src);
        std::string dst_base = basename(dst);
        std::string dst_dir = dst;
        if (src_base == dst_base)
        {
            dst_dir = dirname(dst);
        }
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
        if (exists(dst) == EC::PassCheck)
        {
            return EC::RemoteFileExists;
        }
        int rcr = libssh2_sftp_rename(amsession->sftp, src.c_str(), dst.c_str());
        if (rcr != 0)
        {
            return EC::MoveError;
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

        return EC::Success;
    };
};

PYBIND11_MODULE(AMSFTP, m)
{
    py::enum_<TransferErrorCode>(m, "TransferErrorCode")
        .value("Success", TransferErrorCode::Success)
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
        .value("TargetExists", TransferErrorCode::TargetExists)
        .value("CopyError", TransferErrorCode::CopyError)
        .value("PathNotExist", TransferErrorCode::PathNotExist)
        .value("PermissionDenied", TransferErrorCode::PermissionDenied)
        .value("ParentDirectoryNotExist", TransferErrorCode::ParentDirectoryNotExist)
        .value("DirNotEmpty", TransferErrorCode::DirNotEmpty)
        .value("InvalidTrashDir", TransferErrorCode::InvalidTrashDir)
        .value("MoveError", TransferErrorCode::MoveError)
        .value("TargetNotAFile", TransferErrorCode::TargetNotAFile)
        .value("TargetNotADirectory", TransferErrorCode::TargetNotADirectory)
        .value("EmptyDirRemoveError", TransferErrorCode::EmptyDirRemoveError)
        .value("RemoteFileDeleteError", TransferErrorCode::RemoteFileDeleteError);

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

    py::class_<BufferSet>(m, "BufferSet")
        .def(py::init<>())
        .def_readwrite("A_buffer", &BufferSet::A_buffer)
        .def_readwrite("A_size", &BufferSet::A_size)
        .def_readwrite("B_buffer", &BufferSet::B_buffer)
        .def_readwrite("B_size", &BufferSet::B_size)
        .def_readwrite("C_buffer", &BufferSet::C_buffer)
        .def_readwrite("C_size", &BufferSet::C_size)
        .def_readwrite("D_buffer", &BufferSet::D_buffer)
        .def_readwrite("D_size", &BufferSet::D_size)
        .def_readwrite("E_buffer", &BufferSet::E_buffer)
        .def_readwrite("E_size", &BufferSet::E_size);

    py::class_<AMSFTPWorker>(m, "AMSFTPWorker")
        .def(py::init<uint64_t, std::vector<std::string>, ConRequst, TransferSet, TransferCallback, TASKS>(), py::arg("ID"), py::arg("private_keys"), py::arg("request"), py::arg("set"), py::arg("callback"), py::arg("tasks"))
        .def("terminate", &AMSFTPWorker::terminate)
        .def("pause", &AMSFTPWorker::pause)
        .def("resume", &AMSFTPWorker::resume)
        .def("start", &AMSFTPWorker::start);
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