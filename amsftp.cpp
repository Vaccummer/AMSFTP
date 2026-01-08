#include "AMEnum.hpp"
#include "AMPath.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <fmt/core.h>
#include <iostream>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <memory>
#include <numeric>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <regex>
#include <stdio.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#endif

#define _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR // in case mutex constructor is not supported

namespace py = pybind11;
namespace fs = std::filesystem;
using PathInfo = AMFS::PathInfo;
using PathType = AMFS::PathType;
using EC = ErrorCode;
using result_map = std::unordered_map<std::string, ErrorCode>;
using ECM = std::pair<EC, std::string>;
static std::atomic<bool> is_wsa_initialized(false);

static void cleanup_wsa()
{
    if (is_wsa_initialized)
    {
        WSACleanup();
        is_wsa_initialized = false;
    }
}

inline double timenow()
{
    return std::chrono::duration<double>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

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

struct ProgressCBInfo
{
    std::string src;
    std::string dst;
    std::string src_host;
    std::string dst_host;
    uint64_t this_size;
    uint64_t file_size;
    uint64_t accumulated_size;
    uint64_t total_size;
    ProgressCBInfo(std::string src, std::string dst, std::string src_host, std::string dst_host, uint64_t this_size, uint64_t file_size, uint64_t accumulated_size, uint64_t total_size)
        : src(src), dst(dst), src_host(src_host), dst_host(dst_host), this_size(this_size), file_size(file_size), accumulated_size(accumulated_size), total_size(total_size) {}
};

struct ErrorCBInfo
{
    std::pair<ErrorCode, std::string> ecm;
    std::string src;
    std::string dst;
    std::string src_host;
    std::string dst_host;
    ErrorCBInfo(std::pair<ErrorCode, std::string> ecm, std::string src, std::string dst, std::string src_host, std::string dst_host)
        : ecm(ecm), src(src), dst(dst), src_host(src_host), dst_host(dst_host) {}
};

struct AuthCBInfo
{
    bool NeedPassword; // if true, python password callback need to return password, if false, callback function just tells you the password is wrong
    ConRequst request;
    int trial_times;
    AuthCBInfo(bool NeedPassword, ConRequst request, int trial_times)
        : NeedPassword(NeedPassword), request(request), trial_times(trial_times) {}
};

struct TransferCallback
{
    bool need_error_cb;
    bool need_progress_cb;
    bool need_total_size_cb;
    py::function error_cb;      // Callable[[ErrorCBInfo], None]
    py::function progress_cb;   // Callable[[ProgressCBInfo], EC]
    py::function total_size_cb; // Callable[[int], None]

    TransferCallback(
        py::object total_size = py::none(),
        py::object error = py::none(),
        py::object progress = py::none())
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
    std::string src_host;
    std::string dst;
    std::string dst_host;
    uint64_t size;
    AMFS::PathType path_type = PathType::FILE;
    bool IsSuccess = false;
    ECM rc = ECM(EC::Success, "");
    TransferTask(std::string src, std::string src_host, std::string dst, std::string dst_host, uint64_t size, PathType path_type = PathType::FILE)
        : src(src), src_host(src_host), dst(dst), dst_host(dst_host), size(size), path_type(path_type) {}
};

class BaseFileMapper
{
public:
    char *file_ptr = nullptr;
    uint64_t file_size = 0;
    virtual ~BaseFileMapper() = default; // 虚析构函数，确保派生类析构被调用
};

#ifdef _WIN32
class WindowsFileMapper : public BaseFileMapper
{
public:
    HANDLE hFile;
    HANDLE hMap;
    LPVOID addr;
    LARGE_INTEGER file_size_ptr;

    ~WindowsFileMapper()
    {

        UnmapViewOfFile(addr);

        CloseHandle(hMap);

        CloseHandle(hFile);
        file_ptr = nullptr;
    }

    WindowsFileMapper()
    {
        this->hFile = nullptr;
        this->hMap = nullptr;
        this->addr = nullptr;
        this->file_ptr = nullptr;
    }

    WindowsFileMapper(const std::string &file_path, MapType map_type, std::string &error_msg, uint64_t file_size = 0)
    {
        LARGE_INTEGER li;
        li.QuadPart = file_size;
        bool is_ok = false;

        if (map_type == MapType::Read)
        {
            this->hFile = CreateFileW(AMFS::Str::AMStr(file_path).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

        this->hFile = CreateFileW(AMFS::Str::AMStr(file_path).c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
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
#else
class UnixFileMapper : public BaseFileMapper
{
private:
    int fd;                // 文件描述符
    void *addr;            // 映射内存地址
    struct stat file_stat; // 文件状态信息

public:
    ~UnixFileMapper()
    {
        // 解除内存映射
        if (addr != MAP_FAILED && addr != nullptr)
        {
            munmap(addr, file_size);
        }

        // 关闭文件描述符
        if (fd != -1)
        {
            close(fd);
        }

        file_ptr = nullptr;
    }

    UnixFileMapper() : fd(-1), addr(nullptr), file_ptr(nullptr), file_size(0) {}

    UnixFileMapper(const std::string &file_path, MapType map_type, std::string &error_msg, uint64_t file_size = 0)
        : fd(-1), addr(nullptr), file_ptr(nullptr), file_size(0)
    {

        bool is_ok = false;
        int open_flags = 0;
        int prot_flags = 0;
        int map_flags = MAP_SHARED;

        try
        {
            if (map_type == MapType::Read)
            {
                // 只读模式
                open_flags = O_RDONLY;
                prot_flags = PROT_READ;

                // 打开文件
                fd = open(file_path.c_str(), open_flags);
                if (fd == -1)
                {
                    throw std::string("Failed to open file: ") + strerror(errno);
                }

                // 获取文件大小
                if (fstat(fd, &file_stat) == -1)
                {
                    throw std::string("Failed to get file status: ") + strerror(errno);
                }
                this->file_size = file_stat.st_size;

                // 映射文件到内存
                addr = mmap(nullptr, this->file_size, prot_flags, map_flags, fd, 0);
                if (addr == MAP_FAILED)
                {
                    throw std::string("Failed to map file to memory: ") + strerror(errno);
                }

                file_ptr = static_cast<char *>(addr);
                is_ok = true;
            }
            else
            {
                // 写入模式
                open_flags = O_RDWR | O_CREAT | O_TRUNC; // 创建并截断文件
                prot_flags = PROT_READ | PROT_WRITE;
                mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // 权限: 644

                // 打开文件
                fd = open(file_path.c_str(), open_flags, file_mode);
                if (fd == -1)
                {
                    throw std::string("Failed to create/open file: ") + strerror(errno);
                }

                // 设置文件大小
                this->file_size = file_size;
                if (ftruncate(fd, this->file_size) == -1)
                {
                    throw std::string("Failed to set file size: ") + strerror(errno);
                }

                // 映射文件到内存
                addr = mmap(nullptr, this->file_size, prot_flags, map_flags, fd, 0);
                if (addr == MAP_FAILED)
                {
                    throw std::string("Failed to map file to memory: ") + strerror(errno);
                }

                file_ptr = static_cast<char *>(addr);
                is_ok = true;
            }
        }
        catch (const std::string &err)
        {
            error_msg = err;

            // 清理已分配的资源
            if (addr != MAP_FAILED && addr != nullptr)
            {
                munmap(addr, file_size);
                addr = nullptr;
            }
            if (fd != -1)
            {
                close(fd);
                fd = -1;
            }
            file_ptr = nullptr;
            file_size = 0;
        }
    }

    // 同步内存映射到文件
    bool sync()
    {
        if (addr == nullptr || addr == MAP_FAILED || file_size == 0)
        {
            return false;
        }
        return msync(addr, file_size, MS_SYNC) == 0;
    }
};
#endif

class FileMapper
{
private:
    std::shared_ptr<BaseFileMapper> ori_mapper;

public:
    char *file_ptr;     // 映射文件数据指针
    uint64_t file_size; // 文件大小
    FileMapper() : file_ptr(nullptr), file_size(0) {}
    FileMapper(const std::string &file_path, MapType map_type, std::string &error_msg, uint64_t file_size = 0)
    {
#ifdef _WIN32
        this->ori_mapper = std::make_shared<WindowsFileMapper>(file_path, map_type, error_msg, file_size);
        this->file_ptr = this->ori_mapper->file_ptr;
        this->file_size = this->ori_mapper->file_size;
#else
        this->ori_mapper = std::make_shared<UnixFileMapper>(file_path, map_type, error_msg, file_size);
        this->file_ptr = unix_mapper->file_ptr;
        this->file_size = unix_mapper->file_size;
#endif
    }
    // 禁止拷贝构造和赋值
    FileMapper(const FileMapper &) = delete;
    FileMapper &operator=(const FileMapper &) = delete;
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

using TASKS = std::vector<TransferTask>;
using int_ptr = std::shared_ptr<uint64_t>;
using safe_int_ptr = std::shared_ptr<std::atomic<uint64_t>>;
using RMR = std::vector<std::pair<std::string, ECM>>;
using TRM = std::vector<std::pair<std::pair<std::string, std::string>, ECM>>;
using RR = std::variant<std::string, ECM>;
using TR = std::variant<TRM, ECM>;
using BR = std::variant<bool, ECM>;
using SR = std::variant<PathInfo, ECM>;
using LR = std::variant<std::vector<PathInfo>, ECM>;
using WRV = std::vector<PathInfo>;
using WRD = std::vector<std::pair<std::vector<std::string>, PathInfo>>;
using WR = std::variant<WRV, ECM>;
using ED = std::pair<EC, std::string>;
using SIZER = std::variant<uint64_t, ECM>;
using ErrorInfo = std::unordered_map<std::string, std::variant<std::string, EC>>;
using CR = std::variant<std::pair<std::string, int>, ECM>;

bool isok(ECM &ecm)
{
    return ecm.first == EC::Success;
}

class CircularBuffer
{
private:
    std::vector<ErrorInfo> buffer = {};
    size_t capacity = 10;

public:
    CircularBuffer() {}

    CircularBuffer(unsigned int buffer_capacity)
    {
        if (buffer_capacity <= 0)
        {
            capacity = 10;
        }
        else
        {
            capacity = buffer_capacity;
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

    size_t GetSize() const { return buffer.size(); }

    size_t GetCapacity() const { return capacity; }

    std::variant<py::object, ErrorInfo> LastTraceError()
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

    bool IsEmpty() const { return buffer.size() == 0; }

    void Clear()
    {
        buffer.clear();
    }

    void SetCapacity(unsigned int size)
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

class AMTracer : public CircularBuffer
{
private:
    py::function trace_cb;
    std::atomic<bool> is_py_trace = false;
    std::atomic<bool> is_pause = false;

public:
    AMTracer(unsigned int buffer_capacity = 10, py::object trace_cb = py::none()) : CircularBuffer(buffer_capacity)
    {
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
        this->push(level_map);
    }

    void pause()
    {
        is_pause.store(true);
    }

    void resume()
    {
        is_pause.store(false);
    }

    void SetPyTrace(py::object trace = py::none())
    {
        if (trace.is_none())
        {
            is_py_trace.store(false);
            trace_cb = py::function();
        }
        else
        {
            trace_cb = py::cast<py::function>(trace);
            is_py_trace.store(true);
        }
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
    py::function auth_cb = py::function(); // Callable[[IsPasswordDemand:bool, ConRequst, TrialTimes:int], str]
    std::recursive_mutex mtx;
    bool password_auth_cb = false;

    bool IsValidKey(const std::string &key)
    {
        return true;
        // 换用fopen_s
        FILE *fp = nullptr;
        fopen_s(&fp, key.c_str(), "r");
        if (!fp)
            return false;

        EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);

        if (!pkey)
            return false;

        int type = EVP_PKEY_id(pkey);
        EVP_PKEY_free(pkey);

        switch (type)
        {
        case EVP_PKEY_NONE:
            return false;
        default:
            return true;
        }
    }

    void LoadDefaultPrivateKeys()
    {
        std::string default_key_dir = AMFS::realpath("~/.ssh");
        for (auto &entry : fs::directory_iterator(default_key_dir))
        {
            if (fs::is_regular_file(entry))
            {
                if (IsValidKey(entry.path().string()))
                {
                    this->private_keys.push_back(entry.path().string());
                }
            }
        }
    }

    ECM Connect()
    {
        std::string msg = "";
        EC rc = EC::Success;
        int rcr;

        // sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        // if (sock == INVALID_SOCKET)
        // {
        //     trace(AMCRITICAL, EC::SocketCreateError, request.nickname, "CreateSocket", "Create but get invalid socket");
        //     return {EC::SocketCreateError, "Create but get invalid socket"};
        // }

        // uint64_t timeout_ms = request.timeout_s * 1000;
        // if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR)
        // {
        //     closesocket(sock);
        //     return {EC::SocketOperationTimeout, "Fail to Set Socket Send Timeout"};
        // }
        // addrinfo *result = nullptr;
        // addrinfo hints = {0};
        // hints.ai_family = AF_INET;       // IPv4
        // hints.ai_socktype = SOCK_STREAM; // TCP
        // hints.ai_protocol = IPPROTO_TCP;

        // int dns_err = getaddrinfo(request.hostname.c_str(), nullptr, &hints, &result);
        // if (dns_err != 0)
        // {
        //     std::string msg = "域名解析失败: " + std::string(gai_strerror(dns_err)) + " (hostname=" + request.hostname + ")";
        //     trace(AMCRITICAL, EC::DNSResolveError, request.nickname, "ConnectSocket", msg);
        //     closesocket(sock);
        //     WSACleanup();
        //     return {EC::DNSResolveError, msg};
        // }

        // sockaddr_in sin = {0};
        // sin.sin_family = AF_INET;
        // sin.sin_port = htons(request.port);
        // inet_pton(AF_INET, request.hostname.c_str(), &sin.sin_addr);
        // rcr = connect(sock, (sockaddr *)&sin, sizeof(sin));

        // timeval timeout;
        // timeout.tv_sec = request.timeout_s;
        // timeout.tv_usec = 0;

        // fd_set writeSet;
        // FD_ZERO(&writeSet);
        // FD_SET(sock, &writeSet);
        // int selectRet = select(sock + 1, nullptr, &writeSet, nullptr, &timeout);

        if (selectRet == 0)
        {
            trace(AMCRITICAL, EC::SocketConnectTimeout, request.nickname, "ConnectSocket", "Socket Connection Establish Timeout");
            return {EC::SocketConnectTimeout, "Socket Connection Establish Timeout"};
        }
        else if (selectRet < 0)
        {
            trace(AMCRITICAL, EC::SocketConnectFailed, request.nickname, "ConnectSocket", "Socket Connection Establish Failed");
            return {EC::SocketConnectFailed, "Socket Connection Establish Failed"};
        }

        session = libssh2_session_init();

        if (!session)
        {
            trace(AMCRITICAL, EC::SessionCreateFailed, request.nickname, "SessionInit", "Session initialization failed");
            return {EC::SessionCreateFailed, "Libssh2 Session initialization failed"};
        }

        libssh2_session_set_blocking(session, 1);

        if (request.compression)
        {
            libssh2_session_flag(session, LIBSSH2_FLAG_COMPRESS, 1);
            libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS, "zlib@openssh.com,zlib,none");
        }

        rcr = libssh2_session_handshake(session, sock);

        if (rcr != 0)
        {
            msg = fmt::format("Session handshake failed: {}", GetLastErrorMsg());
            rc = GetLastEC();
            trace(AMCRITICAL, rc, request.nickname, "SessionHandshake", msg);
            return {rc, msg};
        }

        const char *auth_list = libssh2_userauth_list(session, request.username.c_str(), request.username.length());
        if (auth_list == nullptr)
        {
            msg = fmt::format("Fail to negotiate authentication method: {}", GetLastErrorMsg());
            rc = GetLastEC();
            trace(AMCRITICAL, rc, request.nickname, "GetAuthList", msg);
            return {rc, msg};
        }

        bool password_auth = false;
        if (strstr(auth_list, "password") != NULL)
        {
            password_auth = true;
        }

        rc = EC::AuthFailed;

        std::string password_tmp;
        if (!request.keyfile.empty())
        {
            rcr = libssh2_userauth_publickey_fromfile(session, request.username.c_str(), nullptr, request.keyfile.c_str(), nullptr);
            if (rcr == 0)
            {
                rc = EC::Success;
                msg = "";
                trace(AMINFO, EC::Success, request.nickname, "PublicKeyAuthorize", fmt::format("Public key \"{}\" authorize success", request.keyfile));
                goto OK;
            }
            else
            {
                msg = fmt::format("Public key \"{}\" authorize failed: {}", request.keyfile, GetLastErrorMsg());
                rc = GetLastEC();
                trace(AMWARNING, rc, request.nickname, "PublicKeyAuthorize", msg);
            }
        }

        if (!request.password.empty() && password_auth)
        {
            rcr = libssh2_userauth_password(session, request.username.c_str(), request.password.c_str());
            if (rcr == 0)
            {
                rc = EC::Success;
                msg = "";
                trace(AMINFO, EC::Success, request.nickname, "PasswordAuthorize", "Password authorize success");
                goto OK;
            }
            else
            {
                trace(AMWARNING, EC::AuthFailed, request.nickname, "PasswordAuthorize", "Wrong Password");
            }
        }

        for (auto private_key : private_keys)
        {
            rcr = libssh2_userauth_publickey_fromfile(session, request.username.c_str(), nullptr, private_key.c_str(), nullptr);
            if (rcr == 0)
            {
                msg = fmt::format("Public key \"{}\" authorize success", private_key);
                trace(AMINFO, EC::Success, request.nickname, "PublicKeyAuthorize", msg);
                rc = EC::Success;
                goto OK;
            }
            else
            {
                msg = fmt::format("Public key \"{}\" authorize failed", private_key);
                trace(AMWARNING, EC::PrivateKeyAuthFailed, request.nickname, "PublicKeyAuthorize", msg);
            }
        }

        if (password_auth_cb && password_auth)
        {
            int trial_times = 0;
            while (trial_times < 2)
            {
                {
                    py::gil_scoped_acquire acquire;
                    password_tmp = py::cast<std::string>(auth_cb(AuthCBInfo(true, request, trial_times)));
                }
                if (password_tmp.empty())
                {
                    break;
                }
                rcr = libssh2_userauth_password(session, request.username.c_str(), password_tmp.c_str());
                trial_times++;
                if (rcr == 0)
                {
                    rc = EC::Success;
                    msg = "";
                    trace(AMINFO, EC::Success, request.nickname, "PasswordAuthorize", "Password authorize success");
                    goto OK;
                }
                else
                {
                    trace(AMWARNING, EC::AuthFailed, request.nickname, "PasswordAuthorize", "Wrong Password");
                    {
                        py::gil_scoped_acquire acquire;
                        auth_cb(false, request, trial_times);
                    }
                }
            }
        }
    OK:
        if (rc != EC::Success)
        {
            trace(AMCRITICAL, EC::AuthFailed, request.nickname, "FinalAuthorizeState", "All authorize methods failed");
            return {rc, "All authorize methods failed"};
        }

        sftp = libssh2_sftp_init(session);

        if (!sftp)
        {
            rc = GetLastEC();
            msg = fmt::format("SFTP initialization failed: {}", GetLastErrorMsg());
            trace(AMCRITICAL, rc, request.nickname, "SFTPInitialization", msg);
            return {rc, msg};
        }

        return {EC::Success, ""};
    }

    ECM Check()
    {
        if (!sftp)
        {
            trace(AMCRITICAL, EC::NoConnection, "Sftp", "SFTPCheck", "SFTP not initialized");
            return {EC::NoConnection, "SFTP not initialized"};
        }

        if (!session)
        {
            trace(AMCRITICAL, EC::NoSession, "Session", "SessionCheck", "Session not initialized");
            return {EC::NoSession, "Session not initialized"};
        }

        LIBSSH2_SFTP_ATTRIBUTES attrs;
        int rct;
        {
            std::lock_guard<std::recursive_mutex> lock(mtx);
            rct = libssh2_sftp_stat(sftp, "./amtrial", &attrs);
        }
        EC rc;
        if (rct != 0)
        {
            rc = GetLastEC();
            if (rc != EC::PathNotExist && rc != EC::FileNotExist)
            {
                std::string msg = fmt::format("Session check failed: {}", GetLastErrorMsg());
                trace(AMCRITICAL, rc, "Session", "SessionCheck", msg);
                return {rc, msg};
            }
        }
        trace(AMINFO, EC::Success, fmt::format("{}@{}", request.nickname, "SSHSeesion"), "Check", "");
        return {EC::Success, ""};
    }

    EC GetLastEC()
    {
        if (!session)
        {
            return EC::NoSession;
        }
        int ori_code = libssh2_session_last_errno(session);
        if (ori_code != LIBSSH2_ERROR_SFTP_PROTOCOL)
        {
            return Int2EC.at(ori_code);
        }
        else
        {
            if (!sftp)
            {
                return EC::NoConnection;
            }
            return Int2EC.at(libssh2_sftp_last_error(sftp));
        }
    }

    std::string GetLastErrorMsg()
    {
        if (!session)
        {
            return "Session not initialized";
        }
        int ori_code = libssh2_session_last_errno(session);
        if (ori_code != LIBSSH2_ERROR_SFTP_PROTOCOL)
        {
            char *errmsg = NULL;
            int errmsg_len;
            int errcode = libssh2_session_last_error(session, &errmsg, &errmsg_len, 0);
            return std::string(errmsg);
        }
        else
        {
            if (!sftp)
            {
                return "SFTP not initialized";
            }
            ori_code = libssh2_sftp_last_error(sftp);
            if (SFTPMessage.find(ori_code) != SFTPMessage.end())
            {
                return SFTPMessage.at(ori_code);
            }
            return "Unknown SFTP error";
        }
    }

    void clean()
    {
        if (sftp)
        {
            libssh2_sftp_shutdown(sftp);
            sftp = nullptr;
        }
        if (session)
        {
            libssh2_session_disconnect(session, "Normal Shutdown");
            libssh2_session_free(session);
            session = nullptr;
        }
        if (sock != INVALID_SOCKET)
        {
            closesocket(sock);
            sock = INVALID_SOCKET;
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
        if (private_keys.empty())
        {
            LoadDefaultPrivateKeys();
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
    std::shared_ptr<AMSession> session_t;
    std::string error_msg = "";
    EC error_code = EC::Success;
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
        this->session_t = amsession;
        this->channel = libssh2_channel_open_ex(amsession->session,
                                                "session",
                                                sizeof("session") - 1,
                                                4 * AMMB,
                                                32 * AMKB,
                                                nullptr,
                                                0);
        if (!this->channel)
        {
            this->error_msg = session_t->GetLastErrorMsg();
            this->error_code = session_t->GetLastEC();
        }
    }

    CR ConductCmd(std::string cmd)
    {
        if (!channel)
        {
            return ECM{error_code, error_msg};
        }

        int out;
        {
            std::lock_guard<std::recursive_mutex> lock(session_t->mtx);
            out = libssh2_channel_exec(channel, cmd.c_str());
        }

        if (out < 0)
        {
            error_code = session_t->GetLastEC();
            error_msg = fmt::format("{} Host channel operation failed: {}", session_t->request.nickname, session_t->GetLastErrorMsg());
            return ECM{error_code, error_msg};
        }
        char cmd_out[4096];
        int nbytes;
        {
            std::lock_guard<std::recursive_mutex> lock(session_t->mtx);
            nbytes = libssh2_channel_read(channel, cmd_out, sizeof(cmd_out) - 1);
        }

        if (nbytes < 0)
        {
            error_code = session_t->GetLastEC();
            error_msg = fmt::format("{} Host channel output read failed: {}", session_t->request.nickname, session_t->GetLastErrorMsg());
            return ECM{error_code, error_msg};
        }

        int exit_status;
        {
            std::lock_guard<std::recursive_mutex> lock(session_t->mtx);
            exit_status = libssh2_channel_get_exit_status(channel);
        }
        std::string output(cmd_out, nbytes);
        output.erase(std::find_if(output.rbegin(), output.rend(), [](char c)
                                  { return c != '\n' && c != '\r'; })
                         .base(),
                     output.end());
        return std::make_pair(output, exit_status);
    }
};

class BaseSFTPClient
{
private:
    OS_TYPE os_type = OS_TYPE::Uncertain;
    std::shared_ptr<AMTracer> amtracer;

public:
    std::string trash_dir;
    std::vector<std::string> private_keys;
    ConRequst request;
    std::shared_ptr<AMSession> amsession;
    // std::lock_guard<std::recursive_mutex> lock(mtx);

    BaseSFTPClient()
    {
        this->trash_dir = "";
        this->private_keys = {};
        this->request = ConRequst();
        this->amtracer = nullptr;
    }

    BaseSFTPClient(ConRequst request, std::vector<std::string> keys, unsigned int error_num = 10, py::object trace_cb = py::none(), py::object auth_cb = py::none())
    {
        if (request.trash_dir.empty())
        {
            this->trash_dir = "./.AMSFTP_Trash";
        }
        else
        {
            this->trash_dir = request.trash_dir;
        }

        this->private_keys = keys;
        this->request = request;
        this->amtracer = std::make_shared<AMTracer>(error_num, trace_cb);
        this->amsession = std::make_shared<AMSession>(request, keys, amtracer, auth_cb);
    }

    void trace(std::string level, EC error_code, std::string target = "", std::string action = "", std::string msg = "")
    {
        amtracer->trace(level, error_code, target, action, msg);
    }

    std::variant<py::object, ErrorInfo> LastTraceError()
    {
        return amtracer->LastTraceError();
    }

    inline std::vector<ErrorInfo> GetAllTraceErrors()
    {
        return amtracer->GetAllErrors();
    }

    inline int GetTraceNum()
    {
        return amtracer->GetSize();
    }

    inline int GetTraceCapacity()
    {
        return amtracer->GetCapacity();
    }

    inline std::string GetTrashDir()
    {
        return this->trash_dir;
    }

    inline std::string Nickname()
    {
        return this->request.nickname;
    }

    bool IsValidKey(const std::string &key)
    {
        return amsession->IsValidKey(key);
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

    void SetPyTrace(py::object trace_cb = py::none())
    {
        amtracer->SetPyTrace(trace_cb);
    }

    EC GetLastEC()
    {
        return amsession->GetLastEC();
    }

    std::string GetLastErrorMsg()
    {
        // int session_err = libssh2_session_last_errno(amsession->session);
        // if (session_err == LIBSSH2_ERROR_EAGAIN)
        // {
        //     return "EAGAIN";
        // }
        // else if (session_err == LIBSSH2_ERROR_SFTP_PROTOCOL)
        // {
        //     int sftp_err = libssh2_sftp_last_error(amsession->sftp);

        //     if (SFTPMessage.find(sftp_err) != SFTPMessage.end())
        //     {
        //         return SFTPMessage.at(sftp_err);
        //     }
        //     return "Unknown SFTP error";
        // }

        // char *errmsg = NULL;
        // int errmsg_len;
        // int errcode = libssh2_session_last_error(amsession->session, &errmsg, &errmsg_len, 0);
        // return std::string(errmsg);
        return amsession->GetLastErrorMsg();
    }

    ECM Check()
    {
        return amsession->Check();
    }

    ECM Connect()
    {
        ECM ecm = amsession->Connect();
        if (!isok(ecm))
        {
            return ecm;
        }
        trash_dir = this->request.trash_dir;
        return {EC::Success, ""};
    }

    void Disconnect()
    {
        amsession->clean();
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

    ECM EnsureConnect()
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

    OS_TYPE GetOSType()
    {
        if (os_type != OS_TYPE::Uncertain)
        {
            return os_type;
        }
        SafeChannel channel(amsession);
        auto out = channel.ConductCmd("uname -s");
        if (!std::holds_alternative<std::pair<std::string, int>>(out))
        {
            os_type = OS_TYPE::Uncertain;
            return os_type;
        }
        int code = std::get<std::pair<std::string, int>>(out).second;
        if (code == 0)
        {
            std::string out_str = std::get<std::pair<std::string, int>>(out).first;
            // 将out_str转换为小写
            std::transform(out_str.begin(), out_str.end(), out_str.begin(), ::tolower);
            if (out_str.find("linux") != std::string::npos)
            {
                os_type = OS_TYPE::Linux;
            }
            else if (out_str.find("darwin") != std::string::npos)
            {
                os_type = OS_TYPE::MacOS;
            }
            else if (out_str.find("cygwin") != std::string::npos)
            {
                os_type = OS_TYPE::Windows;
            }
            else if (out_str.find("freebsd") != std::string::npos)
            {
                os_type = OS_TYPE::FreeBSD;
            }
            else
            {
                os_type = OS_TYPE::Unix;
            }
            return os_type;
        }

        SafeChannel channel2(amsession);
        auto out2 = channel2.ConductCmd("systeminfo | findstr /i \"OS Name\"");
        if (!std::holds_alternative<std::pair<std::string, int>>(out2))
        {
            os_type = OS_TYPE::Uncertain;
            return os_type;
        }

        code = std::get<std::pair<std::string, int>>(out2).second;
        if (code != 0)
        {
            os_type = OS_TYPE::Unknown;
            return os_type;
        }
        std::string out_str2 = std::get<std::pair<std::string, int>>(out2).first;
        if (out_str2.find("Windows") != std::string::npos)
        {
            os_type = OS_TYPE::Windows;
            return os_type;
        }
        os_type = OS_TYPE::Unix;
        return os_type;
    }

    virtual std::string StrUid(long uid) { return ""; };

    virtual ECM EnsureTrashDir() { return {EC::Success, ""}; };
};

class AMSFTPClient : public BaseSFTPClient
{
private:
    std::map<long, std::string> user_id_map;
    bool is_trash_dir_ensure = false;

    void _iwalk(std::string path, WRV &result, bool ignore_sepcial_file = true)
    {
        // 搜索目录下所有最深层的路径, 用于递归传输路径
        SR info = stat(path);
        if (!std::holds_alternative<PathInfo>(info))
        {
            return;
        }
        PathInfo info_path = std::get<PathInfo>(info);
        if (info_path.type != PathType::DIR)
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
            if (info.type == PathType::DIR)
            {
                _iwalk(info.path, result, ignore_sepcial_file);
                all_file = false;
            }
            else
            {
                if (ignore_sepcial_file && static_cast<int>(info.type) < 0)
                {
                    continue;
                }
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

    void _walk(std::vector<std::string> parts, WRD &result, int cur_depth = 0, int max_depth = -1, bool ignore_sepcial_file = true)
    {
        if (max_depth != -1 && cur_depth > max_depth)
        {
            return;
        }
        std::string path = AMFS::join(parts);
        SR info = stat(path);
        if (!std::holds_alternative<PathInfo>(info))
        {
            return;
        }
        PathInfo info_path = std::get<PathInfo>(info);
        if (info_path.type != PathType::DIR)
        {
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
            if (parts.size() == 1)
            {
                return;
            }
            std::vector<std::string> ta = parts;
            ta.pop_back();
            result.push_back(std::make_pair(ta, info_path));
            return;
        }
        bool all_file = true;
        for (auto &info : list_info)
        {
            if (info.type == PathType::DIR)
            {
                auto new_parts = parts;
                new_parts.push_back(info.name);
                _walk(new_parts, result, cur_depth + 1, max_depth, ignore_sepcial_file);
            }
            else
            {
                if (ignore_sepcial_file && static_cast<int>(info.type) < 0)
                {
                    continue;
                }
                auto t_parts = parts;
                t_parts.push_back(info.name);
                result.push_back(std::make_pair(t_parts, info));
            }
        }
    }

    void _GetSize(std::string path, uint64_t &size, bool ignore_sepcial_file = true)
    {
        SR info = stat(path);
        if (!std::holds_alternative<PathInfo>(info))
        {
            return;
        }
        PathInfo path_info = std::get<PathInfo>(info);
        switch (path_info.type)
        {
        case PathType::FILE:
            size += path_info.size;
            return;
        case PathType::SYMLINK:
            return;
        case PathType::DIR:
            break;
        default:
            if (ignore_sepcial_file && static_cast<int>(path_info.type) < 0)
            {
                return;
            }
            else
            {
                size += path_info.size;
            }
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

    void _chmod(std::string path, std::string mode, bool recursive, std::map<std::string, ECM> &errors)
    {
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        EC rc;
        std::string msg = "";

        int rct;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rct = libssh2_sftp_stat(amsession->sftp, path.c_str(), &attrs);
        }

        if (rct != 0)
        {
            rc = GetLastEC();
            msg = fmt::format("stat {} failed: {}", path, GetLastErrorMsg());
            errors[path] = {rc, msg};
            return;
        }
        if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS))
        {
            msg = fmt::format("stat {} does not have permission attribute", path);
            errors[path] = {EC::NoPermissionAttribute, msg};
            return;
        }

        std::string new_mode = AMFS::Str::MergeModeStr(AMFS::Str::ModeTrans(attrs.permissions & 0777), mode);

        uint64_t new_mode_int = AMFS::Str::ModeTrans(new_mode);

        uint64_t file_type = attrs.permissions & LIBSSH2_SFTP_S_IFMT;
        new_mode_int = (new_mode_int & ~LIBSSH2_SFTP_S_IFMT) | file_type;

        attrs.permissions = new_mode_int;

        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rcr = libssh2_sftp_setstat(amsession->sftp, path.c_str(), &attrs);
        }

        if (rcr < 0)
        {
            rc = GetLastEC();
            msg = fmt::format("chmod {} failed: {}", path, GetLastErrorMsg());
            errors[path] = {rc, msg};
        }

        if (recursive && file_type == LIBSSH2_SFTP_S_IFDIR)
        {
            LR list = listdir(path);
            if (std::holds_alternative<WRV>(list))
            {
                for (auto &item : std::get<WRV>(list))
                {
                    _chmod(item.path, mode, recursive, errors);
                }
            }
            else
            {
                errors[path] = std::get<ECM>(list);
            }
        }
    }

    void _chmod(std::string path, uint64_t mode, bool recursive, std::map<std::string, ECM> &errors)
    {
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        EC rc;
        std::string msg = "";

        int rct;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rct = libssh2_sftp_stat(amsession->sftp, path.c_str(), &attrs);
        }

        if (rct != 0)
        {
            rc = GetLastEC();
            msg = fmt::format("stat {} failed: {}", path, GetLastErrorMsg());
            errors[path] = {rc, msg};
            return;
        }
        if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS))
        {
            msg = fmt::format("stat {} does not have permission attribute", path);
            errors[path] = {EC::NoPermissionAttribute, msg};
            return;
        }

        uint64_t file_type = attrs.permissions & LIBSSH2_SFTP_S_IFMT;
        uint64_t new_mode_int = (mode & ~LIBSSH2_SFTP_S_IFMT) | file_type;

        attrs.permissions = new_mode_int;

        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rcr = libssh2_sftp_setstat(amsession->sftp, path.c_str(), &attrs);
        }

        if (rcr < 0)
        {
            rc = GetLastEC();
            msg = fmt::format("chmod {} failed: {}", path, GetLastErrorMsg());
            errors[path] = {rc, msg};
        }

        if (recursive && file_type == LIBSSH2_SFTP_S_IFDIR)
        {
            LR list = listdir(path);
            if (std::holds_alternative<WRV>(list))
            {
                for (auto &item : std::get<WRV>(list))
                {
                    _chmod(item.path, mode, recursive, errors);
                }
            }
            else
            {
                errors[path] = std::get<ECM>(list);
            }
        }
    }

    PathInfo FormatStat(std::string path, LIBSSH2_SFTP_ATTRIBUTES &attrs)
    {
        PathInfo info;
        info.path = path;
        info.name = AMFS::basename(path);
        info.dir = AMFS::dirname(path);
        long uid = attrs.uid;
        std::string user_name = StrUid(uid);
        if (user_name.empty())
        {
            info.owner = std::to_string(uid);
        }
        else
        {
            info.owner = user_name;
        }

        if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE)
        {
            info.size = attrs.filesize;
        }

        if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME)
        {
            info.access_time = attrs.atime;
            info.modify_time = attrs.mtime;
        }

        if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)
        {
            const uint32_t mode = attrs.permissions;
            const uint32_t file_type = mode & LIBSSH2_SFTP_S_IFMT;
            switch (file_type)
            {
            case LIBSSH2_SFTP_S_IFDIR:
                info.type = PathType::DIR;
                break;
            case LIBSSH2_SFTP_S_IFLNK:
                info.type = PathType::SYMLINK;
                break;
            case LIBSSH2_SFTP_S_IFREG:
                info.type = PathType::FILE;
                break;
            case LIBSSH2_SFTP_S_IFBLK:
                info.type = PathType::BlockDevice;
                break;
            case LIBSSH2_SFTP_S_IFCHR:
                info.type = PathType::CharacterDevice;
                break;
            case LIBSSH2_SFTP_S_IFSOCK:
                info.type = PathType::Socket;
                break;
            case LIBSSH2_SFTP_S_IFIFO:
                info.type = PathType::FIFO;
                break;
            default:
                info.type = PathType::Unknown;
                break;
            }
            info.mode_int = mode & 0777;
            info.mode_str = AMFS::Str::ModeTrans(info.mode_int);
        }

        return info;
    }

public:
    ~AMSFTPClient()
    {
    }

    AMSFTPClient(ConRequst request, std::vector<std::string> keys, unsigned int error_num = 10, py::object trace_cb = py::none(), py::object auth_cb = py::none()) : BaseSFTPClient(request, keys, error_num, trace_cb, auth_cb)
    {
    }

    std::string StrUid(long uid)
    {
        if (user_id_map.find(uid) != user_id_map.end())
        {
            return user_id_map[uid];
        }
        SafeChannel channel(amsession);
        if (!channel.channel)
        {
            return "";
        }
        std::string cmd = fmt::format("id -un {}", uid);
        CR cr = channel.ConductCmd(cmd);
        if (std::holds_alternative<ECM>(cr))
        {
            return "unkown";
        }
        std::pair<std::string, int> resp = std::get<std::pair<std::string, int>>(cr);
        if (resp.second != 0)
        {
            return "unkown";
        }
        else
        {
            user_id_map[uid] = resp.first;
            return resp.first;
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
        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rcr = libssh2_sftp_realpath(amsession->sftp, ".", path_t, sizeof(path_t));
        }
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
            this->trash_dir = AMFS::join(cwd, ".amsftp_trash");
        }
        trace(AMINFO, EC::Success, "TrashDir", "DefaultTrashDir", fmt::format("Trash directory set to default: \"{}\"", this->trash_dir));
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

    std::variant<std::map<std::string, ECM>, ECM> chmod(std::string path, std::variant<std::string, uint64_t> mode, bool recursive = false)
    {
        if (static_cast<int>(GetOSType()) <= 0)
        {
            return ECM{EC::UnImplentedMethod, "Chmod only supported on Unix System"};
        }

        if (!amsession->sftp)
        {
            return ECM{EC::NoConnection, "SFTP not initialized"};
        }

        BR br = exists(path);
        if (!std::holds_alternative<bool>(br))
        {
            return std::get<ECM>(br);
        }
        else if (!std::get<bool>(br))
        {
            return ECM{EC::PathNotExist, fmt::format("Path does not exist: {}", path)};
        }
        std::map<std::string, ECM> ecm_map;

        if (std::holds_alternative<std::string>(mode))
        {
            if (!AMFS::Str::IsModeValid(std::get<std::string>(mode)))
            {
                return ECM{EC::InvalidArg, fmt::format("Invalid mode: {}", std::get<std::string>(mode))};
            }
            _chmod(path, std::get<std::string>(mode), recursive, ecm_map);
        }
        else if (std::holds_alternative<uint64_t>(mode))
        {
            if (!AMFS::Str::IsModeValid(std::get<uint64_t>(mode)))
            {
                return ECM{EC::InvalidArg, fmt::format("Invalid mode: {}", std::get<uint64_t>(mode))};
            }
            _chmod(path, std::get<uint64_t>(mode), recursive, ecm_map);
        }
        else
        {
            return ECM{EC::InvalidArg, fmt::format("Invalid mode data type")};
        }
        return ecm_map;
    }

    RR realpath(std::string path)
    {
        if (!amsession->sftp)
        {
            return std::make_pair(EC::NoConnection, "SFTP not initialized");
        }
        char path_t[1024];
        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rcr = libssh2_sftp_realpath(amsession->sftp, path.c_str(), path_t, sizeof(path_t));
        }
        if (rcr < 0)
        {
            EC rc = GetLastEC();
            std::string msg = fmt::format("realpath {} failed: {}", path, GetLastErrorMsg());
            trace(AMERROR, rc, fmt::format("{}@{}", request.nickname, path), "Realpath", msg);
            return std::make_pair(rc, msg);
        }
        else
        {
            return std::string(path_t);
        }
    }

    SR stat(std::string path)
    {
        if (!amsession->sftp)
        {
            return std::make_pair(EC::NoConnection, "SFTP not initialized");
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        EC rc;
        std::string msg = "";
        int rct;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rct = libssh2_sftp_stat(amsession->sftp, path.c_str(), &attrs);
        }

        if (rct != 0)
        {
            rc = GetLastEC();
            msg = fmt::format("stat {} failed: {}", path, GetLastErrorMsg());
            trace(AMWARNING, rc, fmt::format("{}@{}", request.nickname, path), "Stat", msg);
            return std::make_pair(rc, msg);
        }
        RR rp = realpath(path);
        if (std::holds_alternative<std::string>(rp))
        {
            path = std::get<std::string>(rp);
        }
        return FormatStat(path, attrs);
    }

    std::variant<PathType, ECM> get_path_type(std::string path)
    {
        SR info = stat(path);
        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).type;
        }
        else
        {
            return std::get<ECM>(info);
        }
    }

    BR exists(std::string path)
    {
        if (!amsession->sftp)
        {
            return std::make_pair(EC::NoConnection, "SFTP not initialized");
        }
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        EC rc;
        int rct;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rct = libssh2_sftp_stat(amsession->sftp, path.c_str(), &attrs);
        }
        if (rct != 0)
        {
            rc = GetLastEC();
            std::string msg = fmt::format("stat {} failed: {}", path, GetLastErrorMsg());
            switch (rc)
            {
            case EC::PathNotExist:
                return false;
            case EC::PermissionDenied:
                return std::make_pair(rc, fmt::format("No Permission to access path: {}", path));
            default:
                trace(AMERROR, rc, fmt::format("{}@{}", request.nickname, path), "Exists", msg);
                return std::make_pair(rc, msg);
            }
        }
        return true;
    }

    BR is_regular(std::string path)
    {
        SR info = stat(path);
        if (std::holds_alternative<PathInfo>(info))
        {
            return std::get<PathInfo>(info).type == PathType::FILE ? true : false;
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
            return std::get<PathInfo>(info).type == PathType::DIR ? true : false;
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
            return std::get<PathInfo>(info).type == PathType::SYMLINK ? true : false;
        }
        else
        {
            return std::get<ECM>(info);
        }
    }

    LR listdir(std::string path, long max_time_ms = -1)
    {
        if (!amsession->sftp)
        {
            return std::make_pair(EC::NoConnection, "SFTP not initialized");
        }
        std::string msg = "";
        std::vector<PathInfo> file_list = {};
        BR br = is_dir(path);
        double start_time = timenow();
        double end_time = start_time;
        double max_time = max_time_ms / 1000.0;

        if (std::holds_alternative<bool>(br))
        {
            if (!std::get<bool>(br))
            {
                return std::make_pair(EC::NotADirectory, fmt::format("Path is not a directory: {}", path));
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

        std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
        sftp_handle = libssh2_sftp_open_ex(
            amsession->sftp,
            normalized_path.c_str(),
            normalized_path.size(),
            0,
            LIBSSH2_SFTP_OPENDIR,
            LIBSSH2_FXF_READ);

        if (!sftp_handle)
        {
            std::string tmp_msg = GetLastErrorMsg();
            trace(AMWARNING, EC::InvalidHandle, fmt::format("{}@{}", request.nickname, path), "ListDir", tmp_msg);
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
            if (max_time_ms > 0)
            {
                end_time = timenow();
                if (end_time - start_time > max_time)
                {
                    is_sucess = true;
                    break;
                }
            }

            if (rct < 0)
            {
                rc = GetLastEC();
                std::string tmp_msg = GetLastErrorMsg();
                trace(AMWARNING, rc, fmt::format("{}@{}", request.nickname, path), "ListDir", tmp_msg);
                msg = fmt::format("Path: {} readdir failed: {}", path, tmp_msg);
                goto clean;
            }
            else if (rct == 0)
            {
                is_sucess = true;
                break;
            }
            name.assign(filename_buffer.data(), rct);

            if (name == "." || name == "..")
            {
                continue;
            }

            path_i = AMFS::join(normalized_path, name);
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
        if (!amsession->sftp)
        {
            return std::make_pair(EC::NoConnection, "SFTP not initialized");
        }
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
                return {EC::FileAlreadyExists, fmt::format("Path exists and is not a directory: {}", path)};
            }
            else
            {
                return {EC::Success, ""};
            }
        }
        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rcr = libssh2_sftp_mkdir_ex(amsession->sftp, path.c_str(), path.size(), 0740);
        }

        if (rcr != 0)
        {
            EC rc = GetLastEC();
            std::string msg_tmp = GetLastErrorMsg();
            msg = fmt::format("Path: {} mkdir failed: {}", path, msg_tmp);
            trace(AMWARNING, rc, fmt::format("{}@{}", request.nickname, path), "Mkdir", msg_tmp);
            return {rc, msg};
        }
        return {EC::Success, ""};
    }

    ECM mkdirs(std::string path)
    {
        if (!amsession->sftp)
        {
            return std::make_pair(EC::NoConnection, "SFTP not initialized");
        }
        if (path.empty())
        {
            return {EC::InvalidArg, "path parameter can't be an empty string"};
        }

        std::replace(path.begin(), path.end(), '\\', '/');
        std::vector<std::string> parts = AMFS::split(path);
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
            current_path = AMFS::join(current_path, part);

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
        if (!amsession->sftp)
        {
            return std::make_pair(EC::NoConnection, "SFTP not initialized");
        }
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
            PathType type = std::get<PathInfo>(info).type;
            switch (type)
            {
            case PathType::DIR:
                msg = fmt::format("Path is not a file: {}", path);
                return {EC::NotAFile, msg};
            case PathType::SYMLINK:
            {
            }
            case PathType::FILE:
            {
            }
            default:
            {
                msg = fmt::format("Path is special file: {}", path);
                return {EC::OperationUnsupported, msg};
            }
            }
        }
        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rcr = libssh2_sftp_unlink(amsession->sftp, path.c_str());
        }

        if (rcr != 0)
        {
            rc = GetLastEC();
            std::string tmp_msg = GetLastErrorMsg();
            msg = fmt::format("rmfile {} failed: {}", path, tmp_msg);
            trace(AMWARNING, rc, fmt::format("{}@{}", request.nickname, path), "Rmfile", tmp_msg);
            return {rc, msg};
        }
        return {EC::Success, ""};
    }

    ECM rmdir(std::string path)
    {
        if (!amsession->sftp)
        {
            return std::make_pair(EC::NoConnection, "SFTP not initialized");
        }
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
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rcr = libssh2_sftp_rmdir(amsession->sftp, path.c_str());
        }
        if (rcr < 0)
        {
            rc = GetLastEC();
            std::string tmp_msg = GetLastErrorMsg();
            msg = fmt::format("Path: {} rmdir failed: {}", path, tmp_msg);
            trace(AMWARNING, rc, fmt::format("{}@{}", request.nickname, path), "Rmdir", tmp_msg);
            return {rc, msg};
        }
        return {EC::Success, ""};
    }

    std::variant<RMR, ECM> remove(std::string path)
    {
        if (!amsession->sftp)
        {
            return ECM{EC::NoConnection, "SFTP not initialized"};
        }
        RMR errors = {};
        _rm(path, errors);
        return errors;
    }

    ECM saferm(std::string path)
    {
        if (!amsession->sftp)
        {
            return ECM{EC::NoConnection, "SFTP not initialized"};
        }
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
            return {EC::NotADirectory, fmt::format("Trash dir not ready: {}", this->trash_dir)};
        }
        std::string base = AMFS::basename(path);
        std::string target_path;
        std::string base_name = base;
        std::string base_ext = "";
        size_t dot_pos = base.find_last_of('.');
        if (dot_pos != std::string::npos)
        {
            base_name = base.substr(0, dot_pos);
            base_ext = base.substr(dot_pos);
        }

        target_path = AMFS::join(trash_dir, base);
        size_t i = 1;
        br = exists(target_path);
        if (std::holds_alternative<ECM>(br))
        {
            return std::get<ECM>(br);
        }
        while (std::holds_alternative<bool>(br) && std::get<bool>(br))
        {
            target_path = AMFS::join(trash_dir, base_name + std::string("_") + std::to_string(i) + base_ext);
            i++;
            br = exists(target_path);
        }
        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rcr = libssh2_sftp_rename(amsession->sftp, path.c_str(), target_path.c_str());
        }
        EC rc;
        if (rcr != 0)
        {
            rc = GetLastEC();
            std::string msg = GetLastErrorMsg();

            return {rc, fmt::format("Rename {} to {} failed: {}", path, target_path, msg)};
        }
        return {EC::Success, ""};
    }

    ECM rename(std::string src, std::string newname)
    {
        std::string src_dir = AMFS::dirname(src);
        std::string dst_path = AMFS::join(src_dir, newname);
        return move(src, dst_path);
    }

    ECM move(std::string src, std::string dst, bool need_mkdir = false, bool force_write = false)
    {
        if (!amsession->sftp)
        {
            return ECM{EC::NoConnection, "SFTP not initialized"};
        }
        SR sr = stat(src);
        ECM ecm;

        if (std::holds_alternative<ECM>(sr))
        {
            return std::get<ECM>(sr);
        }
        PathInfo src_stat = std::get<PathInfo>(sr);

        std::string src_base = AMFS::basename(src);
        std::string dst_dir = dst;
        std::string dst_path = AMFS::join(dst_dir, src_base);
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
                return {EC::FileAlreadyExists, fmt::format("Dst already exists: {} but not a directory", dst_dir)};
            }
        }

        SR dst_stat = stat(dst_path);
        if (std::holds_alternative<PathInfo>(dst_stat))
        {
            PathInfo dst_stat_info = std::get<PathInfo>(dst_stat);
            if (!force_write)
            {
                return {EC::FileAlreadyExists, fmt::format("Dst already exists: {}", dst_path)};
            }
            if ((dst_stat_info.type == PathType::DIR) != (src_stat.type == PathType::DIR))
            {
                return {EC::FileAlreadyExists, fmt::format("Dst already exists and has different type with src: {}", dst_path)};
            }
        }

        int rcr;
        {
            std::lock_guard<std::recursive_mutex> lock(amsession->mtx);
            rcr = libssh2_sftp_rename_ex(amsession->sftp, src.c_str(), src.size(), dst_path.c_str(), dst_path.size(), LIBSSH2_SFTP_RENAME_OVERWRITE);
        }

        EC rc;
        std::string msg = "";
        if (rcr != 0)
        {
            rc = GetLastEC();
            std::string msg_tmp = GetLastErrorMsg();
            msg = fmt::format("Move {} to {} failed: {}", src, dst_path, msg_tmp);
            if (rc != EC::PermissionDenied && rc != EC::PathNotExist && rc != EC::FileAlreadyExists)
            {
                trace(AMWARNING, rc, fmt::format("{}@{}->{}", request.nickname, src, dst_path), "Move", msg_tmp);
            }
            return {rc, msg};
        }

        return {EC::Success, ""};
    }

    ECM copy(std::string src, std::string dst, bool need_mkdir = false)
    {
        if (!amsession->sftp)
        {
            return ECM{EC::NoConnection, "SFTP not initialized"};
        }
        BR br = exists(src);
        if (std::holds_alternative<ECM>(br))
        {
            return std::get<ECM>(br);
        }
        else if (!std::get<bool>(br))
        {

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

                    return {EC::ParentDirectoryNotExist, fmt::format("Dst dir not exists: {}", dst)};
                }
            }
        }
        else if (!std::get<bool>(br))
        {

            return {EC::PathNotExist, fmt::format("Dst exists but not a directory: {}", dst)};
        }

        std::string command = "cp -r \"" + src + "\" \"" + dst + "\"";
        SafeChannel channel(amsession);
        if (!channel.channel)
        {
            std::string msg = fmt::format("Channel creation failed: {}", channel.error_msg);
            trace(AMCRITICAL, channel.error_code, fmt::format("{}@{}", request.nickname, src), "Copy", msg);
            return {channel.error_code, msg};
        }
        CR cr = channel.ConductCmd(command);

        if (std::holds_alternative<ECM>(cr))
        {
            return std::get<ECM>(cr);
        }
        std::pair<std::string, int> resp = std::get<std::pair<std::string, int>>(cr);

        if (resp.second != 0)
        {
            std::string msg = fmt::format("Copy cmd conducted failed with exit code: {}, error: {}", resp.second, resp.first);
            trace(AMWARNING, EC::InhostCopyFailed, fmt::format("{}@{}->{}", request.nickname, src, dst), "Copy", msg);
            return {EC::InhostCopyFailed, msg};
        }

        return {EC::Success, ""};
    }

    WRV iwalk(std::string path, bool ignore_sepcial_file = true)
    {
        // 搜索某一路径下的所有文件, 返回pathinfo的vector
        if (!amsession->sftp)
        {
            return {};
        }
        // get all files and deepest folders
        WRV result = {};
        _iwalk(path, result, ignore_sepcial_file);
        return result;
    }

    std::variant<WRD, ECM> walk(std::string path, int max_depth = -1, bool ignore_special_file = true)
    {
        // 真正的walk函数, 返回pathinfo的嵌套dict, 键为目录名的字符串, 值为pathinfo, 无下级的目录值为空dict
        // 数据类型[([root_path, part1, part2, ...], PathInfo)]
        BR br = exists(path);
        if (!std::holds_alternative<bool>(br))
        {
            return std::get<ECM>(br);
        }
        else if (!std::get<bool>(br))
        {
            return ECM{EC::NotADirectory, fmt::format("Path is not a directory: {}", path)};
        }
        WRD result_dict = {};
        std::vector<std::string> parts = {path};
        _walk(parts, result_dict, 0, max_depth, ignore_special_file);
        // 打印result_dict的类型
        return result_dict;
    }

    SIZER getsize(std::string path, bool ignore_sepcial_file = true)
    {
        if (!amsession->sftp)
        {
            return ECM{EC::NoConnection, "SFTP not initialized"};
        }
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

class Hostd
{
private:
    std::unordered_map<std::string, std::shared_ptr<AMSFTPClient>> hosts;
    std::unordered_map<std::string, ECM> host_status;

public:
    Hostd()
    {
    }

    std::vector<std::string> get_hosts()
    {
        std::vector<std::string> host_list;
        for (auto &host : hosts)
        {
            host_list.push_back(host.first);
        }
        return host_list;
    }

    void add_host(std::string host, std::shared_ptr<AMSFTPClient> client, bool overwrite = false)
    {
        if (hosts.find(host) != hosts.end() && !overwrite)
        {
            return;
        }
        hosts[host] = client;
    }

    void remove_host(std::string host)
    {
        if (hosts.find(host) != hosts.end())
        {
            hosts.erase(host);
        }
        if (host_status.find(host) != host_status.end())
        {
            host_status.erase(host);
        }
    }

    std::shared_ptr<AMSFTPClient> get_host(std::string host)
    {
        if (hosts.find(host) == hosts.end())
        {
            return nullptr;
        }
        return hosts[host];
    }

    ECM test_host(std::string host)
    {
        if (hosts.find(host) == hosts.end())
        {
            return ECM{EC::NoSession, "Client not found"};
        }
        if (host_status.find(host) != host_status.end())
        {
            return host_status[host];
        }
        auto client = hosts[host];
        auto rc = client->Check();
        host_status[host] = rc;
        return rc;
    }

    void reset()
    {
        host_status.clear();
    }
};

class AMSFTPWorker
{
private:
    inline void InnerCallback(const std::string &src, const std::string &dst, const std::string &src_host, const std::string &dst_host, uint64_t this_size, uint64_t file_size, uint64_t accumulated_size, uint64_t total_size)
    {
        if (callback.need_progress_cb)
        {
            auto time_now = timenow();
            if ((time_now - cb_time) > cb_interval_s)
            {
                cb_time = time_now;
                py::gil_scoped_acquire acquire;
                py::object result = callback.progress_cb(ProgressCBInfo(src, dst, src_host, dst_host, this_size, file_size, accumulated_size, total_size));
                if (!result.is_none())
                {
                    if (py::isinstance<TransferControl>(result))
                    {
                        auto control = result.cast<TransferControl>();
                        switch (control)
                        {
                        case TransferControl::Pause:
                            pause();
                            break;
                        case TransferControl::Terminate:
                            terminate();
                            break;
                        default:
                            break;
                        }
                    }
                }
            }
        }
    }

    ECM Local2Local(const std::string &src, const std::string &dst, uint64_t chunk_size)
    {
        ErrorCode rc_r = EC::Success;
        std::string error_msg = "";
        FileMapper srcm(src, MapType::Read, error_msg);
        if (!srcm.file_ptr)
        {
            EC rc = EC::LocalFileMapError;
            return {rc, error_msg};
        }
        AMFS::mkdirs(AMFS::dirname(dst));
        FileMapper dstm(dst, MapType::Write, error_msg);
        if (!dstm.file_ptr)
        {
            EC rc = EC::LocalFileMapError;
            return {rc, error_msg};
        }

        uint64_t offset = 0;
        uint64_t remaining = srcm.file_size;
        uint64_t buffer_size;
        uint64_t local_size = 0;
        py::object result;
        char *src_ptr = static_cast<char *>(srcm.file_ptr);
        char *dst_ptr = static_cast<char *>(dstm.file_ptr);

        double time_end = timenow();

        while (remaining > 0)
        {

            local_size = 0;
            buffer_size = std::min<uint64_t>(chunk_size, remaining);

            while (local_size < buffer_size)
            {
                // 使用两个文件映射进行读写
                CopyMemory(dst_ptr + offset, src_ptr + offset, static_cast<SIZE_T>(buffer_size));
            }

            remaining -= buffer_size;
            offset += buffer_size;
            current_size += buffer_size;
            InnerCallback(src, dst, "", "", offset, srcm.file_size, current_size, total_size);

            while (IsPause() && !IsTerminate())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }

            if (IsTerminate())
            {
                rc_r = EC::Terminate;
                error_msg = "Transfer cancelled";
                goto clean;
            }
        }

    clean:
        if (callback.need_progress_cb)
        {
            py::gil_scoped_acquire acquire;
            callback.progress_cb(ProgressCBInfo(src, dst, "", "", offset, srcm.file_size, current_size, total_size));
        }

        return {rc_r, error_msg};
    }

    ECM Local2Remote(const std::string &src, const std::string &dst, std::shared_ptr<AMSFTPClient> client, uint64_t chunk_size)
    {
        ErrorCode rc_r = EC::Success;
        long rct;
        LIBSSH2_SFTP_HANDLE *sftpFile;
        std::string error_msg = "Error to create FileMapper";
        std::lock_guard<std::recursive_mutex> lock(client->amsession->mtx);

        sftpFile = libssh2_sftp_open(client->amsession->sftp, dst.c_str(), LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0744);
        if (!sftpFile)
        {
            rct = libssh2_sftp_last_error(client->amsession->sftp);
            if (rct == LIBSSH2_FX_NO_SUCH_FILE)
            {
                client->mkdirs(AMFS::dirname(dst));
                sftpFile = libssh2_sftp_open(client->amsession->sftp, dst.c_str(), LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT, 0744);
                if (!sftpFile)
                {
                    std::string msg = fmt::format("Failed to open remote file: {}, cause {}", dst, client->GetLastErrorMsg());
                    client->trace(AMERROR, client->GetLastEC(), fmt::format("{}@{}", client->request.nickname, dst), "Remote2Local", msg);
                    return {client->GetLastEC(), msg};
                }
            }
            else
            {
                std::string msg = fmt::format("Failed to open remote file: {}, cause {}", dst, client->GetLastErrorMsg());
                rc_r = client->GetLastEC();
                client->trace(AMERROR, rc_r, fmt::format("{}@{}", client->request.nickname, dst), "Remote2Local", msg);
                return {rc_r, msg};
            }
        }

        FileMapper l_file_m(src, MapType::Read, error_msg);
        if (!l_file_m.file_ptr)
        {
            libssh2_sftp_close_handle(sftpFile);
            EC rc = EC::LocalFileMapError;
            return {rc, error_msg};
        }

        uint64_t offset = 0;
        uint64_t remaining = l_file_m.file_size;
        uint64_t buffer_size;
        uint64_t local_size = 0;
        py::object result;

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
                    rc_r = EC::ConnectionLost;
                    error_msg = fmt::format("Sftp write error: {}", client->GetLastErrorMsg());
                    goto clean;
                }
            }

            remaining -= buffer_size;
            offset += buffer_size;
            current_size += buffer_size;
            InnerCallback(src, dst, "", client->Nickname(), offset, l_file_m.file_size, current_size, total_size);

            while (IsPause() && !IsTerminate())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            if (IsTerminate())
            {
                rc_r = EC::Terminate;
                error_msg = "Transfer cancelled";
                goto clean;
            }
        }
    clean:
        if (callback.need_progress_cb)
        {
            py::gil_scoped_acquire acquire;
            callback.progress_cb(ProgressCBInfo(src, dst, "", client->Nickname(), offset, l_file_m.file_size, current_size, total_size));
        }

        if (sftpFile)
        {
            libssh2_sftp_close_handle(sftpFile);
        }

        return {rc_r, error_msg};
    }

    ECM Remote2Local(const std::string &src, const std::string &dst, std::shared_ptr<AMSFTPClient> client, uint64_t chunk_size)
    {
        EC rc_r = EC::Success;
        LIBSSH2_SFTP_HANDLE *sftpFile;
        std::string error_msg = "";
        std::lock_guard<std::recursive_mutex> lock(client->amsession->mtx);
        sftpFile = libssh2_sftp_open(client->amsession->sftp, src.c_str(), LIBSSH2_FXF_READ, 0400);
        if (!sftpFile)
        {
            rc_r = client->GetLastEC();
            std::string msg = fmt::format("Failed to open remote file: {}, cause {}", src, client->GetLastErrorMsg());
            client->trace(AMERROR, rc_r, fmt::format("{}@{}", client->request.nickname, src), "Remote2Local", msg);
            return {rc_r, msg};
        }

        LIBSSH2_SFTP_ATTRIBUTES attrs;
        libssh2_sftp_fstat(sftpFile, &attrs);
        uint64_t file_size = attrs.filesize;
        if (file_size == 0)
        {
            rc_r = client->GetLastEC();
            error_msg = fmt::format("Failed to get remote file size, cause {}", src, client->GetLastErrorMsg());
            libssh2_sftp_close_handle(sftpFile);
            client->trace(AMERROR, rc_r, fmt::format("{}@{}", client->request.nickname, src), "Remote2Local", error_msg);
            return {rc_r, error_msg};
        }

        AMFS::mkdirs(AMFS::dirname(dst));
        FileMapper l_file_m(dst, MapType::Write, error_msg, file_size);

        if (!l_file_m.file_ptr)
        {
            rc_r = EC::LocalFileMapError;
            libssh2_sftp_close_handle(sftpFile);
            client->trace(AMERROR, rc_r, fmt::format("Local@{}", dst), "Remote2Local", error_msg);
            return {rc_r, error_msg};
        }

        uint64_t buffer_size;
        uint64_t offset = 0;
        uint64_t local_size = 0;
        double time_end = timenow();
        long bytes;
        py::object result;

        while (offset < file_size)
        {
            buffer_size = std::min<uint64_t>(chunk_size, file_size - offset);
            local_size = 0;
            while (local_size < buffer_size)
            {
                bytes = libssh2_sftp_read(sftpFile, l_file_m.file_ptr + offset + local_size, buffer_size - local_size);
                if (bytes > 0)
                {
                    local_size += bytes;
                }

                else if (bytes == 0)
                {
                    if (offset < file_size)
                    {
                        rc_r = EC::UnexpectedEOF;
                    }
                    goto clean;
                }
                else
                {
                    rc_r = EC::ConnectionLost;
                    error_msg = fmt::format("Sftp read error: {}", client->GetLastErrorMsg());
                    goto clean;
                }
            }
            offset += buffer_size;
            current_size += buffer_size;
            InnerCallback(src, dst, client->Nickname(), "", offset, file_size, current_size, total_size);

            while (IsPause() && !IsTerminate())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            if (IsTerminate())
            {
                rc_r = EC::Terminate;
                error_msg = "Transfer cancelled";
                goto clean;
            }
        }

    clean:
        if (callback.need_progress_cb)
        {
            py::gil_scoped_acquire acquire;
            callback.progress_cb(ProgressCBInfo(src, dst, client->Nickname(), "", offset, file_size, current_size, total_size));
        }
        if (sftpFile)
        {
            libssh2_sftp_close_handle(sftpFile);
        }
        return {rc_r, error_msg};
    }

    ECM Bridge(const std::string &src, const std::string &dst, std::shared_ptr<AMSFTPClient> src_worker, std::shared_ptr<AMSFTPClient> dst_worker, uint64_t chunk_size = 256 * AMKB)
    {
        std::shared_ptr<AMSession> src_session;
        std::shared_ptr<AMSession> dst_session;

        ErrorCode rc_final = EC::Success;
        std::string error_msg = "";
        long rct;
        LIBSSH2_SFTP_HANDLE *srcFile;
        LIBSSH2_SFTP_HANDLE *dstFile;
        std::lock_guard<std::recursive_mutex> lock(src_session->mtx);
        std::lock_guard<std::recursive_mutex> lock2(dst_session->mtx);
        srcFile = libssh2_sftp_open(src_session->sftp, src.c_str(), LIBSSH2_FXF_READ, 0400);
        dstFile = libssh2_sftp_open(dst_session->sftp, dst.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);

        if (!srcFile)
        {
            rc_final = src_worker->GetLastEC();
            error_msg = fmt::format("Failed to open src remote file: {}, cause {}", src, src_worker->GetLastErrorMsg());
            src_worker->trace(AMERROR, rc_final, fmt::format("{}@{}", src_worker->request.nickname, src), "Remote2Remote", error_msg);
            return {rc_final, error_msg};
        }

        if (!dstFile)
        {
            rct = libssh2_sftp_last_error(dst_session->sftp);
            if (rct == LIBSSH2_FX_NO_SUCH_FILE)
            {
                ECM tmp_rc = dst_worker->Check();
                dstFile = libssh2_sftp_open(dst_session->sftp, dst.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0744);
                if (!dstFile)
                {
                    rc_final = dst_worker->GetLastEC();
                    error_msg = fmt::format("Failed to open dst remote file: {}, cause {}", dst, dst_worker->GetLastErrorMsg());
                    dst_worker->trace(AMERROR, rc_final, fmt::format("{}@{}", dst_worker->request.nickname, dst), "Remote2Remote", error_msg);
                    return {rc_final, error_msg};
                }
            }
            else
            {
                rc_final = dst_worker->GetLastEC();
                error_msg = fmt::format("Failed to open dst remote file: {}, cause {}", dst, dst_worker->GetLastErrorMsg());
                dst_worker->trace(AMERROR, rc_final, fmt::format("{}@{}", dst_worker->request.nickname, dst), "Remote2Remote", error_msg);
                return {rc_final, error_msg};
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

        libssh2_session_set_blocking(src_session->session, 0);
        libssh2_session_set_blocking(dst_session->session, 0);
        uint64_t read_eagain_count = 0;
        uint64_t write_eagain_count = 0;
        py::object result;

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
                        if (read_eagain_count > 1000 && read_eagain_count % 50 == 0)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(20));
                        }
                        break;
                    }
                    else if (rc_read < 0)
                    {
                        rc_final = src_worker->GetLastEC();
                        error_msg = fmt::format("Sftp read error: {}", src_worker->GetLastErrorMsg());
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
                        if (write_eagain_count > 1000 && write_eagain_count % 50 == 0)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(20));
                        }
                        break;
                    }
                    else if (rc_write < 0)
                    {
                        rc_final = dst_worker->GetLastEC();
                        error_msg = fmt::format("Sftp write error: {}", dst_worker->GetLastErrorMsg());
                        goto clean;
                    }
                } while (rc_write > 0 && ctx.bufferd[wbuffer].written < ctx.bufferd[wbuffer].read);

                if (ctx.bufferd[wbuffer].written == ctx.bufferd[wbuffer].read)
                {
                    time_end = timenow();
                    current_size += ctx.bufferd[wbuffer].written;
                    InnerCallback(src, dst, src_worker->Nickname(), dst_worker->Nickname(), all_write, file_size, current_size, total_size);

                    while (IsPause() && !IsTerminate())
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }

                    if (IsTerminate())
                    {
                        rc_final = EC::Terminate;
                        error_msg = "Transfer cancelled";
                        goto clean;
                    }

                    ctx.finish_write(wbuffer, write_order++);
                    break;
                }
            }
        }

    clean:
        libssh2_session_set_blocking(src_session->session, 1);
        libssh2_session_set_blocking(dst_session->session, 1);

        if (callback.need_progress_cb)
        {
            py::gil_scoped_acquire acquire;
            callback.progress_cb(ProgressCBInfo(src, dst, src_worker->Nickname(), dst_worker->Nickname(), all_write, file_size, current_size, total_size));
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
    TransferCallback callback;
    float cb_interval_s;
    std::atomic<bool> is_terminate = false;
    std::atomic<bool> is_pause = false;
    uint64_t current_size = 0;
    long long total_size = 0;
    std::string current_filename = "";
    double cb_time = timenow();

    double getRTT(std::shared_ptr<AMSFTPClient> client, uint64_t times = 5)
    {
        double total_time = 0;
        double time_start;
        double time_end;
        int rc;
        for (uint64_t i = 0; i < times; i++)
        {
            SafeChannel channel(client->amsession);
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

    AMSFTPWorker(TransferCallback callback = TransferCallback(), float cb_interval_s = 0.2) : callback(callback), cb_interval_s(cb_interval_s) {}

    inline void reset()
    {
        cb_time = timenow();
        current_size = 0;
        total_size = 0;
        current_filename = "";
        is_terminate.store(false, std::memory_order_relaxed);
        is_pause.store(false, std::memory_order_relaxed);
    }

    inline void terminate()
    {
        is_terminate.store(true, std::memory_order_release);
    }

    inline void pause()
    {
        is_pause.store(true, std::memory_order_relaxed);
    }

    inline void resume()
    {
        is_pause.store(false, std::memory_order_release);
    }

    inline bool IsTerminate()
    {
        return is_terminate.load(std::memory_order_acquire);
    }

    inline bool IsPause()
    {
        return is_pause.load(std::memory_order_acquire);
    }

    inline bool IsRunning()
    {
        return !is_terminate.load(std::memory_order_acquire) && !is_pause.load(std::memory_order_acquire);
    }

    inline void set_cb_interval(float interval_s)
    {
        this->cb_interval_s = interval_s;
    }

    TASKS EraseOverlapTasks(TASKS &tasks)
    {
        std::unordered_set<std::string> dst_set{};
        TASKS result{};
        std::string task_id;
        for (auto &task : tasks)
        {
            task_id = task.src + task.src_host + task.dst + task.dst_host;
            if (dst_set.count(task_id) == 0)
            {
                dst_set.insert(task_id);
                result.push_back(task);
            }
        }
        return result;
    }

    TASKS transfer(TASKS tasks, Hostd hostd, uint64_t chunk_large = 16 * AMMB, uint64_t chunk_middle = 2 * AMMB, uint64_t chunk_small = 256 * AMKB)
    {
        if (tasks.empty())
        {
            return {};
        }

        std::unordered_map<std::string, std::string> host_status{};
        reset();

        if (callback.need_total_size_cb)
        {
            uint64_t total_size = 0;
            for (auto &task : tasks)
            {
                total_size += task.size;
            }
            py::gil_scoped_acquire acquire;
            callback.total_size_cb(total_size);
        }
        std::string src_path;
        std::string dst_path;
        std::string src_host;
        std::string dst_host;
        std::shared_ptr<AMSFTPClient> src_client;
        std::shared_ptr<AMSFTPClient> dst_client;
        ECM rc;

        tasks = EraseOverlapTasks(tasks);
        for (auto &task : tasks)
        {
            if (task.IsSuccess)
            {
                // 跳过在load_tasks中，未设置overlap且dst已经存在的任务
                continue;
            }

            if (callback.need_progress_cb)
            {
                py::gil_scoped_acquire acquire;
                callback.progress_cb(ProgressCBInfo(task.src, task.dst, task.src_host, task.dst_host, 0, task.size, current_size, total_size));
            }

            if (IsTerminate())
            {
                rc = ECM(EC::Terminate, "Transfer cancelled");
                goto check;
            }
            src_host = task.src_host;
            dst_host = task.dst_host;

            if (task.path_type == PathType::DIR)
            {
                if (dst_host.empty())
                {
                    std::string errors = AMFS::mkdirs(task.dst);
                    if (!errors.empty())
                    {
                        rc = ECM(EC::UnknownError, errors);
                        goto check;
                    }
                    goto check;
                }
                rc = hostd.test_host(dst_host);
                if (rc.first != EC::Success)
                {
                    goto check;
                }
                dst_client = hostd.get_host(dst_host);
                if (!dst_client)
                {
                    rc = ECM(EC::NoSession, "Destination SFTP Client not found");
                    goto check;
                }
                rc = dst_client->mkdirs(task.dst);
                goto check;
            }

            if (src_host.empty() && dst_host.empty())
            {
                // local2local
                rc = Local2Local(task.src, task.dst, chunk_large);
            }
            else if (src_host.empty() && !dst_host.empty())
            {
                // local2remote
                rc = hostd.test_host(dst_host);
                if (rc.first != EC::Success)
                {
                    goto check;
                }
                dst_client = hostd.get_host(dst_host);
                if (!dst_client)
                {
                    rc = ECM(EC::NoSession, "Destination SFTP Client not found");
                    goto check;
                }
                rc = Local2Remote(task.src, task.dst, dst_client, chunk_middle);
            }
            else if (!src_host.empty() && dst_host.empty())
            {
                // remote2local
                rc = hostd.test_host(src_host);
                if (rc.first != EC::Success)
                {
                    goto check;
                }
                src_client = hostd.get_host(src_host);
                if (!src_client)
                {
                    rc = ECM(EC::NoSession, "Source SFTP Client not found");
                    goto check;
                }
                rc = Remote2Local(task.src, task.dst, src_client, chunk_middle);
            }
            else
            {
                // remote2remote
                rc = hostd.test_host(src_host);
                if (rc.first != EC::Success)
                {
                    goto check;
                }
                rc = hostd.test_host(dst_host);
                if (rc.first != EC::Success)
                {
                    goto check;
                }
                src_client = hostd.get_host(src_host);
                if (!src_client)
                {
                    rc = ECM(EC::NoSession, "Source SFTP Client not found");
                    goto check;
                }
                dst_client = hostd.get_host(dst_host);
                if (!dst_client)
                {
                    rc = ECM(EC::NoSession, "Destination SFTP Client not found");
                    goto check;
                }
                rc = Bridge(task.src, task.dst, src_client, dst_client, chunk_small);
            }
        check:
            task.rc = rc;
            if (rc.first != EC::Success)
            {
                if (callback.need_error_cb && rc.first != EC::Terminate)
                {
                    py::gil_scoped_acquire acquire;
                    callback.error_cb(ErrorCBInfo(rc, src_path, dst_path, src_host, dst_host));
                }
            }
            else
            {
                task.IsSuccess = true;
            }
        }

        return tasks;
    }

    std::pair<TASKS, ECM> load_tasks(std::string src, std::string dst, Hostd hostd, std::string src_hostname = "", std::string dst_hostname = "", bool overwrite = false, bool ignore_sepcial_file = true)
    {
        WRV result = {};
        TASKS tasks = {};
        ECM rc;
        PathInfo src_stat;
        std::shared_ptr<AMSFTPClient> src_client;
        // 去除src的dst左右端的空格
        hostd.reset();
        if (src_hostname.empty())
        {
            auto [error, src_stat] = AMFS::stat(src);
            if (!error.empty())
            {
                return {tasks, ECM(EC::LocalStatError, error)};
            }
        }
        else
        {
            rc = hostd.test_host(src_hostname);
            if (rc.first != EC::Success)
            {
                return {tasks, rc};
            }
            src_client = hostd.get_host(src_hostname);
            if (!src_client)
            {
                return {tasks, ECM(EC::NoSession, "Source SFTP Client not found")};
            }
            auto ori_stat = src_client->stat(src);
            if (std::holds_alternative<ECM>(ori_stat))
            {
                return {tasks, std::get<ECM>(ori_stat)};
            }
            src_stat = std::get<PathInfo>(ori_stat);
        }

        bool is_dst_file = false;
        if (src_stat.type == PathType::FILE)
        {
            // 检查dst的扩展名和src扩展名是否相同
            std::string src_ext = AMFS::extname(src);
            std::string dst_ext = AMFS::extname(dst);
            if (src_ext == dst_ext && !dst_ext.empty())
            {
                is_dst_file = true;
            }
        }

        if (src_stat.type != PathType::DIR)
        {
            if (ignore_sepcial_file && src_stat.type != PathType::FILE)
            {
                return {tasks, ECM(EC::NotAFile, "Target is not a common file and ignore_sepcial_file is true")};
            }
            if (!is_dst_file)
            {
                dst = AMFS::join(dst, AMFS::basename(src));
            }
            tasks.push_back(TransferTask(src, src_hostname, dst, dst_hostname, src_stat.size, src_stat.type));
            return {tasks, ECM(EC::Success, "")};
        }

        result = src_client ? src_client->iwalk(src, ignore_sepcial_file) : AMFS::iwalk(src, ignore_sepcial_file);
        std::string dst_n;
        for (auto &item : result)
        {
            dst_n = AMFS::join(dst, fs::relative(item.path, AMFS::dirname(src)));
            tasks.push_back(TransferTask(item.path, src_hostname, dst_n, dst_hostname, item.size, item.type));
        }
        if (!overwrite)
        {
            auto dst_client = hostd.get_host(dst_hostname);
            if (dst_client && hostd.test_host(dst_hostname).first == EC::Success)
            {
                for (auto &task : tasks)
                {
                    auto is_exist = dst_client->exists(task.dst);
                    if (std::holds_alternative<bool>(is_exist) && std::get<bool>(is_exist))
                    {
                        // 如果dst存在，则修改rc
                        task.rc = ECM(EC::FileAlreadyExists, "Destination file already exists");
                        task.IsSuccess = true;
                    }
                }
            }
        }
        return {tasks, ECM(EC::Success, "")};
    };
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

    auto sub = m.def_submodule("AMFS");

    py::enum_<ErrorCode>(m, "ErrorCode")
        .value("Success", ErrorCode::Success)
        .value("SessionCreateError", ErrorCode::SessionGenericError)
        .value("NoBannerRecv", ErrorCode::NoBannerRecv)
        .value("BannerSendError", ErrorCode::BannerSendError)
        .value("InvalidMacAdress", ErrorCode::InvalidMacAdress)
        .value("KeyExchangeMethodNegotiationFailed", ErrorCode::KeyExchangeMethodNegotiationFailed)
        .value("MemAllocError", ErrorCode::MemAllocError)
        .value("SocketSendError", ErrorCode::SocketSendError)
        .value("KeyExchangeFailed", ErrorCode::KeyExchangeFailed)
        .value("OperationTimeout", ErrorCode::OperationTimeout)
        .value("HostkeyInitFailed", ErrorCode::HostkeyInitFailed)
        .value("HostkeySignFailed", ErrorCode::HostkeySignFailed)
        .value("DataDecryptError", ErrorCode::DataDecryptError)
        .value("SocketDisconnect", ErrorCode::SocketDisconnect)
        .value("SSHProtocolError", ErrorCode::SSHProtocolError)
        .value("PasswordExpired", ErrorCode::PasswordExpired)
        .value("LocalFileError", ErrorCode::LocalFileError)
        .value("NoAuthMethod", ErrorCode::NoAuthMethod)
        .value("AuthFailed", ErrorCode::AuthFailed)
        .value("PublickeyAuthFailed", ErrorCode::PublickeyAuthFailed)
        .value("ChannelOrderError", ErrorCode::ChannelOrderError)
        .value("ChannelOperationError", ErrorCode::ChannelOperationError)
        .value("ChannelRequestDenied", ErrorCode::ChannelRequestDenied)
        .value("ChannelWindowExceeded", ErrorCode::ChannelWindowExceeded)
        .value("ChannelPacketOversize", ErrorCode::ChannelPacketOversize)
        .value("ChannelClosed", ErrorCode::ChannelClosed)
        .value("ChannelAlreadySendEOF", ErrorCode::ChannelAlreadySendEOF)
        .value("SCPProtocolError", ErrorCode::SCPProtocolError)
        .value("ZlibCompressError", ErrorCode::ZlibCompressError)
        .value("SocketOperationTimeout", ErrorCode::SocketOperationTimeout)
        .value("SftpProtocolError", ErrorCode::SftpProtocolError)
        .value("RequestDenied", ErrorCode::RequestDenied)
        .value("InvalidArg", ErrorCode::InvalidArg)
        .value("InvalidPollType", ErrorCode::InvalidPollType)
        .value("PublicKeyProtocolError", ErrorCode::PublicKeyProtocolError)
        .value("SSHEAGAIN", ErrorCode::SSHEAGAIN)
        .value("BufferTooSmall", ErrorCode::BufferTooSmall)
        .value("BadOperationOrder", ErrorCode::BadOperationOrder)
        .value("CompressionError", ErrorCode::CompressionError)
        .value("PointerOverflow", ErrorCode::PointerOverflow)
        .value("SSHAgentProtocolError", ErrorCode::SSHAgentProtocolError)
        .value("SocketRecvError", ErrorCode::SocketRecvError)
        .value("DataEncryptError", ErrorCode::DataEncryptError)
        .value("InvalidSocketType", ErrorCode::InvalidSocketType)
        .value("HostFingerprintMismatch", ErrorCode::HostFingerprintMismatch)
        .value("ChannelWindowFull", ErrorCode::ChannelWindowFull)
        .value("PrivateKeyAuthFailed", ErrorCode::PrivateKeyAuthFailed)
        .value("RandomGenError", ErrorCode::RandomGenError)
        .value("MissingUserAuthBanner", ErrorCode::MissingUserAuthBanner)
        .value("AlgorithmUnsupported", ErrorCode::AlgorithmUnsupported)
        .value("MacAuthFailed", ErrorCode::MacAuthFailed)
        .value("HashInitError", ErrorCode::HashInitError)
        .value("HashCalculateError", ErrorCode::HashCalculateError)
        // positive code represent libssh2 sftp error
        .value("EndOfFile", ErrorCode::EndOfFile)
        .value("FileNotExist", ErrorCode::FileNotExist)
        .value("PermissionDenied", ErrorCode::PermissionDenied)
        .value("CommonFailure", ErrorCode::CommonFailure)
        .value("BadMessageFormat", ErrorCode::BadMessageFormat)
        .value("NoConnection", ErrorCode::NoConnection)
        .value("ConnectionLost", ErrorCode::ConnectionLost)
        .value("OperationUnsupported", ErrorCode::OperationUnsupported)
        .value("InvalidHandle", ErrorCode::InvalidHandle)
        .value("PathNotExist", ErrorCode::PathNotExist)
        .value("FileAlreadyExists", ErrorCode::FileAlreadyExists)
        .value("FileWriteProtected", ErrorCode::FileWriteProtected)
        .value("StorageMediaUnavailable", ErrorCode::StorageMediaUnavailable)
        .value("FilesystemNoSpace", ErrorCode::FilesystemNoSpace)
        .value("SpaceQuotaExceed", ErrorCode::SpaceQuotaExceed)
        .value("UsernameNotExists", ErrorCode::UsernameNotExists)
        .value("PathUsingByOthers", ErrorCode::PathUsingByOthers)
        .value("DirNotEmpty", ErrorCode::DirNotEmpty)
        .value("NotADirectory", ErrorCode::NotADirectory)
        .value("InvalidFilename", ErrorCode::InvalidFilename)
        .value("SymlinkLoop", ErrorCode::SymlinkLoop)
        // following codes are AM Custom Error
        .value("UnknownError", ErrorCode::UnknownError)
        .value("SocketCreateError", ErrorCode::SocketCreateError)
        .value("SocketConnectTimeout", ErrorCode::SocketConnectTimeout)
        .value("SocketConnectFailed", ErrorCode::SocketConnectFailed)
        .value("SessionCreateFailed", ErrorCode::SessionCreateFailed)
        .value("SessionHandshakeFailed", ErrorCode::SessionHandshakeFailed)
        .value("NoSession", ErrorCode::NoSession)
        .value("NotAFile", ErrorCode::NotAFile)
        .value("ParentDirectoryNotExist", ErrorCode::ParentDirectoryNotExist)
        .value("InhostCopyFailed", ErrorCode::InhostCopyFailed)
        .value("LocalFileMapError", ErrorCode::LocalFileMapError)
        .value("UnexpectedEOF", ErrorCode::UnexpectedEOF)
        .value("Terminate", ErrorCode::Terminate)
        .value("UnImplentedMethod", ErrorCode::UnImplentedMethod)
        .value("NoPermissionAttribute", ErrorCode::NoPermissionAttribute)
        .value("LocalStatError", ErrorCode::LocalStatError)
        .value("TransferPause", ErrorCode::TransferPause);

    py::enum_<OS_TYPE>(m, "OS_TYPE")
        .value("Windows", OS_TYPE::Windows)
        .value("Linux", OS_TYPE::Linux)
        .value("MacOS", OS_TYPE::MacOS)
        .value("FreeBSD", OS_TYPE::FreeBSD)
        .value("Unix", OS_TYPE::Unix)
        .value("Unknown", OS_TYPE::Unknown)
        .value("Uncertain", OS_TYPE::Uncertain);

    py::enum_<PathType>(sub, "PathType")
        .value("DIR", PathType::DIR)
        .value("FILE", PathType::FILE)
        .value("SYMLINK", PathType::SYMLINK)
        .value("BLOCK_DEVICE", PathType::BlockDevice)
        .value("CHARACTER_DEVICE", PathType::CharacterDevice)
        .value("SOCKET", PathType::Socket)
        .value("FIFO", PathType::FIFO)
        .value("UNKNOWN", PathType::Unknown);

    py::enum_<TransferControl>(m, "TransferControl")
        .value("Pause", TransferControl::Pause)
        .value("Terminate", TransferControl::Terminate);

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
        .def(py::init<py::object, py::object, py::object>(),
             py::arg("total_size") = py::none(),
             py::arg("error") = py::none(),
             py::arg("progress") = py::none());

    py::class_<ProgressCBInfo>(m, "ProgressCBInfo")
        .def(py::init<std::string, std::string, std::string, std::string, uint64_t, uint64_t, uint64_t, uint64_t>(), py::arg("src"), py::arg("dst"), py::arg("src_host"), py::arg("dst_host"), py::arg("this_size"), py::arg("file_size"), py::arg("accumulated_size"), py::arg("total_size"))
        .def_readwrite("src", &ProgressCBInfo::src)
        .def_readwrite("dst", &ProgressCBInfo::dst)
        .def_readwrite("src_host", &ProgressCBInfo::src_host)
        .def_readwrite("dst_host", &ProgressCBInfo::dst_host)
        .def_readwrite("this_size", &ProgressCBInfo::this_size)
        .def_readwrite("file_size", &ProgressCBInfo::file_size)
        .def_readwrite("accumulated_size", &ProgressCBInfo::accumulated_size)
        .def_readwrite("total_size", &ProgressCBInfo::total_size);

    py::class_<ErrorCBInfo>(m, "ErrorCBInfo")
        .def(py::init<ECM, std::string, std::string, std::string, std::string>(), py::arg("ecm"), py::arg("src"), py::arg("dst"), py::arg("src_host"), py::arg("dst_host"))
        .def_readwrite("ecm", &ErrorCBInfo::ecm)
        .def_readwrite("src", &ErrorCBInfo::src)
        .def_readwrite("dst", &ErrorCBInfo::dst)
        .def_readwrite("src_host", &ErrorCBInfo::src_host)
        .def_readwrite("dst_host", &ErrorCBInfo::dst_host);

    py::class_<AuthCBInfo>(m, "AuthCBInfo")
        .def(py::init<bool, ConRequst, int>(), py::arg("NeedPassword"), py::arg("request"), py::arg("trial_times"))
        .def_readwrite("NeedPassword", &AuthCBInfo::NeedPassword)
        .def_readwrite("request", &AuthCBInfo::request)
        .def_readwrite("trial_times", &AuthCBInfo::trial_times);

    py::class_<TransferTask>(m, "TransferTask")
        .def(py::init<std::string, std::string, std::string, std::string, uint64_t, PathType>(), py::arg("src"), py::arg("src_host"), py::arg("dst"), py::arg("dst_host"), py::arg("size"), py::arg("path_type") = PathType::FILE)
        .def_readwrite("src", &TransferTask::src)
        .def_readwrite("src_host", &TransferTask::src_host)
        .def_readwrite("dst", &TransferTask::dst)
        .def_readwrite("dst_host", &TransferTask::dst_host)
        .def_readwrite("size", &TransferTask::size)
        .def_readwrite("path_type", &TransferTask::path_type);

    py::class_<BaseSFTPClient, std::shared_ptr<BaseSFTPClient>>(m, "BaseSFTPClient")
        .def(py::init<ConRequst, std::vector<std::string>, unsigned int, py::object, py::object>(), py::arg("request"), py::arg("keys"), py::arg("error_num") = 10, py::arg("trace_cb") = py::none(), py::arg("auth_cb") = py::none())
        .def("IsValidKey", &BaseSFTPClient::IsValidKey, py::arg("key"))
        .def("LastTraceError", &BaseSFTPClient::LastTraceError)
        .def("GetAllTraceErrors", &BaseSFTPClient::GetAllTraceErrors)
        .def("GetTraceNum", &BaseSFTPClient::GetTraceNum)
        .def("GetTraceCapacity", &BaseSFTPClient::GetTraceCapacity)
        .def("GetTrashDir", &BaseSFTPClient::GetTrashDir)
        .def("Nickname", &BaseSFTPClient::Nickname)
        .def("SetPyTrace", &BaseSFTPClient::SetPyTrace, py::arg("trace_cb") = py::none())
        .def("SetAuthCallback", &BaseSFTPClient::SetAuthCallback, py::arg("auth_cb") = py::none())
        .def("Check", &BaseSFTPClient::Check)
        .def("Connect", &BaseSFTPClient::Connect)
        .def("Disconnect", &BaseSFTPClient::Disconnect)
        .def("EnsureConnect", &BaseSFTPClient::EnsureConnect)
        .def("GetOSType", &BaseSFTPClient::GetOSType);

    py::class_<AMSFTPClient, BaseSFTPClient, std::shared_ptr<AMSFTPClient>>(m, "AMSFTPClient")
        .def(py::init<ConRequst, std::vector<std::string>, unsigned int, py::object, py::object>(), py::arg("request"), py::arg("keys"), py::arg("error_num") = 10, py::arg("trace_cb") = py::none(), py::arg("auth_cb") = py::none())
        .def("SetTrashDir", &AMSFTPClient::SetTrashDir, py::arg("trash_dir") = "")
        .def("EnsureTrashDir", &AMSFTPClient::EnsureTrashDir)
        .def("chmod", &AMSFTPClient::chmod, py::arg("path"), py::arg("mode"), py::arg("recursive") = false)
        .def("realpath", &AMSFTPClient::realpath, py::arg("path"))
        .def("stat", &AMSFTPClient::stat, py::arg("path"))
        .def("get_path_type", &AMSFTPClient::get_path_type, py::arg("path"))
        .def("exists", &AMSFTPClient::exists, py::arg("path"))
        .def("is_regular", &AMSFTPClient::is_regular, py::arg("path"))
        .def("is_dir", &AMSFTPClient::is_dir, py::arg("path"))
        .def("is_symlink", &AMSFTPClient::is_symlink, py::arg("path"))
        .def("listdir", &AMSFTPClient::listdir, py::arg("path"), py::arg("max_time_ms") = -1)
        .def("mkdir", &AMSFTPClient::mkdir, py::arg("path"))
        .def("mkdirs", &AMSFTPClient::mkdirs, py::arg("path"))
        .def("rmfile", &AMSFTPClient::rmfile, py::arg("path"))
        .def("rmdir", &AMSFTPClient::rmdir, py::arg("path"))
        .def("remove", &AMSFTPClient::remove, py::arg("path"))
        .def("saferm", &AMSFTPClient::saferm, py::arg("path"))
        .def("rename", &AMSFTPClient::rename, py::arg("src"), py::arg("new_name"))
        .def("move", &AMSFTPClient::move, py::arg("src"), py::arg("dst"), py::arg("need_mkdir") = false, py::arg("force_write") = false)
        .def("copy", &AMSFTPClient::copy, py::arg("src"), py::arg("dst"), py::arg("need_mkdir") = false)
        .def("iwalk", &AMSFTPClient::iwalk, py::arg("path"), py::arg("ignore_sepcial_file") = true)
        .def("walk", &AMSFTPClient::walk, py::arg("path"), py::arg("max_depth") = -1, py::arg("ignore_sepcial_file") = true)
        .def("getsize", &AMSFTPClient::getsize, py::arg("path"), py::arg("ignore_sepcial_file") = true);

    py::class_<Hostd>(m, "Hostd")
        .def(py::init<>())
        .def("reset", &Hostd::reset)
        .def("add_host", &Hostd::add_host, py::arg("hostname"), py::arg("client"), py::arg("overwrite") = false)
        .def("remove_host", &Hostd::remove_host, py::arg("hostname"))
        .def("get_host", &Hostd::get_host, py::arg("hostname"))
        .def("get_hosts", &Hostd::get_hosts)
        .def("test_host", &Hostd::test_host, py::arg("hostname"));

    py::class_<AMSFTPWorker>(m, "AMSFTPWorker")
        .def(py::init<TransferCallback, float>(), py::arg("callback") = TransferCallback(), py::arg("cb_interval_s") = 0.1)
        .def("terminate", &AMSFTPWorker::terminate)
        .def("pause", &AMSFTPWorker::pause)
        .def("resume", &AMSFTPWorker::resume)
        .def("IsTerminate", &AMSFTPWorker::IsTerminate)
        .def("IsPause", &AMSFTPWorker::IsPause)
        .def("IsRunning", &AMSFTPWorker::IsRunning)
        .def("reset", &AMSFTPWorker::reset)
        .def("set_cb_interval", &AMSFTPWorker::set_cb_interval, py::arg("interval_s"))
        .def("load_tasks", &AMSFTPWorker::load_tasks, py::arg("src"), py::arg("dst"), py::arg("hostd"), py::arg("src_hostname") = "", py::arg("dst_hostname") = "", py::arg("overwrite") = false, py::arg("ignore_sepcial_file") = true)
        .def("transfer", &AMSFTPWorker::transfer, py::arg("tasks"), py::arg("hostd"), py::arg("chunk_large") = 16 * AMMB, py::arg("chunk_middle") = 2 * AMMB, py::arg("chunk_small") = 256 * AMKB);

    sub.def("IsAbs", &AMFS::IsAbs, py::arg("path"), py::arg("sep") = "")
        .def("HomePath", &AMFS::HomePath)
        .def("extname", &AMFS::extname, py::arg("path"))
        .def("CWD", &AMFS::CWD)
        .def("UnifyPathSep", &AMFS::UnifyPathSep, py::arg("path"), py::arg("sep") = "")
        .def("split", &AMFS::split, py::arg("path"))
        .def("resplit", &AMFS::resplit, py::arg("path"), py::arg("front_esc"), py::arg("back_esc"), py::arg("head") = "")
        .def("realpath", &AMFS::realpath, py::arg("path"), py::arg("force_absolute") = false, py::arg("cwd") = "", py::arg("sep") = "")
        .def("dirname", &AMFS::dirname, py::arg("path"))
        .def("basename", &AMFS::basename, py::arg("path"))
        .def("mkdirs", &AMFS::mkdirs, py::arg("path"))
        .def("stat", &AMFS::stat, py::arg("path"), py::arg("trace_link") = false)
        .def("listdir", &AMFS::listdir, py::arg("path"))
        .def("iwalk", &AMFS::iwalk, py::arg("path"), py::arg("ignore_sepcial_file") = true)
        .def("walk", &AMFS::walk, py::arg("path"), py::arg("max_depth") = -1, py::arg("ignore_sepcial_file") = true)
        .def("extname", &AMFS::extname, py::arg("path"))
        .def("getsize", &AMFS::getsize, py::arg("path"), py::arg("trace_link") = false);

    py::class_<PathInfo>(sub, "PathInfo")
        .def(py::init<std::string, std::string, std::string, std::string, uint64_t, double, double, double, PathType, uint64_t, std::string>(), py::arg("name"), py::arg("path"), py::arg("dir"), py::arg("owner"), py::arg("size"), py::arg("create_time"), py::arg("access_time"), py::arg("modify_time"), py::arg("path_type") = PathType::FILE, py::arg("mode_int") = 0777, py::arg("mode_str") = "rwxrwxrwx")
        .def("FormatTime", &PathInfo::FormatTime, py::arg("time"), py::arg("format") = "%Y-%m-%d %H:%M:%S")
        .def_readwrite("name", &PathInfo::name)
        .def_readwrite("path", &PathInfo::path)
        .def_readwrite("dir", &PathInfo::dir)
        .def_readwrite("owner", &PathInfo::owner)
        .def_readwrite("size", &PathInfo::size)
        .def_readwrite("create_time", &PathInfo::create_time)
        .def_readwrite("access_time", &PathInfo::access_time)
        .def_readwrite("modify_time", &PathInfo::modify_time)
        .def_readwrite("type", &PathInfo::type)
        .def_readwrite("mode_int", &PathInfo::mode_int)
        .def_readwrite("mode_str", &PathInfo::mode_str);
}
