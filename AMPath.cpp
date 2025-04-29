#include "AMPath.hpp"
#include "AMEnum.hpp"
#include <aclapi.h>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fmt/format.h>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sddl.h>
#include <shlwapi.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <windows.h>

namespace fs = std::filesystem;

const std::vector<std::pair<uint64_t, size_t>> GLOBAL_PERMISSIONS_MASK = {
    {0400, 0}, {0200, 1}, {0100, 2}, {0040, 3}, {0020, 4}, {0010, 5}, {0004, 6}, {0002, 7}, {0001, 8}};

const std::regex MODE_STR_PATTERN_RE("^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-]$");

PathInfo::PathInfo()
    : name(""), path(""), dir(""), uname("") {}

PathInfo::PathInfo(std::string name, std::string path, std::string dir, std::string uname, uint64_t size, uint64_t atime, uint64_t mtime, PathType type, uint64_t mode_int, std::string mode_str)
    : name(name), path(path), dir(dir), uname(uname), size(size), atime(atime), mtime(mtime), type(type), mode_int(mode_int), mode_str(mode_str) {}

std::string PathInfo::FormatTime(const uint64_t &time, const std::string &format) const
{
    time_t timeT = static_cast<time_t>(time);

    struct tm timeInfo;

#ifdef _WIN32

    localtime_s(&timeInfo, &timeT);
#else
    localtime_r(&timeT, &timeInfo);
#endif

    std::ostringstream oss;
    oss << std::put_time(&timeInfo, format.c_str());

    return oss.str();
}

std::wstring ansi_to_wstring(const std::string &str)
{
    int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (len <= 0)
        return L"";
    std::wstring result(len - 1, 0); // 去掉结尾的null字符
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &result[0], len);
    return result;
}

// wstring → ANSI (如GBK)
std::string wstring_to_ansi(const std::wstring &wstr)
{
    int len = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return "";
    std::string result(len - 1, 0); // 去掉结尾的null字符
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &result[0], len, nullptr, nullptr);
    return result;
}

std::wstring utf8_to_wstring(const std::string &str)
{
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (len <= 0)
        return L"";
    std::wstring result(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], len);
    return result;
}

// wstring → UTF-8
std::string wstring_to_utf8(const std::wstring &wstr)
{
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return "";
    std::string result(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], len, nullptr, nullptr);
    return result;
}

std::string wstr2str(const std::wstring &wstr)
{
    int bufferSize = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (bufferSize == 0)
        return "";

    std::string result(bufferSize, 0);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &result[0], bufferSize, nullptr, nullptr);
    result.resize(bufferSize - 1);
    return result;
}

bool is_valid_utf8(const std::string &str)
{
    int remaining = 0;
    for (unsigned char c : str)
    {
        if (remaining > 0)
        {
            if ((c & 0xC0) != 0x80)
                return false;
            --remaining;
        }
        else
        {
            if ((c & 0x80) == 0x00)
                continue; // 单字节 0xxxxxxx
            else if ((c & 0xE0) == 0xC0)
                remaining = 1; // 双字节 110xxxxx
            else if ((c & 0xF0) == 0xE0)
                remaining = 2; // 三字节 1110xxxx
            else if ((c & 0xF8) == 0xF0)
                remaining = 3; // 四字节 11110xxx
            else
                return false;
        }
    }
    return (remaining == 0);
}

std::wstring str2wstr(const std::string &str)
{
    if (is_valid_utf8(str))
    {
        return utf8_to_wstring(str);
    }
    return ansi_to_wstring(str);
}

std::string ModeTrans(uint64_t mode_int)
{
    // 把mode_int转换为8进制字符串, 长度为9
    if (mode_int > 0777 || mode_int == 0777)
    {
        return "rwxrwxrwx";
    }
    std::string out = "";
    uint64_t tmp_int;
    uint64_t start = 8 * 8 * 8;
    for (int i = 3; i > 0; i--)
    {
        tmp_int = (mode_int % start) / (start / 8);
        start /= 8;
        switch (tmp_int)
        {
        case 1:
            out += "--x";
            break;
        case 2:
            out += "-w-";
            break;
        case 3:
            out += "-wx";
            break;
        case 4:
            out += "r--";
            break;
        case 5:
            out += "r-x";
            break;
        case 6:
            out += "rw-";
            break;
        case 7:
            out += "rwx";
            break;
        default:
            out += "---";
        }
    }
    return out;
}

uint64_t ModeTrans(std::string mode_str)
{
    std::regex pattern("^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-]$");
    if (!std::regex_match(mode_str, pattern))
    {
        throw std::invalid_argument(fmt::format("Invalid mode string: {}", mode_str));
    }
    uint64_t mode_int = 0;
    for (int i = 0; i < 9; i++)
    {
        if (mode_str[i] != '?' && mode_str[i] != '-')
        {
            mode_int += (1ULL << (8 - i));
        }
    }
    return mode_int;
}

std::string MergeModeStr(std::string base_mode_str, std::string new_mode_str)
{
    std::string pattern_f = "^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-]$";
    std::regex pattern(pattern_f);

    if (!std::regex_match(base_mode_str, pattern))
    {
        throw std::invalid_argument(fmt::format("Invalid base mode string: {}", base_mode_str));
    }

    if (!std::regex_match(new_mode_str, pattern))
    {
        throw std::invalid_argument(fmt::format("Invalid new mode string: {}", new_mode_str));
    }

    std::string mode_str = "";
    for (int i = 0; i < 9; i++)
    {
        mode_str += (new_mode_str[i] == '?' ? base_mode_str[i] : new_mode_str[i]);
    }
    return mode_str;
}

bool IsModeValid(std::string mode_str)
{
    return std::regex_match(mode_str, MODE_STR_PATTERN_RE);
}

bool IsModeValid(uint64_t mode_int)
{
    return mode_int <= 0777;
}

namespace WinTool
{
    uint64_t FileTimeToUnixTime(const FILETIME &ft)
    {
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        return (uli.QuadPart / 10000000ULL) - 11644473600ULL;
    }

    std::string GetFileOwner(const std::wstring &path)
    {
        PSID pSidOwner = NULL;
        PSECURITY_DESCRIPTOR pSD = NULL;
        DWORD dwRtnCode = GetNamedSecurityInfoW(
            path.c_str(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &pSidOwner,
            NULL,
            NULL,
            NULL,
            &pSD);

        std::wstring owner = L"unknown";
        if (dwRtnCode == ERROR_SUCCESS)
        {
            wchar_t szOwnerName[256];
            wchar_t szDomainName[256];
            DWORD dwNameLen = 256;
            DWORD dwDomainLen = 256;
            SID_NAME_USE eUse;

            if (LookupAccountSidW(
                    NULL,
                    pSidOwner,
                    szOwnerName,
                    &dwNameLen,
                    szDomainName,
                    &dwDomainLen,
                    &eUse))
            {
                owner = szOwnerName;
            }
        }

        if (pSD)
        {
            LocalFree(pSD);
        }

        return wstr2str(owner);
    }

    void GetTime(const std::wstring &path, PathInfo &info)
    {
        HANDLE hFile = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return;
        }
        FILETIME ftAccess, ftModify;
        GetFileTime(hFile, NULL, &ftAccess, &ftModify);
        CloseHandle(hFile); // 立即释放句柄
        ULARGE_INTEGER uliAccess{
            ftAccess.dwLowDateTime,
            ftAccess.dwHighDateTime};
        ULARGE_INTEGER uliModify{
            ftModify.dwLowDateTime,
            ftModify.dwHighDateTime};
        info.atime = (uliAccess.QuadPart - 116444736000000000ULL) / 1e7;
        info.mtime = (uliModify.QuadPart - 116444736000000000ULL) / 1e7;
    }

    bool is_readonly(const std::wstring &path)
    {
        DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_READONLY)
        {
            return true;
        }
        return false;
    }
}

namespace WT = WinTool;

namespace AMFS
{
    std::string dirname(const std::string &path)
    {
        fs::path p(realpath(path));
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

    bool is_absolute(const std::string &path)
    {
        std::regex regex1("^[A-Za-z]:[/\\]");
        std::regex regex2("^/");
        return std::regex_match(path, regex1) || std::regex_match(path, regex2);
    }

    std::string realpath(const std::string &path, bool force_absolute)
    {
        std::string cwd = fs::current_path().string();
        std::vector<std::string> parts = AMFS::split(path);
        if (parts[0] == "." || parts[0] == "~")
        {
            parts.erase(parts.begin());
            std::vector<std::string> parts_t = AMFS::split(cwd);
            parts.insert(parts.begin(), parts_t.begin(), parts_t.end());
        }
        else if (!is_absolute(path))
        {
            std::vector<std::string> parts_t = AMFS::split(cwd);
            parts.insert(parts.begin(), parts_t.begin(), parts_t.end());
        }
        std::vector<std::string> new_parts;
        for (const auto &part : parts)
        {
            if (part == ".")
            {
                continue;
            }
            else if (part == "..")
            {
                if (!new_parts.empty())
                {
                    new_parts.pop_back();
                }
            }
            else
            {
                new_parts.push_back(part);
            }
        }
        return AMFS::join(new_parts);
    }

    std::pair<ErrorCode, std::string> mkdirs(const std::string &path)
    {
        try
        {
            fs::path p(path);
            fs::create_directories(p);
            return std::make_pair(ErrorCode::Success, "");
        }
        catch (const std::exception &e)
        {
            return std::make_pair(ErrorCode::LocalFileError, e.what());
        }
    }

    std::variant<PathInfo, std::pair<ErrorCode, std::string>> stat(const std::string &path, bool trace_link)
    {
        PathInfo info;
        fs::path p(path);
        std::wstring wpath = str2wstr(path);
        info.name = p.filename().string();
        info.path = realpath(path);
        info.dir = p.parent_path().string();
        if (!fs::exists(p))
        {
            return std::make_pair(ErrorCode::PathNotExist, fmt::format("Local path not found: {}", path));
        }
        fs::file_status status;
        if (trace_link)
        {
            status = fs::status(p);
        }
        else
        {
            status = fs::symlink_status(p);
        }
        switch (status.type())
        {
        case fs::file_type::directory:
            info.type = PathType::DIR;
            break;
        case fs::file_type::symlink:
            info.type = PathType::SYMLINK;
            break;
        case fs::file_type::regular:
            info.type = PathType::FILE;
            break;
        case fs::file_type::block:
            info.type = PathType::BlockDevice;
            break;
        case fs::file_type::character:
            info.type = PathType::CharacterDevice;
            break;
        case fs::file_type::fifo:
            info.type = PathType::FIFO;
            break;
        case fs::file_type::socket:
            info.type = PathType::Socket;
            break;
        case fs::file_type::unknown:
            info.type = PathType::Unknown;
            break;
        default:
            info.type = PathType::Unknown;
            break;
        }

        if (info.type == PathType::FILE)
        {
            try
            {
                info.size = fs::file_size(p);
            }
            catch (const std::exception)
            {
            }
        }

        if (WT::is_readonly(str2wstr(path)))
        {
            info.mode_int = 0333;
            info.mode_str = "r-xr-xr-x";
        }
        else
        {
            info.mode_int = 0666;
            info.mode_str = "rwxrwxrwx";
        }

        WT::GetTime(wpath, info);
        info.uname = WT::GetFileOwner(wpath);
        return info;
    }

    void _walk(std::string path, std::vector<PathInfo> &result, bool ignore_sepcial_file, bool trace_link)
    {
        fs::path p(path);
        fs::file_status status;
        if (!fs::exists(p))
        {
            return;
        }
        auto sr = stat(path, trace_link);
        if (std::holds_alternative<PathInfo>(sr))
        {
            result.push_back(std::get<PathInfo>(sr));
        }
    }

    std::vector<PathInfo> walk(const std::string &path, bool ignore_sepcial_file, bool trace_link)
    {
        std::vector<PathInfo> result = {};

        _walk(path, result, ignore_sepcial_file, trace_link);

        return result;
    }

    std::vector<PathInfo> listdir(const std::string &path)
    {
        std::vector<PathInfo> result = {};
        fs::path p(path);
        if (!fs::exists(p))
        {
            return result;
        }
        if (!fs::is_directory(p))
        {
            return result;
        }
        std::variant<PathInfo, std::pair<ErrorCode, std::string>> sr;
        for (const auto &entry : fs::directory_iterator(p))
        {
            sr = stat(entry.path().string(), false);
            if (std::holds_alternative<PathInfo>(sr))
            {
                result.push_back(std::get<PathInfo>(sr));
            }
        }
        return result;
    }

    std::vector<std::string> split(const std::string &path)
    {
        std::vector<std::string> segments;
        fs::path p(path);
        for (const auto &seg : p)
        {
            segments.push_back(seg.string());
        }
        return segments;
    }

    std::vector<std::string> split(const fs::path &path)
    {
        std::vector<std::string> segments;
        for (const auto &seg : path)
        {
            segments.push_back(seg.string());
        }
        return segments;
    }

    void _getsize(const std::string &path, uint64_t &result, bool trace_link)
    {
        fs::path p(path);
        if (!fs::exists(p))
        {
            return;
        }
        if (fs::is_directory(p))
        {
            for (const auto &entry : fs::directory_iterator(p))
            {
                _getsize(entry.path().string(), result, trace_link);
            }
        }
        else if (fs::is_symlink(p))
        {
            if (trace_link)
            {
                _getsize(fs::read_symlink(p).string(), result, trace_link);
            }
        }
        else if (fs::is_regular_file(p))
        {
            result += fs::file_size(p);
        }
    }

    uint64_t getsize(const std::string &path, bool trace_link)
    {
        uint64_t result = 0;
        _getsize(path, result, trace_link);
        return result;
    }

}