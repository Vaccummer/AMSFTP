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
using EC = ErrorCode;
using ECM = std::pair<EC, std::string>;

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

std::string wstr2str(const std::wstring &wstr)
{
    int bufferSize = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (bufferSize == 0)
        return "";

    std::string result(bufferSize, 0);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &result[0], bufferSize, nullptr, nullptr);
    result.resize(bufferSize - 1); // 去除末尾的'\0'
    return result;
}

std::wstring str2wstr(const std::string &str)
{
    int bufferSize = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (bufferSize == 0)
        return L"";

    std::wstring result(bufferSize, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &result[0], bufferSize);
    result.resize(bufferSize - 1); // 去除末尾的L'\0'
    return result;
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

    void GetFilePermissions(const std::string &path, uint64_t &mode_int, std::string &mode_str)
    {
        mode_int = 0;
        mode_str = "";

        DWORD attributes = GetFileAttributesA(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            return;
        }

        bool canRead = true;
        bool canWrite = !(attributes & FILE_ATTRIBUTE_READONLY);

        if (canRead)
            mode_int += 0444;
        if (canWrite)
            mode_int += 0222;

        mode_int += 0111;

        mode_str += canRead ? 'r' : '-';
        mode_str += canWrite ? 'w' : '-';
        mode_str += 'x';
        mode_str = mode_str + mode_str + mode_str;
    }

}

namespace WT = WinTool;

namespace AMFS
{
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

    std::string realpath(const std::string &path)
    {
        fs::path p(path);
        return p.lexically_normal().generic_string();
    }

    ECM mkdirs(const std::string &path)
    {
        try
        {
            fs::path p(path);
            fs::create_directories(p);
            return ECM(EC::Success, "");
        }
        catch (const std::exception &e)
        {
            return ECM(EC::LocalFileError, e.what());
        }
    }

    std::variant<PathInfo, ECM> stat(const std::string &path)
    {
        PathInfo info;

        WIN32_FILE_ATTRIBUTE_DATA fileData;
        if (!GetFileAttributesExW(str2wstr(path).c_str(), GetFileExInfoStandard, &fileData))
        {
            return ECM(EC::PathNotExist, fmt::format("Local path not found: {}", path));
        }

        std::filesystem::path fsPath(path);
        fsPath = fs::absolute(fsPath);
        info.name = fsPath.filename().string();
        info.path = fsPath.generic_string();
        info.dir = fsPath.parent_path().string();

        if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            info.type = PathType::DIR;
        }
        else
        {
            info.type = PathType::FILE;
        }

        if (info.type == PathType::FILE)
        {
            ULARGE_INTEGER fileSize;
            fileSize.LowPart = fileData.nFileSizeLow;
            fileSize.HighPart = fileData.nFileSizeHigh;
            info.size = fileSize.QuadPart;
            DWORD attributes = GetFileAttributesW(str2wstr(path).c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_READONLY)
            {
                info.mode_int = 0333;
                info.mode_str = "r-xr-xr-x";
            }
        }
        info.atime = WT::FileTimeToUnixTime(fileData.ftLastAccessTime);
        info.mtime = WT::FileTimeToUnixTime(fileData.ftLastWriteTime);
        info.uname = WT::GetFileOwner(str2wstr(path));
        return info;
    }

    void _walk(std::string path, std::vector<PathInfo> &result, bool ignore_sepcial_file)
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
                _walk(entry.path().string(), result, ignore_sepcial_file);
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

    std::vector<PathInfo> walk(const std::string &path, bool ignore_sepcial_file)
    {
        std::vector<PathInfo> result = {};

        _walk(path, result, ignore_sepcial_file);

        return result;
    }

    std::vector<PathInfo> listdir(const std::string &path)
    {
        std::vector<PathInfo> result = {};
        fs::path p(path);
        std::variant<PathInfo, ECM> sr;
        for (const auto &entry : fs::directory_iterator(p))
        {
            sr = stat(entry.path().string());
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
}