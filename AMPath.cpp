#include "AMPath.hpp"
#include "AMEnum.hpp"
#include <aclapi.h>
#include <filesystem>
#include <fmt/format.h>
#include <iostream>
#include <regex>
#include <sddl.h>
#include <shlwapi.h>
#include <stdexcept>
#include <string>
#include <variant>
#include <windows.h>

namespace fs = std::filesystem;
using EC = ErrorCode;
using ECM = std::pair<EC, std::string>;
const std::vector<std::pair<uint64_t, size_t>> GLOBAL_PERMISSIONS_MASK = {
    {0400, 0}, {0200, 1}, {0100, 2}, {0040, 3}, {0020, 4}, {0010, 5}, {0004, 6}, {0002, 7}, {0001, 8}};

PathInfo::PathInfo()
    : name(""), path(""), dir(""), uname("") {}

PathInfo::PathInfo(std::string name, std::string path, std::string dir, std::string uname, uint64_t size, uint64_t atime, uint64_t mtime, PathType type, uint64_t mode_int, std::string mode_str)
    : name(name), path(path), dir(dir), uname(uname), size(size), atime(atime), mtime(mtime), type(type), mode_int(mode_int), mode_str(mode_str) {}

std::wstring str2wstr(const std::string &narrowStr)
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

std::string wstr2str(const std::wstring &wideStr)
{
    int length = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string narrowStr(length, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, &narrowStr[0], length, nullptr, nullptr);
    return narrowStr;
}

std::string ModeTrans(uint64_t mode_int)
{
    std::string mode_str = "";
    int mode_v;
    for (int i = 0; i < 3; i++)
    {
        mode_v = mode_int & (8 ^ (3 - i) - 1);
        switch (mode_v)
        {
        case 0:
            mode_str += "---";
            break;
        case 1:
            mode_str += "--x";
            break;
        case 2:
            mode_str += "r--";
            break;
        case 3:
            mode_str += "r-x";
            break;
        case 4:
            mode_str += "rw-";
            break;
        case 5:
            mode_str += "-wx";
            break;
        case 6:
            mode_str += "rw-";
            break;
        case 7:
            mode_str += "rwx";
            break;
        }
    }
    return mode_str;
}

uint64_t ModeTrans(std::string mode_str)
{
    uint64_t mode_int = 0;
    for (size_t i = mode_str.size() - 1; i >= 0; i--)
    {
        switch (mode_str[i])
        {
        case 'r':
            mode_int += 2 * (8 ^ (i / 3));
            break;
        case 'w':
            mode_int += 4 * (8 ^ (i / 3));
            break;
        case 'x':
            mode_int += 1 * (8 ^ (i / 3));
            break;
        }
    }
    return mode_int;
}

std::string MergeModeStr(std::string base_mode_str, std::string new_mode_str)
{
    std::string pattern_f = "^[r-\\?][w-\\?][x-\\?][r-\\?][w-\\?][x-\\?][r-\\?][w-\\?][x-\\?]$";
    std::regex pattern(pattern_f);

    if (!std::regex_match(base_mode_str, pattern))
    {
        throw std::invalid_argument("Invalid base mode string");
    }

    if (!std::regex_match(new_mode_str, pattern))
    {
        throw std::invalid_argument("Invalid new mode string");
    }

    std::string mode_str = "";
    for (size_t i = 0; i < 9; i++)
    {
        mode_str += (base_mode_str[i] == '?' ? new_mode_str[i] : base_mode_str[i]);
    }
    return mode_str;
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

    bool mkdirs(const std::string &path)
    {
        try
        {
            fs::path p(path);
            fs::create_directories(p);
            return true;
        }
        catch (const fs::filesystem_error)
        {
            return false;
        }
    }

    std::variant<PathInfo, ECM> stat(const std::string &path)
    {
        PathInfo info;

        // 检查路径是否存在
        WIN32_FILE_ATTRIBUTE_DATA fileData;
        if (!GetFileAttributesExW(str2wstr(path).c_str(), GetFileExInfoStandard, &fileData))
        {
            return ECM(EC::PathNotExist, fmt::format("Path not found: {}", path));
        }
        wchar_t fullPath[MAX_PATH];
        if (!GetFullPathNameW(str2wstr(path).c_str(), MAX_PATH, fullPath, NULL))
        {
            return ECM(EC::PathNotExist, fmt::format("Can't get full path: {}", path));
        }

        std::filesystem::path fsPath(path);
        info.name = fsPath.filename().string();
        info.path = wstr2str(fullPath);
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

    std::vector<PathInfo> walk(std::string path, bool ignore_sepcial_file)
    {
        std::vector<PathInfo> result = {};

        _walk(path, result, ignore_sepcial_file);

        return result;
    }

    std::vector<std::string> split(std::string path)
    {
        std::vector<std::string> segments;
        fs::path p(path);
        for (const auto &seg : p)
        {
            segments.push_back(seg.string());
        }
        return segments;
    }

    std::vector<std::string> split(fs::path path)
    {
        std::vector<std::string> segments;
        for (const auto &seg : path)
        {
            segments.push_back(seg.string());
        }
        return segments;
    }
}