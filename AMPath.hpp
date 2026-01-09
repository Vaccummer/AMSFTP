#pragma once
// 标准库头文件（跨平台，无需条件编译）
#include <chrono>
#include <codecvt>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>

// 第三方库头文件（跨平台，需链接 fmt 库）
#include <fmt/format.h>

// Windows 特有头文件（仅在 Windows 平台包含）
#ifdef _WIN32
#include <aclapi.h> // Windows ACL API
#include <sddl.h>   // Windows SDDL API
#include <shlobj.h>
#include <shlwapi.h> // Windows Shell 轻量级 API
#include <windows.h>
#include <windows.h> // Windows 核心 API
#else
#include <pwd.h>
#include <sys/stat.h> // Unix 文件状态 API（stat 函数等）
#include <unistd.h>
#endif

namespace AMFS
{
    namespace fs = std::filesystem;
    using CB = std::shared_ptr<std::function<void(std::string, std::string, std::string)>>;
    constexpr char *exc1 = "am1sp2exg6";
    constexpr char *exc2 = "amtmpexc5";
    constexpr char *exc3 = "atmasdapxch";
    constexpr char *exc4 = "amtmasdapaexch";
    constexpr char *exc5 = "amtessixhxch";
    constexpr char *exc6 = "amtasdmpexsch";

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

    enum class PathFormat
    {
        Absolute = 1,
        Relative = 2,
        User = 3
    };

    enum class SearchType
    {
        All = 0,
        File = 1,
        Directory = 2
    };

    enum class SepType
    {
        Unix = 0,
        Windows = 1
    };

    namespace Str
    {
        std::wstring AMStr(const std::string &str)
        {
            std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
            try
            {
                return converter.from_bytes(str);
            }
            catch (const std::range_error)
            {
                return L"";
            }
        }

        std::string AMStr(const std::wstring &wstr)
        {
            std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
            try
            {
                return converter.to_bytes(wstr);
            }
            catch (const std::range_error)
            {
                return "";
            }
        }

        std::string AMStr(wchar_t *wstr)
        {
            return AMStr(std::wstring(wstr));
        }

        std::wstring AMStr(char *str)
        {
            return AMStr(std::string(str));
        }

        std::pair<bool, int> endswith(const std::string &str, const std::string &suffix)
        {
            if (suffix.empty())
                return std::make_pair(true, str.size());
            if (str.size() < suffix.size())
                return std::make_pair(false, 0);
            return std::make_pair(str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0, str.size() - suffix.size());
        }

        std::pair<bool, std::string> isPatternsValid(const std::vector<std::string> &patterns)
        {
            std::regex pattern_f;
            for (auto pattern : patterns)
            {
                if (pattern.empty())
                {
                    return std::make_pair(false, "Recive an empty pattern");
                }
                if (pattern[0] != '<')
                {
                    continue;
                }
                if (pattern.size() == 1)
                {
                    return std::make_pair(false, "Recive a single <");
                };

                try
                {
                    pattern_f = std::regex(pattern.substr(1));
                    std::regex_search("abc", pattern_f);
                }
                catch (std::exception e)
                {
                    std::string msg = fmt::format("Pattern \"{}\" parsing failed: {}", pattern, e.what());
                    return std::make_pair(false, msg);
                }
            }
            return std::make_pair(true, "");
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

        std::string MergeModeStr(const std::string &base_mode_str, const std::string &new_mode_str)
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
            return std::regex_match(mode_str, std::regex("^[r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-][r?\\-][w?\\-][x?\\-]$"));
        }

        bool IsModeValid(uint64_t mode_int)
        {
            return mode_int <= 0777;
        }

        std::string RegexEscape(const std::string &input)
        {
            std::string escaped;
            escaped.reserve(input.size() * 2); // 预分配内存优化性能

            for (char c : input)
            {
                // 匹配需要转义的正则元字符
                switch (c)
                {
                case '\\':
                case '^':
                case '$':
                case '.':
                case '|':
                case '?':
                case '*':
                case '+':
                case '(':
                case ')':
                case '[':
                case ']':
                case '{':
                case '}':
                    escaped += '\\'; // 添加转义符
                    break;
                default:
                    break;
                }
                escaped += c; // 追加当前字符
            }

            return escaped;
        }

        std::string Strip(std::string path)
        {
            const std::string trim_chars = " \t\n\r\"'";

            size_t start = path.find_first_not_of(trim_chars);

            if (start == std::string::npos || start > path.size() - 2)
            {
                return "";
            }

            size_t end = path.find_last_not_of(trim_chars);
            return path.substr(start, end - start + 1);
        }

        void VStrip(std::string &path)
        {
            const std::string trim_chars = " \t\n\r\"'";

            size_t start = path.find_first_not_of(trim_chars);
            if (start == std::string::npos)
            {
                path = "";
            }

            size_t end = path.find_last_not_of(trim_chars);
            path = path.substr(start, end - start + 1);
        }

        std::string GetPathSep(const std::string &path)
        {
            if (path[0] == '/')
            {
                return "/";
            }
            else if (path[0] == '\\')
            {
                return "\\";
            }
            int slash_count = 0;
            int anti_slash_count = 0;
            for (auto &c : path)
            {
                if (c == '/')
                {
                    slash_count++;
                }
                else if (c == '\\')
                {
                    anti_slash_count++;
                }
            }
            return slash_count < anti_slash_count ? "\\" : "/";
        }

        bool _match(const std::string &name, const std::string &pattern_f, const bool &use_regex)
        {
            std::string pattern = pattern_f;
            if (!use_regex || pattern.front() != '<')
            {
                pattern = std::regex_replace(pattern, std::regex("\\*"), std::string(exc1));
                pattern = RegexEscape(pattern);
                pattern = std::regex_replace(pattern, std::regex(exc1), ".*");

                std::wstring p_w = AMStr(pattern);

                std::wstring n_w = AMStr(name);
                try
                {
                    return std::regex_search(n_w, std::wregex(p_w));
                }
                catch (std::exception e)
                {
                    return false;
                }
            }
            else
            {
                pattern = pattern.substr(1);
                std::wregex pattern_f(AMStr(pattern));
                try
                {
                    bool result = std::regex_search(AMStr(name), pattern_f);
                    return result;
                }
                catch (const std::regex_error)
                {
                    return false;
                }
            }
        }
    };

#ifdef _WIN32
    struct FileTimes
    {
        double creation_time; // 创建时间
        double modify_time;   // 修改时间
        double access_time;   // 最近访问时间
    };

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

    std::string AMStr(const std::wstring &wstr)
    {
        int codePage = GetACP();
        int len = WideCharToMultiByte(codePage, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0)
            return "";
        std::string result(len - 1, 0);
        WideCharToMultiByte(codePage, 0, wstr.c_str(), -1, &result[0], len, nullptr, nullptr);
        return result;
    };

    std::string AMStr(const wchar_t *wstr)
    {
        int codePage = GetACP();
        int len = WideCharToMultiByte(codePage, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0)
            return "";
        std::string result(len - 1, 0);
        WideCharToMultiByte(codePage, 0, wstr, -1, &result[0], len, nullptr, nullptr);
        return result;
    }

    std::wstring AMStr(const std::string &str)
    {
        int codePage = CP_ACP;
        if (is_valid_utf8(str))
        {
            codePage = CP_UTF8;
        }
        int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
        if (len <= 0)
            return L"";
        std::wstring result(len - 1, 0);
        MultiByteToWideChar(codePage, 0, str.c_str(), -1, &result[0], len);
        return result;
    };

    std::wstring AMStr(const char *str)
    {
        int codePage = CP_ACP;
        if (is_valid_utf8(str))
        {
            codePage = CP_UTF8;
        }
        int len = MultiByteToWideChar(CP_ACP, 0, str, -1, nullptr, 0);
        if (len <= 0)
            return L"";
        std::wstring result(len - 1, 0);
        MultiByteToWideChar(codePage, 0, str, -1, &result[0], len);
        return result;
    }

    double FileTimeToUnixTime(const FILETIME &ft)
    {
        const int64_t UNIX_EPOCH_DIFF = 11644473600LL; // 1601-01-01 到 1970-01-01 的秒数
        int64_t filetime_100ns = (static_cast<int64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        return static_cast<double>(filetime_100ns) / 1e7 - UNIX_EPOCH_DIFF;
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

        std::wstring owner = L"";
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
            else
            {
                wchar_t username[257];
                DWORD username_len = 257;
                if (GetUserNameW(username, &username_len))
                {
                    owner = std::wstring(username, username_len - 1);
                }
            }
        }

        if (pSD)
        {
            LocalFree(pSD);
        }

        return AMStr(owner);
    }

    std::tuple<double, double, double> GetTime(const std::wstring &path)
    {
        std::wstring wpath(path.begin(), path.end());

        // 使用 FindFirstFile 获取文件信息（支持文件和目录）
        WIN32_FIND_DATAW find_data;
        HANDLE hFind = FindFirstFileW(wpath.c_str(), &find_data);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            return {0, 0, 0};
        }
        FindClose(hFind);
        return std::make_tuple(
            FileTimeToUnixTime(find_data.ftCreationTime),
            FileTimeToUnixTime(find_data.ftLastWriteTime),
            FileTimeToUnixTime(find_data.ftLastAccessTime));
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
#endif

    double timespec_to_double(const struct timespec &ts)
    {
        return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1e9;
    }

    class PathInfo
    {
    public:
        std::string name;
        std::string path;
        std::string dir;
        std::string owner;
        uint64_t size = 0;
        double create_time = 0;
        double access_time = 0;
        double modify_time = 0;
        PathType type = PathType::FILE;
        uint64_t mode_int = 0777;
        std::string mode_str = "rwxrwxrwx";
        PathInfo() : name(""), path(""), dir(""), owner("") {}

        PathInfo(std::string name, std::string path, std::string dir, std::string owner, uint64_t size, double create_time, double access_time, double modify_time, PathType type, uint64_t mode_int, std::string mode_str) : name(name), path(path), dir(dir), owner(owner), size(size), create_time(create_time), access_time(access_time), modify_time(modify_time), type(type), mode_int(mode_int), mode_str(mode_str) {}
    };

    std::string FormatTime(const uint64_t &time, const std::string &format = "%Y-%m-%d %H:%M:%S")
    {
        time_t timeT = static_cast<time_t>(time);

        struct tm timeInfo;
        {

#ifdef _WIN32

            localtime_s(&timeInfo, &timeT);
#else
            localtime_r(&timeT, &timeInfo);
#endif

            std::ostringstream oss;
            oss << std::put_time(&timeInfo, format.c_str());

            return oss.str();
        };
    }

    std::string UnifyPathSep(std::string path, std::string sep = "")
    {
        path = Str::Strip(path);
        if (path.size() < 2)
            return path;
        sep = sep.empty() ? Str::GetPathSep(path) : sep;
        std::string head = path.substr(0, 2);
        if (head == "//" || head == "\\\\")
        {
            path = path.substr(2);
        }
        else
        {
            head.clear();
        }
        path = std::regex_replace(path, std::regex("[\\\\/]+"), sep);
        return head + path;
    }

    bool IsAbs(const std::string &path, const std::string &sep = "")
    {
        return std::regex_search(UnifyPathSep(path, sep), std::regex("^(?:[A-Za-z]:[/\\\\]?|/|[\\\\/]{2}|~[\\\\/])")) || path == "~";
    }

    std::string HomePath()
    {
#ifdef _WIN32
        // Windows: 优先使用API
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path)))
        {
            return AMStr(path);
        }
        // 备选环境变量
        const char *userprofile = std::getenv("USERPROFILE");
        if (userprofile)
            return std::string(userprofile);
#else
        // Linux/macOS
        const char *home = std::getenv("HOME");
        if (home)
            return std::string(home);

        // 备选: 读取/etc/passwd

        struct passwd *pw = getpwuid(getuid());
        if (pw && pw->pw_dir)
            return std::string(pw->pw_dir);
#endif
        return "";
    }

    std::string extname(const std::string &path)
    {
        std::string base = Str::Strip(path);
        std::string ext = "";
        size_t dot_pos = path.find_last_of('.');
        if (dot_pos != std::string::npos)
        {
            ext = path.substr(dot_pos + 1);
            std::string test_ext = ".tar." + ext;
            if (Str::endswith(base, test_ext).first)
            {
                return test_ext.substr(1);
            }
            else
            {
                return ext;
            }
        }
        else
        {
            return "";
        }
    }

    std::pair<std::string, std::string> split_basename(const std::string &basename)
    {
        std::string base = Str::Strip(basename);
        std::string ext = "";
        size_t dot_pos = base.find_last_of('.');
        if (dot_pos != std::string::npos)
        {
            ext = base.substr(dot_pos + 1);
            std::string test_ext = ".tar." + ext;
            // 检测base是否已test_ext结尾
            auto [check, pos] = Str::endswith(base, test_ext);
            if (check)
            {
                return {base.substr(0, pos), test_ext.substr(1)};
            }
            else
            {
                return {base.substr(0, dot_pos), ext};
            }
        }
        else
        {
            return {base, ""};
        }
    }

    std::string CWD()
    {
        return fs::current_path().string();
    }

    std::vector<std::string> split(std::string path)
    {
        if (path.size() < 2)
        {
            return {path};
        }

        std::vector<std::string> result{};
        std::string head = path.substr(0, 2);
        if (head == "//" || head == "\\\\")
        {
            // 匹配网络路径
            path = path.substr(2);
        }
        else if (head[0] == '/')
        {
            // 匹配unix根目录
            result.push_back("/");
            path = path.substr(1);
            head.clear();
        }
        else
        {
            head.clear();
        }

        std::string cur = "";
        for (auto c : path)
        {
            if (c == '\\' || c == '/')
            {
                if (!cur.empty())
                {
                    result.push_back(cur);
                    cur = "";
                }
            }
            else
            {
                cur += c;
            }
        }
        if (!cur.empty())
        {
            result.push_back(cur);
        }

        if (!head.empty())
        {
            result[0] = head + result[0];
        }

        return result;
    }

    std::vector<std::string> resplit(std::string path, char front_esc, char back_esc, std::string head = "")
    {
        if (path.size() < 3)
        {
            return {path};
        }
        std::vector<std::string> parts{};
        std::string tmp_str = "";
        bool in_brackets = false;
        std::string bracket_str = "";
        for (auto &sig : path)
        {
            if (in_brackets)
            {
                if (sig == back_esc)
                {
                    in_brackets = false;
                    if (!bracket_str.empty())
                    {
                        parts.push_back(head + bracket_str);
                        bracket_str.clear();
                    }
                }
                else
                {
                    bracket_str += sig;
                }
            }
            else
            {
                if (sig == front_esc)
                {
                    in_brackets = true;
                }
                else if (sig == '/' || sig == '\\')
                {
                    if (!tmp_str.empty())
                    {
                        parts.push_back(tmp_str);
                        tmp_str.clear();
                    }
                }
                else
                {
                    tmp_str += sig;
                }
            }
        }
        return parts;
    }

    template <typename... Args>
    std::string join(Args &&...args)
    {
        std::vector<std::string> segments;
        std::string ori_str;
        fs::path combined;
        std::string sep = "";

        auto process_arg = [&](auto &&arg)
        {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, std::filesystem::path>)
            {
                if (!arg.empty())
                {
                    segments.push_back(arg.string());
                    ori_str += arg.string();
                }
            }
            else if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, const std::string>)
            {
                if (!arg.empty())
                {
                    segments.push_back(arg);
                    ori_str += arg;
                }
            }
            else if constexpr (std::is_same_v<T, std::vector<std::string>> || std::is_same_v<T, const std::vector<std::string>>)
            {
                for (auto &seg : arg)
                {
                    if (!seg.empty())
                    {
                        segments.push_back(seg);
                        ori_str += seg;
                    }
                }
            }
            else if constexpr (std::is_same_v<T, std::wstring> || std::is_same_v<T, const std::wstring>)
            {
                std::string s = AMPathTools::AMstr(arg);
                if (!s.empty())
                {
                    segments.push_back(s);
                    ori_str += s;
                }
            }
            else if constexpr (std::is_same_v<T, const char *> || std::is_same_v<T, char *>)
            {
                std::string s = std::string(arg);
                if (!s.empty())
                {
                    segments.push_back(s);
                    ori_str += s;
                }
            }
            else if constexpr (std::is_same_v<T, const wchar_t *> || std::is_same_v<T, wchar_t *>)
            {
                std::string s = AMPathTools::AMstr(arg);
                if (!s.empty())
                {
                    segments.push_back(s);
                    ori_str += s;
                }
            }
            else if constexpr (std::is_same_v<T, SepType>)
            {
                switch (arg)
                {
                case SepType::Unix:
                    sep = "/";
                    break;
                case SepType::Windows:
                    sep = "\\";
                    break;
                }
            }
        };

        (process_arg(std::forward<Args>(args)), ...);

        if (segments.empty())
            return "";
        else if (segments.size() == 1)
        {
            return segments.front();
        }

        std::string result;

        if (segments[0] == "/")
        {
            result = "/";
            sep = "/";
        }
        else if (segments[0] == "//")
        {
            result = "//";
            sep = "/";
        }
        else if (segments[0] == "\\\\")
        {
            result = "\\\\";
            sep = "\\";
        }
        else
        {
            sep = sep.empty() ? Str::GetPathSep(ori_str) : sep;
            result = segments[0] + sep;
        }

        for (int i = 1; i < segments.size(); i++)
        {
            result += segments[i] + sep;
        }

        result = UnifyPathSep(result, sep);

        return result;
    };

    // 解析真实存在的路径，返回绝对路径
    std::string realpath(const std::string &path, bool force_parsing = false, const std::string &cwd = "", const std::string &sep = "")
    {
        std::string new_path = UnifyPathSep(path, sep);

        if ((new_path.size() < 4 || IsAbs(new_path, sep)) && !force_parsing)
        {
            return path;
        }

        std::string new_sep = sep.empty() ? Str::GetPathSep(path) : sep;

        if (!IsAbs(new_path, new_sep))
        {
            new_path = cwd.empty() ? CWD() + new_sep + new_path : cwd + new_sep + new_path;
        }

        std::vector<std::string> parts = split(new_path);

        if (parts.empty())
        {
            return "";
        }

        std::vector<std::string> new_parts{};

        if (parts.front() == "~")
        {
            std::string hm = HomePath();
            for (const auto &seg : split(hm))
            {
                new_parts.push_back(seg);
            }
            parts.erase(parts.begin());
        }

        std::string tmp_part;
        for (auto tmp_part : parts)
        {
            if (tmp_part == ".")
            {
                continue;
            }
            else if (tmp_part == "..")
            {
                if (!new_parts.empty())
                {
                    new_parts.pop_back();
                }
            }
            else
            {
                new_parts.push_back(tmp_part);
            }
        }

        std::string result;
        for (const auto part : new_parts)
        {
            result += part + new_sep;
        }

        return result;
    }

    // 将路径转换为绝对路径，支持解析~ . ..符号， 不要求路径存在
    std::string abspath(const std::string &path,
                        const bool parsing_home = true,
                        const std::string &home = "",
                        const std::string &cwd = "",
                        const std::string &sep = "")
    {
        std::string new_path = UnifyPathSep(path, sep);

        if (IsAbs(new_path, sep) && !parsing_home)
        {
            return new_path;
        }

        std::string new_sep = sep.empty() ? Str::GetPathSep(path) : sep;

        if (!IsAbs(new_path, new_sep))
        {
            new_path = cwd.empty() ? CWD() + new_sep + new_path : cwd + new_sep + new_path;
        }

        std::vector<std::string> parts = split(new_path);

        if (parts.empty())
        {
            return "";
        }

        std::vector<std::string> new_parts{};

        std::string tmp_part;
        std::string result;
        if (parts.empty())
        {

            return "";
        }
        else if (parts.size() == 1)
        {
            return parts.front();
        }
        else if (parts.front() == "/")
        {
            new_parts.push_back("/");
            new_sep = "/";
        }
        else if (parts.front() == "~" && parsing_home)
        {
            std::string hm = home.empty() ? HomePath() : home;
            for (const auto &seg : split(hm))
            {
                new_parts.push_back(seg);
            }
            parts.erase(parts.begin());
        }
        else
        {
            result = parts.front() + new_sep;
        }

        for (int i = 1; i < parts.size(); i++)
        {
            tmp_part = parts[i];
            if (tmp_part == ".")
            {
                continue;
            }
            else if (tmp_part == "..")
            {
                if (!new_parts.empty())
                {
                    new_parts.pop_back();
                }
            }
            else
            {
                new_parts.push_back(tmp_part);
            }
        }

        if (new_parts.size() == 0)
        {
            return "";
        }
        else if (new_parts.size() == 1)
        {
            return new_parts.front();
        }
        for (int i = 1; i < new_parts.size(); i++)
        {
            result += new_parts[i] + new_sep;
        }

        return result;
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

    std::string basename(std::string path)
    {
        while ((path.back() == '/' || path.back() == '\\') && path.size() > 1)
        {
            path.pop_back();
        }
        fs::path p(path);
        return p.filename().string();
    }

    std::string mkdirs(const std::string &path)
    {
        try
        {
            fs::path p(path);
            fs::create_directories(p);
            return "";
        }
        catch (const std::exception &e)
        {
            return fmt::format("Mkdir error: {}", e.what());
        }
    }

    std::pair<std::string, PathInfo> stat(std::string path, bool trace_link = false)
    {
        PathInfo info;
        path = realpath(path);
        fs::path p(path);
        info.name = p.filename().string();
        info.path = realpath(path);
        info.dir = p.parent_path().string();
        fs::file_status status;
        try
        {
            if (trace_link)
            {
                status = fs::status(p);
            }
            else
            {
                status = fs::symlink_status(p);
            }
        }
        catch (const fs::filesystem_error)
        {
            return std::make_pair("Stat error: " + path, PathInfo());
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
            catch (const std::exception &e)
            {
                return std::make_pair(fmt::format("Fail to get file size: {}", e.what()), PathInfo());
            }
        }

#ifdef _WIN32
        if (is_readonly(Str::AMStr(path)))
        {
            info.mode_int = 0333;
            info.mode_str = "r-xr-xr-x";
        }
        else
        {
            info.mode_int = 0666;
            info.mode_str = "rwxrwxrwx";
        }

        auto [create_time, access_time, modify_time] = GetTime(Str::AMStr(path));
        info.create_time = create_time;
        info.access_time = access_time;
        info.modify_time = modify_time;
        info.owner = GetFileOwner(Str::AMStr(path));
#else
        struct stat file_stat;
        // 调用 stat 获取文件元数据（支持符号链接，若需跟随链接用 stat 而非 lstat）
        if (stat(path.c_str(), &file_stat) == -1)
        {
            return std::make_pair("", info);
        }

        // 1. 拥有者和组（通过 UID/GID 转换）
        struct passwd *pw = getpwuid(file_stat.st_uid); // UID -> 用户名
        info.owner = pw ? pw->pw_name : std::to_string(file_stat.st_uid);

        // 2. 八进制权限（0777格式）
        info.mode_int = file_stat.st_mode & 0777;
        info.mode_str = ModeTrans(info.mode_int);

        // 3. 访问时间（access time）和修改时间（modify time）
        // 使用 struct timespec 成员（包含秒和纳秒，POSIX 标准）
        info.access_time = timespec_to_double(file_stat.st_atim); // st_atim 是 timespec 类型
        info.modify_time = timespec_to_double(file_stat.st_mtim); // st_mtim 是 timespec 类型
#endif
#ifdef __APPLE__
        info.create_time = timespec_to_double(file_stat.st_birthtimespec);
#endif
        return std::make_pair("", info);
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
        std::variant<PathInfo, std::pair<std::string, std::exception>> sr;
        for (const auto &entry : fs::directory_iterator(p))
        {
            auto [error, info] = stat(entry.path().string(), false);
            if (!error.empty())
            {
                continue;
            }
            result.push_back(info);
        }
        return result;
    }

    void _iwalk(std::string path, std::vector<PathInfo> &result, bool ignore_sepcial_file)
    {
        auto [error, info] = stat(path);
        if (!error.empty())
        {
            return;
        }
        bool end_dir = true;

        switch (info.type)
        {
        case PathType::DIR:

            for (const auto &entry : listdir(path))
            {
                if (entry.type == PathType::DIR)
                {
                    end_dir = false;
                }
                _iwalk(entry.path, result, ignore_sepcial_file);
            }
            if (end_dir)
            {
                result.push_back(info);
            }
            break;
        default:
            if (ignore_sepcial_file && static_cast<int>(info.type) < 0)
            {
                return;
            }
            result.push_back(info);
            break;
        }
    }

    void _walk(std::vector<std::string> parts, std::vector<std::pair<std::vector<std::string>, PathInfo>> &result, int cur_depth, int max_depth, bool ignore_sepcial_file)
    {
        if (max_depth > 0 && cur_depth > max_depth)
        {
            return;
        }
        std::string path = join(parts);
        auto [error, info] = stat(path);
        if (!error.empty())
        {
            return;
        }
        switch (info.type)
        {
        case PathType::DIR:
        {
            try
            {
                bool empty_dir = true;
                for (const auto &entry : listdir(path))
                {
                    empty_dir = false;
                    auto n_parts = parts;
                    n_parts.push_back(entry.name);
                    _walk(n_parts, result, cur_depth + 1, max_depth, ignore_sepcial_file);
                }
                if (empty_dir)
                {
                    if (parts.size() > 1)
                    {
                        // 如果是末级目录， 则加入此目录
                        auto b_parts = parts;
                        b_parts.pop_back();
                        result.push_back(std::make_pair(b_parts, info));
                    }
                }
            }
            catch (const std::exception)
            {
            }
            break;
        }
        default:
        {
            if (ignore_sepcial_file && static_cast<int>(info.type) < 0)
            {
                return;
            }
            auto d_parts = parts;
            d_parts.pop_back();
            result.push_back(std::make_pair(d_parts, info));
            break;
        }
        }
    }

    std::vector<PathInfo> iwalk(const std::string &path, bool ignore_sepcial_file)
    {
        std::vector<PathInfo> result = {};

        _iwalk(path, result, ignore_sepcial_file);

        return result;
    }

    std::vector<std::pair<std::vector<std::string>, PathInfo>> walk(const std::string &path, int max_depth, bool ignore_sepcial_file)
    {
        std::vector<std::pair<std::vector<std::string>, PathInfo>> result = {};
        std::vector<std::string> parts = {path};

        _walk(parts, result, 0, max_depth, ignore_sepcial_file);

        return result;
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

    uint64_t getsize(const std::string &path, bool trace_link = false)
    {
        uint64_t result = 0;
        _getsize(path, result, trace_link);
        return result;
    }

    std::tuple<std::vector<std::string>, std::string, bool> preprocess(std::string path, bool use_regex)
    {

        Str::VStrip(path);

        std::string sep = Str::GetPathSep(path);

        if (!IsAbs(path, sep))
        {
            path = HomePath() + sep + path;
        }

        std::vector<std::string> ori_parts;
        if (use_regex)
        {
            ori_parts = resplit(path, '<', '>', "<");
        }
        else
        {
            ori_parts = split(path);
        }

        std::vector<std::string> path_parts = {};

        bool is2star = false;
        bool is_recursive = false;
        for (int i = 0; i < ori_parts.size(); i++)
        {
            auto part = ori_parts[i];
            if (part == "**")
            {
                is_recursive = true;
                if (is2star)
                {
                    continue;
                }
                else
                {
                    is2star = true;
                    path_parts.push_back(part);
                }
            }
            else
            {
                is2star = false;
                path_parts.push_back(part);
            }
        }

        std::vector<std::string> match_parts;
        std::vector<std::string> root_parts;

        int num_i = 0;
        bool is_match;
        bool is_end = false;
        for (int i = 0; i < path_parts.size(); i++)
        {
            auto part = path_parts[i];
            if (is_end)
            {
                match_parts.push_back(part);
                continue;
            }

            if (use_regex)
            {
                is_match = part[0] == '<' || part.find("*") != std::string::npos;
            }
            else
            {
                is_match = part.find("*") != std::string::npos;
            }

            if (is_match)
            {
                match_parts.push_back(part);
                is_end = true;
            }
            else
            {
                root_parts.push_back(part);
            }
        }

        return std::make_tuple(match_parts, realpath(join(root_parts), false, "\\"), is_recursive);
    }

    void search(std::vector<std::string> &results, fs::path root, std::string name, std::vector<std::string> remains, SearchType type, bool use_regex, bool silence, CB callback)
    {
        if (!remains.empty())
        {
            if (!fs::is_directory(root))
            {
                return;
            }
            try
            {
                fs::path cur_path;
                std::string cur_name;
                bool is_dir;
                bool is_match;
                bool next_match;
                for (auto &entry : fs::directory_iterator(root))
                {
                    cur_name = entry.path().filename().string();
                    cur_path = join(root, cur_name);
                    is_dir = fs::is_directory(cur_path);
                    is_match = Str::_match(cur_name, name, use_regex);

                    if (name == "**")
                    {
                        next_match = Str::_match(cur_name, remains.front(), use_regex);
                        if (is_dir)
                        {
                            search(results, cur_path, name, remains, type, use_regex, silence, callback);
                            if (next_match)
                            {
                                auto new_name = remains.front();
                                auto new_remains = remains;
                                new_remains.erase(new_remains.begin());
                                search(results, cur_path, new_name, new_remains, type, use_regex, silence, callback);
                            }
                        }
                        else
                        {
                            if (next_match)
                            {
                                results.push_back(cur_path.string());
                            }
                        }
                        continue;
                    }

                    search(results, cur_path, name, remains, type, use_regex, silence, callback);
                    if (is_match)
                    {
                        auto new_name = remains.front();
                        auto new_remains = remains;
                        new_remains.erase(new_remains.begin());
                        search(results, cur_path, new_name, new_remains, type, use_regex, silence, callback);
                    }
                    continue;
                }

                if (is_match && is_dir)
                {
                    std::string new_name = remains[0];
                    auto new_remains = remains;
                    new_remains.erase(new_remains.begin());
                    search(results, cur_path, new_name, new_remains, type, use_regex, silence, callback);
                }
            }
            catch (const std::exception e)
            {
                if (!silence && callback)
                {
                    (*callback)(root.string(), "IterdirFailed", e.what());
                }
            }
        }
        else
        {
            if (!fs::is_directory(root))
            {
                if (type != SearchType::Directory && Str::_match(root.filename().string(), name, use_regex))
                {
                    results.push_back(root.string());
                }
                return;
            }

            if (name == "**")
            {
                fs::path cur_path;
                std::string cur_name;
                bool is_dir;
                for (auto &entry : fs::directory_iterator(root))
                {
                    cur_name = entry.path().filename().string();
                    cur_path = join(root, cur_name);
                    is_dir = fs::is_directory(cur_path);
                    if (!is_dir)
                    {
                        if (type != SearchType::Directory)
                        {
                            results.push_back(cur_path.string());
                        }
                        continue;
                    }
                    if (fs::is_empty(cur_path))
                    {
                        if (type != SearchType::File)
                        {
                            results.push_back(cur_path.string());
                        }
                        continue;
                    }
                    search(results, cur_path, "**", {}, type, use_regex, silence, callback);
                }
                return;
            }

            bool is_dir2;
            std::string cur_name;
            fs::path cur_path;
            try
            {
                for (auto &entry : fs::directory_iterator(root))
                {
                    cur_name = entry.path().filename().string();
                    cur_path = join(root, cur_name);
                    if (!Str::_match(cur_name, name, use_regex))
                    {
                        continue;
                    }
                    is_dir2 = fs::is_directory(cur_path);
                    if (is_dir2 && type != SearchType::File)
                    {
                        results.push_back(cur_path.string());
                    }
                    else if (!is_dir2 && type != SearchType::Directory)
                    {
                        results.push_back(cur_path.string());
                    }
                }
            }
            catch (const std::exception e)
            {
                std::cout << "error: " << e.what() << std::endl;
                if (!silence && callback)
                {
                    (*callback)(root.string(), "IterdirFailed", e.what());
                }
            }
        }
    }

    std::vector<std::string> find(const std::string &path_f, SearchType type = SearchType::All, bool use_regex = false, bool silence = false, CB callback = nullptr)
    {

        std::string path = path_f;
        if (fs::exists(path) && !use_regex)
        {
            return std::vector<std::string>{path};
        }
        auto pre_result = preprocess(path, use_regex);
        auto match_parts = std::get<0>(pre_result);
        auto root_path = std::get<1>(pre_result);
        bool is_recursive = std::get<2>(pre_result);
        std::vector<std::string> results;

        if (root_path.empty())
        {
            if (callback)
            {
                (*callback)(path_f, "FailToParsingRoot", "Parsed Root is Empty");
            }
            return {};
        }

        if (!fs::exists(root_path))
        {
            return {};
        }

        if (match_parts.empty())
        {
            return std::vector<std::string>{root_path};
        }

        if (use_regex)
        {
            auto reg_check = Str::isPatternsValid(match_parts);
            if (!std::get<0>(reg_check))
            {
                return {};
            }
        }

        std::string name_first = match_parts.front();
        match_parts.erase(match_parts.begin());

        if (root_path.find("\\") == std::string::npos && root_path.find("/") == std::string::npos)
        {
            root_path = root_path + "\\";
        }

        search(results, fs::path(root_path), name_first, match_parts, type, use_regex, silence, callback);
        return results;
    }
}
