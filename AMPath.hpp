#pragma once
#include "AMEnum.hpp"
#include <filesystem>
#include <regex>
#include <string>
#include <variant>
#include <vector>
#include <windows.h>

extern const std::vector<std::pair<uint64_t, size_t>> GLOBAL_PERMISSIONS_MASK;
extern const std::regex MODE_STR_PATTERN_RE;

std::wstring str2wstr(const std::string &str);

std::string wstr2str(const std::wstring &wstr);

std::string ModeTrans(uint64_t mode_int);

uint64_t ModeTrans(std::string mode_str);

std::string MergeModeStr(std::string base_mode_str, std::string new_mode_str);

bool IsModeValid(std::string mode_str);

bool IsModeValid(uint64_t mode_int);

struct PathInfo
{
public:
    std::string name;
    std::string path;
    std::string dir;
    std::string uname;
    uint64_t size = 0;
    uint64_t atime = 0;
    uint64_t mtime = 0;
    PathType type = PathType::FILE;
    uint64_t mode_int = 0777;
    std::string mode_str = "rwxrwxrwx";
    PathInfo();
    PathInfo(std::string name, std::string path, std::string dir, std::string uname, uint64_t size = 0, uint64_t atime = 0, uint64_t mtime = 0, PathType type = PathType::FILE, uint64_t mode_int = 0777, std::string mode_str = "rwxrwxrwx");
    std::string FormatTime(const uint64_t &time, const std::string &format = "%Y-%m-%d %H:%M:%S") const;
};

namespace AMFS
{
    std::string dirname(const std::string &path);

    std::string basename(const std::string &path);

    std::string realpath(const std::string &path, bool already_absolute = false);

    std::pair<ErrorCode, std::string> mkdirs(const std::string &path);

    std::vector<PathInfo> listdir(const std::string &path);

    template <typename... Args>
    std::string join(Args &&...args)
    {
        std::vector<std::string> segments;
        fs::path combined;

        auto process_arg = [&](auto &&arg)
        {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, std::filesystem::path>)
            {
                segments.push_back(arg.string());
            }
            else if constexpr (std::is_same_v<T, std::string>)
            {
                std::string s = std::forward<decltype(arg)>(arg);
                if (s.empty())
                {
                    return;
                }
                segments.push_back(s);
            }
            else if constexpr (std::is_same_v<T, std::vector<std::string>>)
            {
                segments.insert(segments.end(), arg.begin(), arg.end());
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

    std::variant<PathInfo, std::pair<ErrorCode, std::string>> stat(const std::string &path, bool trace_link = false);

    std::vector<PathInfo> walk(const std::string &path, bool ignore_sepcial_file = true, bool trace_link = false);

    std::vector<std::string> split(const std::string &path);

    std::vector<std::string> split(const std::filesystem::path &path);

    uint64_t getsize(const std::string &path, bool trace_link = false);
}