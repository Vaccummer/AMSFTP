#pragma once
#include "AMEnum.hpp"
#include <filesystem>
#include <regex>
#include <string>
#include <variant>
#include <vector>
#include <windows.h>

using EC = ErrorCode;
using ECM = std::pair<EC, std::string>;
extern const std::vector<std::pair<uint64_t, size_t>> GLOBAL_PERMISSIONS_MASK;
extern const std::regex MODE_STR_PATTERN_RE;

std::string wstr2str(const std::wstring &wstr);

std::wstring str2wstr(const std::string &str);

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
    std::string dirname(const std::string &path) {

    };

    std::string basename(const std::string &path);

    std::string realpath(const std::string &path);

    ECM mkdirs(const std::string &path);

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
            else if constexpr (std::is_same_v<T, std::vector<std::string>>)
            {
                // 处理vector<string>类型，将每个元素作为单独的段
                for (auto &item : arg)
                {
                    if (!item.empty())
                    {
                        segments.push_back(item);
                    }
                }
            }
            else
            {
                // 尝试将其他类型转换为string
                try
                {
                    std::string s = std::forward<decltype(arg)>(arg);
                    if (!s.empty())
                    {
                        segments.push_back(s);
                    }
                }
                catch (const std::exception &)
                {
                    // 如果转换失败，忽略该参数
                    return;
                }
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

    std::variant<PathInfo, ECM> stat(const std::string &path);

    std::vector<PathInfo> iwalk(const std::string &path, bool ignore_sepcial_file = true);

    std::vector<std::pair<std::vector<std::string>, PathInfo>> walk(const std::string &path, int max_depth = -1, bool ignore_sepcial_file = true);

    std::vector<std::string> split(const std::string &path);

    std::vector<std::string> split(const std::filesystem::path &path);

    std::string extname(const std::string &path);

    std::string format(const std::string &path);
}