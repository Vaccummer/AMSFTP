#pragma once
#include "AMEnum.hpp"
#include <filesystem>
#include <string>
#include <variant>
#include <vector>
#include <windows.h>

using EC = ErrorCode;
using ECM = std::pair<EC, std::string>;

std::wstring str2wstr(const std::string &narrowStr);

std::string ModeTrans(uint64_t mode_int);

uint64_t ModeTrans(std::string mode_str);

std::string MergeModeStr(std::string base_mode_str, std::string new_mode_str);

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
};

namespace AMFS
{
    std::string dirname(const std::string &path);

    std::string basename(const std::string &path);

    std::string realpath(const std::string &path);

    bool mkdirs(const std::string &path);

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
            else
            {
                std::string s = std::forward<decltype(arg)>(arg);
                if (s.empty())
                {
                    return;
                }
                segments.push_back(s);
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

    std::vector<PathInfo> walk(std::string path, bool ignore_sepcial_file = true);

    std::vector<std::string> split(std::string path);

    std::vector<std::string> split(std::filesystem::path path);
}