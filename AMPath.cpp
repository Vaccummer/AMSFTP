#include "AMPath.hpp"
#include "AMEnum.hpp"
#include <filesystem>
#include <string>
namespace fs = std::filesystem;

struct PathInfo
{
    std::string name;
    std::string path;
    std::string dir;
    std::string uname;
    uint64_t size = -1;
    uint64_t atime = -1;
    uint64_t mtime = -1;
    PathType path_type = PathType::FILE;
    uint64_t permission = 777;
    PathInfo()
        : name(""), path(""), dir(""), uname(""), size(-1), atime(-1), mtime(-1), path_type(PathType::FILE), permission(0) {}
    PathInfo(std::string name, std::string path, std::string dir, std::string uname, uint64_t size, uint64_t atime, uint64_t mtime, PathType path_type = PathType::FILE, uint64_t permission = 777)
        : name(name), path(path), dir(dir), uname(uname), size(size), atime(atime), mtime(mtime), path_type(path_type), permission(permission) {}
};

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

    void _walk(std::string path, std::vector<PathInfo> &result)
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
                _walk(entry.path().string(), result);
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

    std::vector<PathInfo> walk(std::string path)
    {
        std::vector<PathInfo> result = {};

        _walk(path, result);

        return result;
    }
}