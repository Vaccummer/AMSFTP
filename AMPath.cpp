#include <filesystem>
#include <string>
#include "AMPath.hpp"
namespace fs = std::filesystem;

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

    bool lmkdirs(const std::string &path)
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
}