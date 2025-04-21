#pragma once
#include <string>
#include <filesystem>
#include <vector>

std::wstring str2wstr(const std::string &narrowStr);
namespace AMFS
{
    std::string dirname(const std::string &path);

    std::string basename(const std::string &path);

    std::string realpath(const std::string &path);

    bool mkdirs(const std::string &path);

    template <typename... Args>
    std::string join(Args &&...args);

    std::vector<std::string> split(std::string path);

    std::vector<std::string> split(std::filesystem::path path);
}