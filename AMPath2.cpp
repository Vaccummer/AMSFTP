#include "AMPath2.hpp"
#include <Poco/File.h>
#include <Poco/FileInfo.h>
#include <Poco/Path.h>
#include <Poco/Timestamp.h>
#include <Poco/Exception.h>

namespace fs = std::filesystem;
using EC = ErrorCode;
using ECM = std::pair<EC, std::string>;

PathInfo::PathInfo()
    : name(""), path(""), dir(""), onwer(""), size(0), create_time(0), access_time(0), modify_time(0), type(PathType::FILE), mode_int(0777), mode_str("rwxrwxrwx") {}

namespace AMFS
{
    std::string realpath(const std::string &path)
    {
        try
        {
            fs::path p(path);
            return fs::canonical(p).generic_string();
        }
        catch (const std::exception &)
        {
            fs::path p(path);
            return fs::absolute(p).lexically_normal().generic_string();
        }
    }

    std::variant<PathInfo, ECM> stat(const std::string &path)
    {
        PathInfo info;

        try
        {
            // Use Poco::File for cross-platform file operations
            Poco::File file(path);

            // Check if path exists
            if (!file.exists())
            {
                return ECM(EC::PathNotExist, fmt::format("Path does not exist: {}", path));
            }

            // Get absolute path using Poco::Path
            Poco::Path pocoPath(path);
            pocoPath.makeAbsolute();
            info.path = pocoPath.toString();
            info.name = pocoPath.getFileName();
            info.dir = pocoPath.parent().toString();

            // Get file type
            if (file.isFile())
            {
                info.type = PathType::FILE;
                info.size = file.getSize();
            }
            else if (file.isDirectory())
            {
                info.type = PathType::DIR;
                info.size = 0;
            }
            else if (file.isLink())
            {
                info.type = PathType::SYMLINK;
                // For symlinks, try to get target size
                try
                {
                    Poco::File targetFile(path);
                    if (targetFile.exists() && targetFile.isFile())
                    {
                        info.size = targetFile.getSize();
                    }
                    else
                    {
                        info.size = 0;
                    }
                }
                catch (...)
                {
                    info.size = 0;
                }
            }
            else
            {
                // Check for other file types using filesystem
                fs::file_status status = fs::status(path);
                switch (status.type())
                {
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
                default:
                    info.type = PathType::Unknown;
                    break;
                }
                info.size = 0;
            }

            // Get file owner using Poco::FileInfo
            try
            {
                Poco::FileInfo fileInfo(path);
                info.onwer = fileInfo.getOwner();
            }
            catch (const Poco::Exception &)
            {
                info.onwer = "unknown";
            }

            // Get timestamps using Poco::File
            Poco::Timestamp modifyTs = file.getLastModified();
            info.modify_time = modifyTs.epochTime();
            info.access_time = modifyTs.epochTime(); // Poco::File doesn't provide access time directly

            // Get creation time using Poco::FileInfo
            try
            {
                Poco::FileInfo fileInfo(path);
                Poco::Timestamp createTs = fileInfo.created();
                info.create_time = createTs.epochTime();
            }
            catch (const Poco::Exception &)
            {
                // Fallback to modify time if creation time is not available
                info.create_time = info.modify_time;
            }

            // Get file permissions using Poco::File
            // Poco::File provides canRead(), canWrite(), canExecute() which are cross-platform
            uint64_t mode_int = 0;
            std::string user_perm = "";

            // Build user permissions
            if (file.canRead())
            {
                mode_int += 0400; // user read
                user_perm += "r";
            }
            else
            {
                user_perm += "-";
            }

            if (file.canWrite())
            {
                mode_int += 0200; // user write
                user_perm += "w";
            }
            else
            {
                user_perm += "-";
            }

            if (file.canExecute())
            {
                mode_int += 0100; // user execute
                user_perm += "x";
            }
            else
            {
                user_perm += "-";
            }

            // For group and other, we'll use the same permissions as user
            // This is a simplification; on Unix, actual permissions may differ
            // But Poco::File doesn't provide separate group/other permissions
            // Replicate user permissions to group and other
            mode_int = mode_int | (mode_int >> 3) | (mode_int >> 6);
            info.mode_str = user_perm + user_perm + user_perm;

            info.mode_int = mode_int;

            // If mode_int is 0, set default permissions
            if (info.mode_int == 0)
            {
                info.mode_int = 0777;
                info.mode_str = "rwxrwxrwx";
            }
        }
        catch (const Poco::Exception &e)
        {
            return ECM(EC::LocalStatError, fmt::format("Failed to stat path {}: {}", path, e.displayText()));
        }
        catch (const std::exception &e)
        {
            return ECM(EC::LocalStatError, fmt::format("Failed to stat path {}: {}", path, e.what()));
        }
        catch (...)
        {
            return ECM(EC::LocalStatError, fmt::format("Unknown error while statting path: {}", path));
        }

        return info;
    }
}
