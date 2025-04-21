#include "AMEnum.hpp"
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <unordered_map>
#include <string>
#include <magic_enum/magic_enum.hpp>

const std::unordered_map<int, std::string> SFTPMessage = {
    {LIBSSH2_FX_EOF, "End of file"},
    {LIBSSH2_FX_NO_SUCH_FILE, "File does not exist"},
    {LIBSSH2_FX_PERMISSION_DENIED, "Permission denied"},
    {LIBSSH2_FX_FAILURE, "Generic failure"},
    {LIBSSH2_FX_BAD_MESSAGE, "Bad message format"},
    {LIBSSH2_FX_NO_CONNECTION, "No connection exists"},
    {LIBSSH2_FX_CONNECTION_LOST, "Connection lost"},
    {LIBSSH2_FX_OP_UNSUPPORTED, "Operation not supported"},
    {LIBSSH2_FX_INVALID_HANDLE, "Invalid handle"},
    {LIBSSH2_FX_NO_SUCH_PATH, "No such path"},
    {LIBSSH2_FX_FILE_ALREADY_EXISTS, "File already exists"},
    {LIBSSH2_FX_WRITE_PROTECT, "Target is write protected"},
    {LIBSSH2_FX_NO_MEDIA, "Target Storage Media is not available"},
    {LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM, "No space on filesystem"},
    {LIBSSH2_FX_QUOTA_EXCEEDED, "Space quota exceeded"},
    {LIBSSH2_FX_UNKNOWN_PRINCIPAL, "User not found in host"},
    {LIBSSH2_FX_LOCK_CONFLICT, "Path is locked by another process"},
    {LIBSSH2_FX_DIR_NOT_EMPTY, "Directory is not empty"},
    {LIBSSH2_FX_NOT_A_DIRECTORY, "Target is not a directory"},
    {LIBSSH2_FX_INVALID_FILENAME, "Filename is invalid"},
    {LIBSSH2_FX_LINK_LOOP, "Symbolic link loop"}};

const std::unordered_map<int, TransferErrorCode> Int2EC = []
{
    std::unordered_map<int, TransferErrorCode> map;
    for (auto [val, name] : magic_enum::enum_entries<TransferErrorCode>())
    {
        map[static_cast<int>(val)] = val;
    }
    return map;
}();

std::string GetECName(TransferErrorCode ec)
{
    return std::string(magic_enum::enum_name(ec));
}