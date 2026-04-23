#pragma once

#include <string>
#include <vector>

namespace AMInterface::filesystem {

struct FilesystemStatArg {
  std::vector<std::string> raw_paths = {};
  bool trace_link = false;
};

struct FilesystemLsArg {
  std::string raw_path = {};
  bool list_like = false;
  bool show_all = false;
};

struct FilesystemCdArg {
  std::string raw_path = {};
};

struct FilesystemMkdirsArg {
  std::vector<std::string> raw_paths = {};
};

struct FilesystemGetSizeArg {
  std::vector<std::string> raw_paths = {};
};

struct FilesystemFindArg {
  std::string raw_path = {};
  std::string raw_pattern = {};
};

struct FilesystemRealpathArg {
  std::string raw_path = {};
};

struct FilesystemTreeArg {
  std::string raw_path = {};
  int max_depth = -1;
  bool only_dir = false;
  bool show_all = false;
  bool ignore_special_file = true;
  bool quiet = false;
};

struct FilesystemTestRTTArg {
  int times = 1;
};

struct FilesystemRenameArg {
  std::string target = {};
  std::string dst = {};
  bool mkdir = true;
  bool overwrite = false;
};

struct FilesystemMoveArg {
  std::string target = {};
  std::string dst = {};
  bool mkdir = true;
  bool overwrite = false;
};

struct FilesystemSafermArg {
  std::vector<std::string> targets = {};
};

struct FilesystemRmfileArg {
  std::vector<std::string> targets = {};
};

struct FilesystemRmdirArg {
  std::vector<std::string> targets = {};
};

struct FilesystemPermanentRemoveArg {
  std::vector<std::string> targets = {};
  bool quiet = false;
};

} // namespace AMInterface::filesystem
