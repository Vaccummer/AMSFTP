#include <filesystem>
#include <iostream>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

int main() {
  const fs::path target_dir = "./test_directory";

  std::vector<fs::path> all_files;
  std::unordered_set<fs::path> all_dirs;   // 存储所有目录
  std::unordered_set<fs::path> has_subdir; // 存储有子目录的目录（非末级）

  try {
    for (const auto &entry : fs::recursive_directory_iterator(target_dir)) {
      if (entry.is_regular_file()) {
        all_files.push_back(entry.path());
      } else if (entry.is_directory()) {
        const fs::path &current_dir = entry.path();
        all_dirs.insert(current_dir);

        // 记录其父目录：如果当前目录存在，说明父目录有子文件夹，不是末级
        const fs::path &parent_dir = current_dir.parent_path();
        if (parent_dir !=
            current_dir) { // 避免根目录自己标记自己（根目录的父目录是自己）
          has_subdir.insert(parent_dir);
        }
      }
    }
  } catch (const fs::filesystem_error &e) {
    std::cerr << "遍历失败: " << e.what() << std::endl;
    return 1;
  }

  // 末级文件夹 = 所有目录 - 有子目录的目录
  std::vector<fs::path> leaf_dirs;
  for (const auto &dir : all_dirs) {
    if (has_subdir.find(dir) == has_subdir.end()) {
      leaf_dirs.push_back(dir);
    }
  }

  // 输出结果（同方法1）
  std::cout << "=================== 所有文件路径 ==================="
            << std::endl;
  for (const auto &file : all_files) {
    std::cout << file << std::endl;
  }

  std::cout << "\n=================== 末级文件夹路径 ==================="
            << std::endl;
  for (const auto &dir : leaf_dirs) {
    std::cout << dir << std::endl;
  }

  return 0;
}