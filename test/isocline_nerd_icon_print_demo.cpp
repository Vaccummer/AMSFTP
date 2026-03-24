#include "Isocline/isocline.h"
#include <iostream>
#include <string>

/**
 * @brief Manual demo for Nerd icon rendering through isocline ic_print.
 *
 * Expected: the three icons render the same in std::cout and ic_print output.
 */
int main() {
  const std::string icon_macos = u8"\uf179";
  const std::string icon_linux = u8"\uf17c";
  const std::string icon_windows = u8"\U000F0A21";
  const std::string icons = icon_macos + " " + icon_linux + " " + icon_windows;

  std::cout << "std::cout: " << icons << std::endl;

  const std::string styled = "[#FFFFFF]ic_print (styled): " + icons + "[/]";
  ic_println(styled.c_str());
  ic_term_flush();

  const std::string plain = "ic_print (plain): " + icons;
  ic_println(plain.c_str());
  ic_term_flush();
  return 0;
}
