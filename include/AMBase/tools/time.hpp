#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

double timenow();
std::int64_t am_ms();
double am_s();
std::string FormatTime(const size_t &time,
                       const std::string &format = "%Y-%m-%d %H:%M:%S");
std::string FormatTimeHM(double timestamp);
