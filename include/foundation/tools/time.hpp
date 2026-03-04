#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace AMTime {
double seconds();
int64_t miliseconds();
std::string Str(std::string_view format = "%Y-%m-%d %H:%M:%S",
                std::optional<double> timestamp = std::nullopt);
std::chrono::steady_clock::time_point SteadyNow();
double IntervalS(const std::chrono::steady_clock::time_point &start,
                 const std::chrono::steady_clock::time_point &end);
double IntervalMS(const std::chrono::steady_clock::time_point &start,
                  const std::chrono::steady_clock::time_point &end);

} // namespace AMTime

double timenow();
std::int64_t am_ms();
double am_s();
std::string FormatTime(const size_t &time,
                       const std::string &format = "%Y-%m-%d %H:%M:%S");
std::string FormatTimeHM(double timestamp);
