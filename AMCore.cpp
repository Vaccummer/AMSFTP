#include "AMCore.hpp"
std::atomic<bool> is_wsa_initialized(false);
void cleanup_wsa()
{
    if (is_wsa_initialized)
    {
        WSACleanup();
        is_wsa_initialized = false;
    }
}