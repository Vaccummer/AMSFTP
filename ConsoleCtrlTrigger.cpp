#ifdef _WIN32
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

/**
 * Print command-line usage details and basic behavior notes.
 */
static void PrintUsage(const char* exe_path)
{
    std::fprintf(stderr,
                 "Usage: %s <pid> [--group] [--break] [--wait-ms N]\n"
                 "  <pid>       Target process id (decimal or 0x... hex).\n"
                 "  --group     Send to process group id = pid (requires target to be group leader).\n"
                 "  --break     Send CTRL+BREAK instead of CTRL+C.\n"
                 "  --wait-ms   Milliseconds to wait after sending (default 200).\n"
                 "Notes:\n"
                 "  - Target process must share a console with this tool.\n"
                 "  - If targeting a process group, create the target with CREATE_NEW_PROCESS_GROUP.\n",
                 exe_path);
}

/**
 * Parse a DWORD value from a command-line token (accepts decimal or 0x-prefixed hex).
 */
static bool ParseDword(const char* text, DWORD* value)
{
    if (text == nullptr || value == nullptr || text[0] == '\0')
    {
        return false;
    }

    char* end = nullptr;
    unsigned long parsed = std::strtoul(text, &end, 0);
    if (end == text || *end != '\0')
    {
        return false;
    }

    if (parsed > 0xFFFFFFFFUL)
    {
        return false;
    }

    *value = static_cast<DWORD>(parsed);
    return true;
}

/**
 * Print the last Win32 error message for a failing API call.
 */
static void PrintLastError(const char* action)
{
    DWORD err = GetLastError();
    char* msg = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageA(flags, nullptr, err, 0, reinterpret_cast<LPSTR>(&msg), 0, nullptr);

    if (len == 0 || msg == nullptr)
    {
        std::fprintf(stderr, "%s failed with error %lu.\n", action, static_cast<unsigned long>(err));
        return;
    }

    std::fprintf(stderr, "%s failed with error %lu: %s", action, static_cast<unsigned long>(err), msg);
    LocalFree(msg);
}

/**
 * Check whether a target PID is already in the current console process list.
 */
static bool IsProcessInCurrentConsole(DWORD pid)
{
    DWORD count = GetConsoleProcessList(nullptr, 0);
    if (count == 0)
    {
        return false;
    }

    std::vector<DWORD> pids(count, 0);
    count = GetConsoleProcessList(pids.data(), static_cast<DWORD>(pids.size()));
    if (count == 0)
    {
        return false;
    }

    for (DWORD listed : pids)
    {
        if (listed == pid)
        {
            return true;
        }
    }

    return false;
}

/**
 * Attach to the console of the target PID if needed, handling the "already attached" case.
 */
static bool EnsureAttachedToTargetConsole(DWORD pid)
{
    if (AttachConsole(pid))
    {
        return true;
    }

    DWORD err = GetLastError();
    if (err != ERROR_ACCESS_DENIED)
    {
        PrintLastError("AttachConsole");
        return false;
    }

    if (IsProcessInCurrentConsole(pid))
    {
        return true;
    }

    FreeConsole();
    if (!AttachConsole(pid))
    {
        PrintLastError("AttachConsole");
        return false;
    }

    return true;
}

/**
 * Entry point: parse arguments, attach to the target console, and send CTRL events.
 */
int main(int argc, char** argv)
{
    DWORD pid = 0;
    bool use_group = false;
    DWORD ctrl_event = CTRL_C_EVENT;
    DWORD wait_ms = 200;

    if (argc < 2)
    {
        PrintUsage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; ++i)
    {
        const char* arg = argv[i];
        if (std::strcmp(arg, "-h") == 0 || std::strcmp(arg, "--help") == 0)
        {
            PrintUsage(argv[0]);
            return 0;
        }

        if (std::strcmp(arg, "--group") == 0)
        {
            use_group = true;
            continue;
        }

        if (std::strcmp(arg, "--break") == 0)
        {
            ctrl_event = CTRL_BREAK_EVENT;
            continue;
        }

        if (std::strcmp(arg, "--wait-ms") == 0)
        {
            if (i + 1 >= argc)
            {
                std::fprintf(stderr, "Missing value after --wait-ms.\n");
                return 1;
            }

            if (!ParseDword(argv[++i], &wait_ms))
            {
                std::fprintf(stderr, "Invalid --wait-ms value.\n");
                return 1;
            }

            continue;
        }

        if (arg[0] == '-')
        {
            std::fprintf(stderr, "Unknown option: %s\n", arg);
            return 1;
        }

        if (pid != 0)
        {
            std::fprintf(stderr, "Multiple pids provided; only one target is supported.\n");
            return 1;
        }

        if (!ParseDword(arg, &pid))
        {
            std::fprintf(stderr, "Invalid pid: %s\n", arg);
            return 1;
        }
    }

    if (pid == 0)
    {
        PrintUsage(argv[0]);
        return 1;
    }

    if (!EnsureAttachedToTargetConsole(pid))
    {
        return 2;
    }

    if (!SetConsoleCtrlHandler(nullptr, TRUE))
    {
        PrintLastError("SetConsoleCtrlHandler");
        return 3;
    }

    DWORD group_id = use_group ? pid : 0;
    if (!GenerateConsoleCtrlEvent(ctrl_event, group_id))
    {
        PrintLastError("GenerateConsoleCtrlEvent");
        return 4;
    }

    if (wait_ms > 0)
    {
        Sleep(wait_ms);
    }

    FreeConsole();
    return 0;
}
#else
#include <cstdio>

/**
 * Entry point for non-Windows builds.
 */
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "ctrlc_trigger is only supported on Windows.\n");
    return 1;
}
#endif
