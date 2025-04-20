#include <libssh2.h>
#include <fmt/core.h>
#include <libssh2_sftp.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
#include <windows.h>
#include <time.h>
#include <fcntl.h>
#include <atomic>
#include <string>
#include <stdio.h>
#include <vector>
#include <iostream>
#include <time.h>
#include <unordered_map>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <filesystem>
#include <algorithm>
#include <chrono>
#include <numeric>
#include <memory>
#include <cstdint>

namespace py = pybind11;
LIBSSH2_SESSION *init_session()
{

    std::string host = "172.26.36.83";
    std::string username = "am";
    std::string password = "1984";
    std::string msg = "";
    WSADATA wsaData;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    unsigned long nonblocking = 1;
    ioctlsocket(sock, FIONBIO, &nonblocking);

    sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    inet_pton(AF_INET, host.c_str(), &sin.sin_addr);
    int rcr = connect(sock, (sockaddr *)&sin, sizeof(sin));

    timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    int selectRet = select(sock + 1, nullptr, &writeSet, nullptr, &timeout);
    if (selectRet <= 0)
    {
        std::cout << "Connect Timeout" << std::endl;
        return nullptr;
    }

    LIBSSH2_SESSION *session = libssh2_session_init();

    if (!session)
    {
        std::cout << "SessionCreateError" << std::endl;
        return nullptr;
    }

    libssh2_session_set_blocking(session, 1);

    int rc_handshake = libssh2_session_handshake(session, sock);

    if (rc_handshake != 0)
    {
        std::cout << "HandshakeEstablishError" << std::endl;
        return nullptr;
    }
    int rca = libssh2_userauth_password(session, username.c_str(), password.c_str());
    if (rca < 0)
    {
        std::cout << "AuthorizeFailed" << std::endl;
        return nullptr;
    }
    return session;
}

int test_am(std::string path)
{
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        throw std::runtime_error("WSAStartup failed");
    }
    LIBSSH2_SESSION *session = init_session();
    if (!session)
    {
        std::cout << "SessionCreateError" << std::endl;
        return 0;
    }
    LIBSSH2_SFTP *sftp = libssh2_sftp_init(session);
    if (!sftp)
    {
        std::cout << "SFTPInitError" << std::endl;
        return 0;
    }

    char path_t[1024];
    int rcr = libssh2_sftp_realpath(sftp, path.c_str(), path_t, sizeof(path_t));
    if (rcr < 0)
    {
        char *errmsg = NULL;
        int errmsg_len;
        int errcode = libssh2_session_last_error(session, &errmsg, &errmsg_len, 0);
        std::cout << errmsg << std::endl;
        return 0;
    }
    else
    {
        std::cout << path_t << std::endl;
    }
    libssh2_session_free(session);
    WSACleanup();
    return 0;
}

PYBIND11_MODULE(debug_test, m)
{
    m.def("test_am", &test_am, py::arg("path") = "/home/am/test");
}
