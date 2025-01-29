#pragma once

#ifdef _WIN32
  #include <ws2tcpip.h>   // for socklen_t, etc.
#else
    <sys/socket.h>    
#endif

#include <string>
#include <cstdint>


struct NTPResult {
    double offset;
    double rtt;
};

class NTPClient {
public:
    NTPClient(const std::string& server, unsigned short port = 123);
    ~NTPClient();

    bool connect();
    void disconnect();

    NTPResult offset();
private:
    std::string _server;
    unsigned short _port;

#ifdef _WIN32
    using socket_t = unsigned long long;
    socket_t _socket;
    bool _wsa_initialized;
#else
    using socket_t = int;
    socket_t _socket;
#endif
    bool _is_connected;

    struct sockaddr_storage _socket_address;
    socklen_t _socket_address_length;

    bool _open_socket();
};