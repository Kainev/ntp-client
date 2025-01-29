#include "NTPClient.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <BaseTsd.h>

    typedef SSIZE_T ssize_t;

    #pragma comment(lib, "Ws2_32.lib")

    #define CLOSE_SOCKET(x) closesocket(x)
    
    static bool g_wsa_initialized = false; 
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <unistd.h>

    #define CLOSE_SOCKET(x) close(x)
#endif

#include <iostream>
#include <cstring>
#include <chrono>
#include <bit>
#include <climits>
#include <cstdint>

static constexpr uint64_t NTP_TIMESTAMP_DELTA = 2208988800ULL; // offset 1900 to 1970
static constexpr size_t   NTP_PACKET_SIZE    = 48;
static constexpr double   MIN_RTT            = 1e-9;

#pragma pack(push, 1)
struct NTPPacket {
    uint8_t li_vn_mode; // Leap indicator (2 bits), Version (3 bits), Mode (3 bits)
    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t ref_id;
    uint64_t ref_timestamp;
    uint64_t orig_timestamp;
    uint64_t recv_timestamp;
    uint64_t tx_timestamp;
};
#pragma pack(pop)

constexpr uint64_t htonll_impl(uint64_t val)
{
    if constexpr (std::endian::native != std::endian::big) {
        static_assert(CHAR_BIT == 8);
        // Byte-swap 64-bit
        uint64_t h = val;
        h = ((h & 0x00FF00FF00FF00FFULL) <<  8) | ((h & 0xFF00FF00FF00FF00ULL) >>  8);
        h = ((h & 0x0000FFFF0000FFFFULL) << 16) | ((h & 0xFFFF0000FFFF0000ULL) >> 16);
        h = ((h & 0x00000000FFFFFFFFULL) << 32) | ((h & 0xFFFFFFFF00000000ULL) >> 32);
        return h;
    } else {
        return val;
    }
}
constexpr uint64_t ntohll_impl(uint64_t val) { return htonll_impl(val); }

static double ntp_to_seconds(uint64_t ntp_val)
{
    uint32_t sec  = (ntp_val >> 32) & 0xFFFFFFFFULL;
    uint32_t frac = ntp_val & 0xFFFFFFFFULL;
    double fraction = static_cast<double>(frac) / static_cast<double>(1ULL << 32);
    double total    = static_cast<double>(sec) + fraction - static_cast<double>(NTP_TIMESTAMP_DELTA);
    return total;
}

// system_clock -> NTP 64-bit
static uint64_t ntp_now()
{
    using namespace std::chrono;
    auto now     = system_clock::now();
    auto secs    = duration_cast<seconds>(now.time_since_epoch()).count();
    auto usecs   = duration_cast<microseconds>(now.time_since_epoch()).count() % 1000000ULL;
    uint64_t ntp_seconds  = static_cast<uint64_t>(secs) + NTP_TIMESTAMP_DELTA;
    uint64_t ntp_fraction = static_cast<uint64_t>(
        (static_cast<double>(usecs) * static_cast<double>(1ULL << 32)) / 1.0e6
    );
    return (ntp_seconds << 32) | (ntp_fraction & 0xFFFFFFFFULL);
}


NTPClient::NTPClient(const std::string& server, unsigned short port) :
    _server(server),
    _port(port),
    _socket(static_cast<socket_t>(-1)),
    _is_connected(false)
{
    std::memset(&_socket_address, 0, sizeof(_socket_address));
    _socket_address_length = 0;
}

NTPClient::~NTPClient()
{
    disconnect();
}

bool NTPClient::connect()
{
    if(_is_connected) {
        return true;
    }

#   ifdef _WIN32
    if(!g_wsa_initialized) {
        WSADATA wsa_data;
        int error = WSAStartup(MAKEWORD(2, 2), &wsa_data);

        if(error != 0) {
            std::cerr << "[NTPClient] WSAStartup failed: " << error << "\n";
            return false;
        }

        g_wsa_initialized = true;
    }
#   endif

    return _open_socket();
}

void NTPClient::disconnect()
{
    if(!_is_connected) {
        return;
    }

    CLOSE_SOCKET(_socket);
    _socket = static_cast<socket_t>(-1);
    _is_connected = false;
}

bool NTPClient::_open_socket()
{
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;  
    hints.ai_protocol = IPPROTO_UDP; 

    char port_string[16];
    std:snprintf(port_string, sizeof(port_string), "%u", _port);

    struct addrinfo* addr_info = nullptr;

#   ifdef _WIN32
    int status = getaddrinfo(_server.c_str(), port_string, &hints, &addr_info);
    if (status != 0) {
        std::cerr << "[NTPClient] getaddrinfo failed for " 
                << _server << ": " << status << "\n";
        return false;
    }
#   else
    int status = getaddrinfo(_server.c_str(), port_string, &hints, &addr_info);
    if (status != 0) {
        std::cerr << "[NTPClient] getaddrinfo failed for "
                << _server << ": " << gai_strerror(status) << "\n";
        return false;
    }
#   endif

    bool success = false;
    for (auto addr_info_p = addr_info; addr_info_p != nullptr; addr_info_p = addr_info_p->ai_next)
    {
#       ifdef _WIN32
        SOCKET s = ::socket(addr_info_p->ai_family, addr_info_p->ai_socktype, addr_info_p->ai_protocol);
        if (s == INVALID_SOCKET) {
            continue;
        }
#       else
        int s = ::socket(addr_info_p->ai_family, addr_info_p->ai_socktype, addr_info_p->ai_protocol);
        if (s < 0) {
            continue;
        }
#       endif

        std::memcpy(&_socket_address, addr_info_p->ai_addr, addr_info_p->ai_addrlen);
        _socket_address_length = static_cast<socklen_t>(addr_info_p->ai_addrlen);

        _socket = static_cast<socket_t>(s);
        success = true;
        break;
    }

    freeaddrinfo(addr_info);  

    if (!success) {
        std::cerr << "[NTPClient] Could not open socket for " << _server << "\n";
        return false;
    }

#   ifdef _WIN32
    DWORD timeout_ms = 1500;
    setsockopt(_socket, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#   else
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#   endif

    _is_connected = true;
    return true;
}

NTPResult NTPClient::offset()
{
    if (!_is_connected) {
        std::cerr << "[NTPClient] Not connected. Call connect() first.\n";
        return {0.0, 9999.0};
    }

    NTPPacket packet;
    std::memset(&packet, 0, sizeof(packet));
    packet.li_vn_mode = (0 << 6) | (4 << 3) | 3;
    uint64_t tx = ntp_now();
    packet.tx_timestamp = htonll_impl(tx);

    auto t0 = std::chrono::steady_clock::now();

    ssize_t sent = ::sendto(
        _socket,
        reinterpret_cast<const char*>(&packet),
        static_cast<int>(sizeof(packet)),
        0,
        reinterpret_cast<sockaddr*>(&_socket_address),
        _socket_address_length
    );

#   ifdef _WIN32
    if (sent == SOCKET_ERROR || sent < (ssize_t)sizeof(packet)) {
        return {0.0, 9999.0};
    }
#   else
    if (sent < 0 || static_cast<size_t>(sent) < sizeof(packet)) {
        return {0.0, 9999.0};
    }
#   endif

    NTPPacket response;
    std::memset(&response, 0, sizeof(response));
    sockaddr_storage from;
    socklen_t from_size = sizeof(from);

    ssize_t recvd = ::recvfrom(
        _socket,
        reinterpret_cast<char*>(&response),
        static_cast<int>(sizeof(response)),
        0,
        reinterpret_cast<sockaddr*>(&from), 
        &from_size
    );
    auto t1 = std::chrono::steady_clock::now();

    if (recvd < (ssize_t)sizeof(response)) {
        // No or partial response
        return {0.0, 9999.0};
    }

    double rtt = std::chrono::duration<double>(t1 - t0).count();
    if (rtt < MIN_RTT) rtt = MIN_RTT;

    // Parse response (Network byte-order to host byte-order)
    uint64_t orig = ntohll_impl(response.orig_timestamp);
    uint64_t recv = ntohll_impl(response.recv_timestamp);
    uint64_t txsv = ntohll_impl(response.tx_timestamp);
    uint64_t dst  = ntp_now();

    // ((recv - orig) + (txsv - dst)) / 2
    double offset_value = ((ntp_to_seconds(recv) - ntp_to_seconds(orig)) +
                        (ntp_to_seconds(txsv) - ntp_to_seconds(dst))) * 0.5;

    return {offset_value, rtt};
}