#include "NTPClient.h" 
#include <iostream>
#include <string>
#include <vector>

int main() {
    std::vector<std::string> test_servers = {
        "0.au.pool.ntp.org",
        "1.au.pool.ntp.org",
        "2.au.pool.ntp.org",
        "3.au.pool.ntp.org"
    };

    for (const auto& server : test_servers) {
        std::cout << "Testing NTP Server: " << server << std::endl;

        NTPClient client(server);

        if (!client.connect()) {
            std::cerr << "Failed to connect to " << server << std::endl;
            continue;
        }

        NTPResult result = client.offset();

        if (result.rtt >= 9999.0) {
            std::cerr << "No response from " << server << std::endl;
        } else {
            std::cout << "Offset: " << result.offset << " seconds" << std::endl;
            std::cout << "RTT: " << result.rtt << " seconds" << std::endl;
        }

        client.disconnect();

        std::cout << "----------------------------------------\n" << std::endl;
    }

    std::cout << "Press enter to exit." << std::cin.get();
    return 0;
}
