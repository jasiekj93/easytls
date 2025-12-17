/**
 * @file Main.cpp
 * @author Adrian Szczepanski
 * @date 2025-12-04
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include <mbedtlspp/Client.hpp>

#include "SocketBio.hpp"

using namespace mbedtlspp;

extern "C" int mbedtls_hardware_poll(void *data,
                          unsigned char *output, size_t len, size_t *olen)
{
    // Simple hardware poll implementation using /dev/urandom
    (void)data; // Unused parameter
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (!urandom) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    urandom.read(reinterpret_cast<char*>(output), len);
    if (urandom.gcount() != static_cast<std::streamsize>(len)) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    *olen = len;
    return 0;
}

// Function to read file contents
std::string readFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void doHandshake(Client& ssl)
{
    int ret = 0;

    std::cout << "Starting TLS handshake over Unix socket..." << std::endl;

    while ((ret = ssl.handshake()) != 0) 
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) 
        {
            std::cout << "TLS handshake failed with error: " << ret << " (0x" << std::hex << -ret << std::dec << ")" << std::endl;
            throw std::runtime_error("TLS handshake failed with error: " + std::to_string(ret));
        }

        usleep(1000);
    }
    
    std::cout << "TLS handshake completed successfully!" << std::endl;
}

int sendMessage(Client& ssl)
{
    // Send encrypted data
    const char *message = "Hello from TLS over Unix socket!";
    int ret = ssl.write({ (unsigned char *)message, strlen(message) });
    if (ret > 0) 
        std::cout << "Sent: " << message << std::endl;
    
    // Read encrypted response
    unsigned char buffer[256];

    while(true)
    {
        ret = ssl.read({ buffer, sizeof(buffer) - 1 });

        if (ret == MBEDTLS_ERR_SSL_WANT_READ) 
        {
            usleep(1000);
            continue;
        }

        if (ret > 0) 
        {
            buffer[ret] = '\0';
            std::cout << "Received: " << buffer << std::endl;
            break;
        }

    }

    return ret;
}


int main(int argc, char* argv[])
{
    // Initialize PSA crypto for TLS 1.3
    psa_status_t psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        throw std::runtime_error("PSA crypto initialization failed");
    }
    
    SocketBio bio("/tmp/mbedtls-test.sock", false);

    auto caCertData = readFile("test-client/ca-cert.pem");
    auto cacert = x509::Crt::parse({ reinterpret_cast<const unsigned char*>(caCertData.c_str()), caCertData.length() + 1 });

    if(not cacert)
        throw std::runtime_error("Failed to parse CA certificates");
    
    Client ssl(bio, cacert.value());

    doHandshake(ssl);
    auto ret = sendMessage(ssl);
    ssl.closeNotify();

    std::cout << "TLS Connection closed." << std::endl;
    return ret;
}
