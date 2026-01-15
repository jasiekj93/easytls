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

#include <libeasytls/Client.hpp>

#include "SocketBio.hpp"
#include "CoutDebug.hpp"
#include "TimeImpl.hpp"

using namespace easytls;

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
    SocketBio bio("/tmp/mbedtls-test.sock", false);
    auto debug = std::make_shared<CoutDebug>();
    Debug::setGlobal(debug);
    auto time = std::make_shared<TimeImpl>();
    Time::setGlobal(time);

    auto caCertData = readFile("certificates/ca-cert.pem");
    auto caCert = x509::Certificate::parse({ reinterpret_cast<const unsigned char*>(caCertData.c_str()), caCertData.length() + 1 });

    if(not caCert)
        throw std::runtime_error("Failed to parse CA certificates. Status: " + std::to_string(x509::Certificate::getParseStatus()));

    auto clientCertData = readFile("certificates/client-cert.pem");
    auto clientCert = x509::Certificate::parse({ reinterpret_cast<const unsigned char*>(clientCertData.c_str()), clientCertData.length() + 1 });

    if(not clientCert)
        throw std::runtime_error("Failed to parse client certificate. Status: " + std::to_string(x509::Certificate::getParseStatus()));

    auto clientKeyData = readFile("certificates/client-key.pem");
    auto clientKey = PrivateKey::parse({ reinterpret_cast<const unsigned char*>(clientKeyData.c_str()), clientKeyData.length() + 1 });

    if(not clientKey)
        throw std::runtime_error("Failed to parse client private key. Status: " + std::to_string(PrivateKey::getParseStatus()));
    
    Client tls(bio, "localhost", caCert.value(), clientCert.value(), clientKey.value());

    if(not tls.isValid())
        throw std::runtime_error("Failed to create TLS client. Result: " + std::to_string(tls.getErrorCode()));

    tls.setDebug(Tls::DebugLevel::INFO);

    doHandshake(tls);
    auto ret = sendMessage(tls);
    tls.closeNotify();

    std::cout << "TLS Connection closed." << std::endl;
    return ret;
}
