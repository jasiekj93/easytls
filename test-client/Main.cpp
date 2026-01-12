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

static const char certificatePem[] = 
"-----BEGIN CERTIFICATE-----\n"
"MIID1TCCAr2gAwIBAgIUTPYgsarQSBs48l4sOqItj/IzVL0wDQYJKoZIhvcNAQEL\n"
"BQAwejELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\n"
"DVNhbiBGcmFuY2lzY28xGjAYBgNVBAoMEVRlc3QgT3JnYW5pemF0aW9uMRAwDgYD\n"
"VQQLDAdUZXN0IENBMRAwDgYDVQQDDAdUZXN0IENBMB4XDTI1MTIxNTExNTUwMVoX\n"
"DTI2MTIxNTExNTUwMVowejELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3Ju\n"
"aWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xGjAYBgNVBAoMEVRlc3QgT3JnYW5p\n"
"emF0aW9uMRAwDgYDVQQLDAdUZXN0IENBMRAwDgYDVQQDDAdUZXN0IENBMIIBIjAN\n"
"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl7toc58rhveSaFTnK6rUX0QGrMLU\n"
"J9qM8pyMJBb+ZXkLyTfSx9K5luNNrVbKhSdR6lUXuaa0TUIOcHEG2LYNL6zHJysG\n"
"u9sOY35G33+Fag9uz6Bl5WtmWIUTh2xTD5j1T6umAuKraDKQJzxRBNYpBP+Opvmq\n"
"H4V99+1uu6FqLMMiO/v5gf+HNFUQqj98T7YBF33EdJPlni77p99psbLZsQMG6yZ4\n"
"BmrJbUlfUnu7pGz24ufzmg8+/pPrZG+gIJn4vb4rkHMMyWL0q56CWIhZ067EZEbv\n"
"nMwjXEImsdgsQCEdBYAqnpsTdbgFMcnhHPUX14MigEOD0EAOyb1YAJkzTwIDAQAB\n"
"o1MwUTAdBgNVHQ4EFgQUWmOZIxsQ2D8aCQQXehCpkupihW8wHwYDVR0jBBgwFoAU\n"
"WmOZIxsQ2D8aCQQXehCpkupihW8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n"
"AQsFAAOCAQEAC91QjcIFhjPySxyG4yd+efCAB4jYDSqBYdRlDXxk/e06rf8MVqWj\n"
"oqMynHd7qXjzwZcdPRcXStGHPp9BZvdOqC9E9jGa7LZmQSQySSHJvJb/u/gQsb0S\n"
"JfI+/n80lL1NIK4Mv/RaOTR/K+6fGYiUs4flQPjOkHqtqn/MXVHEMT/CH6T1mWv7\n"
"2H8F5PPwATSYN7sqAZG5uU4Ve63PEhfRIIuCBpg4QALislgT9xUkUM1scnn32KbV\n"
"R4YY7grLSCYMOXuDY8ZPZQJipG5jYLjAAjQdJPD3j9gajZxvljLUjfoQrCVpulcf\n"
"FKNV2ozfBxFpRGUS+s5doD3Yh0w1Cyv+hA==\n"
"-----END CERTIFICATE-----\n";

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

    // auto caCertData = readFile("test-client/ca-cert.pem");
    // auto cacert = x509::Certificate::parse({ reinterpret_cast<const unsigned char*>(caCertData.c_str()), caCertData.length() + 1 });

    auto cacert = easytls::x509::Certificate::parse(
        etl::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(certificatePem),
            sizeof(certificatePem)
        )
    );

    if(not cacert)
        throw std::runtime_error("Failed to parse CA certificates. Status: " + std::to_string(x509::Certificate::getParseStatus()));
    
    Client tls(bio, "localhost", cacert.value());

    if(not tls.isValid())
        throw std::runtime_error("Failed to create TLS client. Result: " + std::to_string(tls.getErrorCode()));

    tls.setDebug(Tls::DebugLevel::DEBUG);

    doHandshake(tls);
    auto ret = sendMessage(tls);
    tls.closeNotify();

    std::cout << "TLS Connection closed." << std::endl;
    return ret;
}
