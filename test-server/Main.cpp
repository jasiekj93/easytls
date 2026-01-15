/**
 * @file Main.cpp
 * @author Adrian Szczepanski
 * @date 2025-12-04
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>

#include <unistd.h>

#include <libeasytls/Server.hpp>

#include "SocketBio.hpp"
#include "CoutDebug.hpp"
#include "TimeImpl.hpp"

using namespace easytls;

std::string readFile(const std::string& filename) 
{
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    return content;
}

void doHandshake(Server& ssl)
{
    int ret = 0;

    std::cout << "Waiting for TLS handshake over Unix socket..." << std::endl;

    while ((ret = ssl.handshake()) != 0) 
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ and ret != MBEDTLS_ERR_SSL_WANT_WRITE) 
            throw std::runtime_error("TLS handshake failed with error: " + std::to_string(ret));

        usleep(1000);
    }
    std::cout << "TLS handshake completed!" << std::endl;
}

int receiveData(Server& ssl)
{
    int ret = 0;
    unsigned char buffer[256];
    while (true) 
    {
        ret = ssl.read({ buffer, sizeof(buffer) - 1 });
        
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) 
        {
            usleep(1000);
            continue;
        }
        
        if (ret <= 0) 
        {
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) 
                std::cout << "Client disconnected" << std::endl;

            break;
        }
        
        buffer[ret] = '\0';
        std::cout << "Received: " << buffer << std::endl;
        
        const char *response = "Message received over TLS/Unix socket";
        ssl.write({ (unsigned char *)response, strlen(response) });
    }

    return ret;
}


int main(int argc, char* argv[])
{
    SocketBio bio("/tmp/mbedtls-test.sock", true);
    auto debug = std::make_shared<CoutDebug>();
    Debug::setGlobal(debug);
    auto time = std::make_shared<TimeImpl>();
    Time::setGlobal(time);

    auto caCertData = readFile("certificates/ca-cert.pem");
    auto caCert = x509::Certificate::parse({ reinterpret_cast<const unsigned char*>(caCertData.c_str()), caCertData.length() + 1 });

    if (not caCert)
        throw std::runtime_error("Failed to parse CA certificate. Status: " + std::to_string(x509::Certificate::getParseStatus()));
    
    auto serverCertData = readFile("certificates/server-cert.pem");
    auto serverCert = x509::Certificate::parse({ reinterpret_cast<const unsigned char*>(serverCertData.c_str()), serverCertData.length() + 1 });

    if (not serverCert)
        throw std::runtime_error("Failed to parse server certificate. Status: " + std::to_string(x509::Certificate::getParseStatus()));
    
    auto serverKeyData = readFile("certificates/server-key.pem");
    auto serverKey = PrivateKey::parse({ reinterpret_cast<const unsigned char*>(serverKeyData.c_str()), serverKeyData.length() + 1 });

    if (not serverKey)
        throw std::runtime_error("Failed to parse server private key. Status: " + std::to_string(PrivateKey::getParseStatus()));
    
    Server tls(bio, "test-client", serverCert.value(), serverKey.value(), caCert.value());

    if(not tls.isValid())
        throw std::runtime_error("Failed to create TLS server. Result: " + std::to_string(tls.getErrorCode()));

    tls.setDebug(Tls::DebugLevel::INFO);

    doHandshake(tls);
    auto ret = receiveData(tls);  

    if(ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        tls.closeNotify();

    std::cout << "TLS Connection closed." << std::endl;
	return ret;
}
