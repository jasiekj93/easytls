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
#include <sys/socket.h>
#include <sys/un.h>
#include <cstring>
#include <errno.h>
#include <cstdarg>

#include <mbedtls/debug.h>

#include <mbedtlspp/Ssl.hpp>
#include <mbedtls/ssl_ciphersuites.h>

using namespace mbedtlspp;

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

class BioImpl : public Bio
{
private:
    int socket_fd;
    
public:
    BioImpl(const std::string& socket_path, bool isServer) 
    {
        socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            throw std::runtime_error("Failed to create socket");
        }
        
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
        
        if (isServer) {
            unlink(socket_path.c_str()); // Remove existing socket
            if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(socket_fd);
                throw std::runtime_error("Failed to bind socket");
            }
            if (listen(socket_fd, 1) < 0) {
                close(socket_fd);
                throw std::runtime_error("Failed to listen on socket");
            }
            
            std::cout << "Server waiting for connection on " << socket_path << std::endl;
            int client_fd = accept(socket_fd, nullptr, nullptr);
            if (client_fd < 0) {
                close(socket_fd);
                throw std::runtime_error("Failed to accept connection");
            }
            close(socket_fd);
            socket_fd = client_fd;
            std::cout << "Client connected!" << std::endl;
        } else {
            if (connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(socket_fd);
                throw std::runtime_error("Failed to connect to socket");
            }
        }
    }
    
    ~BioImpl() {
        if (socket_fd >= 0) {
            close(socket_fd);
        }
    }
    
    // read/write implementations using socket_fd
    int read(etl::span<unsigned char> buffer) override
    {
        ssize_t ret = ::read(socket_fd, buffer.data(), buffer.size());

        if (ret < 0) {
            std::cout << "[SERVER] Socket read error: " << strerror(errno) << std::endl;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return MBEDTLS_ERR_SSL_WANT_READ;
            }
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        if (ret == 0) {
            std::cout << "[SERVER] Socket closed by peer" << std::endl;
            return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY; // Connection closed
        }
        std::cout << "[SERVER] Successfully read " << ret << " bytes from socket" << std::endl;
        return static_cast<int>(ret);
    }

    int read(etl::span<unsigned char> buffer, unsigned timeout) override
    {
        fd_set read_fds;
        struct timeval tv;
        
        FD_ZERO(&read_fds);
        FD_SET(socket_fd, &read_fds);
        
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        
        int ret = select(socket_fd + 1, &read_fds, nullptr, nullptr, &tv);
        
        if (ret > 0 && FD_ISSET(socket_fd, &read_fds)) {
            return read(buffer);
        } else if (ret == 0) {
            return MBEDTLS_ERR_SSL_WANT_READ; // Timeout
        } else {
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR; // Error
        }
    }

    int write(etl::span<const unsigned char> buffer) override
    {
        ssize_t ret = ::write(socket_fd, buffer.data(), buffer.size());

        if (ret < 0) {
            std::cout << "[SERVER] Socket write error: " << strerror(errno) << std::endl;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return MBEDTLS_ERR_SSL_WANT_WRITE;
            }
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        return static_cast<int>(ret);
    }
};


int main(int argc, char* argv[])
{
    BioImpl bio("/tmp/mbedtls-test.sock", true);
    Configuration configuration(MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    Entropy entropy;
    drbg::Hmac drbg(entropy);
    
    static std::string serverCertData = readFile("test-server/server-cert.pem");
    
    // For PEM parsing, mbedTLS expects null-terminated data WITH the null terminator in size
    // c_str() is null-terminated, but length() doesn't include it, so add 1
    auto serverCert = x509::Crt::parse({ reinterpret_cast<const unsigned char*>(serverCertData.c_str()), serverCertData.length() + 1 });
    
    static std::string serverKeyData = readFile("test-server/server-key.pem");
    
    // For PEM parsing, mbedTLS expects null-terminated data WITH the null terminator in size
    auto serverKey = PrivateKey::parse({ reinterpret_cast<const unsigned char*>(serverKeyData.c_str()), serverKeyData.length() + 1 });

    if (not serverCert)
        throw std::runtime_error("Failed to parse server certificate");
    
    if (not serverKey)
        throw std::runtime_error("Failed to parse server private key");
    
    
    // Let's try without specifying cipher suites first to see what happens
    // static const int ciphersuites[] = {
    //     MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
    //     0 // terminator
    // };
    // configuration.setCiphersuites(ciphersuites);
    
    configuration.setOwnCert(serverCert.value(), serverKey.value());
    configuration.setRng(drbg);

    Ssl ssl(configuration, bio);
    int ret = 0;

    // Wait for TLS handshake
    std::cout << "Waiting for TLS handshake over Unix socket..." << std::endl;

    while ((ret = ssl.handshake()) != 0) 
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) 
        {
            throw std::runtime_error("TLS handshake failed with error: " + std::to_string(ret));
        }

        usleep(1000);
    }
    
    std::cout << "TLS handshake completed!" << std::endl;
    
    // Handle encrypted communication
    unsigned char buffer[256];
    while (1) 
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
        
        // Echo response
        const char *response = "Message received over TLS/Unix socket";
        ssl.write({ (unsigned char *)response, strlen(response) });
    }
    
    ssl.closeNotify();
	return ret;
}
