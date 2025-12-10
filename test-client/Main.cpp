/**
 * @file Main.cpp
 * @author Adrian Szczepanski
 * @date 2025-12-04
 */

#include <iostream>
#include <fstream>
#include <sstream>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstring>
#include <errno.h>

#include <mbedtlspp/Ssl.hpp>
#include <mbedtls/ssl_ciphersuites.h>
#include <iomanip>

using namespace mbedtlspp;

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
            std::cout << "Connecting to server at " << socket_path << std::endl;
            if (connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(socket_fd);
                throw std::runtime_error("Failed to connect to socket: " + std::string(strerror(errno)));
            }
            std::cout << "Connected to server!" << std::endl;
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
        // std::cout << "BIO read() called, requesting " << buffer.size() << " bytes" << std::endl;
        ssize_t ret = ::read(socket_fd, buffer.data(), buffer.size());
        // std::cout << "Socket read() returned " << ret << std::endl;
        if (ret < 0) {
            std::cout << "Socket read error: " << strerror(errno) << std::endl;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return MBEDTLS_ERR_SSL_WANT_READ;
            }
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        if (ret == 0) {
            std::cout << "Socket closed by peer" << std::endl;
            return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY; // Connection closed
        }
        std::cout << "[CLIENT] Successfully read " << ret << " bytes from socket" << std::endl;
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
        // std::cout << "BIO write() called, sending " << buffer.size() << " bytes" << std::endl;
        ssize_t ret = ::write(socket_fd, buffer.data(), buffer.size());

        // for(auto i = 0; i < buffer.size(); i++)
        // {
        //     std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]) << " ";
        // }

        // std::cout << "Socket write() returned " << ret << std::endl;
        if (ret < 0) {
            std::cout << "Socket write error: " << strerror(errno) << std::endl;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return MBEDTLS_ERR_SSL_WANT_WRITE;
            }
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        // std::cout << "Successfully wrote " << ret << " bytes to socket" << std::endl;
        return static_cast<int>(ret);
    }
};

int main(int argc, char* argv[])
{
    BioImpl bio("/tmp/mbedtls-test.sock", false);
    Configuration configuration(MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    Entropy entropy;
    drbg::Hmac drbg(entropy);

    // std::cout << "Reading CA certificate from file..." << std::endl;
    static std::string caCertData = readFile("test-client/ca-cert.pem");
    // std::cout << "CA certificate length: " << caCertData.length() << std::endl;
    // For PEM parsing, include null terminator in size
    auto cacert = x509::Crt::parse({ reinterpret_cast<const unsigned char*>(caCertData.c_str()), caCertData.length() + 1 });

    if(not cacert)
        throw std::runtime_error("Failed to parse CA certificates");
    
    // std::cout << "CA certificate parsed successfully!" << std::endl;
    
    // Let's try without specifying cipher suites first
    static const int ciphersuites[] = {
        MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
        0 // terminator
    };
    configuration.setCiphersuites(ciphersuites);
    
    // For initial testing, disable certificate verification completely
    configuration.setAuthMode(MBEDTLS_SSL_VERIFY_NONE);
    configuration.setRng(drbg);    // Enable debugging to see what's happening during the handshake
    //configuration.setDebugThreshold(4);  // We'll add this if available

    Ssl ssl(configuration, bio);
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
    
    // Send encrypted data
    const char *message = "Hello from TLS over Unix socket!";
    ret = ssl.write({ (unsigned char *)message, strlen(message) });

    if (ret > 0) 
        std::cout << "Sent: " << message << std::endl;
    
    // Read encrypted response
    unsigned char buffer[256];
    ret = ssl.read({ buffer, sizeof(buffer) - 1 });

    if (ret > 0) 
    {
        buffer[ret] = '\0';
        std::cout << "Received: " << buffer << std::endl;
    }
    
    ssl.closeNotify();
    return ret;
}
