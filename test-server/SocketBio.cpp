#include "SocketBio.hpp"

#include <iostream>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <mbedtls/ssl.h>

SocketBio::SocketBio(const std::string& path, bool isServer) 
{
    name = (isServer? "[SERVER] " : "[CLIENT] ");
    
    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (socket_fd < 0) 
        throw std::runtime_error("Failed to create socket");
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    
    if (isServer) 
    {
        unlink(path.c_str()); // Remove existing socket
        if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
        {
            close(socket_fd);
            throw std::runtime_error("Failed to bind socket");
        }

        if (listen(socket_fd, 1) < 0) 
        {
            close(socket_fd);
            throw std::runtime_error("Failed to listen on socket");
        }
        
        std::cout << "Server waiting for connection on " << path << std::endl;
        int client_fd = accept(socket_fd, nullptr, nullptr);
        if (client_fd < 0) {
            close(socket_fd);
            throw std::runtime_error("Failed to accept connection");
        }
        close(socket_fd);
        socket_fd = client_fd;
        std::cout << "Client connected!" << std::endl;
    } 
    else 
    {
        std::cout << "Connecting to server at " << path << std::endl;
        if (connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
        {
            close(socket_fd);
            throw std::runtime_error("Failed to connect to socket");
        }
        std::cout << "Connected to server!" << std::endl;
    }
}

SocketBio::~SocketBio() 
{
    if (socket_fd >= 0) 
        close(socket_fd);
}

int SocketBio::read(etl::span<unsigned char> buffer)
{
    ssize_t ret = ::read(socket_fd, buffer.data(), buffer.size());

    if (ret < 0) 
    {
        std::cout <<  name << "Socket read error: " << strerror(errno) << std::endl;
        if (errno == EAGAIN || errno == EWOULDBLOCK) 
            return MBEDTLS_ERR_SSL_WANT_READ;
        else
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    else if (ret == 0) 
    {
        std::cout << name << "Socket closed by peer" << std::endl;
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY; // Connection closed
    }

    std::cout << name << "Successfully read " << ret << " bytes from socket" << std::endl;
    return static_cast<int>(ret);
}

int SocketBio::write(etl::span<const unsigned char> buffer)
{
    ssize_t ret = ::write(socket_fd, buffer.data(), buffer.size());

    if (ret < 0) 
    {
        std::cout << name << "Socket write error: " << strerror(errno) << std::endl;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        else
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    std::cout << name << "Successfully wrote " << ret << " bytes to socket" << std::endl;
    return static_cast<int>(ret);
}
