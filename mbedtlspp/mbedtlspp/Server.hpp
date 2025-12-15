#pragma once

#include <mbedtlspp/Ssl.hpp>

namespace mbedtlspp
{
    class Server : public Ssl
    {
    public:
        static const etl::vector<int, 2> DEFAULT_CIPHERSUITE;  

        Server(Bio&, x509::Crt&, PrivateKey&, const Ciphersuites& = DEFAULT_CIPHERSUITE);

        using Ssl::handshake;
        using Ssl::closeNotify;

        using Ssl::read;
        using Ssl::write;

    private:
        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;

        Entropy entropy;
        drbg::Hmac drbg;
        Configuration configuration;
    };
}