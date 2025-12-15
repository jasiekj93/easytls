#pragma once

#include <mbedtlspp/Ssl.hpp>

namespace mbedtlspp
{
    class Client : public Ssl
    {
    public:
        static const etl::vector<int, 2> DEFAULT_CIPHERSUITE;  

        Client(Bio&, x509::Crt&, const Ciphersuites& = DEFAULT_CIPHERSUITE);

        using Ssl::handshake;
        using Ssl::closeNotify;

        using Ssl::read;
        using Ssl::write;

    private:
        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;

        Entropy entropy;
        drbg::Hmac drbg;
        Configuration configuration;
    };
}