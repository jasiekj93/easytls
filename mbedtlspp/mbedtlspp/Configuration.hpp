#pragma once

/**
 * @file Configuration.hpp
 * @author Adrian Szczepanski
 * @date 04-12-2025
 */

#include <mbedtls/ssl.h>

#include <mbedtlspp/x509/Crt.hpp>
#include <mbedtlspp/drbg/Hmac.hpp>
#include <mbedtlspp/PrivateKey.hpp>

namespace mbedtlspp
{
    class Configuration
    {
    public:
        Configuration(int protocol, int transport, int preset);
        ~Configuration();

        void setAuthMode(int mode);
        void setCaChain(x509::Crt&);
        void setOwnCert(x509::Crt&, PrivateKey&);
        void setRng(drbg::Hmac&);
        void setCiphersuites(const int ciphersuites[]);

        inline auto& operator()() { return conf; }

        Configuration(Configuration&& other) noexcept;
        Configuration& operator=(Configuration&& other) noexcept;

    private:
        Configuration(const Configuration&) = delete;
        Configuration& operator=(const Configuration&) = delete;

        mbedtls_ssl_config conf;
    };
}