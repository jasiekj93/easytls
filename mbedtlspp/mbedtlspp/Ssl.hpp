#pragma once

/**
 * @file Ssl.hpp
 * @author Adrian Szczepanski
 * @date 04-12-2025
 */

#include <mbedtls/ssl.h>

#include <mbedtlspp/Bio.hpp>
#include <mbedtlspp/Configuration.hpp>

namespace mbedtlspp
{
    class Ssl
    {
    public:
        Ssl(Configuration&, Bio&);
        ~Ssl();

        int handshake();
        int closeNotify();

        int write(etl::span<const unsigned char>);
        int read(etl::span<unsigned char>);


    private:
        Ssl(const Ssl&) = delete;
        Ssl& operator=(const Ssl&) = delete;

        mbedtls_ssl_context ssl;
    };
}