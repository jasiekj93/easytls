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
        virtual ~Ssl();

        int handshake();
        int closeNotify();

        int write(etl::span<const unsigned char>);
        int read(etl::span<unsigned char>);

        Ssl(Ssl&& other) noexcept;
        Ssl& operator=(Ssl&& other) noexcept;

    protected:
        Ssl() = default;

        void init(Configuration&, Bio&);


    private:
        Ssl(const Ssl&) = delete;
        Ssl& operator=(const Ssl&) = delete;

        mbedtls_ssl_context ssl;
    };
}