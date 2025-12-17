#pragma once

/**
 * @file Tls.hpp
 * @author Adrian Szczepanski
 * @date 04-12-2025
 */

#include <mbedtls/ssl.h>

#include <mbedtlspp/Bio.hpp>
#include <mbedtlspp/Configuration.hpp>

namespace mbedtlspp
{
    class Tls
    {
    public:
        Tls(Configuration&, Bio&);
        virtual ~Tls();

        int handshake();
        int closeNotify();
        void setHostname(const char* hostname);

        int write(etl::span<const unsigned char>);
        int read(etl::span<unsigned char>);

        Tls(Tls&& other) noexcept;
        Tls& operator=(Tls&& other) noexcept;

    protected:
        Tls() = default;

        void init(Configuration&, Bio&);


    private:
        Tls(const Tls&) = delete;
        Tls& operator=(const Tls&) = delete;

        mbedtls_ssl_context ssl;
    };
}