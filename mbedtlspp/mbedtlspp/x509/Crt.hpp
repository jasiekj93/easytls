#pragma once

/**
 * @file Crt.hpp
 * @author Adrian Szczepanski
 * @date 04-12-2025
 */

#include <etl/span.h>
#include <etl/optional.h>

#include <mbedtls/x509_crt.h>

namespace mbedtlspp::x509
{
    class Crt
    {
    public:
        // For PEM parsing, mbedTLS expects null-terminated data WITH the null terminator in size
        static etl::optional<Crt> parse(etl::span<const unsigned char> buf);

        ~Crt();

        Crt(Crt&& other) noexcept;
        Crt& operator=(Crt&& other) noexcept;

        inline auto& operator()() { return crt; }

    protected:

    private:
        Crt();

        mbedtls_x509_crt crt;
    };
}