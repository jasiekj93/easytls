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
        static etl::optional<Crt> parse(etl::span<const unsigned char> buf);

        ~Crt();

        inline auto& operator()() { return crt; }

    protected:

    private:
        Crt();

        mbedtls_x509_crt crt;
    };
}