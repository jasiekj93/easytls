#pragma once

/**
 * @file Hmac.hpp
 * @author Adrian Szczepanski
 * @date 04-12-2025
 */

#include <etl/span.h>

#include <mbedtls/hmac_drbg.h>

#include <mbedtlspp/Entropy.hpp>

namespace mbedtlspp::drbg
{
    class Hmac
    {
    public:
        using Personalization = etl::span<const unsigned char>;

        Hmac(Entropy&, Personalization = {});
        ~Hmac();

        int seed(Entropy&, Personalization = {});
        int random(etl::span<unsigned char>);

    private:
        Hmac(const Hmac&) = delete;
        Hmac& operator=(const Hmac&) = delete;

        mbedtls_hmac_drbg_context drbg;
    };
}