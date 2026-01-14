#pragma once

/**
 * @file Tls.hpp
 * @author Adrian Szczepanski
 * @date 17-12-2025
 */

#include <etl/string_view.h>
#include <etl/vector.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hmac_drbg.h>

#include <libeasytls/Tls.hpp>
#include <libeasytls/Bio.hpp>

namespace easytls
{
    class Tls
    {
    public:
        enum class DebugLevel : int
        {
            NONE    = 0,
            ERROR   = 1,
            WARNING = 2,
            INFO    = 3,
            DEBUG   = 4
        };

        virtual ~Tls();

        int handshake();
        int closeNotify();

        int write(etl::span<const unsigned char>);
        int read(etl::span<unsigned char>);

        void setDebug(DebugLevel);

        etl::string_view getHostName();

        inline bool isValid() const { return errorCode == 0; }
        inline auto getErrorCode() const { return errorCode; }

    protected:
        Tls(Bio&, etl::string_view hostname);

        int errorCode;

        mbedtls_ssl_context ssl;
        mbedtls_ssl_config config;
        mbedtls_hmac_drbg_context drbg;

    private:
        Tls(const Tls&) = delete;
        Tls& operator=(const Tls&) = delete;
        Tls(Tls&&) = delete;
        Tls& operator=(Tls&&) = delete;

        static const etl::vector<int, 2> DEFAULT_CIPHERSUITE;  
    };
}