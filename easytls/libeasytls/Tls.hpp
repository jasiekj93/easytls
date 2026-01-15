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

        /**
         * @brief Perform the TLS handshake. It may require multiple calls to complete (until it returns 0
         * or error).
         * 
         * @return int - 0 on success, negative error code on failure, MBEDTLS_ERR_SSL_WANT_READ/WRITE if more data is needed.
         * 
         */
        int handshake();

        /**
         * @brief Send close notify alert to the peer
         * 
         * @return int - 0 on success, negative error code on failure
         */
        int closeNotify();

        /**
         * @brief Write data to the TLS connection
         * 
         * @param data - buffer with data to write
         * @return int - number of bytes written on success, negative error code on failure
         */
        int write(etl::span<const unsigned char>);

        /**
         * @brief Read data from the TLS connection
         * 
         * @param data - buffer to store read data
         * @return int - number of bytes read on success, negative error code on failure or 
         * MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY if the connection was closed by the peer
         */
        int read(etl::span<unsigned char>);

        void setDebug(DebugLevel);

        etl::string_view getHostName();

        /**
         * @brief Check if the TLS context is valid. This is very important method to call after construction, because the mbedtls structures
         * are non-copyable and there is no other way to check if the initialization was successful.
         * 
         */
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