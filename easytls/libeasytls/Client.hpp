#pragma once

/**
 * @file Client.hpp
 * @author Adrian Szczepanski
 * @date 18-12-2025
 */

#include <etl/optional.h>

#include <mbedtls/entropy.h>

#include <libeasytls/Tls.hpp>
#include <libeasytls/x509/Certificate.hpp>
#include <libeasytls/PrivateKey.hpp>

namespace easytls
{
    class Client : public Tls
    {
    public:
        /**
         * @brief Constructor for server authentication only
         * 
         * @param hostname - name of the secondary party (server) in certificate verification
         * @param caCert - CA certificate to validate server certificates
         */
        Client(Bio&, etl::string_view hostname, x509::Certificate& caCert);
        
        /**
         * @brief Constructor for bidirectional authentication (mutual TLS)
         * 
         * @param hostname - name of the secondary party (server) in certificate verification
         * @param caCert - CA certificate to validate server certificates
         * @param clientCert - client own certificate
         * @param clientKey - client own private key
         */
        Client(Bio&, etl::string_view hostname, x509::Certificate& caCert, 
               x509::Certificate& clientCert, PrivateKey& clientKey);

        using Tls::handshake;
        using Tls::closeNotify;

        using Tls::read;
        using Tls::write;

        using Tls::setDebug;
    };
}