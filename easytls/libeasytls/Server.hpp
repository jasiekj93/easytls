#pragma once

/**
 * @file Server.hpp
 * @author Adrian Szczepanski
 * @date 18-12-2025
 */

#include <etl/optional.h>

#include <libeasytls/Tls.hpp>
#include <libeasytls/x509/Certificate.hpp>
#include <libeasytls/PrivateKey.hpp>

namespace easytls
{
    class Server : public Tls
    {
    public:
        /**
         * @brief Constructor for server authentication only 
         * 
         * @param hostname - name of the secondary party (client) in certificate verification
         * @param serverCert - server own certificate
         * @param serverKey - server own private key
         */
        Server(Bio&, etl::string_view hostname, x509::Certificate& serverCert, PrivateKey& serverKey);
        
        /**
         * @brief Constructor for bidirectional authentication (mutual TLS)
         * 
         * @param hostname - name of the secondary party (client) in certificate verification
         * @param serverCert - server own certificate
         * @param serverKey - server own private key
         * @param caCert - CA certificate to validate client certificates
         */
        Server(Bio&, etl::string_view hostname, x509::Certificate& serverCert, PrivateKey& serverKey,
               x509::Certificate& caCert);

        using Tls::handshake;
        using Tls::closeNotify;

        using Tls::read;
        using Tls::write;

        using Tls::setDebug;
    };
}