#include "Server.hpp"

using namespace mbedtlspp;

const etl::vector<int, 2> Server::DEFAULT_CIPHERSUITE = { MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384, 0 };

Server::Server(Bio& bio, x509::Crt& certificate, PrivateKey& privateKey, const Ciphersuites& ciphersuites)
    : entropy()
    , drbg(entropy)
    , configuration(MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)
{
    configuration.setCiphersuites(ciphersuites);
    configuration.setOwnCert(certificate, privateKey);
    configuration.setRng(drbg);
    // Enforce TLS 1.2 only
    configuration.setTlsVersion(MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    init(configuration, bio);
}