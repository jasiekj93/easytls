#include "Client.hpp"

using namespace mbedtlspp;

const etl::vector<int, 2> Client::DEFAULT_CIPHERSUITE = { MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384, 0 };

Client::Client(Bio& bio, x509::Crt& certificate, const Ciphersuites& ciphersuites)
    : entropy()
    , drbg(entropy)
    , configuration(MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)
{
    configuration.setCiphersuites(ciphersuites);
    configuration.setAuthMode(MBEDTLS_SSL_VERIFY_REQUIRED);
    configuration.setCaChain(certificate);
    configuration.setRng(drbg);
    configuration.setVersion(Configuration::Version::TLS1_3);

    init(configuration, bio);
}