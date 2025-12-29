#include "Server.hpp"
#include "Psa.hpp"

using namespace easytls;

Server::Server(Bio &bio, etl::string_view hostname, x509::Certificate &certificate, PrivateKey &privateKey)
    : Tls(bio, hostname)
{
    errorCode = mbedtls_ssl_config_defaults(&config, 
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT);
    
    if(errorCode != 0)
        return;

    //TODO config
    mbedtls_ssl_conf_read_timeout(&config, 10000); 

    mbedtls_ssl_conf_own_cert(&config, &certificate(), &privateKey());
    errorCode = mbedtls_ssl_setup(&ssl, &config);
}