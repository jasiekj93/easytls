#include "Client.hpp"
#include "Psa.hpp"

using namespace easytls;

Client::Client(Bio &bio, etl::string_view hostname, x509::Certificate &certificate)
    : Tls(bio, hostname)
{
    errorCode = mbedtls_ssl_config_defaults(&config, 
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT);
    
    if(errorCode != 0)
        return;

    //TODO config
    // mbedtls_ssl_conf_read_timeout(&config, 10000); 
                    
    mbedtls_ssl_conf_ca_chain(&config, &certificate(), nullptr);
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
    errorCode = mbedtls_ssl_setup(&ssl, &config);
}
