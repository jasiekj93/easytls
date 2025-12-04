#include "Configuration.hpp"

using namespace mbedtlspp;

static int rngWrapper(void *ctx, unsigned char *buf, size_t len)
{
    mbedtlspp::drbg::Hmac* drbg = static_cast<mbedtlspp::drbg::Hmac*>(ctx);
    return drbg->random(etl::span<unsigned char>(buf, len));
}


Configuration::Configuration(int protocol, int transport, int preset)
{
    mbedtls_ssl_config_init(&conf);
}

Configuration::~Configuration()
{
    mbedtls_ssl_config_free(&conf);
}

void Configuration::setAuthMode(int mode)
{
    mbedtls_ssl_conf_authmode(&conf, mode);
}

void Configuration::setCaChain(x509::Crt& certificate)
{
    mbedtls_ssl_conf_ca_chain(&conf, &certificate(), nullptr);
}

void Configuration::setRng(drbg::Hmac& drbg)
{
    mbedtls_ssl_conf_rng(&conf, rngWrapper, &drbg);
}