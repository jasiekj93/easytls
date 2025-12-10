#include "Configuration.hpp"
#include <stdexcept>
#include <string>

using namespace mbedtlspp;

static int rngWrapper(void *ctx, unsigned char *buf, size_t len)
{
    mbedtlspp::drbg::Hmac* drbg = static_cast<mbedtlspp::drbg::Hmac*>(ctx);
    return drbg->random(etl::span<unsigned char>(buf, len));
}


Configuration::Configuration(int protocol, int transport, int preset)
{
    mbedtls_ssl_config_init(&conf);
    
    // Load reasonable default values - this is critical!
    int ret = mbedtls_ssl_config_defaults(&conf, protocol, transport, preset);
    if (ret != 0) {
        throw std::runtime_error("Failed to set SSL config defaults: " + std::to_string(ret));
    }
}

Configuration::Configuration(Configuration&& other) noexcept
{
    mbedtls_ssl_config_init(&conf);
    conf = other.conf;
    mbedtls_ssl_config_init(&other.conf);
}

Configuration& Configuration::operator=(Configuration&& other) noexcept
{
    if (this != &other)
    {
        mbedtls_ssl_config_free(&conf);
        conf = other.conf;
        mbedtls_ssl_config_init(&other.conf);
    }
    return *this;
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

void Configuration::setOwnCert(x509::Crt& certificate, PrivateKey& privateKey)
{
    mbedtls_ssl_conf_own_cert(&conf, &certificate(), &privateKey());
}

void Configuration::setRng(drbg::Hmac& drbg)
{
    mbedtls_ssl_conf_rng(&conf, rngWrapper, &drbg);
}

void Configuration::setCiphersuites(const int ciphersuites[])
{
    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);
}