#include "Configuration.hpp"
#include <stdexcept>
#include <string>
#include <iostream>

#include <mbedtls/debug.h>
#include <psa/crypto.h>

using namespace mbedtlspp;

static int rngWrapper(void *ctx, unsigned char *buf, size_t len)
{
    mbedtlspp::drbg::Hmac* drbg = static_cast<mbedtlspp::drbg::Hmac*>(ctx);
    return drbg->random(etl::span<unsigned char>(buf, len));
}

void printDebug(void *ctx, int level, const char *file, int line, const char *str)
{
    std::cout << "[" << level << "] " << file << ":" << line << ": " << str;
}


Configuration::Configuration(int protocol, int transport, int preset)
{
    mbedtls_ssl_config_init(&conf);
    
    int ret = mbedtls_ssl_config_defaults(&conf, protocol, transport, preset);
    assert(ret == 0);

    mbedtls_ssl_conf_dbg(&conf,
                          printDebug,
                          nullptr);
    mbedtls_debug_set_threshold(4);
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

bool Configuration::setCiphersuites(const Ciphersuites& ciphersuites)
{
    if(ciphersuites.empty() or ciphersuites.back() != 0)
        return false;

    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites.data());
    return true;
}

void Configuration::setVersion(Version version)
{
    mbedtls_ssl_conf_min_tls_version(&conf, static_cast<mbedtls_ssl_protocol_version>(version));
    mbedtls_ssl_conf_max_tls_version(&conf, static_cast<mbedtls_ssl_protocol_version>(version));
}