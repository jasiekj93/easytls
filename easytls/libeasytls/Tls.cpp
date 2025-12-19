#include "Tls.hpp"
#include "Debug.hpp"
#include "Rng.hpp"
#include "Psa.hpp"

#include <mbedtls/debug.h>

using namespace easytls;

static int bioWriteWrapper(void *ctx, const unsigned char *buf, size_t len);
static int bioReadWrapper(void *ctx, unsigned char *buf, size_t len);
static int bioReadTimeoutWrapper(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);

const etl::vector<int, 2> Tls::DEFAULT_CIPHERSUITE = { MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384, 0 };

Tls::Tls(Bio& bio, etl::string_view hostname)
    : errorCode(0)
{
    if(not Psa::isInitialized())
        errorCode = Psa::init();
    
    if(not Psa::isInitialized())
        return;
    
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    mbedtls_hmac_drbg_init(&drbg);

    errorCode = mbedtls_hmac_drbg_seed(&drbg, mbedtls_md_info_from_type(MBEDTLS_MD_SHA3_512),
                                  Rng::rand, nullptr, 
                                  nullptr, 0);
    
    if(errorCode != 0)
        return;

    mbedtls_ssl_set_bio(&ssl, &bio, 
        bioWriteWrapper, 
        bioReadWrapper, 
        bioReadTimeoutWrapper);

    if(errorCode = mbedtls_ssl_set_hostname(&ssl, hostname.data()), errorCode != 0)
        return;

    mbedtls_ssl_conf_ciphersuites(&config, DEFAULT_CIPHERSUITE.data());

    mbedtls_ssl_conf_rng(&config, mbedtls_hmac_drbg_random, &drbg);

    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
}

Tls::~Tls()
{
    mbedtls_hmac_drbg_free(&drbg);
    mbedtls_ssl_config_free(&config);
    mbedtls_ssl_free(&ssl);
}

int Tls::handshake()
{
    return mbedtls_ssl_handshake(&ssl);
}

int Tls::closeNotify()
{
    return mbedtls_ssl_close_notify(&ssl);
}

int Tls::write(etl::span<const unsigned char> data)
{
    return mbedtls_ssl_write(&ssl, data.data(), data.size());
}

int Tls::read(etl::span<unsigned char> buffer)
{
    return mbedtls_ssl_read(&ssl, buffer.data(), buffer.size());
}

void Tls::setDebug(DebugLevel level)
{
    mbedtls_ssl_conf_dbg(&config, Debug::log, nullptr);
    mbedtls_debug_set_threshold(static_cast<int>(level));
}


static int bioWriteWrapper(void *ctx, const unsigned char *buf, size_t len)
{
    Bio* bio = static_cast<Bio*>(ctx);
    return bio->write(etl::span<const unsigned char>(buf, len));
}

static int bioReadWrapper(void *ctx, unsigned char *buf, size_t len)
{
    Bio* bio = static_cast<Bio*>(ctx);
    return bio->read(etl::span<unsigned char>(buf, len));
}

static int bioReadTimeoutWrapper(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
    Bio* bio = static_cast<Bio*>(ctx);
    return bio->read(etl::span<unsigned char>(buf, len), timeout);
}