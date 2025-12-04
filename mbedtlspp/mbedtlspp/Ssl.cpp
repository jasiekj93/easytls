#include "Ssl.hpp"

using namespace mbedtlspp;

static int bioWriteWrapper(void *ctx, const unsigned char *buf, size_t len);
static int bioReadWrapper(void *ctx, unsigned char *buf, size_t len);
static int bioReadTimeoutWrapper(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);

Ssl::Ssl(Configuration& conf, Bio& bio)
{
    mbedtls_ssl_init(&ssl);
    auto result = mbedtls_ssl_setup(&ssl, &conf());
    //TODO : handle result

    mbedtls_ssl_set_bio(&ssl, &bio, 
        bioWriteWrapper, 
        bioReadWrapper, 
        bioReadTimeoutWrapper);
}

Ssl::~Ssl()
{
    mbedtls_ssl_free(&ssl);
}

int Ssl::handshake()
{
    return mbedtls_ssl_handshake(&ssl);
}

int Ssl::closeNotify()
{
    return mbedtls_ssl_close_notify(&ssl);
}

int Ssl::write(etl::span<const unsigned char> data)
{
    return mbedtls_ssl_write(&ssl, data.data(), data.size());
}

int Ssl::read(etl::span<unsigned char> buffer)
{
    return mbedtls_ssl_read(&ssl, buffer.data(), buffer.size());
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