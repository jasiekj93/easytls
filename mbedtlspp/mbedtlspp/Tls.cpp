#include "Tls.hpp"

using namespace mbedtlspp;

static int bioWriteWrapper(void *ctx, const unsigned char *buf, size_t len);
static int bioReadWrapper(void *ctx, unsigned char *buf, size_t len);
static int bioReadTimeoutWrapper(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);

Tls::Tls(Configuration& conf, Bio& bio)
{
    init(conf, bio);
}

Tls::Tls(Tls&& other) noexcept
{
    mbedtls_ssl_init(&ssl);
    ssl = other.ssl;
    mbedtls_ssl_init(&other.ssl);
}

Tls& Tls::operator=(Tls&& other) noexcept
{
    if (this != &other)
    {
        mbedtls_ssl_free(&ssl);
        ssl = other.ssl;
        mbedtls_ssl_init(&other.ssl);
    }
    return *this;
}

Tls::~Tls()
{
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

void Tls::init(Configuration& conf, Bio& bio)
{
    mbedtls_ssl_init(&ssl);
    auto result = mbedtls_ssl_setup(&ssl, &conf());
    //TODO : handle result

    mbedtls_ssl_set_bio(&ssl, &bio, 
        bioWriteWrapper, 
        bioReadWrapper, 
        bioReadTimeoutWrapper);
}

void Tls::setHostname(const char* hostname)
{
    mbedtls_ssl_set_hostname(&ssl, hostname);
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