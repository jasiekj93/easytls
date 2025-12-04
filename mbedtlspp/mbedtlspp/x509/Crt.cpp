#include "Crt.hpp"

using namespace mbedtlspp;
using namespace mbedtlspp::x509;

etl::optional<Crt> mbedtlspp::x509::Crt::parse(etl::span<const unsigned char> buf)
{
    Crt certificate;
    int ret = mbedtls_x509_crt_parse(&certificate.crt, buf.data(), buf.size());

    if (ret == 0)
        return etl::optional<Crt>(etl::move(certificate));
    else
        return etl::nullopt;
}

Crt::Crt()
{
    mbedtls_x509_crt_init(&crt);
}

Crt::~Crt()
{
    mbedtls_x509_crt_free(&crt);
}

