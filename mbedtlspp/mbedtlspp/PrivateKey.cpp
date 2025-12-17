#include "PrivateKey.hpp"
#include "Rng.hpp"

using namespace mbedtlspp;

etl::optional<PrivateKey> PrivateKey::parse(KeyData data, Password password)
{
    PrivateKey key;

    auto ret = mbedtls_pk_parse_key(&key.pkey,
                                     data.data(),
                                     data.size(),
                                     password.data(),
                                     password.size(),
                                     Rng::rand,
                                     nullptr);

    if (ret == 0)
        return etl::optional<PrivateKey>(etl::move(key));
    else
        return etl::nullopt;
}

PrivateKey::PrivateKey()
{
    mbedtls_pk_init(&pkey);
}

PrivateKey::PrivateKey(PrivateKey&& other) noexcept
{
    mbedtls_pk_init(&pkey);
    pkey = other.pkey;
    mbedtls_pk_init(&other.pkey);
}

PrivateKey& PrivateKey::operator=(PrivateKey&& other) noexcept
{
    if (this != &other)
    {
        mbedtls_pk_free(&pkey);
        pkey = other.pkey;
        mbedtls_pk_init(&other.pkey);
    }
    return *this;
}

PrivateKey::~PrivateKey()
{
    mbedtls_pk_free(&pkey);
}
