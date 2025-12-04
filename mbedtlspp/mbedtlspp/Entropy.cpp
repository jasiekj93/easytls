#include "Entropy.hpp"

using namespace mbedtlspp;

Entropy::Entropy()
{
    mbedtls_entropy_init(&entropy);
}

Entropy::~Entropy()
{
    mbedtls_entropy_free(&entropy);
}