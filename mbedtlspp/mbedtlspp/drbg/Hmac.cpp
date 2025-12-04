#include "Hmac.hpp"

using namespace mbedtlspp;
using namespace mbedtlspp::drbg;

Hmac::Hmac(Entropy& entropy, Personalization personalization)
{
    mbedtls_hmac_drbg_init(&drbg);
    seed(entropy, personalization);
}

Hmac::~Hmac()
{
    mbedtls_hmac_drbg_free(&drbg);
}

int Hmac::seed(Entropy& entropy, Personalization personalization)
{
    return mbedtls_hmac_drbg_seed(&drbg, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                                  mbedtls_entropy_func, (void*)&entropy(), 
                                  personalization.data(), personalization.size());
}

int Hmac::random(etl::span<unsigned char> output)
{
    return mbedtls_hmac_drbg_random(&drbg, output.data(), output.size());
}
