#include "Rng.hpp"

using namespace mbedtlspp;

static RandRng defaultRng;

std::shared_ptr<Rng> Rng::globalRng = std::make_shared<RandRng>(defaultRng);

void Rng::setGlobal(const std::shared_ptr<Rng> &rng)
{
    globalRng = rng;
}

int Rng::rand(void *context, unsigned char *buffer, size_t length)
{
    if (globalRng)
        return (*globalRng)(etl::span<unsigned char>(buffer, length));

    return -1;
}

int RandRng::operator()(etl::span<unsigned char> buffer)
{
    std::generate(buffer.begin(), buffer.end(), std::rand);
    return 0;
}
