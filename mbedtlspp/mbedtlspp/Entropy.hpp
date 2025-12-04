#pragma once

/**
 * @file Entropy.hpp
 * @author Adrian Szczepanski
 * @date 04-12-2025
 */

#include <mbedtls/entropy.h>

namespace mbedtlspp
{
    class Entropy
    {
    public:
        Entropy();
        ~Entropy();

        inline auto& operator()() { return entropy; }

    private:
        Entropy(const Entropy&) = delete;
        Entropy& operator=(const Entropy&) = delete;

        mbedtls_entropy_context entropy;
    };
}