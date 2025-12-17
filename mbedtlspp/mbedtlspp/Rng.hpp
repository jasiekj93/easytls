#pragma once

/**
 * @file Rng.hpp
 * @author Adrian Szczepanski
 * @date 17-12-2025
 */

#include <memory>

#include <etl/span.h>

namespace mbedtlspp
{
    class Rng
    {
    public:
        static void setGlobal(const std::shared_ptr<Rng>& rng);
        static int rand(void* context, unsigned char* buffer, size_t length);

        virtual ~Rng() = default;
        virtual int operator()(etl::span<unsigned char>) = 0;
    
    private:
        static std::shared_ptr<Rng> globalRng;
        
    };

    class RandRng : public Rng
    {
    public:
        int operator()(etl::span<unsigned char>) override;
    };
}