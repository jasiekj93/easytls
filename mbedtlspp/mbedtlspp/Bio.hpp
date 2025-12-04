#pragma once

/**
 * @file Bio.hpp
 * @author Adrian Szczepanski
 * @date 04-12-2025
 */

#include <etl/span.h>

namespace mbedtlspp
{
    class Bio
    {
    public:
        virtual ~Bio() = default;

        virtual int read(etl::span<unsigned char>) = 0;
        virtual int read(etl::span<unsigned char>, unsigned timeout) = 0;
        virtual int write(etl::span<const unsigned char>) = 0;
    };
} 