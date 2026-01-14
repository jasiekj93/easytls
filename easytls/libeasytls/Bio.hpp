#pragma once

/**
 * @file Bio.hpp
 * @author Adrian Szczepanski
 * @date 04-12-2025
 */

#include <etl/span.h>

namespace easytls
{
    class Bio
    {
    public:
        virtual ~Bio() = default;

        /**
         * @return int - ngetive if error, number of bytes read otherwise
         */
        virtual int read(etl::span<unsigned char>) = 0;

        /**
         * @return int - negative if error, number of bytes written otherwise
         */
        virtual int write(etl::span<const unsigned char>) = 0;
    };
} 