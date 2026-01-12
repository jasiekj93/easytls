#pragma once

/**
 * @file Time.hpp
 * @author Adrian Szczepanski
 * @date 12-01-2026
 */

#include <memory>

#include <mbedtls/platform_time.h>

namespace easytls
{
    class Time
    {
    public:
        static void setGlobal(const std::shared_ptr<Time>&);
        static mbedtls_time_t get(mbedtls_time_t*);
        static struct tm* gmtime_r(const mbedtls_time_t*, struct tm*);

        virtual ~Time() = default;

        virtual mbedtls_time_t getTime(mbedtls_time_t*) = 0;
        virtual struct tm* getGmtime(const mbedtls_time_t*, struct tm*) = 0;

    private:
        static std::shared_ptr<Time> globalTime;
    };
}

extern "C" struct tm* mbedtls_platform_gmtime_r(const mbedtls_time_t* tt, struct tm* tm_buf);