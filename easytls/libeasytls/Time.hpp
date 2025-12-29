#pragma once

/**
 * @file Time.hpp
 * @author Adrian Szczepanski
 * @date 29-12-2025
 */

#include <memory>

#include <mbedtls/platform_time.h>

namespace easytls
{
    class Time
    {
    public:
        using MsTime = mbedtls_ms_time_t;

        static void setGlobal(const std::shared_ptr<Time>&);
        static MsTime getGlobalTime();

        virtual ~Time() = default;

        virtual MsTime get() = 0;

    private:
        static std::shared_ptr<Time> globalTime;
    };

    class DummyTime : public Time
    {
    public:
        inline MsTime get() override
        {
            tick++;
            return tick;
        }

    private:
        MsTime tick = 0;
    };
}

extern "C" mbedtls_ms_time_t mbedtls_ms_time(void);