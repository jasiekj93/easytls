#pragma once

/**
 * @file Timer.hpp
 * @author Adrian Szczepanski
 * @date 29-12-2025
 */

#include <memory>

#include <mbedtls/platform_time.h>

namespace easytls
{
    class Timer
    {
    public:
        using Ticks = mbedtls_ms_time_t;

        static void setGlobal(const std::shared_ptr<Timer>&);
        static Ticks getGlobalTicks();

        virtual ~Timer() = default;

        virtual Ticks get() = 0;

    private:
        static std::shared_ptr<Timer> globalTimer;
    };

    class DummyTimer : public Timer
    {
    public:
        inline Ticks get() override
        {
            tick++;
            return tick;
        }

    private:
        Ticks tick = 0;
    };
}

extern "C" mbedtls_ms_time_t mbedtls_ms_time(void);