#include "Timer.hpp"

using namespace easytls;

static DummyTimer defaultTimer;

std::shared_ptr<Timer> Timer::globalTimer = std::make_shared<DummyTimer>(defaultTimer);

void Timer::setGlobal(const std::shared_ptr<Timer>& timer)
{
    globalTimer = timer;
}

Timer::Ticks Timer::getGlobalTicks()
{
    return globalTimer->get();
}

extern "C" mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return Timer::getGlobalTicks();
}