#include "Time.hpp"

using namespace easytls;

static DummyTime defaultTime;

std::shared_ptr<Time> Time::globalTime = std::make_shared<DummyTime>(defaultTime);

void Time::setGlobal(const std::shared_ptr<Time>& time)
{
    globalTime = time;
}

Time::MsTime Time::getGlobalTime()
{
    return globalTime->get();
}

extern "C" mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return Time::getGlobalTime();
}