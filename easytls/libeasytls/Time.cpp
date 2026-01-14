#include "Time.hpp"

using namespace easytls;

std::shared_ptr<Time> Time::globalTime = nullptr;

void Time::setGlobal(const std::shared_ptr<Time>& time)
{
    globalTime = time;
    mbedtls_platform_set_time(Time::get);
}

mbedtls_time_t Time::get(mbedtls_time_t* tt)
{
    if(not globalTime)
        return mbedtls_time_t();
    else
        return globalTime->getTime(tt);
}

struct tm* Time::gmtime_r(const mbedtls_time_t* tt, struct tm* buffer)
{
    if(not globalTime)
        return nullptr;
    else
        return globalTime->getGmtime(tt, buffer);
}

extern "C" struct tm* mbedtls_platform_gmtime_r(const mbedtls_time_t* tt, struct tm* tm_buf)
{
    if (tt == nullptr or tm_buf == nullptr)
        return nullptr;

    return Time::gmtime_r(tt, tm_buf);
}