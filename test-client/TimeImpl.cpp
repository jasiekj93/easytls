#include "TimeImpl.hpp"
#include <ctime>

mbedtls_time_t TimeImpl::getTime(mbedtls_time_t *tt)
{
    return ::time(tt);
}

tm* TimeImpl::getGmtime(const mbedtls_time_t *tt, tm *buffer)
{
    return ::gmtime_r(tt, buffer);
}
