#pragma once

/**
 * @file TimeImpl.hpp
 * @author Adrian Szczepanski
 * @date 12-01-2026
 */

#include <libeasytls/Time.hpp>

class TimeImpl : public easytls::Time
{
public:
    mbedtls_time_t getTime(mbedtls_time_t* tt) override;
    struct tm* getGmtime(const mbedtls_time_t* tt, struct tm* buffer) override;
};