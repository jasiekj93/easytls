#include "debug.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void mbedtls_debug_print_msg( const mbedtls_ssl_context *ssl, int level,
                              const char *file, int line,
                              const char *format, ... )
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void mbedtls_debug_print_ret( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line,
                      const char *text, int ret )
{
    fprintf(stderr, "%s:%d: %s returned -0x%04X\n", file, line, text, -ret);
}

void mbedtls_debug_print_buf( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line, const char *text,
                      const unsigned char *buf, size_t len )
{
    size_t i;

    fprintf(stderr, "%s:%d: %s (%zu bytes):\n", file, line, text, len);

    for (i = 0; i < len; i++) {
        if (i % 16 == 0) {
            fprintf(stderr, "%04zx: ", i);
        }
        fprintf(stderr, "%02x ", buf[i]);
        if (i % 16 == 15 || i == len - 1) {
            fprintf(stderr, "\n");
        }
    }
}

void mbedtls_debug_print_mpi( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line,
                      const char *text, const mbedtls_mpi *X )
{
    char *buf = NULL;
    size_t buflen = mbedtls_mpi_size(X) * 2 + 1; // Each byte -> 2 hex chars + null terminator
    buf = (char *)malloc(buflen);
    size_t olen = 0;
    if (buf == NULL) {
        fprintf(stderr, "%s:%d: Memory allocation failed in mbedtls_debug_print_mpi\n", file, line);
        return;
    }

    if (mbedtls_mpi_write_string(X, 16, buf, buflen, &olen) != 0) {
        fprintf(stderr, "%s:%d: Failed to write MPI to string\n", file, line);
        free(buf);
        return;
    }
    fprintf(stderr, "%s:%d: %s: %s\n", file, line, text, buf);
    free(buf);
}

void mbedtls_debug_printf_ecdh( const mbedtls_ssl_context *ssl, int level,
                                const char *file, int line,
                                const mbedtls_ecdh_context *ecdh,
                                mbedtls_debug_ecdh_attr attr )
{
    const mbedtls_ecp_point *point = NULL;
    const mbedtls_mpi *mpi = NULL;
    const char *name = NULL;

    switch (attr) {
        case MBEDTLS_DEBUG_ECDH_Q:
            point = &ecdh->Q;
            name = "ECDH Q";
            break;
        case MBEDTLS_DEBUG_ECDH_QP:
            name = "ECDH QP";
            break;
        case MBEDTLS_DEBUG_ECDH_Z:
            mpi = &ecdh->z;
            name = "ECDH Z";
            break;
        default:
            fprintf(stderr, "%s:%d: Unknown ECDH attribute\n", file, line);
            return;
    }

    if (point != NULL) {
        mbedtls_debug_print_ecp(ssl, level, file, line, name, point);
    } else if (mpi != NULL) {
        mbedtls_debug_print_mpi(ssl, level, file, line, name, mpi);
    } 
}

void mbedtls_debug_print_crt( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line,
                      const char *text, const mbedtls_x509_crt *crt )
{
    fprintf(stderr, "%s:%d: %s: Subject: ", file, line, text);
    mbedtls_x509_dn_gets(NULL, 0, &crt->subject); // Get length
    char *buf = (char *)malloc(512); // Arbitrary buffer size
    if (buf == NULL) {
        fprintf(stderr, "%s:%d: Memory allocation failed in mbedtls_debug_print_crt\n", file, line);
        return;
    }
    mbedtls_x509_dn_gets(buf, 512, &crt->subject);
    fprintf(stderr, "%s\n", buf);
    free(buf);
}

void mbedtls_debug_print_ecp( const mbedtls_ssl_context *ssl, int level,
                      const char *file, int line,
                      const char *text, const mbedtls_ecp_point *X )
{
    size_t buf_len = 2 * (mbedtls_mpi_size(&X->X) + mbedtls_mpi_size(&X->Y) + mbedtls_mpi_size(&X->Z)) + 10;
    char *buf = (char *)malloc(buf_len);
    if (buf == NULL) {
        fprintf(stderr, "%s:%d: Memory allocation failed in mbedtls_debug_print_ecp\n", file, line);
        return;
    }

    size_t olen = 0;
    buf[0] = '\0';

    strcat(buf, "X=");
    mbedtls_mpi_write_string(&X->X, 16, buf + strlen(buf), buf_len - strlen(buf), &olen);
    strcat(buf, ", Y=");
    mbedtls_mpi_write_string(&X->Y, 16, buf + strlen(buf), buf_len - strlen(buf), &olen);
    strcat(buf, ", Z=");
    mbedtls_mpi_write_string(&X->Z, 16, buf + strlen(buf), buf_len - strlen(buf), &olen);

    fprintf(stderr, "%s:%d: %s: %s\n", file, line, text, buf);
    free(buf);
}