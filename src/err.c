/* err.c */

#include "err.h"

DWORD __print_err(const char *msg, va_list argptr)
{
    DWORD err_code = GetLastError();

    if (!err_code)
    {
        vfprintf(stderr, msg, argptr);
        fprintf(stderr, "\n");
        return EXIT_FAILURE;
    }

    LPTSTR lp_err_descr_buf;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, err_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&lp_err_descr_buf, 0, NULL);

    if (!lp_err_descr_buf)
    {
        vfprintf(stderr, msg, argptr);
        fprintf(stderr, "\n");
        return EXIT_FAILURE;
    }

    size_t msg_len = strlen(msg) + strlen(argptr) + 1;
    char *formatted_msg = (char *)malloc(msg_len);

    vsnprintf_s(formatted_msg, msg_len, msg_len, msg, argptr);

    fprintf(stderr, "%s: %s\n", formatted_msg, lp_err_descr_buf);

    free(formatted_msg);
    LocalFree(lp_err_descr_buf);
    return err_code;
}

void print_err(const char *msg, ...)
{
    va_list argptr;
    va_start(argptr, msg);
    __print_err(msg, argptr);
    va_end(argptr);
}

void throw_err(const char *msg, ...)
{
    va_list argptr;
    va_start(argptr, msg);
    DWORD err_code = __print_err(msg, argptr);
    va_end(argptr);
    exit(err_code);
}