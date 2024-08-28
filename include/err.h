/* err.h */

#pragma once

#include <windows.h>
#include <stdio.h>

DWORD __print_err(const char *msg, va_list argptr);
extern void print_err(const char *msg, ...);
extern void throw_err(const char *msg, ...);