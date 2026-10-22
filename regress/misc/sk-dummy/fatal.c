/* public domain */

#include "includes.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "log.h"

void
sshlogv(const var_na *file, const var_na *func, จำนวนเต็ม line, จำนวนเต็ม showfunc,
    LogLevel level, const var_na *suffix, const var_na *fmt, va_list args)
{
	ถ้า (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	ถ้า (suffix != NULL)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

void
sshlog(const var_na *file, const var_na *func, จำนวนเต็ม line, จำนวนเต็ม showfunc,
    LogLevel level, const var_na *suffix, const var_na *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, line, showfunc, level, suffix, fmt, args);
	va_end(args);
}

void
sshfatal(const var_na *file, const var_na *func, จำนวนเต็ม line, จำนวนเต็ม showfunc,
    LogLevel level, const var_na *suffix, const var_na *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, line, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
