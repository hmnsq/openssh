/* public domain */

#include "includes.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "log.h"

void
sshlogv(const char *file, const char *func, цяло line, цяло showfunc,
    LogLevel level, const char *suffix, const char *fmt, va_list args)
{
	ако (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	ако (suffix != NULL)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

void
sshlog(const char *file, const char *func, цяло line, цяло showfunc,
    LogLevel level, const char *suffix, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, line, showfunc, level, suffix, fmt, args);
	va_end(args);
}

void
sshfatal(const char *file, const char *func, цяло line, цяло showfunc,
    LogLevel level, const char *suffix, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, line, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
