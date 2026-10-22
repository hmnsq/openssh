/* public domain */

#include "includes.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "log.h"

void
sshlogv(const char *file, const char *func, int लिन्या, int showfunc,
    LogLevel level, const char *suffix, const char *fmt, va_list मगा_कातविरान)
{
	if (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, मगा_कातविरान);
	if (suffix != NULL)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

void
sshlog(const char *file, const char *func, int लिन्या, int showfunc,
    LogLevel level, const char *suffix, const char *fmt, ...)
{
	va_list मगा_कातविरान;

	va_start(मगा_कातविरान, fmt);
	sshlogv(file, func, लिन्या, showfunc, level, suffix, fmt, मगा_कातविरान);
	va_end(मगा_कातविरान);
}

void
sshfatal(const char *file, const char *func, int लिन्या, int showfunc,
    LogLevel level, const char *suffix, const char *fmt, ...)
{
	va_list मगा_कातविरान;

	va_start(मगा_कातविरान, fmt);
	sshlogv(file, func, लिन्या, showfunc, level, suffix, fmt, मगा_कातविरान);
	va_end(मगा_कातविरान);
	_exit(1);
}
