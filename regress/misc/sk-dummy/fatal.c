/* public domain */

#شامل "includes.h"

#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <stdarg.h>
#شامل <unistd.h>

#شامل "log.h"

تهی
sshlogv(ثابت نویسه *file, ثابت نویسه *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت نویسه *suffix, ثابت نویسه *fmt, va_list args)
{
	اگر (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	اگر (suffix != پوچ)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

تهی
sshlog(ثابت نویسه *file, ثابت نویسه *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت نویسه *suffix, ثابت نویسه *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, args);
	va_end(args);
}

تهی
sshfatal(ثابت نویسه *file, ثابت نویسه *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت نویسه *suffix, ثابت نویسه *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
