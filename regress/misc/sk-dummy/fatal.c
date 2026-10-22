/* public domain */

#شامل "includes.h"

#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <stdarg.h>
#شامل <unistd.h>

#شامل "log.h"

خالی
sshlogv(ثابت حرف *file, ثابت حرف *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list دلائل)
{
	اگر (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, دلائل);
	اگر (suffix != تہی)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

خالی
sshlog(ثابت حرف *file, ثابت حرف *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلائل;

	va_start(دلائل, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, دلائل);
	va_end(دلائل);
}

خالی
sshfatal(ثابت حرف *file, ثابت حرف *func, صحیح سطر, صحیح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلائل;

	va_start(دلائل, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, دلائل);
	va_end(دلائل);
	_exit(1);
}
