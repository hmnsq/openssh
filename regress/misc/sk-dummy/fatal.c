/* public domain */

#ضمن "includes.h"

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>

#ضمن "log.h"

فراغ
sshlogv(ثابت حرف *file, ثابت حرف *func, صحيح سطر, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list وسائط)
{
	إذا (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, وسائط);
	إذا (suffix != عدم)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

فراغ
sshlog(ثابت حرف *file, ثابت حرف *func, صحيح سطر, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list وسائط;

	va_start(وسائط, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, وسائط);
	va_end(وسائط);
}

فراغ
sshfatal(ثابت حرف *file, ثابت حرف *func, صحيح سطر, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list وسائط;

	va_start(وسائط, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, وسائط);
	va_end(وسائط);
	_exit(1);
}
