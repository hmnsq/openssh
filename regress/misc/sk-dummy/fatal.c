/* public domain */

#ضمن "includes.h"

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>

#ضمن "log.h"

فراغ
sshlogv(ثابت حرف *file, ثابت حرف *func, صحيح سطر, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list دلیلاں)
{
	إذا (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, دلیلاں);
	إذا (suffix != عدم)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

فراغ
sshlog(ثابت حرف *file, ثابت حرف *func, صحيح سطر, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلیلاں;

	va_start(دلیلاں, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, دلیلاں);
	va_end(دلیلاں);
}

فراغ
sshfatal(ثابت حرف *file, ثابت حرف *func, صحيح سطر, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلیلاں;

	va_start(دلیلاں, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, دلیلاں);
	va_end(دلیلاں);
	_exit(1);
}
