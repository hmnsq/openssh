/* public domain */

#ضمن "includes.h"

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>

#ضمن "log.h"

فراغ
sshlogv(ثابت حرف *file, ثابت حرف *func, صحيح سٽ, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list دليلون)
{
	إذا (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, دليلون);
	إذا (suffix != عدم)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

فراغ
sshlog(ثابت حرف *file, ثابت حرف *func, صحيح سٽ, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دليلون;

	va_start(دليلون, fmt);
	sshlogv(file, func, سٽ, showfunc, level, suffix, fmt, دليلون);
	va_end(دليلون);
}

فراغ
sshfatal(ثابت حرف *file, ثابت حرف *func, صحيح سٽ, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دليلون;

	va_start(دليلون, fmt);
	sshlogv(file, func, سٽ, showfunc, level, suffix, fmt, دليلون);
	va_end(دليلون);
	_exit(1);
}
