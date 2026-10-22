/* public domain */

#ضمن "includes.h"

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>

#ضمن "log.h"

فراغ
sshlogv(ثابت حرف *file, ثابت حرف *func, صحيح لي, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list حجوجي)
{
	إذا (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, حجوجي);
	إذا (suffix != عدم)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

فراغ
sshlog(ثابت حرف *file, ثابت حرف *func, صحيح لي, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list حجوجي;

	va_start(حجوجي, fmt);
	sshlogv(file, func, لي, showfunc, level, suffix, fmt, حجوجي);
	va_end(حجوجي);
}

فراغ
sshfatal(ثابت حرف *file, ثابت حرف *func, صحيح لي, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list حجوجي;

	va_start(حجوجي, fmt);
	sshlogv(file, func, لي, showfunc, level, suffix, fmt, حجوجي);
	va_end(حجوجي);
	_exit(1);
}
