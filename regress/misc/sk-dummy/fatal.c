/* public domain */

#ضمن "includes.h"

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>

#ضمن "log.h"

فراغ
sshlogv(ثابت حرف *file, ثابت حرف *func, صحيح کرښه, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list دلیلونه)
{
	إذا (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, دلیلونه);
	إذا (suffix != عدم)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

فراغ
sshlog(ثابت حرف *file, ثابت حرف *func, صحيح کرښه, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلیلونه;

	va_start(دلیلونه, fmt);
	sshlogv(file, func, کرښه, showfunc, level, suffix, fmt, دلیلونه);
	va_end(دلیلونه);
}

فراغ
sshfatal(ثابت حرف *file, ثابت حرف *func, صحيح کرښه, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list دلیلونه;

	va_start(دلیلونه, fmt);
	sshlogv(file, func, کرښه, showfunc, level, suffix, fmt, دلیلونه);
	va_end(دلیلونه);
	_exit(1);
}
