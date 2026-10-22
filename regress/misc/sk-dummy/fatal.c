/* public domain */

#ضمن "includes.h"

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>

#ضمن "log.h"

فراغ
sshlogv(ثابت حرف *file, ثابت حرف *func, صحيح سطر, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list آرگومانها)
{
	إذا (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, آرگومانها);
	إذا (suffix != عدم)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

فراغ
sshlog(ثابت حرف *file, ثابت حرف *func, صحيح سطر, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list آرگومانها;

	va_start(آرگومانها, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, آرگومانها);
	va_end(آرگومانها);
}

فراغ
sshfatal(ثابت حرف *file, ثابت حرف *func, صحيح سطر, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list آرگومانها;

	va_start(آرگومانها, fmt);
	sshlogv(file, func, سطر, showfunc, level, suffix, fmt, آرگومانها);
	va_end(آرگومانها);
	_exit(1);
}
