/* public domain */

#ضمن "includes.h"

#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>

#ضمن "log.h"

فراغ
sshlogv(ثابت حرف *file, ثابت حرف *func, صحيح هێڵ, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, va_list args)
{
	إذا (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	إذا (suffix != عدم)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

فراغ
sshlog(ثابت حرف *file, ثابت حرف *func, صحيح هێڵ, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, هێڵ, showfunc, level, suffix, fmt, args);
	va_end(args);
}

فراغ
sshfatal(ثابت حرف *file, ثابت حرف *func, صحيح هێڵ, صحيح showfunc,
    LogLevel level, ثابت حرف *suffix, ثابت حرف *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, هێڵ, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
