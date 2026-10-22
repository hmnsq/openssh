/* public domain */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "log.h"

வெறுமை
sshlogv(மாறிலி எழுத்து *file, மாறிலி எழுத்து *func, முழு வரி, முழு showfunc,
    LogLevel level, மாறிலி எழுத்து *suffix, மாறிலி எழுத்து *fmt, va_list args)
{
	எனில் (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	எனில் (suffix != வெற்று)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

வெறுமை
sshlog(மாறிலி எழுத்து *file, மாறிலி எழுத்து *func, முழு வரி, முழு showfunc,
    LogLevel level, மாறிலி எழுத்து *suffix, மாறிலி எழுத்து *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, வரி, showfunc, level, suffix, fmt, args);
	va_end(args);
}

வெறுமை
sshfatal(மாறிலி எழுத்து *file, மாறிலி எழுத்து *func, முழு வரி, முழு showfunc,
    LogLevel level, மாறிலி எழுத்து *suffix, மாறிலி எழுத்து *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, வரி, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
