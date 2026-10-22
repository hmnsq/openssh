/* public domain */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਖਾਲੀ
sshlogv(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਅੱਖਰ *func, ਪੂਰਨ ਸਤਰ, ਪੂਰਨ showfunc,
    LogLevel level, ਅਚਲ ਅੱਖਰ *suffix, ਅਚਲ ਅੱਖਰ *fmt, va_list ਦਲੀਲਾਂ)
{
	ਜੇ (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ਦਲੀਲਾਂ);
	ਜੇ (suffix != ਨਿਰਾ)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

ਖਾਲੀ
sshlog(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਅੱਖਰ *func, ਪੂਰਨ ਸਤਰ, ਪੂਰਨ showfunc,
    LogLevel level, ਅਚਲ ਅੱਖਰ *suffix, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;

	va_start(ਦਲੀਲਾਂ, fmt);
	sshlogv(file, func, ਸਤਰ, showfunc, level, suffix, fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);
}

ਖਾਲੀ
sshfatal(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਅੱਖਰ *func, ਪੂਰਨ ਸਤਰ, ਪੂਰਨ showfunc,
    LogLevel level, ਅਚਲ ਅੱਖਰ *suffix, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;

	va_start(ਦਲੀਲਾਂ, fmt);
	sshlogv(file, func, ਸਤਰ, showfunc, level, suffix, fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);
	_exit(1);
}
