/* public domain */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "log.h"

শূন্য
sshlogv(ধ্রুব বর্ণ *file, ধ্রুব বর্ণ *func, পূর্ণাঙ্ক সারি, পূর্ণাঙ্ক showfunc,
    LogLevel level, ধ্রুব বর্ণ *suffix, ধ্রুব বর্ণ *fmt, va_list args)
{
	যদি (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	যদি (suffix != রিক্ত)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

শূন্য
sshlog(ধ্রুব বর্ণ *file, ধ্রুব বর্ণ *func, পূর্ণাঙ্ক সারি, পূর্ণাঙ্ক showfunc,
    LogLevel level, ধ্রুব বর্ণ *suffix, ধ্রুব বর্ণ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, সারি, showfunc, level, suffix, fmt, args);
	va_end(args);
}

শূন্য
sshfatal(ধ্রুব বর্ণ *file, ধ্রুব বর্ণ *func, পূর্ণাঙ্ক সারি, পূর্ণাঙ্ক showfunc,
    LogLevel level, ধ্রুব বর্ণ *suffix, ধ্রুব বর্ণ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, সারি, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
