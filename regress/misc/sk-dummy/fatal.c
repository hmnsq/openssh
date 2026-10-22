/* public domain */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "log.h"

শূন্য
sshlogv(ধ্রুৱ ৱর্ণ *file, ধ্রুৱ ৱর্ণ *func, পূর্ণাঙ্ক সাৰি, পূর্ণাঙ্ক showfunc,
    LogLevel level, ধ্রুৱ ৱর্ণ *suffix, ধ্রুৱ ৱর্ণ *fmt, va_list args)
{
	যদি (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	যদি (suffix != রিক্ত)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

শূন্য
sshlog(ধ্রুৱ ৱর্ণ *file, ধ্রুৱ ৱর্ণ *func, পূর্ণাঙ্ক সাৰি, পূর্ণাঙ্ক showfunc,
    LogLevel level, ধ্রুৱ ৱর্ণ *suffix, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, সাৰি, showfunc, level, suffix, fmt, args);
	va_end(args);
}

শূন্য
sshfatal(ধ্রুৱ ৱর্ণ *file, ধ্রুৱ ৱর্ণ *func, পূর্ণাঙ্ক সাৰি, পূর্ণাঙ্ক showfunc,
    LogLevel level, ধ্রুৱ ৱর্ণ *suffix, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, সাৰি, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
