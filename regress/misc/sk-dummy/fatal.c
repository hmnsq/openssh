/* public domain */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "log.h"

শূন্য
sshlogv(ধ্রুবক অক্ষর *file, ধ্রুবক অক্ষর *func, পূর্ণসংখ্যা সারি, পূর্ণসংখ্যা showfunc,
    LogLevel level, ধ্রুবক অক্ষর *suffix, ধ্রুবক অক্ষর *fmt, va_list args)
{
	যদি (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	যদি (suffix != ফাঁকা)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

শূন্য
sshlog(ধ্রুবক অক্ষর *file, ধ্রুবক অক্ষর *func, পূর্ণসংখ্যা সারি, পূর্ণসংখ্যা showfunc,
    LogLevel level, ধ্রুবক অক্ষর *suffix, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, সারি, showfunc, level, suffix, fmt, args);
	va_end(args);
}

শূন্য
sshfatal(ধ্রুবক অক্ষর *file, ধ্রুবক অক্ষর *func, পূর্ণসংখ্যা সারি, পূর্ণসংখ্যা showfunc,
    LogLevel level, ধ্রুবক অক্ষর *suffix, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, সারি, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
