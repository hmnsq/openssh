/* public domain */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "log.h"

ଶୂନ୍ୟ
sshlogv(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ଅକ୍ଷର *func, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା showfunc,
    LogLevel level, ଅଚଳ ଅକ୍ଷର *suffix, ଅଚଳ ଅକ୍ଷର *fmt, va_list args)
{
	ଯଦି (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	ଯଦି (suffix != ଖାଲି)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

ଶୂନ୍ୟ
sshlog(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ଅକ୍ଷର *func, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା showfunc,
    LogLevel level, ଅଚଳ ଅକ୍ଷର *suffix, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, ଧାଡ଼ି, showfunc, level, suffix, fmt, args);
	va_end(args);
}

ଶୂନ୍ୟ
sshfatal(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ଅକ୍ଷର *func, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା showfunc,
    LogLevel level, ଅଚଳ ଅକ୍ଷର *suffix, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, ଧାଡ଼ି, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
