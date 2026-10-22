/* public domain */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"

શૂન્ય
sshlogv(અચલ અક્ષર *file, અચલ અક્ષર *func, પૂર્ણાંક લીટી, પૂર્ણાંક showfunc,
    LogLevel level, અચલ અક્ષર *suffix, અચલ અક્ષર *fmt, va_list args)
{
	જો (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	જો (suffix != ખાલી)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

શૂન્ય
sshlog(અચલ અક્ષર *file, અચલ અક્ષર *func, પૂર્ણાંક લીટી, પૂર્ણાંક showfunc,
    LogLevel level, અચલ અક્ષર *suffix, અચલ અક્ષર *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, લીટી, showfunc, level, suffix, fmt, args);
	va_end(args);
}

શૂન્ય
sshfatal(અચલ અક્ષર *file, અચલ અક્ષર *func, પૂર્ણાંક લીટી, પૂર્ણાંક showfunc,
    LogLevel level, અચલ અક્ષર *suffix, અચલ અક્ષર *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, લીટી, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
