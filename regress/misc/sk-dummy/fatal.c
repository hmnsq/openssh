/* public domain */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "log.h"

ശൂന്യം
sshlogv(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം അക്ഷരം *func, പൂർണ്ണസംഖ്യ വരി, പൂർണ്ണസംഖ്യ showfunc,
    LogLevel level, സ്ഥിരം അക്ഷരം *suffix, സ്ഥിരം അക്ഷരം *fmt, va_list args)
{
	എങ്കിൽ (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	എങ്കിൽ (suffix != ശൂന്യ)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

ശൂന്യം
sshlog(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം അക്ഷരം *func, പൂർണ്ണസംഖ്യ വരി, പൂർണ്ണസംഖ്യ showfunc,
    LogLevel level, സ്ഥിരം അക്ഷരം *suffix, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, വരി, showfunc, level, suffix, fmt, args);
	va_end(args);
}

ശൂന്യം
sshfatal(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം അക്ഷരം *func, പൂർണ്ണസംഖ്യ വരി, പൂർണ്ണസംഖ്യ showfunc,
    LogLevel level, സ്ഥിരം അക്ഷരം *suffix, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, വരി, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
