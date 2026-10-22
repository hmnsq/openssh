/* public domain */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"

ಶೂನ್ಯ
sshlogv(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ವರ್ಣ *func, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಪೂರ್ಣಾಙ್ಕ showfunc,
    LogLevel level, ಧ್ರುವ ವರ್ಣ *suffix, ಧ್ರುವ ವರ್ಣ *fmt, va_list args)
{
	ಯದಿ (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	ಯದಿ (suffix != ರಿಕ್ತ)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

ಶೂನ್ಯ
sshlog(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ವರ್ಣ *func, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಪೂರ್ಣಾಙ್ಕ showfunc,
    LogLevel level, ಧ್ರುವ ವರ್ಣ *suffix, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, ಸಾಲು, showfunc, level, suffix, fmt, args);
	va_end(args);
}

ಶೂನ್ಯ
sshfatal(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ವರ್ಣ *func, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಪೂರ್ಣಾಙ್ಕ showfunc,
    LogLevel level, ಧ್ರುವ ವರ್ಣ *suffix, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, ಸಾಲು, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
