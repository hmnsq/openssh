/* public domain */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"

ಶೂನ್ಯ
sshlogv(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಪೂರ್ಣಾಂಕ showfunc,
    LogLevel level, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *suffix, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ವಾದಗಳು)
{
	ಆದರೆ (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ವಾದಗಳು);
	ಆದರೆ (suffix != ಖಾಲಿ)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

ಶೂನ್ಯ
sshlog(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಪೂರ್ಣಾಂಕ showfunc,
    LogLevel level, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *suffix, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ವಾದಗಳು;

	va_start(ವಾದಗಳು, fmt);
	sshlogv(file, func, ಸಾಲು, showfunc, level, suffix, fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);
}

ಶೂನ್ಯ
sshfatal(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಪೂರ್ಣಾಂಕ showfunc,
    LogLevel level, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *suffix, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ವಾದಗಳು;

	va_start(ವಾದಗಳು, fmt);
	sshlogv(file, func, ಸಾಲು, showfunc, level, suffix, fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);
	_exit(1);
}
