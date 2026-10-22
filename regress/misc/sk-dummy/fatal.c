/* public domain */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"

शून्य
sshlogv(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पङ्क्तिः, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, va_list args)
{
	जइ (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, args);
	जइ (suffix != रिक्त)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

शून्य
sshlog(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पङ्क्तिः, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, पङ्क्तिः, showfunc, level, suffix, fmt, args);
	va_end(args);
}

शून्य
sshfatal(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पङ्क्तिः, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, पङ्क्तिः, showfunc, level, suffix, fmt, args);
	va_end(args);
	_exit(1);
}
