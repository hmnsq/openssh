/* public domain */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"

शून्य
sshlogv(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पङ्क्तिः, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, va_list तर्काः)
{
	यदि (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, तर्काः);
	यदि (suffix != रिक्त)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

शून्य
sshlog(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पङ्क्तिः, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, ...)
{
	va_list तर्काः;

	va_start(तर्काः, fmt);
	sshlogv(file, func, पङ्क्तिः, showfunc, level, suffix, fmt, तर्काः);
	va_end(तर्काः);
}

शून्य
sshfatal(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पङ्क्तिः, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, ...)
{
	va_list तर्काः;

	va_start(तर्काः, fmt);
	sshlogv(file, func, पङ्क्तिः, showfunc, level, suffix, fmt, तर्काः);
	va_end(तर्काः);
	_exit(1);
}
