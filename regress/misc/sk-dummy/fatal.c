/* public domain */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"

శూన్య
sshlogv(స్థిరరాశి అక్షరం *file, స్థిరరాశి అక్షరం *func, పూర్ణాంకం పంక్తి, పూర్ణాంకం showfunc,
    LogLevel level, స్థిరరాశి అక్షరం *suffix, స్థిరరాశి అక్షరం *fmt, va_list వాదనలు)
{
	ఒకవేళ (showfunc)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, వాదనలు);
	ఒకవేళ (suffix != ఖాళీ)
		fprintf(stderr, ": %s", suffix);
	fputc('\n', stderr);
}

శూన్య
sshlog(స్థిరరాశి అక్షరం *file, స్థిరరాశి అక్షరం *func, పూర్ణాంకం పంక్తి, పూర్ణాంకం showfunc,
    LogLevel level, స్థిరరాశి అక్షరం *suffix, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;

	va_start(వాదనలు, fmt);
	sshlogv(file, func, పంక్తి, showfunc, level, suffix, fmt, వాదనలు);
	va_end(వాదనలు);
}

శూన్య
sshfatal(స్థిరరాశి అక్షరం *file, స్థిరరాశి అక్షరం *func, పూర్ణాంకం పంక్తి, పూర్ణాంకం showfunc,
    LogLevel level, స్థిరరాశి అక్షరం *suffix, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;

	va_start(వాదనలు, fmt);
	sshlogv(file, func, పంక్తి, showfunc, level, suffix, fmt, వాదనలు);
	va_end(వాదనలు);
	_exit(1);
}
