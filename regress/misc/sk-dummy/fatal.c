/* public domain */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"

शून्य
sshlogv(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पंक्ति, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, बहु_सूची args)
{
	यदि (showfunc)
		ख_लिखो(मानक_त्रुटि, "%s: ", func);
	भख_लिखो(मानक_त्रुटि, fmt, args);
	यदि (suffix != रिक्त)
		ख_लिखो(मानक_त्रुटि, ": %s", suffix);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
}

शून्य
sshlog(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पंक्ति, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	sshlogv(file, func, पंक्ति, showfunc, level, suffix, fmt, args);
	बहु_पूर्ण(args);
}

शून्य
sshfatal(ध्रुव वर्ण *file, ध्रुव वर्ण *func, पूर्णाङ्क पंक्ति, पूर्णाङ्क showfunc,
    LogLevel level, ध्रुव वर्ण *suffix, ध्रुव वर्ण *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	sshlogv(file, func, पंक्ति, showfunc, level, suffix, fmt, args);
	बहु_पूर्ण(args);
	_exit(1);
}
