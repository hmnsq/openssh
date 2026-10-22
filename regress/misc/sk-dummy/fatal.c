/* public domain */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"

शून्य
sshlogv(अचर वर्ण *file, अचर वर्ण *func, पूर्णाङ्क पङ्क्ति, पूर्णाङ्क showfunc,
    LogLevel level, अचर वर्ण *suffix, अचर वर्ण *fmt, बहु_सूची args)
{
	यदि (showfunc)
		ख_लिखो(मानक_त्रुटि, "%s: ", func);
	भख_लिखो(मानक_त्रुटि, fmt, args);
	यदि (suffix != रिक्त)
		ख_लिखो(मानक_त्रुटि, ": %s", suffix);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
}

शून्य
sshlog(अचर वर्ण *file, अचर वर्ण *func, पूर्णाङ्क पङ्क्ति, पूर्णाङ्क showfunc,
    LogLevel level, अचर वर्ण *suffix, अचर वर्ण *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	sshlogv(file, func, पङ्क्ति, showfunc, level, suffix, fmt, args);
	बहु_पूर्ण(args);
}

शून्य
sshfatal(अचर वर्ण *file, अचर वर्ण *func, पूर्णाङ्क पङ्क्ति, पूर्णाङ्क showfunc,
    LogLevel level, अचर वर्ण *suffix, अचर वर्ण *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	sshlogv(file, func, पङ्क्ति, showfunc, level, suffix, fmt, args);
	बहु_पूर्ण(args);
	_exit(1);
}
