/* public domain */

#समावेश "includes.h"

#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <stdarg.h>
#समावेश <unistd.h>

#समावेश "log.h"

व्योम
sshlogv(स्थिर अक्षर *file, स्थिर अक्षर *func, पूर्णांक पंक्ति, पूर्णांक showfunc,
    LogLevel level, स्थिर अक्षर *suffix, स्थिर अक्षर *fmt, बहु_सूची args)
{
	अगर (showfunc)
		ख_लिखो(मानक_त्रुटि, "%s: ", func);
	भख_लिखो(मानक_त्रुटि, fmt, args);
	अगर (suffix != शून्य)
		ख_लिखो(मानक_त्रुटि, ": %s", suffix);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
}

व्योम
sshlog(स्थिर अक्षर *file, स्थिर अक्षर *func, पूर्णांक पंक्ति, पूर्णांक showfunc,
    LogLevel level, स्थिर अक्षर *suffix, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	sshlogv(file, func, पंक्ति, showfunc, level, suffix, fmt, args);
	बहु_पूर्ण(args);
}

व्योम
sshfatal(स्थिर अक्षर *file, स्थिर अक्षर *func, पूर्णांक पंक्ति, पूर्णांक showfunc,
    LogLevel level, स्थिर अक्षर *suffix, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची args;

	बहु_शुरू(args, fmt);
	sshlogv(file, func, पंक्ति, showfunc, level, suffix, fmt, args);
	बहु_पूर्ण(args);
	_निकास(1);
}
