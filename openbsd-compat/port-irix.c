/*
 * Copyright (c) 2000 Denis Parker.  All rights reserved.
 * Copyright (c) 2000 Michael Stone.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#समावेश "includes.h"

#अगर defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || \
    defined(WITH_IRIX_ARRAY)

#समावेश <errno.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित WITH_IRIX_PROJECT
# include <proj.h>
#पूर्ण_अगर /* WITH_IRIX_PROJECT */
#अगर_घोषित WITH_IRIX_JOBS
# include <sys/resource.h>
#पूर्ण_अगर
#अगर_घोषित WITH_IRIX_AUDIT
# include <sat.h>
#पूर्ण_अगर /* WITH_IRIX_AUDIT */

#समावेश "log.h"

व्योम
irix_setusercontext(काष्ठा passwd *pw)
{
#अगर_घोषित WITH_IRIX_PROJECT
	prid_t projid;
#पूर्ण_अगर
#अगर_घोषित WITH_IRIX_JOBS
	jid_t jid = 0;
#या_अगर defined(WITH_IRIX_ARRAY)
	पूर्णांक jid = 0;
#पूर्ण_अगर

#अगर_घोषित WITH_IRIX_JOBS
	jid = jlimit_startjob(pw->pw_name, pw->pw_uid, "interactive");
	अगर (jid == -1)
		fatal("Failed to create job container: %.100s",
		    म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर /* WITH_IRIX_JOBS */
#अगर_घोषित WITH_IRIX_ARRAY
	/* initialize array session */
	अगर (jid == 0  && newarraysess() != 0)
		fatal("Failed to set up new array session: %.100s",
		    म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर /* WITH_IRIX_ARRAY */
#अगर_घोषित WITH_IRIX_PROJECT
	/* initialize irix project info */
	अगर ((projid = getdfltprojuser(pw->pw_name)) == -1) {
		debug("Failed to get project id, using projid 0");
		projid = 0;
	}
	अगर (setprid(projid))
		fatal("Failed to initialize project %d for %s: %.100s",
		    (पूर्णांक)projid, pw->pw_name, म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर /* WITH_IRIX_PROJECT */
#अगर_घोषित WITH_IRIX_AUDIT
	अगर (sysconf(_SC_AUDIT)) {
		debug("Setting sat id to %d", (पूर्णांक) pw->pw_uid);
		अगर (satsetid(pw->pw_uid))
			debug("error setting satid: %.100s", म_त्रुटि(त्रुटि_सं));
	}
#पूर्ण_अगर /* WITH_IRIX_AUDIT */
}


#पूर्ण_अगर /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */
