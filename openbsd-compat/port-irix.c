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

#ضمن "includes.h"

#إذا defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || \
    defined(WITH_IRIX_ARRAY)

#ضمن <errno.h>
#ضمن <string.h>
#ضمن <unistd.h>

#جے_تعریف_شدہ WITH_IRIX_PROJECT
# include <proj.h>
#جے_انت /* WITH_IRIX_PROJECT */
#جے_تعریف_شدہ WITH_IRIX_JOBS
# include <sys/resource.h>
#جے_انت
#جے_تعریف_شدہ WITH_IRIX_AUDIT
# include <sat.h>
#جے_انت /* WITH_IRIX_AUDIT */

#ضمن "log.h"

فراغ
irix_setusercontext(بنية passwd *pw)
{
#جے_تعریف_شدہ WITH_IRIX_PROJECT
	prid_t projid;
#جے_انت
#جے_تعریف_شدہ WITH_IRIX_JOBS
	jid_t jid = 0;
#وإلاإذا defined(WITH_IRIX_ARRAY)
	صحيح jid = 0;
#جے_انت

#جے_تعریف_شدہ WITH_IRIX_JOBS
	jid = jlimit_startjob(pw->pw_name, pw->pw_uid, "interactive");
	إذا (jid == -1)
		fatal("Failed to create job container: %.100s",
		    strerror(errno));
#جے_انت /* WITH_IRIX_JOBS */
#جے_تعریف_شدہ WITH_IRIX_ARRAY
	/* initialize array session */
	إذا (jid == 0  && newarraysess() != 0)
		fatal("Failed to set up new array session: %.100s",
		    strerror(errno));
#جے_انت /* WITH_IRIX_ARRAY */
#جے_تعریف_شدہ WITH_IRIX_PROJECT
	/* initialize irix project info */
	إذا ((projid = getdfltprojuser(pw->pw_name)) == -1) {
		debug("Failed to get project id, using projid 0");
		projid = 0;
	}
	إذا (setprid(projid))
		fatal("Failed to initialize project %d for %s: %.100s",
		    (صحيح)projid, pw->pw_name, strerror(errno));
#جے_انت /* WITH_IRIX_PROJECT */
#جے_تعریف_شدہ WITH_IRIX_AUDIT
	إذا (sysconf(_SC_AUDIT)) {
		debug("Setting sat id to %d", (صحيح) pw->pw_uid);
		إذا (satsetid(pw->pw_uid))
			debug("error setting satid: %.100s", strerror(errno));
	}
#جے_انت /* WITH_IRIX_AUDIT */
}


#جے_انت /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */
