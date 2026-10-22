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

#అన్తర్భావ "includes.h"

#ఒకవేళ defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || \
    defined(WITH_IRIX_ARRAY)

#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే WITH_IRIX_PROJECT
# include <proj.h>
#అయితే_ముగింపు /* WITH_IRIX_PROJECT */
#నిర్వచితమైతే WITH_IRIX_JOBS
# include <sys/resource.h>
#అయితే_ముగింపు
#నిర్వచితమైతే WITH_IRIX_AUDIT
# include <sat.h>
#అయితే_ముగింపు /* WITH_IRIX_AUDIT */

#అన్తర్భావ "log.h"

శూన్య
irix_setusercontext(నిర్మాణం passwd *pw)
{
#నిర్వచితమైతే WITH_IRIX_PROJECT
	prid_t projid;
#అయితే_ముగింపు
#నిర్వచితమైతే WITH_IRIX_JOBS
	jid_t jid = 0;
#లేదావేళ defined(WITH_IRIX_ARRAY)
	పూర్ణాంకం jid = 0;
#అయితే_ముగింపు

#నిర్వచితమైతే WITH_IRIX_JOBS
	jid = jlimit_startjob(pw->pw_name, pw->pw_uid, "interactive");
	ఒకవేళ (jid == -1)
		fatal("Failed to create job container: %.100s",
		    strerror(errno));
#అయితే_ముగింపు /* WITH_IRIX_JOBS */
#నిర్వచితమైతే WITH_IRIX_ARRAY
	/* initialize array session */
	ఒకవేళ (jid == 0  && newarraysess() != 0)
		fatal("Failed to set up new array session: %.100s",
		    strerror(errno));
#అయితే_ముగింపు /* WITH_IRIX_ARRAY */
#నిర్వచితమైతే WITH_IRIX_PROJECT
	/* initialize irix project info */
	ఒకవేళ ((projid = getdfltprojuser(pw->pw_name)) == -1) {
		debug("Failed to get project id, using projid 0");
		projid = 0;
	}
	ఒకవేళ (setprid(projid))
		fatal("Failed to initialize project %d for %s: %.100s",
		    (పూర్ణాంకం)projid, pw->pw_name, strerror(errno));
#అయితే_ముగింపు /* WITH_IRIX_PROJECT */
#నిర్వచితమైతే WITH_IRIX_AUDIT
	ఒకవేళ (sysconf(_SC_AUDIT)) {
		debug("Setting sat id to %d", (పూర్ణాంకం) pw->pw_uid);
		ఒకవేళ (satsetid(pw->pw_uid))
			debug("error setting satid: %.100s", strerror(errno));
	}
#అయితే_ముగింపు /* WITH_IRIX_AUDIT */
}


#అయితే_ముగింపు /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */
