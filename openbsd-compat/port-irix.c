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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || \
    defined(WITH_IRIX_ARRAY)

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_IRIX_PROJECT
# include <proj.h>
#ਜੇ_ਅੰਤ /* WITH_IRIX_PROJECT */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_IRIX_JOBS
# include <sys/resource.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_IRIX_AUDIT
# include <sat.h>
#ਜੇ_ਅੰਤ /* WITH_IRIX_AUDIT */

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਖਾਲੀ
irix_setusercontext(ਬਣਤਰ passwd *pw)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_IRIX_PROJECT
	prid_t projid;
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_IRIX_JOBS
	jid_t jid = 0;
#ਜਾਂਜੇ defined(WITH_IRIX_ARRAY)
	ਪੂਰਨ jid = 0;
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_IRIX_JOBS
	jid = jlimit_startjob(pw->pw_name, pw->pw_uid, "interactive");
	ਜੇ (jid == -1)
		fatal("Failed to create job container: %.100s",
		    strerror(errno));
#ਜੇ_ਅੰਤ /* WITH_IRIX_JOBS */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_IRIX_ARRAY
	/* initialize array session */
	ਜੇ (jid == 0  && newarraysess() != 0)
		fatal("Failed to set up new array session: %.100s",
		    strerror(errno));
#ਜੇ_ਅੰਤ /* WITH_IRIX_ARRAY */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_IRIX_PROJECT
	/* initialize irix project info */
	ਜੇ ((projid = getdfltprojuser(pw->pw_name)) == -1) {
		debug("Failed to get project id, using projid 0");
		projid = 0;
	}
	ਜੇ (setprid(projid))
		fatal("Failed to initialize project %d for %s: %.100s",
		    (ਪੂਰਨ)projid, pw->pw_name, strerror(errno));
#ਜੇ_ਅੰਤ /* WITH_IRIX_PROJECT */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_IRIX_AUDIT
	ਜੇ (sysconf(_SC_AUDIT)) {
		debug("Setting sat id to %d", (ਪੂਰਨ) pw->pw_uid);
		ਜੇ (satsetid(pw->pw_uid))
			debug("error setting satid: %.100s", strerror(errno));
	}
#ਜੇ_ਅੰਤ /* WITH_IRIX_AUDIT */
}


#ਜੇ_ਅੰਤ /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */
