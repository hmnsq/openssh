/*
 * Copyright (c) 2000 Ben Lindstrom.  All rights reserved.
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef HAVE_WAITPID
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ "bsd-waitpid.h"

pid_t
waitpid(ಪೂರ್ಣಾಙ್ಕ pid, ಪೂರ್ಣಾಙ್ಕ *stat_loc, ಪೂರ್ಣಾಙ್ಕ options)
{
	ಸಙ್ಘ wait statusp;
	pid_t wait_pid;

	ಯದಿ (pid <= 0) {
		ಯದಿ (pid != -1) {
			errno = EINVAL;
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
		/* wait4() wants pid=0 for indiscriminate wait. */
		pid = 0;
	}
	wait_pid = wait4(pid, &statusp, options, ರಿಕ್ತ);
	ಯದಿ (stat_loc)
		*stat_loc = (ಪೂರ್ಣಾಙ್ಕ) statusp.w_status;

	ಪ್ರತ್ಯಾಗಮ (wait_pid);
}

#endif /* !HAVE_WAITPID */
