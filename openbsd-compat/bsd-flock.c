/*	$NetBSD: flock.c,v 1.6 2008/04/28 20:24:12 martin Exp $	*/

/*-
 * Copyright (c) 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Todd Vierling.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Emulate flock() with fcntl(), where available.
 * Otherwise, don't do locking; just pretend success.
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef HAVE_FLOCK
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
flock(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା op)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rc = 0;

#ଯଦି defined(F_SETLK) && defined(F_SETLKW)
	ସଂରଚନା flock fl = {0};

	ବାଛ (op & (LOCK_EX|LOCK_SH|LOCK_UN)) {
	ସ୍ଥିତି LOCK_EX:
		fl.l_type = F_WRLCK;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି LOCK_SH:
		fl.l_type = F_RDLCK;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି LOCK_UN:
		fl.l_type = F_UNLCK;
		ଭାଙ୍ଗ;

	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		errno = EINVAL;
		ଫେରନ୍ତୁ -1;
	}

	fl.l_whence = SEEK_SET;
	rc = fcntl(fd, op & LOCK_NB ? F_SETLK : F_SETLKW, &fl);

	ଯଦି (rc && (errno == EAGAIN))
		errno = EWOULDBLOCK;
#ଅନ୍ୟଥା
	rc = -1;
	errno = ENOSYS;
#endif

	ଫେରନ୍ତୁ rc;
}
#endif
