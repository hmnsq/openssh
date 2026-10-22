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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_FLOCK
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>

முழு
flock(முழு fd, முழு op)
{
	முழு rc = 0;

#எனில் defined(F_SETLK) && defined(F_SETLKW)
	கட்டமைப்பு flock fl = {0};

	தேர்வு (op & (LOCK_EX|LOCK_SH|LOCK_UN)) {
	நிலை LOCK_EX:
		fl.l_type = F_WRLCK;
		நிறுத்து;

	நிலை LOCK_SH:
		fl.l_type = F_RDLCK;
		நிறுத்து;

	நிலை LOCK_UN:
		fl.l_type = F_UNLCK;
		நிறுத்து;

	இயல்பு:
		errno = EINVAL;
		திரும்பு -1;
	}

	fl.l_whence = SEEK_SET;
	rc = fcntl(fd, op & LOCK_NB ? F_SETLK : F_SETLKW, &fl);

	எனில் (rc && (errno == EAGAIN))
		errno = EWOULDBLOCK;
#இல்லையெனில்
	rc = -1;
	errno = ENOSYS;
#endif

	திரும்பு rc;
}
#endif
