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

#ضمن "includes.h"

#که_نه_تعریف_شوی HAVE_FLOCK
#ضمن <errno.h>
#ضمن <fcntl.h>

صحيح
flock(صحيح fd, صحيح op)
{
	صحيح rc = 0;

#إذا defined(F_SETLK) && defined(F_SETLKW)
	بنية flock fl = {0};

	بدل (op & (LOCK_EX|LOCK_SH|LOCK_UN)) {
	حالة LOCK_EX:
		fl.l_type = F_WRLCK;
		اكسر;

	حالة LOCK_SH:
		fl.l_type = F_RDLCK;
		اكسر;

	حالة LOCK_UN:
		fl.l_type = F_UNLCK;
		اكسر;

	افتراضي:
		errno = EINVAL;
		أرجع -1;
	}

	fl.l_whence = SEEK_SET;
	rc = fcntl(fd, op & LOCK_NB ? F_SETLK : F_SETLKW, &fl);

	إذا (rc && (errno == EAGAIN))
		errno = EWOULDBLOCK;
#وإلا
	rc = -1;
	errno = ENOSYS;
#د_که_پای

	أرجع rc;
}
#د_که_پای
