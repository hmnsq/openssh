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

#समावेश "includes.h"

#अगर_अघोषित HAVE_FLOCK
#समावेश <errno.h>
#समावेश <fcntl.h>

पूर्णांक
flock(पूर्णांक fd, पूर्णांक op)
{
	पूर्णांक rc = 0;

#अगर defined(F_SETLK) && defined(F_SETLKW)
	काष्ठा flock fl = {0};

	चयन (op & (LOCK_EX|LOCK_SH|LOCK_UN)) {
	हाल LOCK_EX:
		fl.l_type = F_WRLCK;
		अवरोध;

	हाल LOCK_SH:
		fl.l_type = F_RDLCK;
		अवरोध;

	हाल LOCK_UN:
		fl.l_type = F_UNLCK;
		अवरोध;

	शेष:
		त्रुटि_सं = EINVAL;
		वापस -1;
	}

	fl.l_whence = शुरू_से;
	rc = fcntl(fd, op & LOCK_NB ? F_SETLK : F_SETLKW, &fl);

	अगर (rc && (त्रुटि_सं == EAGAIN))
		त्रुटि_सं = EWOULDBLOCK;
#अन्यथा
	rc = -1;
	त्रुटि_सं = ENOSYS;
#पूर्ण_अगर

	वापस rc;
}
#पूर्ण_अगर
