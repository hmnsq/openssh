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
 *
 */

#جيڪڏهن_وصف_نه_ٿيل _BSD_WAITPID_H
#وصف_ڪريو _BSD_WAITPID_H

#جيڪڏهن_وصف_نه_ٿيل HAVE_WAITPID
/* Clean out any potential issues */
#وصف_رد WIFEXITED
#وصف_رد WIFSTOPPED
#وصف_رد WIFSIGNALED

/* Define required functions to mimic a POSIX look and feel */
#وصف_ڪريو _W_INT(w)	(*(صحيح*)&(w))	/* convert union wait to int */
#وصف_ڪريو WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#وصف_ڪريو WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#وصف_ڪريو WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#وصف_ڪريو WEXITSTATUS(w)	(صحيح)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#وصف_ڪريو WTERMSIG(w)	(صحيح)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#وصف_ڪريو WCOREFLAG	0x80
#وصف_ڪريو WCOREDUMP(w)	((_W_INT(w)) & WCOREFLAG)

/* Prototype */
pid_t waitpid(صحيح, صحيح *, صحيح);

#جيڪڏهن_پورو /* !HAVE_WAITPID */
#جيڪڏهن_پورو /* _BSD_WAITPID_H */
