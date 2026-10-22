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

#اگر_غیر_تعریف_شدہ _BSD_WAITPID_H
#تعریف_کرو _BSD_WAITPID_H

#اگر_غیر_تعریف_شدہ HAVE_WAITPID
/* Clean out any potential issues */
#تعریف_منسوخ WIFEXITED
#تعریف_منسوخ WIFSTOPPED
#تعریف_منسوخ WIFSIGNALED

/* Define required functions to mimic a POSIX look and feel */
#تعریف_کرو _W_INT(w)	(*(صحیح*)&(w))	/* convert union wait to int */
#تعریف_کرو WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#تعریف_کرو WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#تعریف_کرو WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#تعریف_کرو WEXITSTATUS(w)	(صحیح)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#تعریف_کرو WTERMSIG(w)	(صحیح)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#تعریف_کرو WCOREFLAG	0x80
#تعریف_کرو WCOREDUMP(w)	((_W_INT(w)) & WCOREFLAG)

/* Prototype */
pid_t waitpid(صحیح, صحیح *, صحیح);

#اگر_ختم /* !HAVE_WAITPID */
#اگر_ختم /* _BSD_WAITPID_H */
