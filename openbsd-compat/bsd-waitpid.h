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

#اگر_تعریف_نشده _BSD_WAITPID_H
#تعریف_کن _BSD_WAITPID_H

#اگر_تعریف_نشده HAVE_WAITPID
/* Clean out any potential issues */
#لغو_تعریف WIFEXITED
#لغو_تعریف WIFSTOPPED
#لغو_تعریف WIFSIGNALED

/* Define required functions to mimic a POSIX look and feel */
#تعریف_کن _W_INT(w)	(*(صحيح*)&(w))	/* convert union wait to int */
#تعریف_کن WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#تعریف_کن WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#تعریف_کن WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#تعریف_کن WEXITSTATUS(w)	(صحيح)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#تعریف_کن WTERMSIG(w)	(صحيح)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#تعریف_کن WCOREFLAG	0x80
#تعریف_کن WCOREDUMP(w)	((_W_INT(w)) & WCOREFLAG)

/* Prototype */
pid_t waitpid(صحيح, صحيح *, صحيح);

#پایان_اگر /* !HAVE_WAITPID */
#پایان_اگر /* _BSD_WAITPID_H */
