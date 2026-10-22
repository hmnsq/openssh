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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _BSD_WAITPID_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _BSD_WAITPID_H

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_WAITPID
/* Clean out any potential issues */
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ WIFEXITED
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ WIFSTOPPED
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ WIFSIGNALED

/* Define required functions to mimic a POSIX look and feel */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _W_INT(w)	(*(ਪੂਰਨ*)&(w))	/* convert union wait to int */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WEXITSTATUS(w)	(ਪੂਰਨ)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WTERMSIG(w)	(ਪੂਰਨ)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WCOREFLAG	0x80
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WCOREDUMP(w)	((_W_INT(w)) & WCOREFLAG)

/* Prototype */
pid_t waitpid(ਪੂਰਨ, ਪੂਰਨ *, ਪੂਰਨ);

#ਜੇ_ਅੰਤ /* !HAVE_WAITPID */
#ਜੇ_ਅੰਤ /* _BSD_WAITPID_H */
