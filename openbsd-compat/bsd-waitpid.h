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

#यदि_अपरिभाषितम् _BSD_WAITPID_H
#परिभाषय _BSD_WAITPID_H

#यदि_अपरिभाषितम् HAVE_WAITPID
/* Clean out any potential issues */
#अपरिभाषय WIFEXITED
#अपरिभाषय WIFSTOPPED
#अपरिभाषय WIFSIGNALED

/* Define required functions to mimic a POSIX look and feel */
#परिभाषय _W_INT(w)	(*(पूर्णाङ्क*)&(w))	/* convert union wait to int */
#परिभाषय WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#परिभाषय WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#परिभाषय WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#परिभाषय WEXITSTATUS(w)	(पूर्णाङ्क)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#परिभाषय WTERMSIG(w)	(पूर्णाङ्क)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#परिभाषय WCOREFLAG	0x80
#परिभाषय WCOREDUMP(w)	((_W_INT(w)) & WCOREFLAG)

/* Prototype */
pid_t waitpid(पूर्णाङ्क, पूर्णाङ्क *, पूर्णाङ्क);

#यदि_अन्तः /* !HAVE_WAITPID */
#यदि_अन्तः /* _BSD_WAITPID_H */
