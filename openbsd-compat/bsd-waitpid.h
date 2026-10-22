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

#अगर_अघोषित _BSD_WAITPID_H
#घोषणा _BSD_WAITPID_H

#अगर_अघोषित HAVE_WAITPID
/* Clean out any potential issues */
#अघोषित WIFEXITED
#अघोषित WIFSTOPPED
#अघोषित WIFSIGNALED

/* Define required functions to mimic a POSIX look and feel */
#घोषणा _W_INT(w)	(*(पूर्णांक*)&(w))	/* convert union wait to int */
#घोषणा WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#घोषणा WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#घोषणा WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#घोषणा WEXITSTATUS(w)	(पूर्णांक)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#घोषणा WTERMSIG(w)	(पूर्णांक)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#घोषणा WCOREFLAG	0x80
#घोषणा WCOREDUMP(w)	((_W_INT(w)) & WCOREFLAG)

/* Prototype */
pid_t waitpid(पूर्णांक, पूर्णांक *, पूर्णांक);

#पूर्ण_अगर /* !HAVE_WAITPID */
#पूर्ण_अगर /* _BSD_WAITPID_H */
