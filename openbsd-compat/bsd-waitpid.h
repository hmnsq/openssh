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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _BSD_WAITPID_H
#ವ್ಯಾಖ್ಯಾನಿಸು _BSD_WAITPID_H

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_WAITPID
/* Clean out any potential issues */
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು WIFEXITED
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು WIFSTOPPED
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು WIFSIGNALED

/* Define required functions to mimic a POSIX look and feel */
#ವ್ಯಾಖ್ಯಾನಿಸು _W_INT(w)	(*(ಪೂರ್ಣಾಂಕ*)&(w))	/* convert union wait to int */
#ವ್ಯಾಖ್ಯಾನಿಸು WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#ವ್ಯಾಖ್ಯಾನಿಸು WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#ವ್ಯಾಖ್ಯಾನಿಸು WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#ವ್ಯಾಖ್ಯಾನಿಸು WEXITSTATUS(w)	(ಪೂರ್ಣಾಂಕ)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#ವ್ಯಾಖ್ಯಾನಿಸು WTERMSIG(w)	(ಪೂರ್ಣಾಂಕ)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#ವ್ಯಾಖ್ಯಾನಿಸು WCOREFLAG	0x80
#ವ್ಯಾಖ್ಯಾನಿಸು WCOREDUMP(w)	((_W_INT(w)) & WCOREFLAG)

/* Prototype */
pid_t waitpid(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ);

#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_WAITPID */
#ಆದರೆ_ಅಂತ್ಯ /* _BSD_WAITPID_H */
