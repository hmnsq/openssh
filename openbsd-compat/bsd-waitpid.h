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

#నిర్వచితం_కాకపోతే _BSD_WAITPID_H
#నిర్వచించు _BSD_WAITPID_H

#నిర్వచితం_కాకపోతే HAVE_WAITPID
/* Clean out any potential issues */
#నిర్వచనం_రద్దు WIFEXITED
#నిర్వచనం_రద్దు WIFSTOPPED
#నిర్వచనం_రద్దు WIFSIGNALED

/* Define required functions to mimic a POSIX look and feel */
#నిర్వచించు _W_INT(w)	(*(పూర్ణాంకం*)&(w))	/* convert union wait to int */
#నిర్వచించు WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#నిర్వచించు WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#నిర్వచించు WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#నిర్వచించు WEXITSTATUS(w)	(పూర్ణాంకం)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#నిర్వచించు WTERMSIG(w)	(పూర్ణాంకం)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#నిర్వచించు WCOREFLAG	0x80
#నిర్వచించు WCOREDUMP(w)	((_W_INT(w)) & WCOREFLAG)

/* Prototype */
pid_t waitpid(పూర్ణాంకం, పూర్ణాంకం *, పూర్ణాంకం);

#అయితే_ముగింపు /* !HAVE_WAITPID */
#అయితే_ముగింపు /* _BSD_WAITPID_H */
