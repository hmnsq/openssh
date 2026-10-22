/*
 * Copyright (c) 2000,2001 Ben Lindstrom.  All rights reserved.
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

#నిర్వచితం_కాకపోతే తదుపరి_POSIX_H
#నిర్వచించు తదుపరి_POSIX_H

#నిర్వచితమైతే HAVE_తదుపరి
#అన్తర్భావ <sys/dir.h>

/* NGROUPS_MAX is behind -lposix.  Use the BSD version which is NGROUPS */
#నిర్వచనం_రద్దు NGROUPS_MAX
#నిర్వచించు NGROUPS_MAX NGROUPS

/* NeXT's readdir() is BSD (struct direct) not POSIX (struct dirent) */
#నిర్వచించు dirent direct

/* Swap out NeXT's BSD wait() for a more POSIX compliant one */
pid_t posix_wait(పూర్ణాంకం *);
#నిర్వచించు wait(a) posix_wait(a)

/* #ifdef wrapped functions that need defining for clean compiling */
pid_t getppid(శూన్య);
శూన్య vhangup(శూన్య);
పూర్ణాంకం innetgr(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

/* TERMCAP */
పూర్ణాంకం tcgetattr(పూర్ణాంకం, నిర్మాణం termios *);
పూర్ణాంకం tcsetattr(పూర్ణాంకం, పూర్ణాంకం, స్థిరరాశి నిర్మాణం termios *);
పూర్ణాంకం tcsetpgrp(పూర్ణాంకం, pid_t);
speed_t cfgetospeed(స్థిరరాశి నిర్మాణం termios *);
speed_t cfgetispeed(స్థిరరాశి నిర్మాణం termios *);
పూర్ణాంకం cfsetospeed(నిర్మాణం termios *, పూర్ణాంకం);
పూర్ణాంకం cfsetispeed(నిర్మాణం termios *, పూర్ణాంకం);
#అయితే_ముగింపు /* HAVE_NEXT */
#అయితే_ముగింపు /* _NEXT_POSIX_H */
