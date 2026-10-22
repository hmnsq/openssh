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

#ifndef _NEXT_POSIX_H
#define _NEXT_POSIX_H

#ifdef HAVE_NEXT
#ଅନ୍ତର୍ଭାଵ <sys/dir.h>

/* NGROUPS_MAX is behind -lposix.  Use the BSD version which is NGROUPS */
#undef NGROUPS_MAX
#define NGROUPS_MAX NGROUPS

/* NeXT's readdir() is BSD (struct direct) not POSIX (struct dirent) */
#define dirent direct

/* Swap out NeXT's BSD wait() for a more POSIX compliant one */
pid_t posix_wait(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
#define wait(a) posix_wait(a)

/* #ifdef wrapped functions that need defining for clean compiling */
pid_t getppid(ଶୂନ୍ୟ);
ଶୂନ୍ୟ vhangup(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା innetgr(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

/* TERMCAP */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା tcgetattr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା termios *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା tcsetattr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ସଂରଚନା termios *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା tcsetpgrp(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, pid_t);
speed_t cfgetospeed(ଅଚଳ ସଂରଚନା termios *);
speed_t cfgetispeed(ଅଚଳ ସଂରଚନା termios *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା cfsetospeed(ସଂରଚନା termios *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା cfsetispeed(ସଂରଚନା termios *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif /* HAVE_NEXT */
#endif /* _NEXT_POSIX_H */
