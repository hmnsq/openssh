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

#که_نه_تعریف_شوی بل_POSIX_H
#تعریف_کړه بل_POSIX_H

#که_تعریف_شوی HAVE_بل
#ضمن <sys/dir.h>

/* NGROUPS_MAX is behind -lposix.  Use the BSD version which is NGROUPS */
#تعریف_لغوه NGROUPS_MAX
#تعریف_کړه NGROUPS_MAX NGROUPS

/* NeXT's readdir() is BSD (struct direct) not POSIX (struct dirent) */
#تعریف_کړه dirent direct

/* Swap out NeXT's BSD wait() for a more POSIX compliant one */
pid_t posix_wait(صحيح *);
#تعریف_کړه wait(a) posix_wait(a)

/* #ifdef wrapped functions that need defining for clean compiling */
pid_t getppid(فراغ);
فراغ vhangup(فراغ);
صحيح innetgr(ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);

/* TERMCAP */
صحيح tcgetattr(صحيح, بنية termios *);
صحيح tcsetattr(صحيح, صحيح, ثابت بنية termios *);
صحيح tcsetpgrp(صحيح, pid_t);
speed_t cfgetospeed(ثابت بنية termios *);
speed_t cfgetispeed(ثابت بنية termios *);
صحيح cfsetospeed(بنية termios *, صحيح);
صحيح cfsetispeed(بنية termios *, صحيح);
#د_که_پای /* HAVE_NEXT */
#د_که_پای /* _NEXT_POSIX_H */
