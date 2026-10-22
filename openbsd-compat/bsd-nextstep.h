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
#অন্তর্ভাব <sys/dir.h>

/* NGROUPS_MAX is behind -lposix.  Use the BSD version which is NGROUPS */
#undef NGROUPS_MAX
#define NGROUPS_MAX NGROUPS

/* NeXT's readdir() is BSD (struct direct) not POSIX (struct dirent) */
#define dirent direct

/* Swap out NeXT's BSD wait() for a more POSIX compliant one */
pid_t posix_wait(পূর্ণাঙ্ক *);
#define wait(a) posix_wait(a)

/* #ifdef wrapped functions that need defining for clean compiling */
pid_t getppid(শূন্য);
শূন্য vhangup(শূন্য);
পূর্ণাঙ্ক innetgr(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *);

/* TERMCAP */
পূর্ণাঙ্ক tcgetattr(পূর্ণাঙ্ক, সংরচনা termios *);
পূর্ণাঙ্ক tcsetattr(পূর্ণাঙ্ক, পূর্ণাঙ্ক, ধ্রুব সংরচনা termios *);
পূর্ণাঙ্ক tcsetpgrp(পূর্ণাঙ্ক, pid_t);
speed_t cfgetospeed(ধ্রুব সংরচনা termios *);
speed_t cfgetispeed(ধ্রুব সংরচনা termios *);
পূর্ণাঙ্ক cfsetospeed(সংরচনা termios *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক cfsetispeed(সংরচনা termios *, পূর্ণাঙ্ক);
#endif /* HAVE_NEXT */
#endif /* _NEXT_POSIX_H */
