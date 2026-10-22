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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਅਗਲਾ_POSIX_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਅਗਲਾ_POSIX_H

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ਅਗਲਾ
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/dir.h>

/* NGROUPS_MAX is behind -lposix.  Use the BSD version which is NGROUPS */
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ NGROUPS_MAX
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NGROUPS_MAX NGROUPS

/* NeXT's readdir() is BSD (struct direct) not POSIX (struct dirent) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ dirent direct

/* Swap out NeXT's BSD wait() for a more POSIX compliant one */
pid_t posix_wait(ਪੂਰਨ *);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ wait(a) posix_wait(a)

/* #ifdef wrapped functions that need defining for clean compiling */
pid_t getppid(ਖਾਲੀ);
ਖਾਲੀ vhangup(ਖਾਲੀ);
ਪੂਰਨ innetgr(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

/* TERMCAP */
ਪੂਰਨ tcgetattr(ਪੂਰਨ, ਬਣਤਰ termios *);
ਪੂਰਨ tcsetattr(ਪੂਰਨ, ਪੂਰਨ, ਅਚਲ ਬਣਤਰ termios *);
ਪੂਰਨ tcsetpgrp(ਪੂਰਨ, pid_t);
speed_t cfgetospeed(ਅਚਲ ਬਣਤਰ termios *);
speed_t cfgetispeed(ਅਚਲ ਬਣਤਰ termios *);
ਪੂਰਨ cfsetospeed(ਬਣਤਰ termios *, ਪੂਰਨ);
ਪੂਰਨ cfsetispeed(ਬਣਤਰ termios *, ਪੂਰਨ);
#ਜੇ_ਅੰਤ /* HAVE_NEXT */
#ਜੇ_ਅੰਤ /* _NEXT_POSIX_H */
