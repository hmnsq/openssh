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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಮುಂದಿನ_POSIX_H
#ವ್ಯಾಖ್ಯಾನಿಸು ಮುಂದಿನ_POSIX_H

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ಮುಂದಿನ
#ಅನ್ತರ್ಭಾವ <sys/dir.h>

/* NGROUPS_MAX is behind -lposix.  Use the BSD version which is NGROUPS */
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು NGROUPS_MAX
#ವ್ಯಾಖ್ಯಾನಿಸು NGROUPS_MAX NGROUPS

/* NeXT's readdir() is BSD (struct direct) not POSIX (struct dirent) */
#ವ್ಯಾಖ್ಯಾನಿಸು dirent direct

/* Swap out NeXT's BSD wait() for a more POSIX compliant one */
pid_t posix_wait(ಪೂರ್ಣಾಂಕ *);
#ವ್ಯಾಖ್ಯಾನಿಸು wait(a) posix_wait(a)

/* #ifdef wrapped functions that need defining for clean compiling */
pid_t getppid(ಶೂನ್ಯ);
ಶೂನ್ಯ vhangup(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ innetgr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/* TERMCAP */
ಪೂರ್ಣಾಂಕ tcgetattr(ಪೂರ್ಣಾಂಕ, ರಚನೆ termios *);
ಪೂರ್ಣಾಂಕ tcsetattr(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ termios *);
ಪೂರ್ಣಾಂಕ tcsetpgrp(ಪೂರ್ಣಾಂಕ, pid_t);
speed_t cfgetospeed(ಸ್ಥಿರಾಂಕ ರಚನೆ termios *);
speed_t cfgetispeed(ಸ್ಥಿರಾಂಕ ರಚನೆ termios *);
ಪೂರ್ಣಾಂಕ cfsetospeed(ರಚನೆ termios *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ cfsetispeed(ರಚನೆ termios *, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_NEXT */
#ಆದರೆ_ಅಂತ್ಯ /* _NEXT_POSIX_H */
