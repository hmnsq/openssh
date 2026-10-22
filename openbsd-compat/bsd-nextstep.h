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

#अगर_अघोषित अग्र_POSIX_H
#घोषणा अग्र_POSIX_H

#अगर_घोषित HAVE_अग्र
#समावेश <sys/dir.h>

/* NGROUPS_MAX is behind -lposix.  Use the BSD version which is NGROUPS */
#अघोषित NGROUPS_MAX
#घोषणा NGROUPS_MAX NGROUPS

/* NeXT's readdir() is BSD (struct direct) not POSIX (struct dirent) */
#घोषणा dirent direct

/* Swap out NeXT's BSD wait() for a more POSIX compliant one */
pid_t posix_wait(पूर्णांक *);
#घोषणा रुको(a) posix_wait(a)

/* #ifdef wrapped functions that need defining for clean compiling */
pid_t getppid(व्योम);
व्योम vhangup(व्योम);
पूर्णांक innetgr(स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *);

/* TERMCAP */
पूर्णांक tcgetattr(पूर्णांक, काष्ठा termios *);
पूर्णांक tcsetattr(पूर्णांक, पूर्णांक, स्थिर काष्ठा termios *);
पूर्णांक tcsetpgrp(पूर्णांक, pid_t);
speed_t cfgetospeed(स्थिर काष्ठा termios *);
speed_t cfgetispeed(स्थिर काष्ठा termios *);
पूर्णांक cfsetospeed(काष्ठा termios *, पूर्णांक);
पूर्णांक cfsetispeed(काष्ठा termios *, पूर्णांक);
#पूर्ण_अगर /* HAVE_NEXT */
#पूर्ण_अगर /* _NEXT_POSIX_H */
