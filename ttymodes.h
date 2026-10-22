/* $OpenBSD: ttymodes.h,v 1.16 2017/04/30 23:26:54 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/*
 * SSH2 tty modes support by Kevin Steves.
 * Copyright (c) 2001 Kevin Steves.  All rights reserved.
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
 */

/*
 * The tty mode description is a string, consisting of
 * opcode-arguments pairs.  It is terminated by opcode TTY_OP_END (0).
 * Opcodes 1-159 have uint32 arguments.
 * Opcodes 160-255 are not yet defined and cause parsing to stop (they
 * should only be used after any other data).
 *
 * The client puts in the string any modes it knows about, and the
 * server ignores any modes it does not know about.  This allows some degree
 * of machine-independence, at least between systems that use a posix-like
 * tty interface.  The protocol can support other systems as well, but might
 * require reimplementing as mode names would likely be different.
 */

/*
 * Some constants and prototypes are defined in packet.h; this file
 * is only intended for including from ttymodes.c.
 */

/* termios macro */
/* name, op */
TTYCHAR(VINTR, 1)
TTYCHAR(VQUIT, 2)
TTYCHAR(VERASE, 3)
#اگر defined(VKILL)
TTYCHAR(VKILL, 4)
#اگر_ختم /* VKILL */
TTYCHAR(VEOF, 5)
#اگر defined(VEOL)
TTYCHAR(VEOL, 6)
#اگر_ختم /* VEOL */
#اگر_تعریف_شدہ VEOL2
TTYCHAR(VEOL2, 7)
#اگر_ختم /* VEOL2 */
TTYCHAR(VSTART, 8)
TTYCHAR(VSTOP, 9)
#اگر defined(VSUSP)
TTYCHAR(VSUSP, 10)
#اگر_ختم /* VSUSP */
#اگر defined(VDSUSP)
TTYCHAR(VDSUSP, 11)
#اگر_ختم /* VDSUSP */
#اگر defined(VREPRINT)
TTYCHAR(VREPRINT, 12)
#اگر_ختم /* VREPRINT */
#اگر defined(VWERASE)
TTYCHAR(VWERASE, 13)
#اگر_ختم /* VWERASE */
#اگر defined(VLNEXT)
TTYCHAR(VLNEXT, 14)
#اگر_ختم /* VLNEXT */
#اگر defined(VFLUSH)
TTYCHAR(VFLUSH, 15)
#اگر_ختم /* VFLUSH */
#اگر_تعریف_شدہ VSWTCH
TTYCHAR(VSWTCH, 16)
#اگر_ختم /* VSWTCH */
#اگر defined(VSTATUS)
TTYCHAR(VSTATUS, 17)
#اگر_ختم /* VSTATUS */
#اگر_تعریف_شدہ VDISCARD
TTYCHAR(VDISCARD, 18)
#اگر_ختم /* VDISCARD */

/* name, field, op */
TTYMODE(IGNPAR,	c_iflag, 30)
TTYMODE(PARMRK,	c_iflag, 31)
TTYMODE(INPCK,	c_iflag, 32)
TTYMODE(ISTRIP,	c_iflag, 33)
TTYMODE(INLCR,	c_iflag, 34)
TTYMODE(IGNCR,	c_iflag, 35)
TTYMODE(ICRNL,	c_iflag, 36)
#اگر defined(IUCLC)
TTYMODE(IUCLC,	c_iflag, 37)
#اگر_ختم
TTYMODE(IXON,	c_iflag, 38)
TTYMODE(IXANY,	c_iflag, 39)
TTYMODE(IXOFF,	c_iflag, 40)
#اگر_تعریف_شدہ IMAXBEL
TTYMODE(IMAXBEL,c_iflag, 41)
#اگر_ختم /* IMAXBEL */
#اگر_تعریف_شدہ IUTF8
TTYMODE(IUTF8,  c_iflag, 42)
#اگر_ختم /* IUTF8 */

TTYMODE(ISIG,	c_lflag, 50)
TTYMODE(ICANON,	c_lflag, 51)
#اگر_تعریف_شدہ XCASE
TTYMODE(XCASE,	c_lflag, 52)
#اگر_ختم
TTYMODE(ECHO,	c_lflag, 53)
TTYMODE(ECHOE,	c_lflag, 54)
TTYMODE(ECHOK,	c_lflag, 55)
TTYMODE(ECHONL,	c_lflag, 56)
TTYMODE(NOFLSH,	c_lflag, 57)
TTYMODE(TOSTOP,	c_lflag, 58)
#اگر_تعریف_شدہ IEXTEN
TTYMODE(IEXTEN, c_lflag, 59)
#اگر_ختم /* IEXTEN */
#اگر defined(ECHOCTL)
TTYMODE(ECHOCTL,c_lflag, 60)
#اگر_ختم /* ECHOCTL */
#اگر_تعریف_شدہ ECHOKE
TTYMODE(ECHOKE,	c_lflag, 61)
#اگر_ختم /* ECHOKE */
#اگر defined(PENDIN)
TTYMODE(PENDIN,	c_lflag, 62)
#اگر_ختم /* PENDIN */

TTYMODE(OPOST,	c_oflag, 70)
#اگر defined(OLCUC)
TTYMODE(OLCUC,	c_oflag, 71)
#اگر_ختم
#اگر_تعریف_شدہ ONLCR
TTYMODE(ONLCR,	c_oflag, 72)
#اگر_ختم
#اگر_تعریف_شدہ OCRNL
TTYMODE(OCRNL,	c_oflag, 73)
#اگر_ختم
#اگر_تعریف_شدہ ONOCR
TTYMODE(ONOCR,	c_oflag, 74)
#اگر_ختم
#اگر_تعریف_شدہ ONLRET
TTYMODE(ONLRET,	c_oflag, 75)
#اگر_ختم

TTYMODE(CS7,	c_cflag, 90)
TTYMODE(CS8,	c_cflag, 91)
TTYMODE(PARENB,	c_cflag, 92)
TTYMODE(PARODD,	c_cflag, 93)
