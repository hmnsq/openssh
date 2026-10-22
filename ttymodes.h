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
#यदि defined(VKILL)
TTYCHAR(VKILL, 4)
#यदि_अन्तः /* VKILL */
TTYCHAR(VEOF, 5)
#यदि defined(VEOL)
TTYCHAR(VEOL, 6)
#यदि_अन्तः /* VEOL */
#यदि_परिभाषितम् VEOL2
TTYCHAR(VEOL2, 7)
#यदि_अन्तः /* VEOL2 */
TTYCHAR(VSTART, 8)
TTYCHAR(VSTOP, 9)
#यदि defined(VSUSP)
TTYCHAR(VSUSP, 10)
#यदि_अन्तः /* VSUSP */
#यदि defined(VDSUSP)
TTYCHAR(VDSUSP, 11)
#यदि_अन्तः /* VDSUSP */
#यदि defined(VREPRINT)
TTYCHAR(VREPRINT, 12)
#यदि_अन्तः /* VREPRINT */
#यदि defined(VWERASE)
TTYCHAR(VWERASE, 13)
#यदि_अन्तः /* VWERASE */
#यदि defined(VLNEXT)
TTYCHAR(VLNEXT, 14)
#यदि_अन्तः /* VLNEXT */
#यदि defined(VFLUSH)
TTYCHAR(VFLUSH, 15)
#यदि_अन्तः /* VFLUSH */
#यदि_परिभाषितम् VSWTCH
TTYCHAR(VSWTCH, 16)
#यदि_अन्तः /* VSWTCH */
#यदि defined(VSTATUS)
TTYCHAR(VSTATUS, 17)
#यदि_अन्तः /* VSTATUS */
#यदि_परिभाषितम् VDISCARD
TTYCHAR(VDISCARD, 18)
#यदि_अन्तः /* VDISCARD */

/* name, field, op */
TTYMODE(IGNPAR,	c_iflag, 30)
TTYMODE(PARMRK,	c_iflag, 31)
TTYMODE(INPCK,	c_iflag, 32)
TTYMODE(ISTRIP,	c_iflag, 33)
TTYMODE(INLCR,	c_iflag, 34)
TTYMODE(IGNCR,	c_iflag, 35)
TTYMODE(ICRNL,	c_iflag, 36)
#यदि defined(IUCLC)
TTYMODE(IUCLC,	c_iflag, 37)
#यदि_अन्तः
TTYMODE(IXON,	c_iflag, 38)
TTYMODE(IXANY,	c_iflag, 39)
TTYMODE(IXOFF,	c_iflag, 40)
#यदि_परिभाषितम् IMAXBEL
TTYMODE(IMAXBEL,c_iflag, 41)
#यदि_अन्तः /* IMAXBEL */
#यदि_परिभाषितम् IUTF8
TTYMODE(IUTF8,  c_iflag, 42)
#यदि_अन्तः /* IUTF8 */

TTYMODE(ISIG,	c_lflag, 50)
TTYMODE(ICANON,	c_lflag, 51)
#यदि_परिभाषितम् XCASE
TTYMODE(XCASE,	c_lflag, 52)
#यदि_अन्तः
TTYMODE(ECHO,	c_lflag, 53)
TTYMODE(ECHOE,	c_lflag, 54)
TTYMODE(ECHOK,	c_lflag, 55)
TTYMODE(ECHONL,	c_lflag, 56)
TTYMODE(NOFLSH,	c_lflag, 57)
TTYMODE(TOSTOP,	c_lflag, 58)
#यदि_परिभाषितम् IEXTEN
TTYMODE(IEXTEN, c_lflag, 59)
#यदि_अन्तः /* IEXTEN */
#यदि defined(ECHOCTL)
TTYMODE(ECHOCTL,c_lflag, 60)
#यदि_अन्तः /* ECHOCTL */
#यदि_परिभाषितम् ECHOKE
TTYMODE(ECHOKE,	c_lflag, 61)
#यदि_अन्तः /* ECHOKE */
#यदि defined(PENDIN)
TTYMODE(PENDIN,	c_lflag, 62)
#यदि_अन्तः /* PENDIN */

TTYMODE(OPOST,	c_oflag, 70)
#यदि defined(OLCUC)
TTYMODE(OLCUC,	c_oflag, 71)
#यदि_अन्तः
#यदि_परिभाषितम् ONLCR
TTYMODE(ONLCR,	c_oflag, 72)
#यदि_अन्तः
#यदि_परिभाषितम् OCRNL
TTYMODE(OCRNL,	c_oflag, 73)
#यदि_अन्तः
#यदि_परिभाषितम् ONOCR
TTYMODE(ONOCR,	c_oflag, 74)
#यदि_अन्तः
#यदि_परिभाषितम् ONLRET
TTYMODE(ONLRET,	c_oflag, 75)
#यदि_अन्तः

TTYMODE(CS7,	c_cflag, 90)
TTYMODE(CS8,	c_cflag, 91)
TTYMODE(PARENB,	c_cflag, 92)
TTYMODE(PARODD,	c_cflag, 93)
