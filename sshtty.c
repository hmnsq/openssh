/* $OpenBSD: sshtty.c,v 1.14 2010/01/09 05:04:24 djm Exp $ */
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
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <termios.h>
#ضمن <pwd.h>

#ضمن "sshpty.h"

ساكن بنية termios _saved_tio;
ساكن صحيح دننه_raw_ډېرپېښ = 0;

بنية termios *
get_saved_tio(فراغ)
{
	أرجع دننه_raw_ډېرپېښ ? &_saved_tio : عدم;
}

فراغ
leave_raw_ډېرپېښ(صحيح quiet)
{
	إذا (!دننه_raw_ډېرپېښ)
		أرجع;
	إذا (tcsetattr(fileno(stdin), TCSADRAIN, &_saved_tio) == -1) {
		إذا (!quiet)
			perror("tcsetattr");
	} وإلا
		دننه_raw_ډېرپېښ = 0;
}

فراغ
enter_raw_ډېرپېښ(صحيح quiet)
{
	بنية termios tio;

	إذا (tcgetattr(fileno(stdin), &tio) == -1) {
		إذا (!quiet)
			perror("tcgetattr");
		أرجع;
	}
	_saved_tio = tio;
	tio.c_iflag |= IGNPAR;
	tio.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#که_تعریف_شوی IUCLC
	tio.c_iflag &= ~IUCLC;
#د_که_پای
	tio.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
#که_تعریف_شوی IEXTEN
	tio.c_lflag &= ~IEXTEN;
#د_که_پای
	tio.c_oflag &= ~OPOST;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;
	إذا (tcsetattr(fileno(stdin), TCSADRAIN, &tio) == -1) {
		إذا (!quiet)
			perror("tcsetattr");
	} وإلا
		دننه_raw_ډېرپېښ = 1;
}
