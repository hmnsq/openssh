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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <termios.h>
#شامل <pwd.h>

#شامل "sshpty.h"

ساکن ساخت termios _saved_tio;
ساکن صحیح اندر_raw_منوال = 0;

ساخت termios *
get_saved_tio(خالی)
{
	واپس اندر_raw_منوال ? &_saved_tio : تہی;
}

خالی
leave_raw_منوال(صحیح quiet)
{
	اگر (!اندر_raw_منوال)
		واپس;
	اگر (tcsetattr(fileno(stdin), TCSADRAIN, &_saved_tio) == -1) {
		اگر (!quiet)
			perror("tcsetattr");
	} ورنہ
		اندر_raw_منوال = 0;
}

خالی
enter_raw_منوال(صحیح quiet)
{
	ساخت termios tio;

	اگر (tcgetattr(fileno(stdin), &tio) == -1) {
		اگر (!quiet)
			perror("tcgetattr");
		واپس;
	}
	_saved_tio = tio;
	tio.c_iflag |= IGNPAR;
	tio.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#اگر_تعریف_شدہ IUCLC
	tio.c_iflag &= ~IUCLC;
#اگر_ختم
	tio.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
#اگر_تعریف_شدہ IEXTEN
	tio.c_lflag &= ~IEXTEN;
#اگر_ختم
	tio.c_oflag &= ~OPOST;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;
	اگر (tcsetattr(fileno(stdin), TCSADRAIN, &tio) == -1) {
		اگر (!quiet)
			perror("tcsetattr");
	} ورنہ
		اندر_raw_منوال = 1;
}
