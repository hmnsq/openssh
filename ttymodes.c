/* $OpenBSD: ttymodes.c,v 1.37 2026/02/14 00:18:34 jsg Exp $ */
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
 * Encoding and decoding of terminal modes in a portable way.
 * Much of the format is defined in ttymodes.h; it is included multiple times
 * into this file with the appropriate macro definitions to generate the
 * suitable code.
 */

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <errno.h>
#شامل <string.h>
#شامل <termios.h>
#شامل <stdarg.h>

#شامل "packet.h"
#شامل "log.h"
#شامل "compat.h"
#شامل "sshbuf.h"

#تعریف_کرو TTY_OP_انتہا		0
/*
 * uint32 (u_int) follows speed.
 */
#تعریف_کرو TTY_OP_ISPEED	128
#تعریف_کرو TTY_OP_OSPEED	129

/*
 * Converts POSIX speed_t to a baud rate.  The values of the
 * constants for speed_t are not themselves portable.
 */
ساکن صحیح
رفتار_مقصد_baud(speed_t رفتار)
{
	انتخاب (رفتار) {
	حالت B0:
		واپس 0;
	حالت B50:
		واپس 50;
	حالت B75:
		واپس 75;
	حالت B110:
		واپس 110;
	حالت B134:
		واپس 134;
	حالت B150:
		واپس 150;
	حالت B200:
		واپس 200;
	حالت B300:
		واپس 300;
	حالت B600:
		واپس 600;
	حالت B1200:
		واپس 1200;
	حالت B1800:
		واپس 1800;
	حالت B2400:
		واپس 2400;
	حالت B4800:
		واپس 4800;
	حالت B9600:
		واپس 9600;

#اگر_تعریف_شدہ B19200
	حالت B19200:
		واپس 19200;
#ورنہ /* B19200 */
#اگر_تعریف_شدہ EXTA
	حالت EXTA:
		واپس 19200;
#اگر_ختم /* EXTA */
#اگر_ختم /* B19200 */

#اگر_تعریف_شدہ B38400
	حالت B38400:
		واپس 38400;
#ورنہ /* B38400 */
#اگر_تعریف_شدہ EXTB
	حالت EXTB:
		واپس 38400;
#اگر_ختم /* EXTB */
#اگر_ختم /* B38400 */

#اگر_تعریف_شدہ B7200
	حالت B7200:
		واپس 7200;
#اگر_ختم /* B7200 */
#اگر_تعریف_شدہ B14400
	حالت B14400:
		واپس 14400;
#اگر_ختم /* B14400 */
#اگر_تعریف_شدہ B28800
	حالت B28800:
		واپس 28800;
#اگر_ختم /* B28800 */
#اگر_تعریف_شدہ B57600
	حالت B57600:
		واپس 57600;
#اگر_ختم /* B57600 */
#اگر_تعریف_شدہ B76800
	حالت B76800:
		واپس 76800;
#اگر_ختم /* B76800 */
#اگر_تعریف_شدہ B115200
	حالت B115200:
		واپس 115200;
#اگر_ختم /* B115200 */
#اگر_تعریف_شدہ B230400
	حالت B230400:
		واپس 230400;
#اگر_ختم /* B230400 */
	طےشدہ:
		واپس 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
ساکن speed_t
baud_مقصد_رفتار(صحیح baud)
{
	انتخاب (baud) {
	حالت 0:
		واپس B0;
	حالت 50:
		واپس B50;
	حالت 75:
		واپس B75;
	حالت 110:
		واپس B110;
	حالت 134:
		واپس B134;
	حالت 150:
		واپس B150;
	حالت 200:
		واپس B200;
	حالت 300:
		واپس B300;
	حالت 600:
		واپس B600;
	حالت 1200:
		واپس B1200;
	حالت 1800:
		واپس B1800;
	حالت 2400:
		واپس B2400;
	حالت 4800:
		واپس B4800;
	حالت 9600:
		واپس B9600;

#اگر_تعریف_شدہ B19200
	حالت 19200:
		واپس B19200;
#ورنہ /* B19200 */
#اگر_تعریف_شدہ EXTA
	حالت 19200:
		واپس EXTA;
#اگر_ختم /* EXTA */
#اگر_ختم /* B19200 */

#اگر_تعریف_شدہ B38400
	حالت 38400:
		واپس B38400;
#ورنہ /* B38400 */
#اگر_تعریف_شدہ EXTB
	حالت 38400:
		واپس EXTB;
#اگر_ختم /* EXTB */
#اگر_ختم /* B38400 */

#اگر_تعریف_شدہ B7200
	حالت 7200:
		واپس B7200;
#اگر_ختم /* B7200 */
#اگر_تعریف_شدہ B14400
	حالت 14400:
		واپس B14400;
#اگر_ختم /* B14400 */
#اگر_تعریف_شدہ B28800
	حالت 28800:
		واپس B28800;
#اگر_ختم /* B28800 */
#اگر_تعریف_شدہ B57600
	حالت 57600:
		واپس B57600;
#اگر_ختم /* B57600 */
#اگر_تعریف_شدہ B76800
	حالت 76800:
		واپس B76800;
#اگر_ختم /* B76800 */
#اگر_تعریف_شدہ B115200
	حالت 115200:
		واپس B115200;
#اگر_ختم /* B115200 */
#اگر_تعریف_شدہ B230400
	حالت 230400:
		واپس B230400;
#اگر_ختم /* B230400 */
	طےشدہ:
		واپس B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
ساکن u_int
special_char_encode(cc_t c)
{
#اگر_تعریف_شدہ _POSIX_VDISABLE
	اگر (c == _POSIX_VDISABLE)
		واپس 255;
#اگر_ختم /* _POSIX_VDISABLE */
	واپس c;
}

/*
 * Decode a special character from SSH line format.
 */
ساکن cc_t
special_char_decode(u_int c)
{
#اگر_تعریف_شدہ _POSIX_VDISABLE
	اگر (c == 255)
		واپس _POSIX_VDISABLE;
#اگر_ختم /* _POSIX_VDISABLE */
	واپس c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
خالی
ssh_tty_make_modes(ساخت ssh *ssh, صحیح fd, ساخت termios *tiop)
{
	ساخت termios tio;
	ساخت sshbuf *buf;
	صحیح r, ibaud, obaud;

	اگر ((buf = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");

	اگر (tiop == تہی) {
		اگر (fd == -1) {
			debug_f("no fd or tio");
			جاؤ انتہا;
		}
		اگر (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			جاؤ انتہا;
		}
	} ورنہ
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = رفتار_مقصد_baud(cfgetospeed(&tio));
	ibaud = رفتار_مقصد_baud(cfgetispeed(&tio));
	اگر ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#تعریف_کرو TTYCHAR(NAME, OP) \
	اگر ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#تعریف_کرو SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#تعریف_کرو TTYMODE(NAME, میدان_2, OP) \
	اگر (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} ورنہ اگر ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.میدان_2 & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#شامل "ttymodes.h"

#تعریف_منسوخ TTYCHAR
#تعریف_منسوخ TTYMODE

انتہا:
	/* Mark end of mode data. */
	اگر ((r = sshbuf_put_u8(buf, TTY_OP_انتہا)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
خالی
ssh_tty_parse_modes(ساخت ssh *ssh, صحیح fd)
{
	ساخت termios tio;
	ساخت sshbuf *buf;
	ثابت u_char *ڈیٹا;
	u_char opcode;
	u_int baud, u;
	صحیح r, failure = 0;
	سائز_t len;

	اگر ((r = sshpkt_get_string_براہ_راست(ssh, &ڈیٹا, &len)) != 0)
		fatal_fr(r, "parse");
	اگر (len == 0)
		واپس;
	اگر ((buf = sshbuf_from(ڈیٹا, len)) == تہی) {
		error_f("sshbuf_from failed");
		واپس;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	اگر (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	جب (sshbuf_len(buf) > 0) {
		اگر ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		انتخاب (opcode) {
		حالت TTY_OP_انتہا:
			جاؤ سیٹ;

		حالت TTY_OP_ISPEED:
			اگر ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			اگر (failure != -1 &&
			    cfsetispeed(&tio, baud_مقصد_رفتار(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			توڑو;

		حالت TTY_OP_OSPEED:
			اگر ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			اگر (failure != -1 &&
			    cfsetospeed(&tio, baud_مقصد_رفتار(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			توڑو;

#تعریف_کرو TTYCHAR(NAME, OP) \
		حالت OP: \
			اگر ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			توڑو;
#تعریف_کرو TTYMODE(NAME, میدان_2, OP) \
		حالت OP: \
			اگر ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			اگر (u) \
				tio.میدان_2 |= NAME; \
			ورنہ \
				tio.میدان_2 &= ~NAME; \
			توڑو;

#شامل "ttymodes.h"

#تعریف_منسوخ TTYCHAR
#تعریف_منسوخ TTYMODE

		طےشدہ:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			اگر (opcode > 0 && opcode < 160) {
				اگر ((r = sshbuf_get_u32(buf, تہی)) != 0)
					fatal_fr(r, "parse arg");
				توڑو;
			} ورنہ {
				logit_f("unknown opcode %d", opcode);
				جاؤ سیٹ;
			}
		}
	}

سیٹ:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	اگر (len > 0) {
		logit_f("%zu bytes left", len);
		واپس;		/* Don't process bytes passed */
	}
	اگر (failure == -1)
		واپس;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	اگر (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
