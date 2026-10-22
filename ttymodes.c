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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <termios.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "packet.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "sshbuf.h"

#నిర్వచించు TTY_OP_చివర		0
/*
 * uint32 (u_int) follows speed.
 */
#నిర్వచించు TTY_OP_ISPEED	128
#నిర్వచించు TTY_OP_OSPEED	129

/*
 * Converts POSIX speed_t to a baud rate.  The values of the
 * constants for speed_t are not themselves portable.
 */
స్థిర పూర్ణాంకం
వేగం_గమ్యం_baud(speed_t వేగం)
{
	ఎంపిక (వేగం) {
	స్థితి B0:
		తిరిగి 0;
	స్థితి B50:
		తిరిగి 50;
	స్థితి B75:
		తిరిగి 75;
	స్థితి B110:
		తిరిగి 110;
	స్థితి B134:
		తిరిగి 134;
	స్థితి B150:
		తిరిగి 150;
	స్థితి B200:
		తిరిగి 200;
	స్థితి B300:
		తిరిగి 300;
	స్థితి B600:
		తిరిగి 600;
	స్థితి B1200:
		తిరిగి 1200;
	స్థితి B1800:
		తిరిగి 1800;
	స్థితి B2400:
		తిరిగి 2400;
	స్థితి B4800:
		తిరిగి 4800;
	స్థితి B9600:
		తిరిగి 9600;

#నిర్వచితమైతే B19200
	స్థితి B19200:
		తిరిగి 19200;
#లేకపోతే /* B19200 */
#నిర్వచితమైతే EXTA
	స్థితి EXTA:
		తిరిగి 19200;
#అయితే_ముగింపు /* EXTA */
#అయితే_ముగింపు /* B19200 */

#నిర్వచితమైతే B38400
	స్థితి B38400:
		తిరిగి 38400;
#లేకపోతే /* B38400 */
#నిర్వచితమైతే EXTB
	స్థితి EXTB:
		తిరిగి 38400;
#అయితే_ముగింపు /* EXTB */
#అయితే_ముగింపు /* B38400 */

#నిర్వచితమైతే B7200
	స్థితి B7200:
		తిరిగి 7200;
#అయితే_ముగింపు /* B7200 */
#నిర్వచితమైతే B14400
	స్థితి B14400:
		తిరిగి 14400;
#అయితే_ముగింపు /* B14400 */
#నిర్వచితమైతే B28800
	స్థితి B28800:
		తిరిగి 28800;
#అయితే_ముగింపు /* B28800 */
#నిర్వచితమైతే B57600
	స్థితి B57600:
		తిరిగి 57600;
#అయితే_ముగింపు /* B57600 */
#నిర్వచితమైతే B76800
	స్థితి B76800:
		తిరిగి 76800;
#అయితే_ముగింపు /* B76800 */
#నిర్వచితమైతే B115200
	స్థితి B115200:
		తిరిగి 115200;
#అయితే_ముగింపు /* B115200 */
#నిర్వచితమైతే B230400
	స్థితి B230400:
		తిరిగి 230400;
#అయితే_ముగింపు /* B230400 */
	అప్రమేయ:
		తిరిగి 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
స్థిర speed_t
baud_గమ్యం_వేగం(పూర్ణాంకం baud)
{
	ఎంపిక (baud) {
	స్థితి 0:
		తిరిగి B0;
	స్థితి 50:
		తిరిగి B50;
	స్థితి 75:
		తిరిగి B75;
	స్థితి 110:
		తిరిగి B110;
	స్థితి 134:
		తిరిగి B134;
	స్థితి 150:
		తిరిగి B150;
	స్థితి 200:
		తిరిగి B200;
	స్థితి 300:
		తిరిగి B300;
	స్థితి 600:
		తిరిగి B600;
	స్థితి 1200:
		తిరిగి B1200;
	స్థితి 1800:
		తిరిగి B1800;
	స్థితి 2400:
		తిరిగి B2400;
	స్థితి 4800:
		తిరిగి B4800;
	స్థితి 9600:
		తిరిగి B9600;

#నిర్వచితమైతే B19200
	స్థితి 19200:
		తిరిగి B19200;
#లేకపోతే /* B19200 */
#నిర్వచితమైతే EXTA
	స్థితి 19200:
		తిరిగి EXTA;
#అయితే_ముగింపు /* EXTA */
#అయితే_ముగింపు /* B19200 */

#నిర్వచితమైతే B38400
	స్థితి 38400:
		తిరిగి B38400;
#లేకపోతే /* B38400 */
#నిర్వచితమైతే EXTB
	స్థితి 38400:
		తిరిగి EXTB;
#అయితే_ముగింపు /* EXTB */
#అయితే_ముగింపు /* B38400 */

#నిర్వచితమైతే B7200
	స్థితి 7200:
		తిరిగి B7200;
#అయితే_ముగింపు /* B7200 */
#నిర్వచితమైతే B14400
	స్థితి 14400:
		తిరిగి B14400;
#అయితే_ముగింపు /* B14400 */
#నిర్వచితమైతే B28800
	స్థితి 28800:
		తిరిగి B28800;
#అయితే_ముగింపు /* B28800 */
#నిర్వచితమైతే B57600
	స్థితి 57600:
		తిరిగి B57600;
#అయితే_ముగింపు /* B57600 */
#నిర్వచితమైతే B76800
	స్థితి 76800:
		తిరిగి B76800;
#అయితే_ముగింపు /* B76800 */
#నిర్వచితమైతే B115200
	స్థితి 115200:
		తిరిగి B115200;
#అయితే_ముగింపు /* B115200 */
#నిర్వచితమైతే B230400
	స్థితి 230400:
		తిరిగి B230400;
#అయితే_ముగింపు /* B230400 */
	అప్రమేయ:
		తిరిగి B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
స్థిర u_int
special_char_encode(cc_t c)
{
#నిర్వచితమైతే _POSIX_VDISABLE
	ఒకవేళ (c == _POSIX_VDISABLE)
		తిరిగి 255;
#అయితే_ముగింపు /* _POSIX_VDISABLE */
	తిరిగి c;
}

/*
 * Decode a special character from SSH line format.
 */
స్థిర cc_t
special_char_decode(u_int c)
{
#నిర్వచితమైతే _POSIX_VDISABLE
	ఒకవేళ (c == 255)
		తిరిగి _POSIX_VDISABLE;
#అయితే_ముగింపు /* _POSIX_VDISABLE */
	తిరిగి c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
శూన్య
ssh_tty_make_modes(నిర్మాణం ssh *ssh, పూర్ణాంకం fd, నిర్మాణం termios *tiop)
{
	నిర్మాణం termios tio;
	నిర్మాణం sshbuf *buf;
	పూర్ణాంకం r, ibaud, obaud;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");

	ఒకవేళ (tiop == ఖాళీ) {
		ఒకవేళ (fd == -1) {
			debug_f("no fd or tio");
			వెళ్ళు చివర;
		}
		ఒకవేళ (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			వెళ్ళు చివర;
		}
	} లేకపోతే
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = వేగం_గమ్యం_baud(cfgetospeed(&tio));
	ibaud = వేగం_గమ్యం_baud(cfgetispeed(&tio));
	ఒకవేళ ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#నిర్వచించు TTYCHAR(NAME, OP) \
	ఒకవేళ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#నిర్వచించు SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#నిర్వచించు TTYMODE(NAME, క్షేత్రం_2, OP) \
	ఒకవేళ (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} లేకపోతే ఒకవేళ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.క్షేత్రం_2 & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#అన్తర్భావ "ttymodes.h"

#నిర్వచనం_రద్దు TTYCHAR
#నిర్వచనం_రద్దు TTYMODE

చివర:
	/* Mark end of mode data. */
	ఒకవేళ ((r = sshbuf_put_u8(buf, TTY_OP_చివర)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
శూన్య
ssh_tty_parse_modes(నిర్మాణం ssh *ssh, పూర్ణాంకం fd)
{
	నిర్మాణం termios tio;
	నిర్మాణం sshbuf *buf;
	స్థిరరాశి u_char *దత్తాంశం;
	u_char opcode;
	u_int baud, u;
	పూర్ణాంకం r, failure = 0;
	కొలత_t len;

	ఒకవేళ ((r = sshpkt_get_string_ప్రత్యక్ష(ssh, &దత్తాంశం, &len)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (len == 0)
		తిరిగి;
	ఒకవేళ ((buf = sshbuf_from(దత్తాంశం, len)) == ఖాళీ) {
		error_f("sshbuf_from failed");
		తిరిగి;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	ఒకవేళ (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	అయితే (sshbuf_len(buf) > 0) {
		ఒకవేళ ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		ఎంపిక (opcode) {
		స్థితి TTY_OP_చివర:
			వెళ్ళు సమితి;

		స్థితి TTY_OP_ISPEED:
			ఒకవేళ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			ఒకవేళ (failure != -1 &&
			    cfsetispeed(&tio, baud_గమ్యం_వేగం(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			ఆపు;

		స్థితి TTY_OP_OSPEED:
			ఒకవేళ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			ఒకవేళ (failure != -1 &&
			    cfsetospeed(&tio, baud_గమ్యం_వేగం(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			ఆపు;

#నిర్వచించు TTYCHAR(NAME, OP) \
		స్థితి OP: \
			ఒకవేళ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			ఆపు;
#నిర్వచించు TTYMODE(NAME, క్షేత్రం_2, OP) \
		స్థితి OP: \
			ఒకవేళ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			ఒకవేళ (u) \
				tio.క్షేత్రం_2 |= NAME; \
			లేకపోతే \
				tio.క్షేత్రం_2 &= ~NAME; \
			ఆపు;

#అన్తర్భావ "ttymodes.h"

#నిర్వచనం_రద్దు TTYCHAR
#నిర్వచనం_రద్దు TTYMODE

		అప్రమేయ:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			ఒకవేళ (opcode > 0 && opcode < 160) {
				ఒకవేళ ((r = sshbuf_get_u32(buf, ఖాళీ)) != 0)
					fatal_fr(r, "parse arg");
				ఆపు;
			} లేకపోతే {
				logit_f("unknown opcode %d", opcode);
				వెళ్ళు సమితి;
			}
		}
	}

సమితి:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	ఒకవేళ (len > 0) {
		logit_f("%zu bytes left", len);
		తిరిగి;		/* Don't process bytes passed */
	}
	ఒకవేళ (failure == -1)
		తిరిగి;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	ఒకవేళ (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
