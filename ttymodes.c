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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <termios.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "packet.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "sshbuf.h"

#परिभाषय TTY_OP_अन्तः		0
/*
 * uint32 (u_int) follows speed.
 */
#परिभाषय TTY_OP_ISPEED	128
#परिभाषय TTY_OP_OSPEED	129

/*
 * Converts POSIX speed_t to a baud rate.  The values of the
 * constants for speed_t are not themselves portable.
 */
स्थिर पूर्णाङ्क
जवः_गन्तव्यम्_baud(speed_t जवः)
{
	विकल्प (जवः) {
	पक्ष B0:
		प्रत्यागम 0;
	पक्ष B50:
		प्रत्यागम 50;
	पक्ष B75:
		प्रत्यागम 75;
	पक्ष B110:
		प्रत्यागम 110;
	पक्ष B134:
		प्रत्यागम 134;
	पक्ष B150:
		प्रत्यागम 150;
	पक्ष B200:
		प्रत्यागम 200;
	पक्ष B300:
		प्रत्यागम 300;
	पक्ष B600:
		प्रत्यागम 600;
	पक्ष B1200:
		प्रत्यागम 1200;
	पक्ष B1800:
		प्रत्यागम 1800;
	पक्ष B2400:
		प्रत्यागम 2400;
	पक्ष B4800:
		प्रत्यागम 4800;
	पक्ष B9600:
		प्रत्यागम 9600;

#यदि_परिभाषितम् B19200
	पक्ष B19200:
		प्रत्यागम 19200;
#अन्यथा /* B19200 */
#यदि_परिभाषितम् EXTA
	पक्ष EXTA:
		प्रत्यागम 19200;
#यदि_अन्तः /* EXTA */
#यदि_अन्तः /* B19200 */

#यदि_परिभाषितम् B38400
	पक्ष B38400:
		प्रत्यागम 38400;
#अन्यथा /* B38400 */
#यदि_परिभाषितम् EXTB
	पक्ष EXTB:
		प्रत्यागम 38400;
#यदि_अन्तः /* EXTB */
#यदि_अन्तः /* B38400 */

#यदि_परिभाषितम् B7200
	पक्ष B7200:
		प्रत्यागम 7200;
#यदि_अन्तः /* B7200 */
#यदि_परिभाषितम् B14400
	पक्ष B14400:
		प्रत्यागम 14400;
#यदि_अन्तः /* B14400 */
#यदि_परिभाषितम् B28800
	पक्ष B28800:
		प्रत्यागम 28800;
#यदि_अन्तः /* B28800 */
#यदि_परिभाषितम् B57600
	पक्ष B57600:
		प्रत्यागम 57600;
#यदि_अन्तः /* B57600 */
#यदि_परिभाषितम् B76800
	पक्ष B76800:
		प्रत्यागम 76800;
#यदि_अन्तः /* B76800 */
#यदि_परिभाषितम् B115200
	पक्ष B115200:
		प्रत्यागम 115200;
#यदि_अन्तः /* B115200 */
#यदि_परिभाषितम् B230400
	पक्ष B230400:
		प्रत्यागम 230400;
#यदि_अन्तः /* B230400 */
	स्वभाव:
		प्रत्यागम 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
स्थिर speed_t
baud_गन्तव्यम्_जवः(पूर्णाङ्क baud)
{
	विकल्प (baud) {
	पक्ष 0:
		प्रत्यागम B0;
	पक्ष 50:
		प्रत्यागम B50;
	पक्ष 75:
		प्रत्यागम B75;
	पक्ष 110:
		प्रत्यागम B110;
	पक्ष 134:
		प्रत्यागम B134;
	पक्ष 150:
		प्रत्यागम B150;
	पक्ष 200:
		प्रत्यागम B200;
	पक्ष 300:
		प्रत्यागम B300;
	पक्ष 600:
		प्रत्यागम B600;
	पक्ष 1200:
		प्रत्यागम B1200;
	पक्ष 1800:
		प्रत्यागम B1800;
	पक्ष 2400:
		प्रत्यागम B2400;
	पक्ष 4800:
		प्रत्यागम B4800;
	पक्ष 9600:
		प्रत्यागम B9600;

#यदि_परिभाषितम् B19200
	पक्ष 19200:
		प्रत्यागम B19200;
#अन्यथा /* B19200 */
#यदि_परिभाषितम् EXTA
	पक्ष 19200:
		प्रत्यागम EXTA;
#यदि_अन्तः /* EXTA */
#यदि_अन्तः /* B19200 */

#यदि_परिभाषितम् B38400
	पक्ष 38400:
		प्रत्यागम B38400;
#अन्यथा /* B38400 */
#यदि_परिभाषितम् EXTB
	पक्ष 38400:
		प्रत्यागम EXTB;
#यदि_अन्तः /* EXTB */
#यदि_अन्तः /* B38400 */

#यदि_परिभाषितम् B7200
	पक्ष 7200:
		प्रत्यागम B7200;
#यदि_अन्तः /* B7200 */
#यदि_परिभाषितम् B14400
	पक्ष 14400:
		प्रत्यागम B14400;
#यदि_अन्तः /* B14400 */
#यदि_परिभाषितम् B28800
	पक्ष 28800:
		प्रत्यागम B28800;
#यदि_अन्तः /* B28800 */
#यदि_परिभाषितम् B57600
	पक्ष 57600:
		प्रत्यागम B57600;
#यदि_अन्तः /* B57600 */
#यदि_परिभाषितम् B76800
	पक्ष 76800:
		प्रत्यागम B76800;
#यदि_अन्तः /* B76800 */
#यदि_परिभाषितम् B115200
	पक्ष 115200:
		प्रत्यागम B115200;
#यदि_अन्तः /* B115200 */
#यदि_परिभाषितम् B230400
	पक्ष 230400:
		प्रत्यागम B230400;
#यदि_अन्तः /* B230400 */
	स्वभाव:
		प्रत्यागम B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
स्थिर u_int
special_char_encode(cc_t c)
{
#यदि_परिभाषितम् _POSIX_VDISABLE
	यदि (c == _POSIX_VDISABLE)
		प्रत्यागम 255;
#यदि_अन्तः /* _POSIX_VDISABLE */
	प्रत्यागम c;
}

/*
 * Decode a special character from SSH line format.
 */
स्थिर cc_t
special_char_decode(u_int c)
{
#यदि_परिभाषितम् _POSIX_VDISABLE
	यदि (c == 255)
		प्रत्यागम _POSIX_VDISABLE;
#यदि_अन्तः /* _POSIX_VDISABLE */
	प्रत्यागम c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
शून्य
ssh_tty_make_modes(संरचना ssh *ssh, पूर्णाङ्क fd, संरचना termios *tiop)
{
	संरचना termios tio;
	संरचना sshbuf *buf;
	पूर्णाङ्क r, ibaud, obaud;

	यदि ((buf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	यदि (tiop == रिक्त) {
		यदि (fd == -1) {
			debug_f("no fd or tio");
			गच्छ अन्तः;
		}
		यदि (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			गच्छ अन्तः;
		}
	} अन्यथा
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = जवः_गन्तव्यम्_baud(cfgetospeed(&tio));
	ibaud = जवः_गन्तव्यम्_baud(cfgetispeed(&tio));
	यदि ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#परिभाषय TTYCHAR(NAME, OP) \
	यदि ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#परिभाषय SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#परिभाषय TTYMODE(NAME, क्षेत्रम्_2, OP) \
	यदि (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} अन्यथा यदि ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.क्षेत्रम्_2 & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#अन्तर्भाव "ttymodes.h"

#अपरिभाषय TTYCHAR
#अपरिभाषय TTYMODE

अन्तः:
	/* Mark end of mode data. */
	यदि ((r = sshbuf_put_u8(buf, TTY_OP_अन्तः)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
शून्य
ssh_tty_parse_modes(संरचना ssh *ssh, पूर्णाङ्क fd)
{
	संरचना termios tio;
	संरचना sshbuf *buf;
	ध्रुव u_char *दत्त;
	u_char opcode;
	u_int baud, u;
	पूर्णाङ्क r, failure = 0;
	आकार_t len;

	यदि ((r = sshpkt_get_string_प्रत्यक्षम्(ssh, &दत्त, &len)) != 0)
		fatal_fr(r, "parse");
	यदि (len == 0)
		प्रत्यागम;
	यदि ((buf = sshbuf_from(दत्त, len)) == रिक्त) {
		error_f("sshbuf_from failed");
		प्रत्यागम;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	यदि (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	यावत् (sshbuf_len(buf) > 0) {
		यदि ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		विकल्प (opcode) {
		पक्ष TTY_OP_अन्तः:
			गच्छ समुच्चयः;

		पक्ष TTY_OP_ISPEED:
			यदि ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			यदि (failure != -1 &&
			    cfsetispeed(&tio, baud_गन्तव्यम्_जवः(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			भङ्ग;

		पक्ष TTY_OP_OSPEED:
			यदि ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			यदि (failure != -1 &&
			    cfsetospeed(&tio, baud_गन्तव्यम्_जवः(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			भङ्ग;

#परिभाषय TTYCHAR(NAME, OP) \
		पक्ष OP: \
			यदि ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			भङ्ग;
#परिभाषय TTYMODE(NAME, क्षेत्रम्_2, OP) \
		पक्ष OP: \
			यदि ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			यदि (u) \
				tio.क्षेत्रम्_2 |= NAME; \
			अन्यथा \
				tio.क्षेत्रम्_2 &= ~NAME; \
			भङ्ग;

#अन्तर्भाव "ttymodes.h"

#अपरिभाषय TTYCHAR
#अपरिभाषय TTYMODE

		स्वभाव:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			यदि (opcode > 0 && opcode < 160) {
				यदि ((r = sshbuf_get_u32(buf, रिक्त)) != 0)
					fatal_fr(r, "parse arg");
				भङ्ग;
			} अन्यथा {
				logit_f("unknown opcode %d", opcode);
				गच्छ समुच्चयः;
			}
		}
	}

समुच्चयः:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	यदि (len > 0) {
		logit_f("%zu bytes left", len);
		प्रत्यागम;		/* Don't process bytes passed */
	}
	यदि (failure == -1)
		प्रत्यागम;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	यदि (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
