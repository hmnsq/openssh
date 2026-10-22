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

#define TTY_OP_END		0
/*
 * uint32 (u_int) follows speed.
 */
#define TTY_OP_ISPEED	128
#define TTY_OP_OSPEED	129

/*
 * Converts POSIX speed_t to a baud rate.  The values of the
 * constants for speed_t are not themselves portable.
 */
स्थिर पूर्णाङ्क
speed_to_baud(speed_t speed)
{
	विकल्प (speed) {
	पक्ष B0:
		फर्काऊ 0;
	पक्ष B50:
		फर्काऊ 50;
	पक्ष B75:
		फर्काऊ 75;
	पक्ष B110:
		फर्काऊ 110;
	पक्ष B134:
		फर्काऊ 134;
	पक्ष B150:
		फर्काऊ 150;
	पक्ष B200:
		फर्काऊ 200;
	पक्ष B300:
		फर्काऊ 300;
	पक्ष B600:
		फर्काऊ 600;
	पक्ष B1200:
		फर्काऊ 1200;
	पक्ष B1800:
		फर्काऊ 1800;
	पक्ष B2400:
		फर्काऊ 2400;
	पक्ष B4800:
		फर्काऊ 4800;
	पक्ष B9600:
		फर्काऊ 9600;

#ifdef B19200
	पक्ष B19200:
		फर्काऊ 19200;
#अन्यथा /* B19200 */
#ifdef EXTA
	पक्ष EXTA:
		फर्काऊ 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	पक्ष B38400:
		फर्काऊ 38400;
#अन्यथा /* B38400 */
#ifdef EXTB
	पक्ष EXTB:
		फर्काऊ 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	पक्ष B7200:
		फर्काऊ 7200;
#endif /* B7200 */
#ifdef B14400
	पक्ष B14400:
		फर्काऊ 14400;
#endif /* B14400 */
#ifdef B28800
	पक्ष B28800:
		फर्काऊ 28800;
#endif /* B28800 */
#ifdef B57600
	पक्ष B57600:
		फर्काऊ 57600;
#endif /* B57600 */
#ifdef B76800
	पक्ष B76800:
		फर्काऊ 76800;
#endif /* B76800 */
#ifdef B115200
	पक्ष B115200:
		फर्काऊ 115200;
#endif /* B115200 */
#ifdef B230400
	पक्ष B230400:
		फर्काऊ 230400;
#endif /* B230400 */
	स्वभाव:
		फर्काऊ 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
स्थिर speed_t
baud_to_speed(पूर्णाङ्क baud)
{
	विकल्प (baud) {
	पक्ष 0:
		फर्काऊ B0;
	पक्ष 50:
		फर्काऊ B50;
	पक्ष 75:
		फर्काऊ B75;
	पक्ष 110:
		फर्काऊ B110;
	पक्ष 134:
		फर्काऊ B134;
	पक्ष 150:
		फर्काऊ B150;
	पक्ष 200:
		फर्काऊ B200;
	पक्ष 300:
		फर्काऊ B300;
	पक्ष 600:
		फर्काऊ B600;
	पक्ष 1200:
		फर्काऊ B1200;
	पक्ष 1800:
		फर्काऊ B1800;
	पक्ष 2400:
		फर्काऊ B2400;
	पक्ष 4800:
		फर्काऊ B4800;
	पक्ष 9600:
		फर्काऊ B9600;

#ifdef B19200
	पक्ष 19200:
		फर्काऊ B19200;
#अन्यथा /* B19200 */
#ifdef EXTA
	पक्ष 19200:
		फर्काऊ EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	पक्ष 38400:
		फर्काऊ B38400;
#अन्यथा /* B38400 */
#ifdef EXTB
	पक्ष 38400:
		फर्काऊ EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	पक्ष 7200:
		फर्काऊ B7200;
#endif /* B7200 */
#ifdef B14400
	पक्ष 14400:
		फर्काऊ B14400;
#endif /* B14400 */
#ifdef B28800
	पक्ष 28800:
		फर्काऊ B28800;
#endif /* B28800 */
#ifdef B57600
	पक्ष 57600:
		फर्काऊ B57600;
#endif /* B57600 */
#ifdef B76800
	पक्ष 76800:
		फर्काऊ B76800;
#endif /* B76800 */
#ifdef B115200
	पक्ष 115200:
		फर्काऊ B115200;
#endif /* B115200 */
#ifdef B230400
	पक्ष 230400:
		फर्काऊ B230400;
#endif /* B230400 */
	स्वभाव:
		फर्काऊ B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
स्थिर u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	यदि (c == _POSIX_VDISABLE)
		फर्काऊ 255;
#endif /* _POSIX_VDISABLE */
	फर्काऊ c;
}

/*
 * Decode a special character from SSH line format.
 */
स्थिर cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	यदि (c == 255)
		फर्काऊ _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	फर्काऊ c;
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
			गच्छ end;
		}
		यदि (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", म_त्रुटि(त्रुटि_सं));
			गच्छ end;
		}
	} अन्यथा
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	यदि ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	यदि ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	यदि (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} अन्यथा यदि ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#अन्तर्भाव "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	यदि ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
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
	अचर u_char *data;
	u_char opcode;
	u_int baud, u;
	पूर्णाङ्क r, failure = 0;
	माप_प्रकार len;

	यदि ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	यदि (len == 0)
		फर्काऊ;
	यदि ((buf = sshbuf_from(data, len)) == रिक्त) {
		error_f("sshbuf_from failed");
		फर्काऊ;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	यदि (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", म_त्रुटि(त्रुटि_सं));
		failure = -1;
	}

	जबसम्म (sshbuf_len(buf) > 0) {
		यदि ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		विकल्प (opcode) {
		पक्ष TTY_OP_END:
			गच्छ set;

		पक्ष TTY_OP_ISPEED:
			यदि ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			यदि (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			रोक;

		पक्ष TTY_OP_OSPEED:
			यदि ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			यदि (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			रोक;

#define TTYCHAR(NAME, OP) \
		पक्ष OP: \
			यदि ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			रोक;
#define TTYMODE(NAME, FIELD, OP) \
		पक्ष OP: \
			यदि ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			यदि (u) \
				tio.FIELD |= NAME; \
			अन्यथा \
				tio.FIELD &= ~NAME; \
			रोक;

#अन्तर्भाव "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

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
				रोक;
			} अन्यथा {
				logit_f("unknown opcode %d", opcode);
				गच्छ set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	यदि (len > 0) {
		logit_f("%zu bytes left", len);
		फर्काऊ;		/* Don't process bytes passed */
	}
	यदि (failure == -1)
		फर्काऊ;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	यदि (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", म_त्रुटि(त्रुटि_सं));
}
