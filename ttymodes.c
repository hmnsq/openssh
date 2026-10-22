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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <termios.h>
#অন্তর্ভাৱ <stdarg.h>

#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "compat.h"
#অন্তর্ভাৱ "sshbuf.h"

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
স্থির পূর্ণাঙ্ক
speed_to_baud(speed_t speed)
{
	ৱিকল্প (speed) {
	পক্ষ B0:
		ঘূৰাই 0;
	পক্ষ B50:
		ঘূৰাই 50;
	পক্ষ B75:
		ঘূৰাই 75;
	পক্ষ B110:
		ঘূৰাই 110;
	পক্ষ B134:
		ঘূৰাই 134;
	পক্ষ B150:
		ঘূৰাই 150;
	পক্ষ B200:
		ঘূৰাই 200;
	পক্ষ B300:
		ঘূৰাই 300;
	পক্ষ B600:
		ঘূৰাই 600;
	পক্ষ B1200:
		ঘূৰাই 1200;
	পক্ষ B1800:
		ঘূৰাই 1800;
	পক্ষ B2400:
		ঘূৰাই 2400;
	পক্ষ B4800:
		ঘূৰাই 4800;
	পক্ষ B9600:
		ঘূৰাই 9600;

#ifdef B19200
	পক্ষ B19200:
		ঘূৰাই 19200;
#অন্যথা /* B19200 */
#ifdef EXTA
	পক্ষ EXTA:
		ঘূৰাই 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	পক্ষ B38400:
		ঘূৰাই 38400;
#অন্যথা /* B38400 */
#ifdef EXTB
	পক্ষ EXTB:
		ঘূৰাই 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	পক্ষ B7200:
		ঘূৰাই 7200;
#endif /* B7200 */
#ifdef B14400
	পক্ষ B14400:
		ঘূৰাই 14400;
#endif /* B14400 */
#ifdef B28800
	পক্ষ B28800:
		ঘূৰাই 28800;
#endif /* B28800 */
#ifdef B57600
	পক্ষ B57600:
		ঘূৰাই 57600;
#endif /* B57600 */
#ifdef B76800
	পক্ষ B76800:
		ঘূৰাই 76800;
#endif /* B76800 */
#ifdef B115200
	পক্ষ B115200:
		ঘূৰাই 115200;
#endif /* B115200 */
#ifdef B230400
	পক্ষ B230400:
		ঘূৰাই 230400;
#endif /* B230400 */
	স্ৱভাৱ:
		ঘূৰাই 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
স্থির speed_t
baud_to_speed(পূর্ণাঙ্ক baud)
{
	ৱিকল্প (baud) {
	পক্ষ 0:
		ঘূৰাই B0;
	পক্ষ 50:
		ঘূৰাই B50;
	পক্ষ 75:
		ঘূৰাই B75;
	পক্ষ 110:
		ঘূৰাই B110;
	পক্ষ 134:
		ঘূৰাই B134;
	পক্ষ 150:
		ঘূৰাই B150;
	পক্ষ 200:
		ঘূৰাই B200;
	পক্ষ 300:
		ঘূৰাই B300;
	পক্ষ 600:
		ঘূৰাই B600;
	পক্ষ 1200:
		ঘূৰাই B1200;
	পক্ষ 1800:
		ঘূৰাই B1800;
	পক্ষ 2400:
		ঘূৰাই B2400;
	পক্ষ 4800:
		ঘূৰাই B4800;
	পক্ষ 9600:
		ঘূৰাই B9600;

#ifdef B19200
	পক্ষ 19200:
		ঘূৰাই B19200;
#অন্যথা /* B19200 */
#ifdef EXTA
	পক্ষ 19200:
		ঘূৰাই EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	পক্ষ 38400:
		ঘূৰাই B38400;
#অন্যথা /* B38400 */
#ifdef EXTB
	পক্ষ 38400:
		ঘূৰাই EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	পক্ষ 7200:
		ঘূৰাই B7200;
#endif /* B7200 */
#ifdef B14400
	পক্ষ 14400:
		ঘূৰাই B14400;
#endif /* B14400 */
#ifdef B28800
	পক্ষ 28800:
		ঘূৰাই B28800;
#endif /* B28800 */
#ifdef B57600
	পক্ষ 57600:
		ঘূৰাই B57600;
#endif /* B57600 */
#ifdef B76800
	পক্ষ 76800:
		ঘূৰাই B76800;
#endif /* B76800 */
#ifdef B115200
	পক্ষ 115200:
		ঘূৰাই B115200;
#endif /* B115200 */
#ifdef B230400
	পক্ষ 230400:
		ঘূৰাই B230400;
#endif /* B230400 */
	স্ৱভাৱ:
		ঘূৰাই B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
স্থির u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	যদি (c == _POSIX_VDISABLE)
		ঘূৰাই 255;
#endif /* _POSIX_VDISABLE */
	ঘূৰাই c;
}

/*
 * Decode a special character from SSH line format.
 */
স্থির cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	যদি (c == 255)
		ঘূৰাই _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	ঘূৰাই c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
শূন্য
ssh_tty_make_modes(সংরচনা ssh *ssh, পূর্ণাঙ্ক fd, সংরচনা termios *tiop)
{
	সংরচনা termios tio;
	সংরচনা sshbuf *buf;
	পূর্ণাঙ্ক r, ibaud, obaud;

	যদি ((buf = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");

	যদি (tiop == রিক্ত) {
		যদি (fd == -1) {
			debug_f("no fd or tio");
			গচ্ছ end;
		}
		যদি (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			গচ্ছ end;
		}
	} অন্যথা
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	যদি ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	যদি ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	যদি (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} অন্যথা যদি ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#অন্তর্ভাৱ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	যদি ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
শূন্য
ssh_tty_parse_modes(সংরচনা ssh *ssh, পূর্ণাঙ্ক fd)
{
	সংরচনা termios tio;
	সংরচনা sshbuf *buf;
	ধ্রুৱ u_char *data;
	u_char opcode;
	u_int baud, u;
	পূর্ণাঙ্ক r, failure = 0;
	size_t len;

	যদি ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	যদি (len == 0)
		ঘূৰাই;
	যদি ((buf = sshbuf_from(data, len)) == রিক্ত) {
		error_f("sshbuf_from failed");
		ঘূৰাই;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	যদি (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	যেতিয়ালৈ (sshbuf_len(buf) > 0) {
		যদি ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		ৱিকল্প (opcode) {
		পক্ষ TTY_OP_END:
			গচ্ছ set;

		পক্ষ TTY_OP_ISPEED:
			যদি ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			যদি (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			ভঙ্গ;

		পক্ষ TTY_OP_OSPEED:
			যদি ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			যদি (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			ভঙ্গ;

#define TTYCHAR(NAME, OP) \
		পক্ষ OP: \
			যদি ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			ভঙ্গ;
#define TTYMODE(NAME, FIELD, OP) \
		পক্ষ OP: \
			যদি ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			যদি (u) \
				tio.FIELD |= NAME; \
			অন্যথা \
				tio.FIELD &= ~NAME; \
			ভঙ্গ;

#অন্তর্ভাৱ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		স্ৱভাৱ:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			যদি (opcode > 0 && opcode < 160) {
				যদি ((r = sshbuf_get_u32(buf, রিক্ত)) != 0)
					fatal_fr(r, "parse arg");
				ভঙ্গ;
			} অন্যথা {
				logit_f("unknown opcode %d", opcode);
				গচ্ছ set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	যদি (len > 0) {
		logit_f("%zu bytes left", len);
		ঘূৰাই;		/* Don't process bytes passed */
	}
	যদি (failure == -1)
		ঘূৰাই;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	যদি (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
