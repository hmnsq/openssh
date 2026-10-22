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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <errno.h>
#ضمن <string.h>
#ضمن <termios.h>
#ضمن <stdarg.h>

#ضمن "packet.h"
#ضمن "log.h"
#ضمن "compat.h"
#ضمن "sshbuf.h"

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
ساكن صحيح
speed_to_baud(speed_t speed)
{
	بدل (speed) {
	حالة B0:
		إرجاع 0;
	حالة B50:
		إرجاع 50;
	حالة B75:
		إرجاع 75;
	حالة B110:
		إرجاع 110;
	حالة B134:
		إرجاع 134;
	حالة B150:
		إرجاع 150;
	حالة B200:
		إرجاع 200;
	حالة B300:
		إرجاع 300;
	حالة B600:
		إرجاع 600;
	حالة B1200:
		إرجاع 1200;
	حالة B1800:
		إرجاع 1800;
	حالة B2400:
		إرجاع 2400;
	حالة B4800:
		إرجاع 4800;
	حالة B9600:
		إرجاع 9600;

#ifdef B19200
	حالة B19200:
		إرجاع 19200;
#وإلا /* B19200 */
#ifdef EXTA
	حالة EXTA:
		إرجاع 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	حالة B38400:
		إرجاع 38400;
#وإلا /* B38400 */
#ifdef EXTB
	حالة EXTB:
		إرجاع 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	حالة B7200:
		إرجاع 7200;
#endif /* B7200 */
#ifdef B14400
	حالة B14400:
		إرجاع 14400;
#endif /* B14400 */
#ifdef B28800
	حالة B28800:
		إرجاع 28800;
#endif /* B28800 */
#ifdef B57600
	حالة B57600:
		إرجاع 57600;
#endif /* B57600 */
#ifdef B76800
	حالة B76800:
		إرجاع 76800;
#endif /* B76800 */
#ifdef B115200
	حالة B115200:
		إرجاع 115200;
#endif /* B115200 */
#ifdef B230400
	حالة B230400:
		إرجاع 230400;
#endif /* B230400 */
	افتراضي:
		إرجاع 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
ساكن speed_t
baud_to_speed(صحيح baud)
{
	بدل (baud) {
	حالة 0:
		إرجاع B0;
	حالة 50:
		إرجاع B50;
	حالة 75:
		إرجاع B75;
	حالة 110:
		إرجاع B110;
	حالة 134:
		إرجاع B134;
	حالة 150:
		إرجاع B150;
	حالة 200:
		إرجاع B200;
	حالة 300:
		إرجاع B300;
	حالة 600:
		إرجاع B600;
	حالة 1200:
		إرجاع B1200;
	حالة 1800:
		إرجاع B1800;
	حالة 2400:
		إرجاع B2400;
	حالة 4800:
		إرجاع B4800;
	حالة 9600:
		إرجاع B9600;

#ifdef B19200
	حالة 19200:
		إرجاع B19200;
#وإلا /* B19200 */
#ifdef EXTA
	حالة 19200:
		إرجاع EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	حالة 38400:
		إرجاع B38400;
#وإلا /* B38400 */
#ifdef EXTB
	حالة 38400:
		إرجاع EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	حالة 7200:
		إرجاع B7200;
#endif /* B7200 */
#ifdef B14400
	حالة 14400:
		إرجاع B14400;
#endif /* B14400 */
#ifdef B28800
	حالة 28800:
		إرجاع B28800;
#endif /* B28800 */
#ifdef B57600
	حالة 57600:
		إرجاع B57600;
#endif /* B57600 */
#ifdef B76800
	حالة 76800:
		إرجاع B76800;
#endif /* B76800 */
#ifdef B115200
	حالة 115200:
		إرجاع B115200;
#endif /* B115200 */
#ifdef B230400
	حالة 230400:
		إرجاع B230400;
#endif /* B230400 */
	افتراضي:
		إرجاع B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
ساكن u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	إذا (c == _POSIX_VDISABLE)
		إرجاع 255;
#endif /* _POSIX_VDISABLE */
	إرجاع c;
}

/*
 * Decode a special character from SSH line format.
 */
ساكن cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	إذا (c == 255)
		إرجاع _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	إرجاع c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
فراغ
ssh_tty_make_modes(بنية ssh *ssh, صحيح fd, بنية termios *tiop)
{
	بنية termios tio;
	بنية sshbuf *buf;
	صحيح r, ibaud, obaud;

	إذا ((buf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	إذا (tiop == عدم) {
		إذا (fd == -1) {
			debug_f("no fd or tio");
			اذهب end;
		}
		إذا (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			اذهب end;
		}
	} وإلا
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	إذا ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	إذا ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	إذا (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} وإلا إذا ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#ضمن "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	إذا ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
فراغ
ssh_tty_parse_modes(بنية ssh *ssh, صحيح fd)
{
	بنية termios tio;
	بنية sshbuf *buf;
	ثابت u_char *data;
	u_char opcode;
	u_int baud, u;
	صحيح r, failure = 0;
	size_t len;

	إذا ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	إذا (len == 0)
		إرجاع;
	إذا ((buf = sshbuf_from(data, len)) == عدم) {
		error_f("sshbuf_from failed");
		إرجاع;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	إذا (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	بينما (sshbuf_len(buf) > 0) {
		إذا ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		بدل (opcode) {
		حالة TTY_OP_END:
			اذهب set;

		حالة TTY_OP_ISPEED:
			إذا ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			إذا (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			اكسر;

		حالة TTY_OP_OSPEED:
			إذا ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			إذا (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			اكسر;

#define TTYCHAR(NAME, OP) \
		حالة OP: \
			إذا ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			اكسر;
#define TTYMODE(NAME, FIELD, OP) \
		حالة OP: \
			إذا ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			إذا (u) \
				tio.FIELD |= NAME; \
			وإلا \
				tio.FIELD &= ~NAME; \
			اكسر;

#ضمن "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		افتراضي:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			إذا (opcode > 0 && opcode < 160) {
				إذا ((r = sshbuf_get_u32(buf, عدم)) != 0)
					fatal_fr(r, "parse arg");
				اكسر;
			} وإلا {
				logit_f("unknown opcode %d", opcode);
				اذهب set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	إذا (len > 0) {
		logit_f("%zu bytes left", len);
		إرجاع;		/* Don't process bytes passed */
	}
	إذا (failure == -1)
		إرجاع;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	إذا (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
