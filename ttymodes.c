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

#include "includes.h"

#include <sys/types.h>

#include <errno.h>
#include <string.h>
#include <termios.h>
#include <stdarg.h>

#include "packet.h"
#include "log.h"
#include "compat.h"
#include "sshbuf.h"

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
static số_nguyên
speed_to_baud(speed_t speed)
{
	switch (speed) {
	case B0:
		trả_về 0;
	case B50:
		trả_về 50;
	case B75:
		trả_về 75;
	case B110:
		trả_về 110;
	case B134:
		trả_về 134;
	case B150:
		trả_về 150;
	case B200:
		trả_về 200;
	case B300:
		trả_về 300;
	case B600:
		trả_về 600;
	case B1200:
		trả_về 1200;
	case B1800:
		trả_về 1800;
	case B2400:
		trả_về 2400;
	case B4800:
		trả_về 4800;
	case B9600:
		trả_về 9600;

#ifdef B19200
	case B19200:
		trả_về 19200;
#không_thì /* B19200 */
#ifdef EXTA
	case EXTA:
		trả_về 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	case B38400:
		trả_về 38400;
#không_thì /* B38400 */
#ifdef EXTB
	case EXTB:
		trả_về 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	case B7200:
		trả_về 7200;
#endif /* B7200 */
#ifdef B14400
	case B14400:
		trả_về 14400;
#endif /* B14400 */
#ifdef B28800
	case B28800:
		trả_về 28800;
#endif /* B28800 */
#ifdef B57600
	case B57600:
		trả_về 57600;
#endif /* B57600 */
#ifdef B76800
	case B76800:
		trả_về 76800;
#endif /* B76800 */
#ifdef B115200
	case B115200:
		trả_về 115200;
#endif /* B115200 */
#ifdef B230400
	case B230400:
		trả_về 230400;
#endif /* B230400 */
	default:
		trả_về 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
static speed_t
baud_to_speed(số_nguyên baud)
{
	switch (baud) {
	case 0:
		trả_về B0;
	case 50:
		trả_về B50;
	case 75:
		trả_về B75;
	case 110:
		trả_về B110;
	case 134:
		trả_về B134;
	case 150:
		trả_về B150;
	case 200:
		trả_về B200;
	case 300:
		trả_về B300;
	case 600:
		trả_về B600;
	case 1200:
		trả_về B1200;
	case 1800:
		trả_về B1800;
	case 2400:
		trả_về B2400;
	case 4800:
		trả_về B4800;
	case 9600:
		trả_về B9600;

#ifdef B19200
	case 19200:
		trả_về B19200;
#không_thì /* B19200 */
#ifdef EXTA
	case 19200:
		trả_về EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	case 38400:
		trả_về B38400;
#không_thì /* B38400 */
#ifdef EXTB
	case 38400:
		trả_về EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	case 7200:
		trả_về B7200;
#endif /* B7200 */
#ifdef B14400
	case 14400:
		trả_về B14400;
#endif /* B14400 */
#ifdef B28800
	case 28800:
		trả_về B28800;
#endif /* B28800 */
#ifdef B57600
	case 57600:
		trả_về B57600;
#endif /* B57600 */
#ifdef B76800
	case 76800:
		trả_về B76800;
#endif /* B76800 */
#ifdef B115200
	case 115200:
		trả_về B115200;
#endif /* B115200 */
#ifdef B230400
	case 230400:
		trả_về B230400;
#endif /* B230400 */
	default:
		trả_về B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
static u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	nếu (c == _POSIX_VDISABLE)
		trả_về 255;
#endif /* _POSIX_VDISABLE */
	trả_về c;
}

/*
 * Decode a special character from SSH line format.
 */
static cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	nếu (c == 255)
		trả_về _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	trả_về c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
void
ssh_tty_make_modes(struct ssh *ssh, số_nguyên fd, struct termios *tiop)
{
	struct termios tio;
	struct sshbuf *buf;
	số_nguyên r, ibaud, obaud;

	nếu ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	nếu (tiop == NULL) {
		nếu (fd == -1) {
			debug_f("no fd or tio");
			goto end;
		}
		nếu (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			goto end;
		}
	} không_thì
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	nếu ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	nếu ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	nếu (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} không_thì nếu ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#include "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	nếu ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
void
ssh_tty_parse_modes(struct ssh *ssh, số_nguyên fd)
{
	struct termios tio;
	struct sshbuf *buf;
	const u_char *data;
	u_char opcode;
	u_int baud, u;
	số_nguyên r, failure = 0;
	size_t len;

	nếu ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	nếu (len == 0)
		trả_về;
	nếu ((buf = sshbuf_from(data, len)) == NULL) {
		error_f("sshbuf_from failed");
		trả_về;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	nếu (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	trong_khi (sshbuf_len(buf) > 0) {
		nếu ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		switch (opcode) {
		case TTY_OP_END:
			goto set;

		case TTY_OP_ISPEED:
			nếu ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			nếu (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			break;

		case TTY_OP_OSPEED:
			nếu ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			nếu (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			break;

#define TTYCHAR(NAME, OP) \
		case OP: \
			nếu ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			break;
#define TTYMODE(NAME, FIELD, OP) \
		case OP: \
			nếu ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			nếu (u) \
				tio.FIELD |= NAME; \
			không_thì \
				tio.FIELD &= ~NAME; \
			break;

#include "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		default:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			nếu (opcode > 0 && opcode < 160) {
				nếu ((r = sshbuf_get_u32(buf, NULL)) != 0)
					fatal_fr(r, "parse arg");
				break;
			} không_thì {
				logit_f("unknown opcode %d", opcode);
				goto set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	nếu (len > 0) {
		logit_f("%zu bytes left", len);
		trả_về;		/* Don't process bytes passed */
	}
	nếu (failure == -1)
		trả_về;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	nếu (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
