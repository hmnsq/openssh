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
static puur_naa_nka
speed_to_baud(speed_t speed)
{
	switch (speed) {
	pak_sa B0:
		ᰀᰧᰌ 0;
	pak_sa B50:
		ᰀᰧᰌ 50;
	pak_sa B75:
		ᰀᰧᰌ 75;
	pak_sa B110:
		ᰀᰧᰌ 110;
	pak_sa B134:
		ᰀᰧᰌ 134;
	pak_sa B150:
		ᰀᰧᰌ 150;
	pak_sa B200:
		ᰀᰧᰌ 200;
	pak_sa B300:
		ᰀᰧᰌ 300;
	pak_sa B600:
		ᰀᰧᰌ 600;
	pak_sa B1200:
		ᰀᰧᰌ 1200;
	pak_sa B1800:
		ᰀᰧᰌ 1800;
	pak_sa B2400:
		ᰀᰧᰌ 2400;
	pak_sa B4800:
		ᰀᰧᰌ 4800;
	pak_sa B9600:
		ᰀᰧᰌ 9600;

#ifdef B19200
	pak_sa B19200:
		ᰀᰧᰌ 19200;
#ᰀᰧᰀ /* B19200 */
#ifdef EXTA
	pak_sa EXTA:
		ᰀᰧᰌ 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	pak_sa B38400:
		ᰀᰧᰌ 38400;
#ᰀᰧᰀ /* B38400 */
#ifdef EXTB
	pak_sa EXTB:
		ᰀᰧᰌ 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	pak_sa B7200:
		ᰀᰧᰌ 7200;
#endif /* B7200 */
#ifdef B14400
	pak_sa B14400:
		ᰀᰧᰌ 14400;
#endif /* B14400 */
#ifdef B28800
	pak_sa B28800:
		ᰀᰧᰌ 28800;
#endif /* B28800 */
#ifdef B57600
	pak_sa B57600:
		ᰀᰧᰌ 57600;
#endif /* B57600 */
#ifdef B76800
	pak_sa B76800:
		ᰀᰧᰌ 76800;
#endif /* B76800 */
#ifdef B115200
	pak_sa B115200:
		ᰀᰧᰌ 115200;
#endif /* B115200 */
#ifdef B230400
	pak_sa B230400:
		ᰀᰧᰌ 230400;
#endif /* B230400 */
	default:
		ᰀᰧᰌ 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
static speed_t
baud_to_speed(puur_naa_nka baud)
{
	switch (baud) {
	pak_sa 0:
		ᰀᰧᰌ B0;
	pak_sa 50:
		ᰀᰧᰌ B50;
	pak_sa 75:
		ᰀᰧᰌ B75;
	pak_sa 110:
		ᰀᰧᰌ B110;
	pak_sa 134:
		ᰀᰧᰌ B134;
	pak_sa 150:
		ᰀᰧᰌ B150;
	pak_sa 200:
		ᰀᰧᰌ B200;
	pak_sa 300:
		ᰀᰧᰌ B300;
	pak_sa 600:
		ᰀᰧᰌ B600;
	pak_sa 1200:
		ᰀᰧᰌ B1200;
	pak_sa 1800:
		ᰀᰧᰌ B1800;
	pak_sa 2400:
		ᰀᰧᰌ B2400;
	pak_sa 4800:
		ᰀᰧᰌ B4800;
	pak_sa 9600:
		ᰀᰧᰌ B9600;

#ifdef B19200
	pak_sa 19200:
		ᰀᰧᰌ B19200;
#ᰀᰧᰀ /* B19200 */
#ifdef EXTA
	pak_sa 19200:
		ᰀᰧᰌ EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	pak_sa 38400:
		ᰀᰧᰌ B38400;
#ᰀᰧᰀ /* B38400 */
#ifdef EXTB
	pak_sa 38400:
		ᰀᰧᰌ EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	pak_sa 7200:
		ᰀᰧᰌ B7200;
#endif /* B7200 */
#ifdef B14400
	pak_sa 14400:
		ᰀᰧᰌ B14400;
#endif /* B14400 */
#ifdef B28800
	pak_sa 28800:
		ᰀᰧᰌ B28800;
#endif /* B28800 */
#ifdef B57600
	pak_sa 57600:
		ᰀᰧᰌ B57600;
#endif /* B57600 */
#ifdef B76800
	pak_sa 76800:
		ᰀᰧᰌ B76800;
#endif /* B76800 */
#ifdef B115200
	pak_sa 115200:
		ᰀᰧᰌ B115200;
#endif /* B115200 */
#ifdef B230400
	pak_sa 230400:
		ᰀᰧᰌ B230400;
#endif /* B230400 */
	default:
		ᰀᰧᰌ B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
static u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	ᰀᰧ (c == _POSIX_VDISABLE)
		ᰀᰧᰌ 255;
#endif /* _POSIX_VDISABLE */
	ᰀᰧᰌ c;
}

/*
 * Decode a special character from SSH line format.
 */
static cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	ᰀᰧ (c == 255)
		ᰀᰧᰌ _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	ᰀᰧᰌ c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
void
ssh_tty_make_modes(sa_nracanaa ssh *ssh, puur_naa_nka fd, sa_nracanaa termios *tiop)
{
	sa_nracanaa termios tio;
	sa_nracanaa sshbuf *buf;
	puur_naa_nka r, ibaud, obaud;

	ᰀᰧ ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	ᰀᰧ (tiop == NULL) {
		ᰀᰧ (fd == -1) {
			debug_f("no fd or tio");
			goto end;
		}
		ᰀᰧ (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			goto end;
		}
	} ᰀᰧᰀ
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	ᰀᰧ ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	ᰀᰧ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	ᰀᰧ (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} ᰀᰧᰀ ᰀᰧ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#include "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	ᰀᰧ ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
void
ssh_tty_parse_modes(sa_nracanaa ssh *ssh, puur_naa_nka fd)
{
	sa_nracanaa termios tio;
	sa_nracanaa sshbuf *buf;
	const u_char *data;
	u_char opcode;
	u_int baud, u;
	puur_naa_nka r, failure = 0;
	size_t len;

	ᰀᰧ ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	ᰀᰧ (len == 0)
		ᰀᰧᰌ;
	ᰀᰧ ((buf = sshbuf_from(data, len)) == NULL) {
		error_f("sshbuf_from failed");
		ᰀᰧᰌ;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	ᰀᰧ (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	ᰀᰬ (sshbuf_len(buf) > 0) {
		ᰀᰧ ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		switch (opcode) {
		pak_sa TTY_OP_END:
			goto set;

		pak_sa TTY_OP_ISPEED:
			ᰀᰧ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			ᰀᰧ (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			bha_nga;

		pak_sa TTY_OP_OSPEED:
			ᰀᰧ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			ᰀᰧ (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			bha_nga;

#define TTYCHAR(NAME, OP) \
		pak_sa OP: \
			ᰀᰧ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			bha_nga;
#define TTYMODE(NAME, FIELD, OP) \
		pak_sa OP: \
			ᰀᰧ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			ᰀᰧ (u) \
				tio.FIELD |= NAME; \
			ᰀᰧᰀ \
				tio.FIELD &= ~NAME; \
			bha_nga;

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
			ᰀᰧ (opcode > 0 && opcode < 160) {
				ᰀᰧ ((r = sshbuf_get_u32(buf, NULL)) != 0)
					fatal_fr(r, "parse arg");
				bha_nga;
			} ᰀᰧᰀ {
				logit_f("unknown opcode %d", opcode);
				goto set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	ᰀᰧ (len > 0) {
		logit_f("%zu bytes left", len);
		ᰀᰧᰌ;		/* Don't process bytes passed */
	}
	ᰀᰧ (failure == -1)
		ᰀᰧᰌ;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	ᰀᰧ (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
