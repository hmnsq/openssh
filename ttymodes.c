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
		ပွၵ်ႈ 0;
	pak_sa B50:
		ပွၵ်ႈ 50;
	pak_sa B75:
		ပွၵ်ႈ 75;
	pak_sa B110:
		ပွၵ်ႈ 110;
	pak_sa B134:
		ပွၵ်ႈ 134;
	pak_sa B150:
		ပွၵ်ႈ 150;
	pak_sa B200:
		ပွၵ်ႈ 200;
	pak_sa B300:
		ပွၵ်ႈ 300;
	pak_sa B600:
		ပွၵ်ႈ 600;
	pak_sa B1200:
		ပွၵ်ႈ 1200;
	pak_sa B1800:
		ပွၵ်ႈ 1800;
	pak_sa B2400:
		ပွၵ်ႈ 2400;
	pak_sa B4800:
		ပွၵ်ႈ 4800;
	pak_sa B9600:
		ပွၵ်ႈ 9600;

#ifdef B19200
	pak_sa B19200:
		ပွၵ်ႈ 19200;
#ပေႃးဢမ်ႇ /* B19200 */
#ifdef EXTA
	pak_sa EXTA:
		ပွၵ်ႈ 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	pak_sa B38400:
		ပွၵ်ႈ 38400;
#ပေႃးဢမ်ႇ /* B38400 */
#ifdef EXTB
	pak_sa EXTB:
		ပွၵ်ႈ 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	pak_sa B7200:
		ပွၵ်ႈ 7200;
#endif /* B7200 */
#ifdef B14400
	pak_sa B14400:
		ပွၵ်ႈ 14400;
#endif /* B14400 */
#ifdef B28800
	pak_sa B28800:
		ပွၵ်ႈ 28800;
#endif /* B28800 */
#ifdef B57600
	pak_sa B57600:
		ပွၵ်ႈ 57600;
#endif /* B57600 */
#ifdef B76800
	pak_sa B76800:
		ပွၵ်ႈ 76800;
#endif /* B76800 */
#ifdef B115200
	pak_sa B115200:
		ပွၵ်ႈ 115200;
#endif /* B115200 */
#ifdef B230400
	pak_sa B230400:
		ပွၵ်ႈ 230400;
#endif /* B230400 */
	default:
		ပွၵ်ႈ 9600;
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
		ပွၵ်ႈ B0;
	pak_sa 50:
		ပွၵ်ႈ B50;
	pak_sa 75:
		ပွၵ်ႈ B75;
	pak_sa 110:
		ပွၵ်ႈ B110;
	pak_sa 134:
		ပွၵ်ႈ B134;
	pak_sa 150:
		ပွၵ်ႈ B150;
	pak_sa 200:
		ပွၵ်ႈ B200;
	pak_sa 300:
		ပွၵ်ႈ B300;
	pak_sa 600:
		ပွၵ်ႈ B600;
	pak_sa 1200:
		ပွၵ်ႈ B1200;
	pak_sa 1800:
		ပွၵ်ႈ B1800;
	pak_sa 2400:
		ပွၵ်ႈ B2400;
	pak_sa 4800:
		ပွၵ်ႈ B4800;
	pak_sa 9600:
		ပွၵ်ႈ B9600;

#ifdef B19200
	pak_sa 19200:
		ပွၵ်ႈ B19200;
#ပေႃးဢမ်ႇ /* B19200 */
#ifdef EXTA
	pak_sa 19200:
		ပွၵ်ႈ EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	pak_sa 38400:
		ပွၵ်ႈ B38400;
#ပေႃးဢမ်ႇ /* B38400 */
#ifdef EXTB
	pak_sa 38400:
		ပွၵ်ႈ EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	pak_sa 7200:
		ပွၵ်ႈ B7200;
#endif /* B7200 */
#ifdef B14400
	pak_sa 14400:
		ပွၵ်ႈ B14400;
#endif /* B14400 */
#ifdef B28800
	pak_sa 28800:
		ပွၵ်ႈ B28800;
#endif /* B28800 */
#ifdef B57600
	pak_sa 57600:
		ပွၵ်ႈ B57600;
#endif /* B57600 */
#ifdef B76800
	pak_sa 76800:
		ပွၵ်ႈ B76800;
#endif /* B76800 */
#ifdef B115200
	pak_sa 115200:
		ပွၵ်ႈ B115200;
#endif /* B115200 */
#ifdef B230400
	pak_sa 230400:
		ပွၵ်ႈ B230400;
#endif /* B230400 */
	default:
		ပွၵ်ႈ B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
static u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	ပေႃး (c == _POSIX_VDISABLE)
		ပွၵ်ႈ 255;
#endif /* _POSIX_VDISABLE */
	ပွၵ်ႈ c;
}

/*
 * Decode a special character from SSH line format.
 */
static cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	ပေႃး (c == 255)
		ပွၵ်ႈ _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	ပွၵ်ႈ c;
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

	ပေႃး ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	ပေႃး (tiop == NULL) {
		ပေႃး (fd == -1) {
			debug_f("no fd or tio");
			goto end;
		}
		ပေႃး (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			goto end;
		}
	} ပေႃးဢမ်ႇ
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	ပေႃး ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	ပေႃး ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	ပေႃး (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} ပေႃးဢမ်ႇ ပေႃး ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#include "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	ပေႃး ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
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

	ပေႃး ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	ပေႃး (len == 0)
		ပွၵ်ႈ;
	ပေႃး ((buf = sshbuf_from(data, len)) == NULL) {
		error_f("sshbuf_from failed");
		ပွၵ်ႈ;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	ပေႃး (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	ၶၢဝ်း (sshbuf_len(buf) > 0) {
		ပေႃး ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		switch (opcode) {
		pak_sa TTY_OP_END:
			goto set;

		pak_sa TTY_OP_ISPEED:
			ပေႃး ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			ပေႃး (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			bha_nga;

		pak_sa TTY_OP_OSPEED:
			ပေႃး ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			ပေႃး (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			bha_nga;

#define TTYCHAR(NAME, OP) \
		pak_sa OP: \
			ပေႃး ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			bha_nga;
#define TTYMODE(NAME, FIELD, OP) \
		pak_sa OP: \
			ပေႃး ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			ပေႃး (u) \
				tio.FIELD |= NAME; \
			ပေႃးဢမ်ႇ \
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
			ပေႃး (opcode > 0 && opcode < 160) {
				ပေႃး ((r = sshbuf_get_u32(buf, NULL)) != 0)
					fatal_fr(r, "parse arg");
				bha_nga;
			} ပေႃးဢမ်ႇ {
				logit_f("unknown opcode %d", opcode);
				goto set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	ပေႃး (len > 0) {
		logit_f("%zu bytes left", len);
		ပွၵ်ႈ;		/* Don't process bytes passed */
	}
	ပေႃး (failure == -1)
		ပွၵ်ႈ;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	ပေႃး (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
