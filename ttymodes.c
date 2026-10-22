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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <termios.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TTY_OP_ਸਿਰਾ		0
/*
 * uint32 (u_int) follows speed.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TTY_OP_ISPEED	128
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TTY_OP_OSPEED	129

/*
 * Converts POSIX speed_t to a baud rate.  The values of the
 * constants for speed_t are not themselves portable.
 */
ਸਥਿਰ ਪੂਰਨ
ਰਫਤਾਰ_ਮੰਜ਼ਿਲ_baud(speed_t ਰਫਤਾਰ)
{
	ਚੋਣ (ਰਫਤਾਰ) {
	ਹਾਲਤ B0:
		ਵਾਪਸ 0;
	ਹਾਲਤ B50:
		ਵਾਪਸ 50;
	ਹਾਲਤ B75:
		ਵਾਪਸ 75;
	ਹਾਲਤ B110:
		ਵਾਪਸ 110;
	ਹਾਲਤ B134:
		ਵਾਪਸ 134;
	ਹਾਲਤ B150:
		ਵਾਪਸ 150;
	ਹਾਲਤ B200:
		ਵਾਪਸ 200;
	ਹਾਲਤ B300:
		ਵਾਪਸ 300;
	ਹਾਲਤ B600:
		ਵਾਪਸ 600;
	ਹਾਲਤ B1200:
		ਵਾਪਸ 1200;
	ਹਾਲਤ B1800:
		ਵਾਪਸ 1800;
	ਹਾਲਤ B2400:
		ਵਾਪਸ 2400;
	ਹਾਲਤ B4800:
		ਵਾਪਸ 4800;
	ਹਾਲਤ B9600:
		ਵਾਪਸ 9600;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B19200
	ਹਾਲਤ B19200:
		ਵਾਪਸ 19200;
#ਨਹੀਂਤਾਂ /* B19200 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ EXTA
	ਹਾਲਤ EXTA:
		ਵਾਪਸ 19200;
#ਜੇ_ਅੰਤ /* EXTA */
#ਜੇ_ਅੰਤ /* B19200 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B38400
	ਹਾਲਤ B38400:
		ਵਾਪਸ 38400;
#ਨਹੀਂਤਾਂ /* B38400 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ EXTB
	ਹਾਲਤ EXTB:
		ਵਾਪਸ 38400;
#ਜੇ_ਅੰਤ /* EXTB */
#ਜੇ_ਅੰਤ /* B38400 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B7200
	ਹਾਲਤ B7200:
		ਵਾਪਸ 7200;
#ਜੇ_ਅੰਤ /* B7200 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B14400
	ਹਾਲਤ B14400:
		ਵਾਪਸ 14400;
#ਜੇ_ਅੰਤ /* B14400 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B28800
	ਹਾਲਤ B28800:
		ਵਾਪਸ 28800;
#ਜੇ_ਅੰਤ /* B28800 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B57600
	ਹਾਲਤ B57600:
		ਵਾਪਸ 57600;
#ਜੇ_ਅੰਤ /* B57600 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B76800
	ਹਾਲਤ B76800:
		ਵਾਪਸ 76800;
#ਜੇ_ਅੰਤ /* B76800 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B115200
	ਹਾਲਤ B115200:
		ਵਾਪਸ 115200;
#ਜੇ_ਅੰਤ /* B115200 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B230400
	ਹਾਲਤ B230400:
		ਵਾਪਸ 230400;
#ਜੇ_ਅੰਤ /* B230400 */
	ਮੂਲ:
		ਵਾਪਸ 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
ਸਥਿਰ speed_t
baud_ਮੰਜ਼ਿਲ_ਰਫਤਾਰ(ਪੂਰਨ baud)
{
	ਚੋਣ (baud) {
	ਹਾਲਤ 0:
		ਵਾਪਸ B0;
	ਹਾਲਤ 50:
		ਵਾਪਸ B50;
	ਹਾਲਤ 75:
		ਵਾਪਸ B75;
	ਹਾਲਤ 110:
		ਵਾਪਸ B110;
	ਹਾਲਤ 134:
		ਵਾਪਸ B134;
	ਹਾਲਤ 150:
		ਵਾਪਸ B150;
	ਹਾਲਤ 200:
		ਵਾਪਸ B200;
	ਹਾਲਤ 300:
		ਵਾਪਸ B300;
	ਹਾਲਤ 600:
		ਵਾਪਸ B600;
	ਹਾਲਤ 1200:
		ਵਾਪਸ B1200;
	ਹਾਲਤ 1800:
		ਵਾਪਸ B1800;
	ਹਾਲਤ 2400:
		ਵਾਪਸ B2400;
	ਹਾਲਤ 4800:
		ਵਾਪਸ B4800;
	ਹਾਲਤ 9600:
		ਵਾਪਸ B9600;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B19200
	ਹਾਲਤ 19200:
		ਵਾਪਸ B19200;
#ਨਹੀਂਤਾਂ /* B19200 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ EXTA
	ਹਾਲਤ 19200:
		ਵਾਪਸ EXTA;
#ਜੇ_ਅੰਤ /* EXTA */
#ਜੇ_ਅੰਤ /* B19200 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B38400
	ਹਾਲਤ 38400:
		ਵਾਪਸ B38400;
#ਨਹੀਂਤਾਂ /* B38400 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ EXTB
	ਹਾਲਤ 38400:
		ਵਾਪਸ EXTB;
#ਜੇ_ਅੰਤ /* EXTB */
#ਜੇ_ਅੰਤ /* B38400 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B7200
	ਹਾਲਤ 7200:
		ਵਾਪਸ B7200;
#ਜੇ_ਅੰਤ /* B7200 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B14400
	ਹਾਲਤ 14400:
		ਵਾਪਸ B14400;
#ਜੇ_ਅੰਤ /* B14400 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B28800
	ਹਾਲਤ 28800:
		ਵਾਪਸ B28800;
#ਜੇ_ਅੰਤ /* B28800 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B57600
	ਹਾਲਤ 57600:
		ਵਾਪਸ B57600;
#ਜੇ_ਅੰਤ /* B57600 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B76800
	ਹਾਲਤ 76800:
		ਵਾਪਸ B76800;
#ਜੇ_ਅੰਤ /* B76800 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B115200
	ਹਾਲਤ 115200:
		ਵਾਪਸ B115200;
#ਜੇ_ਅੰਤ /* B115200 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ B230400
	ਹਾਲਤ 230400:
		ਵਾਪਸ B230400;
#ਜੇ_ਅੰਤ /* B230400 */
	ਮੂਲ:
		ਵਾਪਸ B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
ਸਥਿਰ u_int
special_char_encode(cc_t c)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _POSIX_VDISABLE
	ਜੇ (c == _POSIX_VDISABLE)
		ਵਾਪਸ 255;
#ਜੇ_ਅੰਤ /* _POSIX_VDISABLE */
	ਵਾਪਸ c;
}

/*
 * Decode a special character from SSH line format.
 */
ਸਥਿਰ cc_t
special_char_decode(u_int c)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _POSIX_VDISABLE
	ਜੇ (c == 255)
		ਵਾਪਸ _POSIX_VDISABLE;
#ਜੇ_ਅੰਤ /* _POSIX_VDISABLE */
	ਵਾਪਸ c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
ਖਾਲੀ
ssh_tty_make_modes(ਬਣਤਰ ssh *ssh, ਪੂਰਨ fd, ਬਣਤਰ termios *tiop)
{
	ਬਣਤਰ termios tio;
	ਬਣਤਰ sshbuf *buf;
	ਪੂਰਨ r, ibaud, obaud;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");

	ਜੇ (tiop == ਨਿਰਾ) {
		ਜੇ (fd == -1) {
			debug_f("no fd or tio");
			ਜਾਓ ਸਿਰਾ;
		}
		ਜੇ (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			ਜਾਓ ਸਿਰਾ;
		}
	} ਨਹੀਂਤਾਂ
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = ਰਫਤਾਰ_ਮੰਜ਼ਿਲ_baud(cfgetospeed(&tio));
	ibaud = ਰਫਤਾਰ_ਮੰਜ਼ਿਲ_baud(cfgetispeed(&tio));
	ਜੇ ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TTYCHAR(NAME, OP) \
	ਜੇ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TTYMODE(NAME, ਖੇਤਰ_2, OP) \
	ਜੇ (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.ਖੇਤਰ_2 & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#ਅਨ੍ਤਰ੍ਭਾਵ "ttymodes.h"

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TTYCHAR
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TTYMODE

ਸਿਰਾ:
	/* Mark end of mode data. */
	ਜੇ ((r = sshbuf_put_u8(buf, TTY_OP_ਸਿਰਾ)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
ਖਾਲੀ
ssh_tty_parse_modes(ਬਣਤਰ ssh *ssh, ਪੂਰਨ fd)
{
	ਬਣਤਰ termios tio;
	ਬਣਤਰ sshbuf *buf;
	ਅਚਲ u_char *ਅੰਕੜੇ;
	u_char opcode;
	u_int baud, u;
	ਪੂਰਨ r, failure = 0;
	ਮਾਪ_t len;

	ਜੇ ((r = sshpkt_get_string_ਸਿੱਧਾ(ssh, &ਅੰਕੜੇ, &len)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (len == 0)
		ਵਾਪਸ;
	ਜੇ ((buf = sshbuf_from(ਅੰਕੜੇ, len)) == ਨਿਰਾ) {
		error_f("sshbuf_from failed");
		ਵਾਪਸ;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	ਜੇ (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	ਜਦੋਂ (sshbuf_len(buf) > 0) {
		ਜੇ ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		ਚੋਣ (opcode) {
		ਹਾਲਤ TTY_OP_ਸਿਰਾ:
			ਜਾਓ ਸੈੱਟ;

		ਹਾਲਤ TTY_OP_ISPEED:
			ਜੇ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			ਜੇ (failure != -1 &&
			    cfsetispeed(&tio, baud_ਮੰਜ਼ਿਲ_ਰਫਤਾਰ(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			ਰੋਕੋ;

		ਹਾਲਤ TTY_OP_OSPEED:
			ਜੇ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			ਜੇ (failure != -1 &&
			    cfsetospeed(&tio, baud_ਮੰਜ਼ਿਲ_ਰਫਤਾਰ(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			ਰੋਕੋ;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TTYCHAR(NAME, OP) \
		ਹਾਲਤ OP: \
			ਜੇ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			ਰੋਕੋ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TTYMODE(NAME, ਖੇਤਰ_2, OP) \
		ਹਾਲਤ OP: \
			ਜੇ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			ਜੇ (u) \
				tio.ਖੇਤਰ_2 |= NAME; \
			ਨਹੀਂਤਾਂ \
				tio.ਖੇਤਰ_2 &= ~NAME; \
			ਰੋਕੋ;

#ਅਨ੍ਤਰ੍ਭਾਵ "ttymodes.h"

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TTYCHAR
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ TTYMODE

		ਮੂਲ:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			ਜੇ (opcode > 0 && opcode < 160) {
				ਜੇ ((r = sshbuf_get_u32(buf, ਨਿਰਾ)) != 0)
					fatal_fr(r, "parse arg");
				ਰੋਕੋ;
			} ਨਹੀਂਤਾਂ {
				logit_f("unknown opcode %d", opcode);
				ਜਾਓ ਸੈੱਟ;
			}
		}
	}

ਸੈੱਟ:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	ਜੇ (len > 0) {
		logit_f("%zu bytes left", len);
		ਵਾਪਸ;		/* Don't process bytes passed */
	}
	ਜੇ (failure == -1)
		ਵਾਪਸ;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	ਜੇ (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
