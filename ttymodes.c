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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <termios.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

#ವ್ಯಾಖ್ಯಾನಿಸು TTY_OP_ಕೊನೆ		0
/*
 * uint32 (u_int) follows speed.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು TTY_OP_ISPEED	128
#ವ್ಯಾಖ್ಯಾನಿಸು TTY_OP_OSPEED	129

/*
 * Converts POSIX speed_t to a baud rate.  The values of the
 * constants for speed_t are not themselves portable.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ವೇಗ_ಗಮ್ಯ_baud(speed_t ವೇಗ)
{
	ಆಯ್ಕೆ (ವೇಗ) {
	ಸ್ಥಿತಿ B0:
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ B50:
		ಹಿಂತಿರುಗಿ 50;
	ಸ್ಥಿತಿ B75:
		ಹಿಂತಿರುಗಿ 75;
	ಸ್ಥಿತಿ B110:
		ಹಿಂತಿರುಗಿ 110;
	ಸ್ಥಿತಿ B134:
		ಹಿಂತಿರುಗಿ 134;
	ಸ್ಥಿತಿ B150:
		ಹಿಂತಿರುಗಿ 150;
	ಸ್ಥಿತಿ B200:
		ಹಿಂತಿರುಗಿ 200;
	ಸ್ಥಿತಿ B300:
		ಹಿಂತಿರುಗಿ 300;
	ಸ್ಥಿತಿ B600:
		ಹಿಂತಿರುಗಿ 600;
	ಸ್ಥಿತಿ B1200:
		ಹಿಂತಿರುಗಿ 1200;
	ಸ್ಥಿತಿ B1800:
		ಹಿಂತಿರುಗಿ 1800;
	ಸ್ಥಿತಿ B2400:
		ಹಿಂತಿರುಗಿ 2400;
	ಸ್ಥಿತಿ B4800:
		ಹಿಂತಿರುಗಿ 4800;
	ಸ್ಥಿತಿ B9600:
		ಹಿಂತಿರುಗಿ 9600;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B19200
	ಸ್ಥಿತಿ B19200:
		ಹಿಂತಿರುಗಿ 19200;
#ಇಲ್ಲದಿದ್ದರೆ /* B19200 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ EXTA
	ಸ್ಥಿತಿ EXTA:
		ಹಿಂತಿರುಗಿ 19200;
#ಆದರೆ_ಅಂತ್ಯ /* EXTA */
#ಆದರೆ_ಅಂತ್ಯ /* B19200 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B38400
	ಸ್ಥಿತಿ B38400:
		ಹಿಂತಿರುಗಿ 38400;
#ಇಲ್ಲದಿದ್ದರೆ /* B38400 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ EXTB
	ಸ್ಥಿತಿ EXTB:
		ಹಿಂತಿರುಗಿ 38400;
#ಆದರೆ_ಅಂತ್ಯ /* EXTB */
#ಆದರೆ_ಅಂತ್ಯ /* B38400 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B7200
	ಸ್ಥಿತಿ B7200:
		ಹಿಂತಿರುಗಿ 7200;
#ಆದರೆ_ಅಂತ್ಯ /* B7200 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B14400
	ಸ್ಥಿತಿ B14400:
		ಹಿಂತಿರುಗಿ 14400;
#ಆದರೆ_ಅಂತ್ಯ /* B14400 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B28800
	ಸ್ಥಿತಿ B28800:
		ಹಿಂತಿರುಗಿ 28800;
#ಆದರೆ_ಅಂತ್ಯ /* B28800 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B57600
	ಸ್ಥಿತಿ B57600:
		ಹಿಂತಿರುಗಿ 57600;
#ಆದರೆ_ಅಂತ್ಯ /* B57600 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B76800
	ಸ್ಥಿತಿ B76800:
		ಹಿಂತಿರುಗಿ 76800;
#ಆದರೆ_ಅಂತ್ಯ /* B76800 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B115200
	ಸ್ಥಿತಿ B115200:
		ಹಿಂತಿರುಗಿ 115200;
#ಆದರೆ_ಅಂತ್ಯ /* B115200 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B230400
	ಸ್ಥಿತಿ B230400:
		ಹಿಂತಿರುಗಿ 230400;
#ಆದರೆ_ಅಂತ್ಯ /* B230400 */
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
ಸ್ಥಿರ speed_t
baud_ಗಮ್ಯ_ವೇಗ(ಪೂರ್ಣಾಂಕ baud)
{
	ಆಯ್ಕೆ (baud) {
	ಸ್ಥಿತಿ 0:
		ಹಿಂತಿರುಗಿ B0;
	ಸ್ಥಿತಿ 50:
		ಹಿಂತಿರುಗಿ B50;
	ಸ್ಥಿತಿ 75:
		ಹಿಂತಿರುಗಿ B75;
	ಸ್ಥಿತಿ 110:
		ಹಿಂತಿರುಗಿ B110;
	ಸ್ಥಿತಿ 134:
		ಹಿಂತಿರುಗಿ B134;
	ಸ್ಥಿತಿ 150:
		ಹಿಂತಿರುಗಿ B150;
	ಸ್ಥಿತಿ 200:
		ಹಿಂತಿರುಗಿ B200;
	ಸ್ಥಿತಿ 300:
		ಹಿಂತಿರುಗಿ B300;
	ಸ್ಥಿತಿ 600:
		ಹಿಂತಿರುಗಿ B600;
	ಸ್ಥಿತಿ 1200:
		ಹಿಂತಿರುಗಿ B1200;
	ಸ್ಥಿತಿ 1800:
		ಹಿಂತಿರುಗಿ B1800;
	ಸ್ಥಿತಿ 2400:
		ಹಿಂತಿರುಗಿ B2400;
	ಸ್ಥಿತಿ 4800:
		ಹಿಂತಿರುಗಿ B4800;
	ಸ್ಥಿತಿ 9600:
		ಹಿಂತಿರುಗಿ B9600;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B19200
	ಸ್ಥಿತಿ 19200:
		ಹಿಂತಿರುಗಿ B19200;
#ಇಲ್ಲದಿದ್ದರೆ /* B19200 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ EXTA
	ಸ್ಥಿತಿ 19200:
		ಹಿಂತಿರುಗಿ EXTA;
#ಆದರೆ_ಅಂತ್ಯ /* EXTA */
#ಆದರೆ_ಅಂತ್ಯ /* B19200 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B38400
	ಸ್ಥಿತಿ 38400:
		ಹಿಂತಿರುಗಿ B38400;
#ಇಲ್ಲದಿದ್ದರೆ /* B38400 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ EXTB
	ಸ್ಥಿತಿ 38400:
		ಹಿಂತಿರುಗಿ EXTB;
#ಆದರೆ_ಅಂತ್ಯ /* EXTB */
#ಆದರೆ_ಅಂತ್ಯ /* B38400 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B7200
	ಸ್ಥಿತಿ 7200:
		ಹಿಂತಿರುಗಿ B7200;
#ಆದರೆ_ಅಂತ್ಯ /* B7200 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B14400
	ಸ್ಥಿತಿ 14400:
		ಹಿಂತಿರುಗಿ B14400;
#ಆದರೆ_ಅಂತ್ಯ /* B14400 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B28800
	ಸ್ಥಿತಿ 28800:
		ಹಿಂತಿರುಗಿ B28800;
#ಆದರೆ_ಅಂತ್ಯ /* B28800 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B57600
	ಸ್ಥಿತಿ 57600:
		ಹಿಂತಿರುಗಿ B57600;
#ಆದರೆ_ಅಂತ್ಯ /* B57600 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B76800
	ಸ್ಥಿತಿ 76800:
		ಹಿಂತಿರುಗಿ B76800;
#ಆದರೆ_ಅಂತ್ಯ /* B76800 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B115200
	ಸ್ಥಿತಿ 115200:
		ಹಿಂತಿರುಗಿ B115200;
#ಆದರೆ_ಅಂತ್ಯ /* B115200 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ B230400
	ಸ್ಥಿತಿ 230400:
		ಹಿಂತಿರುಗಿ B230400;
#ಆದರೆ_ಅಂತ್ಯ /* B230400 */
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
ಸ್ಥಿರ u_int
special_char_encode(cc_t c)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _POSIX_VDISABLE
	ಆದರೆ (c == _POSIX_VDISABLE)
		ಹಿಂತಿರುಗಿ 255;
#ಆದರೆ_ಅಂತ್ಯ /* _POSIX_VDISABLE */
	ಹಿಂತಿರುಗಿ c;
}

/*
 * Decode a special character from SSH line format.
 */
ಸ್ಥಿರ cc_t
special_char_decode(u_int c)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _POSIX_VDISABLE
	ಆದರೆ (c == 255)
		ಹಿಂತಿರುಗಿ _POSIX_VDISABLE;
#ಆದರೆ_ಅಂತ್ಯ /* _POSIX_VDISABLE */
	ಹಿಂತಿರುಗಿ c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
ಶೂನ್ಯ
ssh_tty_make_modes(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ fd, ರಚನೆ termios *tiop)
{
	ರಚನೆ termios tio;
	ರಚನೆ sshbuf *buf;
	ಪೂರ್ಣಾಂಕ r, ibaud, obaud;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");

	ಆದರೆ (tiop == ಖಾಲಿ) {
		ಆದರೆ (fd == -1) {
			debug_f("no fd or tio");
			ಹೋಗು ಕೊನೆ;
		}
		ಆದರೆ (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			ಹೋಗು ಕೊನೆ;
		}
	} ಇಲ್ಲದಿದ್ದರೆ
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = ವೇಗ_ಗಮ್ಯ_baud(cfgetospeed(&tio));
	ibaud = ವೇಗ_ಗಮ್ಯ_baud(cfgetispeed(&tio));
	ಆದರೆ ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#ವ್ಯಾಖ್ಯಾನಿಸು TTYCHAR(NAME, OP) \
	ಆದರೆ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#ವ್ಯಾಖ್ಯಾನಿಸು TTYMODE(NAME, ಕ್ಷೇತ್ರ_2, OP) \
	ಆದರೆ (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.ಕ್ಷೇತ್ರ_2 & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#ಅನ್ತರ್ಭಾವ "ttymodes.h"

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TTYCHAR
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TTYMODE

ಕೊನೆ:
	/* Mark end of mode data. */
	ಆದರೆ ((r = sshbuf_put_u8(buf, TTY_OP_ಕೊನೆ)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
ಶೂನ್ಯ
ssh_tty_parse_modes(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ termios tio;
	ರಚನೆ sshbuf *buf;
	ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ;
	u_char opcode;
	u_int baud, u;
	ಪೂರ್ಣಾಂಕ r, failure = 0;
	ಗಾತ್ರ_t len;

	ಆದರೆ ((r = sshpkt_get_string_ನೇರ(ssh, &ದತ್ತಾಂಶ, &len)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((buf = sshbuf_from(ದತ್ತಾಂಶ, len)) == ಖಾಲಿ) {
		error_f("sshbuf_from failed");
		ಹಿಂತಿರುಗಿ;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	ಆದರೆ (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	ಆಗ (sshbuf_len(buf) > 0) {
		ಆದರೆ ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		ಆಯ್ಕೆ (opcode) {
		ಸ್ಥಿತಿ TTY_OP_ಕೊನೆ:
			ಹೋಗು ಗಣ;

		ಸ್ಥಿತಿ TTY_OP_ISPEED:
			ಆದರೆ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			ಆದರೆ (failure != -1 &&
			    cfsetispeed(&tio, baud_ಗಮ್ಯ_ವೇಗ(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ TTY_OP_OSPEED:
			ಆದರೆ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			ಆದರೆ (failure != -1 &&
			    cfsetospeed(&tio, baud_ಗಮ್ಯ_ವೇಗ(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			ನಿಲ್ಲಿಸು;

#ವ್ಯಾಖ್ಯಾನಿಸು TTYCHAR(NAME, OP) \
		ಸ್ಥಿತಿ OP: \
			ಆದರೆ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			ನಿಲ್ಲಿಸು;
#ವ್ಯಾಖ್ಯಾನಿಸು TTYMODE(NAME, ಕ್ಷೇತ್ರ_2, OP) \
		ಸ್ಥಿತಿ OP: \
			ಆದರೆ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			ಆದರೆ (u) \
				tio.ಕ್ಷೇತ್ರ_2 |= NAME; \
			ಇಲ್ಲದಿದ್ದರೆ \
				tio.ಕ್ಷೇತ್ರ_2 &= ~NAME; \
			ನಿಲ್ಲಿಸು;

#ಅನ್ತರ್ಭಾವ "ttymodes.h"

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TTYCHAR
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು TTYMODE

		ಪೂರ್ವನಿಯೋಜಿತ:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			ಆದರೆ (opcode > 0 && opcode < 160) {
				ಆದರೆ ((r = sshbuf_get_u32(buf, ಖಾಲಿ)) != 0)
					fatal_fr(r, "parse arg");
				ನಿಲ್ಲಿಸು;
			} ಇಲ್ಲದಿದ್ದರೆ {
				logit_f("unknown opcode %d", opcode);
				ಹೋಗು ಗಣ;
			}
		}
	}

ಗಣ:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	ಆದರೆ (len > 0) {
		logit_f("%zu bytes left", len);
		ಹಿಂತಿರುಗಿ;		/* Don't process bytes passed */
	}
	ಆದರೆ (failure == -1)
		ಹಿಂತಿರುಗಿ;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	ಆದರೆ (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
