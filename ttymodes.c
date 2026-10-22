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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
speed_to_baud(speed_t speed)
{
	ವಿಕಲ್ಪ (speed) {
	ಪಕ್ಷ B0:
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ B50:
		ಪ್ರತ್ಯಾಗಮ 50;
	ಪಕ್ಷ B75:
		ಪ್ರತ್ಯಾಗಮ 75;
	ಪಕ್ಷ B110:
		ಪ್ರತ್ಯಾಗಮ 110;
	ಪಕ್ಷ B134:
		ಪ್ರತ್ಯಾಗಮ 134;
	ಪಕ್ಷ B150:
		ಪ್ರತ್ಯಾಗಮ 150;
	ಪಕ್ಷ B200:
		ಪ್ರತ್ಯಾಗಮ 200;
	ಪಕ್ಷ B300:
		ಪ್ರತ್ಯಾಗಮ 300;
	ಪಕ್ಷ B600:
		ಪ್ರತ್ಯಾಗಮ 600;
	ಪಕ್ಷ B1200:
		ಪ್ರತ್ಯಾಗಮ 1200;
	ಪಕ್ಷ B1800:
		ಪ್ರತ್ಯಾಗಮ 1800;
	ಪಕ್ಷ B2400:
		ಪ್ರತ್ಯಾಗಮ 2400;
	ಪಕ್ಷ B4800:
		ಪ್ರತ್ಯಾಗಮ 4800;
	ಪಕ್ಷ B9600:
		ಪ್ರತ್ಯಾಗಮ 9600;

#ifdef B19200
	ಪಕ್ಷ B19200:
		ಪ್ರತ್ಯಾಗಮ 19200;
#ಅನ್ಯಥಾ /* B19200 */
#ifdef EXTA
	ಪಕ್ಷ EXTA:
		ಪ್ರತ್ಯಾಗಮ 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	ಪಕ್ಷ B38400:
		ಪ್ರತ್ಯಾಗಮ 38400;
#ಅನ್ಯಥಾ /* B38400 */
#ifdef EXTB
	ಪಕ್ಷ EXTB:
		ಪ್ರತ್ಯಾಗಮ 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	ಪಕ್ಷ B7200:
		ಪ್ರತ್ಯಾಗಮ 7200;
#endif /* B7200 */
#ifdef B14400
	ಪಕ್ಷ B14400:
		ಪ್ರತ್ಯಾಗಮ 14400;
#endif /* B14400 */
#ifdef B28800
	ಪಕ್ಷ B28800:
		ಪ್ರತ್ಯಾಗಮ 28800;
#endif /* B28800 */
#ifdef B57600
	ಪಕ್ಷ B57600:
		ಪ್ರತ್ಯಾಗಮ 57600;
#endif /* B57600 */
#ifdef B76800
	ಪಕ್ಷ B76800:
		ಪ್ರತ್ಯಾಗಮ 76800;
#endif /* B76800 */
#ifdef B115200
	ಪಕ್ಷ B115200:
		ಪ್ರತ್ಯಾಗಮ 115200;
#endif /* B115200 */
#ifdef B230400
	ಪಕ್ಷ B230400:
		ಪ್ರತ್ಯಾಗಮ 230400;
#endif /* B230400 */
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
ಸ್ಥಿರ speed_t
baud_to_speed(ಪೂರ್ಣಾಙ್ಕ baud)
{
	ವಿಕಲ್ಪ (baud) {
	ಪಕ್ಷ 0:
		ಪ್ರತ್ಯಾಗಮ B0;
	ಪಕ್ಷ 50:
		ಪ್ರತ್ಯಾಗಮ B50;
	ಪಕ್ಷ 75:
		ಪ್ರತ್ಯಾಗಮ B75;
	ಪಕ್ಷ 110:
		ಪ್ರತ್ಯಾಗಮ B110;
	ಪಕ್ಷ 134:
		ಪ್ರತ್ಯಾಗಮ B134;
	ಪಕ್ಷ 150:
		ಪ್ರತ್ಯಾಗಮ B150;
	ಪಕ್ಷ 200:
		ಪ್ರತ್ಯಾಗಮ B200;
	ಪಕ್ಷ 300:
		ಪ್ರತ್ಯಾಗಮ B300;
	ಪಕ್ಷ 600:
		ಪ್ರತ್ಯಾಗಮ B600;
	ಪಕ್ಷ 1200:
		ಪ್ರತ್ಯಾಗಮ B1200;
	ಪಕ್ಷ 1800:
		ಪ್ರತ್ಯಾಗಮ B1800;
	ಪಕ್ಷ 2400:
		ಪ್ರತ್ಯಾಗಮ B2400;
	ಪಕ್ಷ 4800:
		ಪ್ರತ್ಯಾಗಮ B4800;
	ಪಕ್ಷ 9600:
		ಪ್ರತ್ಯಾಗಮ B9600;

#ifdef B19200
	ಪಕ್ಷ 19200:
		ಪ್ರತ್ಯಾಗಮ B19200;
#ಅನ್ಯಥಾ /* B19200 */
#ifdef EXTA
	ಪಕ್ಷ 19200:
		ಪ್ರತ್ಯಾಗಮ EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	ಪಕ್ಷ 38400:
		ಪ್ರತ್ಯಾಗಮ B38400;
#ಅನ್ಯಥಾ /* B38400 */
#ifdef EXTB
	ಪಕ್ಷ 38400:
		ಪ್ರತ್ಯಾಗಮ EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	ಪಕ್ಷ 7200:
		ಪ್ರತ್ಯಾಗಮ B7200;
#endif /* B7200 */
#ifdef B14400
	ಪಕ್ಷ 14400:
		ಪ್ರತ್ಯಾಗಮ B14400;
#endif /* B14400 */
#ifdef B28800
	ಪಕ್ಷ 28800:
		ಪ್ರತ್ಯಾಗಮ B28800;
#endif /* B28800 */
#ifdef B57600
	ಪಕ್ಷ 57600:
		ಪ್ರತ್ಯಾಗಮ B57600;
#endif /* B57600 */
#ifdef B76800
	ಪಕ್ಷ 76800:
		ಪ್ರತ್ಯಾಗಮ B76800;
#endif /* B76800 */
#ifdef B115200
	ಪಕ್ಷ 115200:
		ಪ್ರತ್ಯಾಗಮ B115200;
#endif /* B115200 */
#ifdef B230400
	ಪಕ್ಷ 230400:
		ಪ್ರತ್ಯಾಗಮ B230400;
#endif /* B230400 */
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
ಸ್ಥಿರ u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	ಯದಿ (c == _POSIX_VDISABLE)
		ಪ್ರತ್ಯಾಗಮ 255;
#endif /* _POSIX_VDISABLE */
	ಪ್ರತ್ಯಾಗಮ c;
}

/*
 * Decode a special character from SSH line format.
 */
ಸ್ಥಿರ cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	ಯದಿ (c == 255)
		ಪ್ರತ್ಯಾಗಮ _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	ಪ್ರತ್ಯಾಗಮ c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
ಶೂನ್ಯ
ssh_tty_make_modes(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ termios *tiop)
{
	ಸಂರಚನಾ termios tio;
	ಸಂರಚನಾ sshbuf *buf;
	ಪೂರ್ಣಾಙ್ಕ r, ibaud, obaud;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");

	ಯದಿ (tiop == ರಿಕ್ತ) {
		ಯದಿ (fd == -1) {
			debug_f("no fd or tio");
			ಗಚ್ಛ end;
		}
		ಯದಿ (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			ಗಚ್ಛ end;
		}
	} ಅನ್ಯಥಾ
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	ಯದಿ ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	ಯದಿ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	ಯದಿ (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#ಅನ್ತರ್ಭಾವ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	ಯದಿ ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
ಶೂನ್ಯ
ssh_tty_parse_modes(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಸಂರಚನಾ termios tio;
	ಸಂರಚನಾ sshbuf *buf;
	ಧ್ರುವ u_char *data;
	u_char opcode;
	u_int baud, u;
	ಪೂರ್ಣಾಙ್ಕ r, failure = 0;
	size_t len;

	ಯದಿ ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((buf = sshbuf_from(data, len)) == ರಿಕ್ತ) {
		error_f("sshbuf_from failed");
		ಪ್ರತ್ಯಾಗಮ;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	ಯದಿ (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	ಯಾವತ್ (sshbuf_len(buf) > 0) {
		ಯದಿ ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		ವಿಕಲ್ಪ (opcode) {
		ಪಕ್ಷ TTY_OP_END:
			ಗಚ್ಛ set;

		ಪಕ್ಷ TTY_OP_ISPEED:
			ಯದಿ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			ಯದಿ (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			ಭಙ್ಗ;

		ಪಕ್ಷ TTY_OP_OSPEED:
			ಯದಿ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			ಯದಿ (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			ಭಙ್ಗ;

#define TTYCHAR(NAME, OP) \
		ಪಕ್ಷ OP: \
			ಯದಿ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			ಭಙ್ಗ;
#define TTYMODE(NAME, FIELD, OP) \
		ಪಕ್ಷ OP: \
			ಯದಿ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			ಯದಿ (u) \
				tio.FIELD |= NAME; \
			ಅನ್ಯಥಾ \
				tio.FIELD &= ~NAME; \
			ಭಙ್ಗ;

#ಅನ್ತರ್ಭಾವ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		ಸ್ವಭಾವ:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			ಯದಿ (opcode > 0 && opcode < 160) {
				ಯದಿ ((r = sshbuf_get_u32(buf, ರಿಕ್ತ)) != 0)
					fatal_fr(r, "parse arg");
				ಭಙ್ಗ;
			} ಅನ್ಯಥಾ {
				logit_f("unknown opcode %d", opcode);
				ಗಚ್ಛ set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	ಯದಿ (len > 0) {
		logit_f("%zu bytes left", len);
		ಪ್ರತ್ಯಾಗಮ;		/* Don't process bytes passed */
	}
	ಯದಿ (failure == -1)
		ಪ್ರತ್ಯಾಗಮ;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	ಯದಿ (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
