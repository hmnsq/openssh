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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <termios.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "sshbuf.h"

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
സ്ഥിതം പൂർണ്ണസംഖ്യ
speed_to_baud(speed_t speed)
{
	തിരഞ്ഞെടുപ്പ് (speed) {
	അവസ്ഥ B0:
		തിരികെ 0;
	അവസ്ഥ B50:
		തിരികെ 50;
	അവസ്ഥ B75:
		തിരികെ 75;
	അവസ്ഥ B110:
		തിരികെ 110;
	അവസ്ഥ B134:
		തിരികെ 134;
	അവസ്ഥ B150:
		തിരികെ 150;
	അവസ്ഥ B200:
		തിരികെ 200;
	അവസ്ഥ B300:
		തിരികെ 300;
	അവസ്ഥ B600:
		തിരികെ 600;
	അവസ്ഥ B1200:
		തിരികെ 1200;
	അവസ്ഥ B1800:
		തിരികെ 1800;
	അവസ്ഥ B2400:
		തിരികെ 2400;
	അവസ്ഥ B4800:
		തിരികെ 4800;
	അവസ്ഥ B9600:
		തിരികെ 9600;

#ifdef B19200
	അവസ്ഥ B19200:
		തിരികെ 19200;
#അല്ലെങ്കിൽ /* B19200 */
#ifdef EXTA
	അവസ്ഥ EXTA:
		തിരികെ 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	അവസ്ഥ B38400:
		തിരികെ 38400;
#അല്ലെങ്കിൽ /* B38400 */
#ifdef EXTB
	അവസ്ഥ EXTB:
		തിരികെ 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	അവസ്ഥ B7200:
		തിരികെ 7200;
#endif /* B7200 */
#ifdef B14400
	അവസ്ഥ B14400:
		തിരികെ 14400;
#endif /* B14400 */
#ifdef B28800
	അവസ്ഥ B28800:
		തിരികെ 28800;
#endif /* B28800 */
#ifdef B57600
	അവസ്ഥ B57600:
		തിരികെ 57600;
#endif /* B57600 */
#ifdef B76800
	അവസ്ഥ B76800:
		തിരികെ 76800;
#endif /* B76800 */
#ifdef B115200
	അവസ്ഥ B115200:
		തിരികെ 115200;
#endif /* B115200 */
#ifdef B230400
	അവസ്ഥ B230400:
		തിരികെ 230400;
#endif /* B230400 */
	സ്ഥിരസ്ഥിതി:
		തിരികെ 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
സ്ഥിതം speed_t
baud_to_speed(പൂർണ്ണസംഖ്യ baud)
{
	തിരഞ്ഞെടുപ്പ് (baud) {
	അവസ്ഥ 0:
		തിരികെ B0;
	അവസ്ഥ 50:
		തിരികെ B50;
	അവസ്ഥ 75:
		തിരികെ B75;
	അവസ്ഥ 110:
		തിരികെ B110;
	അവസ്ഥ 134:
		തിരികെ B134;
	അവസ്ഥ 150:
		തിരികെ B150;
	അവസ്ഥ 200:
		തിരികെ B200;
	അവസ്ഥ 300:
		തിരികെ B300;
	അവസ്ഥ 600:
		തിരികെ B600;
	അവസ്ഥ 1200:
		തിരികെ B1200;
	അവസ്ഥ 1800:
		തിരികെ B1800;
	അവസ്ഥ 2400:
		തിരികെ B2400;
	അവസ്ഥ 4800:
		തിരികെ B4800;
	അവസ്ഥ 9600:
		തിരികെ B9600;

#ifdef B19200
	അവസ്ഥ 19200:
		തിരികെ B19200;
#അല്ലെങ്കിൽ /* B19200 */
#ifdef EXTA
	അവസ്ഥ 19200:
		തിരികെ EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	അവസ്ഥ 38400:
		തിരികെ B38400;
#അല്ലെങ്കിൽ /* B38400 */
#ifdef EXTB
	അവസ്ഥ 38400:
		തിരികെ EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	അവസ്ഥ 7200:
		തിരികെ B7200;
#endif /* B7200 */
#ifdef B14400
	അവസ്ഥ 14400:
		തിരികെ B14400;
#endif /* B14400 */
#ifdef B28800
	അവസ്ഥ 28800:
		തിരികെ B28800;
#endif /* B28800 */
#ifdef B57600
	അവസ്ഥ 57600:
		തിരികെ B57600;
#endif /* B57600 */
#ifdef B76800
	അവസ്ഥ 76800:
		തിരികെ B76800;
#endif /* B76800 */
#ifdef B115200
	അവസ്ഥ 115200:
		തിരികെ B115200;
#endif /* B115200 */
#ifdef B230400
	അവസ്ഥ 230400:
		തിരികെ B230400;
#endif /* B230400 */
	സ്ഥിരസ്ഥിതി:
		തിരികെ B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
സ്ഥിതം u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	എങ്കിൽ (c == _POSIX_VDISABLE)
		തിരികെ 255;
#endif /* _POSIX_VDISABLE */
	തിരികെ c;
}

/*
 * Decode a special character from SSH line format.
 */
സ്ഥിതം cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	എങ്കിൽ (c == 255)
		തിരികെ _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	തിരികെ c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
ശൂന്യം
ssh_tty_make_modes(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ fd, ഘടന termios *tiop)
{
	ഘടന termios tio;
	ഘടന sshbuf *buf;
	പൂർണ്ണസംഖ്യ r, ibaud, obaud;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");

	എങ്കിൽ (tiop == ശൂന്യ) {
		എങ്കിൽ (fd == -1) {
			debug_f("no fd or tio");
			പോകുക end;
		}
		എങ്കിൽ (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			പോകുക end;
		}
	} അല്ലെങ്കിൽ
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	എങ്കിൽ ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	എങ്കിൽ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	എങ്കിൽ (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#അന്തര്ഭാവ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	എങ്കിൽ ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
ശൂന്യം
ssh_tty_parse_modes(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ fd)
{
	ഘടന termios tio;
	ഘടന sshbuf *buf;
	സ്ഥിരം u_char *data;
	u_char opcode;
	u_int baud, u;
	പൂർണ്ണസംഖ്യ r, failure = 0;
	size_t len;

	എങ്കിൽ ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (len == 0)
		തിരികെ;
	എങ്കിൽ ((buf = sshbuf_from(data, len)) == ശൂന്യ) {
		error_f("sshbuf_from failed");
		തിരികെ;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	എങ്കിൽ (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	ആകുമ്പോൾ (sshbuf_len(buf) > 0) {
		എങ്കിൽ ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		തിരഞ്ഞെടുപ്പ് (opcode) {
		അവസ്ഥ TTY_OP_END:
			പോകുക set;

		അവസ്ഥ TTY_OP_ISPEED:
			എങ്കിൽ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			എങ്കിൽ (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			നിർത്തുക;

		അവസ്ഥ TTY_OP_OSPEED:
			എങ്കിൽ ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			എങ്കിൽ (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			നിർത്തുക;

#define TTYCHAR(NAME, OP) \
		അവസ്ഥ OP: \
			എങ്കിൽ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			നിർത്തുക;
#define TTYMODE(NAME, FIELD, OP) \
		അവസ്ഥ OP: \
			എങ്കിൽ ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			എങ്കിൽ (u) \
				tio.FIELD |= NAME; \
			അല്ലെങ്കിൽ \
				tio.FIELD &= ~NAME; \
			നിർത്തുക;

#അന്തര്ഭാവ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		സ്ഥിരസ്ഥിതി:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			എങ്കിൽ (opcode > 0 && opcode < 160) {
				എങ്കിൽ ((r = sshbuf_get_u32(buf, ശൂന്യ)) != 0)
					fatal_fr(r, "parse arg");
				നിർത്തുക;
			} അല്ലെങ്കിൽ {
				logit_f("unknown opcode %d", opcode);
				പോകുക set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	എങ്കിൽ (len > 0) {
		logit_f("%zu bytes left", len);
		തിരികെ;		/* Don't process bytes passed */
	}
	എങ്കിൽ (failure == -1)
		തിരികെ;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	എങ്കിൽ (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
