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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <termios.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "sshbuf.h"

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
સ્થિર પૂર્ણાંક
speed_to_baud(speed_t speed)
{
	પસંદગી (speed) {
	સ્થિતિ B0:
		પાછા 0;
	સ્થિતિ B50:
		પાછા 50;
	સ્થિતિ B75:
		પાછા 75;
	સ્થિતિ B110:
		પાછા 110;
	સ્થિતિ B134:
		પાછા 134;
	સ્થિતિ B150:
		પાછા 150;
	સ્થિતિ B200:
		પાછા 200;
	સ્થિતિ B300:
		પાછા 300;
	સ્થિતિ B600:
		પાછા 600;
	સ્થિતિ B1200:
		પાછા 1200;
	સ્થિતિ B1800:
		પાછા 1800;
	સ્થિતિ B2400:
		પાછા 2400;
	સ્થિતિ B4800:
		પાછા 4800;
	સ્થિતિ B9600:
		પાછા 9600;

#ifdef B19200
	સ્થિતિ B19200:
		પાછા 19200;
#નહીંતર /* B19200 */
#ifdef EXTA
	સ્થિતિ EXTA:
		પાછા 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	સ્થિતિ B38400:
		પાછા 38400;
#નહીંતર /* B38400 */
#ifdef EXTB
	સ્થિતિ EXTB:
		પાછા 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	સ્થિતિ B7200:
		પાછા 7200;
#endif /* B7200 */
#ifdef B14400
	સ્થિતિ B14400:
		પાછા 14400;
#endif /* B14400 */
#ifdef B28800
	સ્થિતિ B28800:
		પાછા 28800;
#endif /* B28800 */
#ifdef B57600
	સ્થિતિ B57600:
		પાછા 57600;
#endif /* B57600 */
#ifdef B76800
	સ્થિતિ B76800:
		પાછા 76800;
#endif /* B76800 */
#ifdef B115200
	સ્થિતિ B115200:
		પાછા 115200;
#endif /* B115200 */
#ifdef B230400
	સ્થિતિ B230400:
		પાછા 230400;
#endif /* B230400 */
	મૂળભૂત:
		પાછા 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
સ્થિર speed_t
baud_to_speed(પૂર્ણાંક baud)
{
	પસંદગી (baud) {
	સ્થિતિ 0:
		પાછા B0;
	સ્થિતિ 50:
		પાછા B50;
	સ્થિતિ 75:
		પાછા B75;
	સ્થિતિ 110:
		પાછા B110;
	સ્થિતિ 134:
		પાછા B134;
	સ્થિતિ 150:
		પાછા B150;
	સ્થિતિ 200:
		પાછા B200;
	સ્થિતિ 300:
		પાછા B300;
	સ્થિતિ 600:
		પાછા B600;
	સ્થિતિ 1200:
		પાછા B1200;
	સ્થિતિ 1800:
		પાછા B1800;
	સ્થિતિ 2400:
		પાછા B2400;
	સ્થિતિ 4800:
		પાછા B4800;
	સ્થિતિ 9600:
		પાછા B9600;

#ifdef B19200
	સ્થિતિ 19200:
		પાછા B19200;
#નહીંતર /* B19200 */
#ifdef EXTA
	સ્થિતિ 19200:
		પાછા EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	સ્થિતિ 38400:
		પાછા B38400;
#નહીંતર /* B38400 */
#ifdef EXTB
	સ્થિતિ 38400:
		પાછા EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	સ્થિતિ 7200:
		પાછા B7200;
#endif /* B7200 */
#ifdef B14400
	સ્થિતિ 14400:
		પાછા B14400;
#endif /* B14400 */
#ifdef B28800
	સ્થિતિ 28800:
		પાછા B28800;
#endif /* B28800 */
#ifdef B57600
	સ્થિતિ 57600:
		પાછા B57600;
#endif /* B57600 */
#ifdef B76800
	સ્થિતિ 76800:
		પાછા B76800;
#endif /* B76800 */
#ifdef B115200
	સ્થિતિ 115200:
		પાછા B115200;
#endif /* B115200 */
#ifdef B230400
	સ્થિતિ 230400:
		પાછા B230400;
#endif /* B230400 */
	મૂળભૂત:
		પાછા B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
સ્થિર u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	જો (c == _POSIX_VDISABLE)
		પાછા 255;
#endif /* _POSIX_VDISABLE */
	પાછા c;
}

/*
 * Decode a special character from SSH line format.
 */
સ્થિર cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	જો (c == 255)
		પાછા _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	પાછા c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
શૂન્ય
ssh_tty_make_modes(સંરચના ssh *ssh, પૂર્ણાંક fd, સંરચના termios *tiop)
{
	સંરચના termios tio;
	સંરચના sshbuf *buf;
	પૂર્ણાંક r, ibaud, obaud;

	જો ((buf = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");

	જો (tiop == ખાલી) {
		જો (fd == -1) {
			debug_f("no fd or tio");
			જાઓ end;
		}
		જો (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			જાઓ end;
		}
	} નહીંતર
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	જો ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	જો ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	જો (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} નહીંતર જો ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#અન્તર્ભાવ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	જો ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
શૂન્ય
ssh_tty_parse_modes(સંરચના ssh *ssh, પૂર્ણાંક fd)
{
	સંરચના termios tio;
	સંરચના sshbuf *buf;
	અચલ u_char *data;
	u_char opcode;
	u_int baud, u;
	પૂર્ણાંક r, failure = 0;
	size_t len;

	જો ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	જો (len == 0)
		પાછા;
	જો ((buf = sshbuf_from(data, len)) == ખાલી) {
		error_f("sshbuf_from failed");
		પાછા;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	જો (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	જ્યારે (sshbuf_len(buf) > 0) {
		જો ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		પસંદગી (opcode) {
		સ્થિતિ TTY_OP_END:
			જાઓ set;

		સ્થિતિ TTY_OP_ISPEED:
			જો ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			જો (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			તોડો;

		સ્થિતિ TTY_OP_OSPEED:
			જો ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			જો (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			તોડો;

#define TTYCHAR(NAME, OP) \
		સ્થિતિ OP: \
			જો ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			તોડો;
#define TTYMODE(NAME, FIELD, OP) \
		સ્થિતિ OP: \
			જો ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			જો (u) \
				tio.FIELD |= NAME; \
			નહીંતર \
				tio.FIELD &= ~NAME; \
			તોડો;

#અન્તર્ભાવ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		મૂળભૂત:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			જો (opcode > 0 && opcode < 160) {
				જો ((r = sshbuf_get_u32(buf, ખાલી)) != 0)
					fatal_fr(r, "parse arg");
				તોડો;
			} નહીંતર {
				logit_f("unknown opcode %d", opcode);
				જાઓ set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	જો (len > 0) {
		logit_f("%zu bytes left", len);
		પાછા;		/* Don't process bytes passed */
	}
	જો (failure == -1)
		પાછા;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	જો (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
