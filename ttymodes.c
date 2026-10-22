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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <termios.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "sshbuf.h"

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
நிலையான முழு
speed_to_baud(speed_t speed)
{
	தேர்வு (speed) {
	நிலை B0:
		திரும்பு 0;
	நிலை B50:
		திரும்பு 50;
	நிலை B75:
		திரும்பு 75;
	நிலை B110:
		திரும்பு 110;
	நிலை B134:
		திரும்பு 134;
	நிலை B150:
		திரும்பு 150;
	நிலை B200:
		திரும்பு 200;
	நிலை B300:
		திரும்பு 300;
	நிலை B600:
		திரும்பு 600;
	நிலை B1200:
		திரும்பு 1200;
	நிலை B1800:
		திரும்பு 1800;
	நிலை B2400:
		திரும்பு 2400;
	நிலை B4800:
		திரும்பு 4800;
	நிலை B9600:
		திரும்பு 9600;

#ifdef B19200
	நிலை B19200:
		திரும்பு 19200;
#இல்லையெனில் /* B19200 */
#ifdef EXTA
	நிலை EXTA:
		திரும்பு 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	நிலை B38400:
		திரும்பு 38400;
#இல்லையெனில் /* B38400 */
#ifdef EXTB
	நிலை EXTB:
		திரும்பு 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	நிலை B7200:
		திரும்பு 7200;
#endif /* B7200 */
#ifdef B14400
	நிலை B14400:
		திரும்பு 14400;
#endif /* B14400 */
#ifdef B28800
	நிலை B28800:
		திரும்பு 28800;
#endif /* B28800 */
#ifdef B57600
	நிலை B57600:
		திரும்பு 57600;
#endif /* B57600 */
#ifdef B76800
	நிலை B76800:
		திரும்பு 76800;
#endif /* B76800 */
#ifdef B115200
	நிலை B115200:
		திரும்பு 115200;
#endif /* B115200 */
#ifdef B230400
	நிலை B230400:
		திரும்பு 230400;
#endif /* B230400 */
	இயல்பு:
		திரும்பு 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
நிலையான speed_t
baud_to_speed(முழு baud)
{
	தேர்வு (baud) {
	நிலை 0:
		திரும்பு B0;
	நிலை 50:
		திரும்பு B50;
	நிலை 75:
		திரும்பு B75;
	நிலை 110:
		திரும்பு B110;
	நிலை 134:
		திரும்பு B134;
	நிலை 150:
		திரும்பு B150;
	நிலை 200:
		திரும்பு B200;
	நிலை 300:
		திரும்பு B300;
	நிலை 600:
		திரும்பு B600;
	நிலை 1200:
		திரும்பு B1200;
	நிலை 1800:
		திரும்பு B1800;
	நிலை 2400:
		திரும்பு B2400;
	நிலை 4800:
		திரும்பு B4800;
	நிலை 9600:
		திரும்பு B9600;

#ifdef B19200
	நிலை 19200:
		திரும்பு B19200;
#இல்லையெனில் /* B19200 */
#ifdef EXTA
	நிலை 19200:
		திரும்பு EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	நிலை 38400:
		திரும்பு B38400;
#இல்லையெனில் /* B38400 */
#ifdef EXTB
	நிலை 38400:
		திரும்பு EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	நிலை 7200:
		திரும்பு B7200;
#endif /* B7200 */
#ifdef B14400
	நிலை 14400:
		திரும்பு B14400;
#endif /* B14400 */
#ifdef B28800
	நிலை 28800:
		திரும்பு B28800;
#endif /* B28800 */
#ifdef B57600
	நிலை 57600:
		திரும்பு B57600;
#endif /* B57600 */
#ifdef B76800
	நிலை 76800:
		திரும்பு B76800;
#endif /* B76800 */
#ifdef B115200
	நிலை 115200:
		திரும்பு B115200;
#endif /* B115200 */
#ifdef B230400
	நிலை 230400:
		திரும்பு B230400;
#endif /* B230400 */
	இயல்பு:
		திரும்பு B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
நிலையான u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	எனில் (c == _POSIX_VDISABLE)
		திரும்பு 255;
#endif /* _POSIX_VDISABLE */
	திரும்பு c;
}

/*
 * Decode a special character from SSH line format.
 */
நிலையான cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	எனில் (c == 255)
		திரும்பு _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	திரும்பு c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
வெறுமை
ssh_tty_make_modes(கட்டமைப்பு ssh *ssh, முழு fd, கட்டமைப்பு termios *tiop)
{
	கட்டமைப்பு termios tio;
	கட்டமைப்பு sshbuf *buf;
	முழு r, ibaud, obaud;

	எனில் ((buf = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");

	எனில் (tiop == வெற்று) {
		எனில் (fd == -1) {
			debug_f("no fd or tio");
			செல் end;
		}
		எனில் (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			செல் end;
		}
	} இல்லையெனில்
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	எனில் ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	எனில் ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	எனில் (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} இல்லையெனில் எனில் ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#அந்தர்பாவ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	எனில் ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
வெறுமை
ssh_tty_parse_modes(கட்டமைப்பு ssh *ssh, முழு fd)
{
	கட்டமைப்பு termios tio;
	கட்டமைப்பு sshbuf *buf;
	மாறிலி u_char *data;
	u_char opcode;
	u_int baud, u;
	முழு r, failure = 0;
	size_t len;

	எனில் ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	எனில் (len == 0)
		திரும்பு;
	எனில் ((buf = sshbuf_from(data, len)) == வெற்று) {
		error_f("sshbuf_from failed");
		திரும்பு;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	எனில் (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	போது (sshbuf_len(buf) > 0) {
		எனில் ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		தேர்வு (opcode) {
		நிலை TTY_OP_END:
			செல் set;

		நிலை TTY_OP_ISPEED:
			எனில் ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			எனில் (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			நிறுத்து;

		நிலை TTY_OP_OSPEED:
			எனில் ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			எனில் (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			நிறுத்து;

#define TTYCHAR(NAME, OP) \
		நிலை OP: \
			எனில் ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			நிறுத்து;
#define TTYMODE(NAME, FIELD, OP) \
		நிலை OP: \
			எனில் ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			எனில் (u) \
				tio.FIELD |= NAME; \
			இல்லையெனில் \
				tio.FIELD &= ~NAME; \
			நிறுத்து;

#அந்தர்பாவ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		இயல்பு:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			எனில் (opcode > 0 && opcode < 160) {
				எனில் ((r = sshbuf_get_u32(buf, வெற்று)) != 0)
					fatal_fr(r, "parse arg");
				நிறுத்து;
			} இல்லையெனில் {
				logit_f("unknown opcode %d", opcode);
				செல் set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	எனில் (len > 0) {
		logit_f("%zu bytes left", len);
		திரும்பு;		/* Don't process bytes passed */
	}
	எனில் (failure == -1)
		திரும்பு;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	எனில் (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
