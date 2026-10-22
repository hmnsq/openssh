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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <errno.h>
#شامل <string.h>
#شامل <termios.h>
#شامل <stdarg.h>

#شامل "packet.h"
#شامل "log.h"
#شامل "compat.h"
#شامل "sshbuf.h"

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
ایستا صحیح
speed_to_baud(speed_t speed)
{
	انتخاب (speed) {
	حالت B0:
		بازگشت 0;
	حالت B50:
		بازگشت 50;
	حالت B75:
		بازگشت 75;
	حالت B110:
		بازگشت 110;
	حالت B134:
		بازگشت 134;
	حالت B150:
		بازگشت 150;
	حالت B200:
		بازگشت 200;
	حالت B300:
		بازگشت 300;
	حالت B600:
		بازگشت 600;
	حالت B1200:
		بازگشت 1200;
	حالت B1800:
		بازگشت 1800;
	حالت B2400:
		بازگشت 2400;
	حالت B4800:
		بازگشت 4800;
	حالت B9600:
		بازگشت 9600;

#ifdef B19200
	حالت B19200:
		بازگشت 19200;
#وگرنه /* B19200 */
#ifdef EXTA
	حالت EXTA:
		بازگشت 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	حالت B38400:
		بازگشت 38400;
#وگرنه /* B38400 */
#ifdef EXTB
	حالت EXTB:
		بازگشت 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	حالت B7200:
		بازگشت 7200;
#endif /* B7200 */
#ifdef B14400
	حالت B14400:
		بازگشت 14400;
#endif /* B14400 */
#ifdef B28800
	حالت B28800:
		بازگشت 28800;
#endif /* B28800 */
#ifdef B57600
	حالت B57600:
		بازگشت 57600;
#endif /* B57600 */
#ifdef B76800
	حالت B76800:
		بازگشت 76800;
#endif /* B76800 */
#ifdef B115200
	حالت B115200:
		بازگشت 115200;
#endif /* B115200 */
#ifdef B230400
	حالت B230400:
		بازگشت 230400;
#endif /* B230400 */
	پیشفرض:
		بازگشت 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
ایستا speed_t
baud_to_speed(صحیح baud)
{
	انتخاب (baud) {
	حالت 0:
		بازگشت B0;
	حالت 50:
		بازگشت B50;
	حالت 75:
		بازگشت B75;
	حالت 110:
		بازگشت B110;
	حالت 134:
		بازگشت B134;
	حالت 150:
		بازگشت B150;
	حالت 200:
		بازگشت B200;
	حالت 300:
		بازگشت B300;
	حالت 600:
		بازگشت B600;
	حالت 1200:
		بازگشت B1200;
	حالت 1800:
		بازگشت B1800;
	حالت 2400:
		بازگشت B2400;
	حالت 4800:
		بازگشت B4800;
	حالت 9600:
		بازگشت B9600;

#ifdef B19200
	حالت 19200:
		بازگشت B19200;
#وگرنه /* B19200 */
#ifdef EXTA
	حالت 19200:
		بازگشت EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	حالت 38400:
		بازگشت B38400;
#وگرنه /* B38400 */
#ifdef EXTB
	حالت 38400:
		بازگشت EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	حالت 7200:
		بازگشت B7200;
#endif /* B7200 */
#ifdef B14400
	حالت 14400:
		بازگشت B14400;
#endif /* B14400 */
#ifdef B28800
	حالت 28800:
		بازگشت B28800;
#endif /* B28800 */
#ifdef B57600
	حالت 57600:
		بازگشت B57600;
#endif /* B57600 */
#ifdef B76800
	حالت 76800:
		بازگشت B76800;
#endif /* B76800 */
#ifdef B115200
	حالت 115200:
		بازگشت B115200;
#endif /* B115200 */
#ifdef B230400
	حالت 230400:
		بازگشت B230400;
#endif /* B230400 */
	پیشفرض:
		بازگشت B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
ایستا u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	اگر (c == _POSIX_VDISABLE)
		بازگشت 255;
#endif /* _POSIX_VDISABLE */
	بازگشت c;
}

/*
 * Decode a special character from SSH line format.
 */
ایستا cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	اگر (c == 255)
		بازگشت _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	بازگشت c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
تهی
ssh_tty_make_modes(ساختار ssh *ssh, صحیح fd, ساختار termios *tiop)
{
	ساختار termios tio;
	ساختار sshbuf *buf;
	صحیح r, ibaud, obaud;

	اگر ((buf = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");

	اگر (tiop == پوچ) {
		اگر (fd == -1) {
			debug_f("no fd or tio");
			برو end;
		}
		اگر (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			برو end;
		}
	} وگرنه
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	اگر ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	اگر ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	اگر (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} وگرنه اگر ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#شامل "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	اگر ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
تهی
ssh_tty_parse_modes(ساختار ssh *ssh, صحیح fd)
{
	ساختار termios tio;
	ساختار sshbuf *buf;
	ثابت u_char *data;
	u_char opcode;
	u_int baud, u;
	صحیح r, failure = 0;
	size_t len;

	اگر ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	اگر (len == 0)
		بازگشت;
	اگر ((buf = sshbuf_from(data, len)) == پوچ) {
		error_f("sshbuf_from failed");
		بازگشت;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	اگر (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	وقتی (sshbuf_len(buf) > 0) {
		اگر ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		انتخاب (opcode) {
		حالت TTY_OP_END:
			برو set;

		حالت TTY_OP_ISPEED:
			اگر ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			اگر (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			بشکن;

		حالت TTY_OP_OSPEED:
			اگر ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			اگر (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			بشکن;

#define TTYCHAR(NAME, OP) \
		حالت OP: \
			اگر ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			بشکن;
#define TTYMODE(NAME, FIELD, OP) \
		حالت OP: \
			اگر ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			اگر (u) \
				tio.FIELD |= NAME; \
			وگرنه \
				tio.FIELD &= ~NAME; \
			بشکن;

#شامل "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		پیشفرض:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			اگر (opcode > 0 && opcode < 160) {
				اگر ((r = sshbuf_get_u32(buf, پوچ)) != 0)
					fatal_fr(r, "parse arg");
				بشکن;
			} وگرنه {
				logit_f("unknown opcode %d", opcode);
				برو set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	اگر (len > 0) {
		logit_f("%zu bytes left", len);
		بازگشت;		/* Don't process bytes passed */
	}
	اگر (failure == -1)
		بازگشت;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	اگر (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
