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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <termios.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
speed_to_baud(speed_t speed)
{
	ବାଛ (speed) {
	ସ୍ଥିତି B0:
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି B50:
		ଫେରନ୍ତୁ 50;
	ସ୍ଥିତି B75:
		ଫେରନ୍ତୁ 75;
	ସ୍ଥିତି B110:
		ଫେରନ୍ତୁ 110;
	ସ୍ଥିତି B134:
		ଫେରନ୍ତୁ 134;
	ସ୍ଥିତି B150:
		ଫେରନ୍ତୁ 150;
	ସ୍ଥିତି B200:
		ଫେରନ୍ତୁ 200;
	ସ୍ଥିତି B300:
		ଫେରନ୍ତୁ 300;
	ସ୍ଥିତି B600:
		ଫେରନ୍ତୁ 600;
	ସ୍ଥିତି B1200:
		ଫେରନ୍ତୁ 1200;
	ସ୍ଥିତି B1800:
		ଫେରନ୍ତୁ 1800;
	ସ୍ଥିତି B2400:
		ଫେରନ୍ତୁ 2400;
	ସ୍ଥିତି B4800:
		ଫେରନ୍ତୁ 4800;
	ସ୍ଥିତି B9600:
		ଫେରନ୍ତୁ 9600;

#ifdef B19200
	ସ୍ଥିତି B19200:
		ଫେରନ୍ତୁ 19200;
#ଅନ୍ୟଥା /* B19200 */
#ifdef EXTA
	ସ୍ଥିତି EXTA:
		ଫେରନ୍ତୁ 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	ସ୍ଥିତି B38400:
		ଫେରନ୍ତୁ 38400;
#ଅନ୍ୟଥା /* B38400 */
#ifdef EXTB
	ସ୍ଥିତି EXTB:
		ଫେରନ୍ତୁ 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	ସ୍ଥିତି B7200:
		ଫେରନ୍ତୁ 7200;
#endif /* B7200 */
#ifdef B14400
	ସ୍ଥିତି B14400:
		ଫେରନ୍ତୁ 14400;
#endif /* B14400 */
#ifdef B28800
	ସ୍ଥିତି B28800:
		ଫେରନ୍ତୁ 28800;
#endif /* B28800 */
#ifdef B57600
	ସ୍ଥିତି B57600:
		ଫେରନ୍ତୁ 57600;
#endif /* B57600 */
#ifdef B76800
	ସ୍ଥିତି B76800:
		ଫେରନ୍ତୁ 76800;
#endif /* B76800 */
#ifdef B115200
	ସ୍ଥିତି B115200:
		ଫେରନ୍ତୁ 115200;
#endif /* B115200 */
#ifdef B230400
	ସ୍ଥିତି B230400:
		ଫେରନ୍ତୁ 230400;
#endif /* B230400 */
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
ସ୍ଥିର speed_t
baud_to_speed(ପୂର୍ଣ୍ଣସଂଖ୍ୟା baud)
{
	ବାଛ (baud) {
	ସ୍ଥିତି 0:
		ଫେରନ୍ତୁ B0;
	ସ୍ଥିତି 50:
		ଫେରନ୍ତୁ B50;
	ସ୍ଥିତି 75:
		ଫେରନ୍ତୁ B75;
	ସ୍ଥିତି 110:
		ଫେରନ୍ତୁ B110;
	ସ୍ଥିତି 134:
		ଫେରନ୍ତୁ B134;
	ସ୍ଥିତି 150:
		ଫେରନ୍ତୁ B150;
	ସ୍ଥିତି 200:
		ଫେରନ୍ତୁ B200;
	ସ୍ଥିତି 300:
		ଫେରନ୍ତୁ B300;
	ସ୍ଥିତି 600:
		ଫେରନ୍ତୁ B600;
	ସ୍ଥିତି 1200:
		ଫେରନ୍ତୁ B1200;
	ସ୍ଥିତି 1800:
		ଫେରନ୍ତୁ B1800;
	ସ୍ଥିତି 2400:
		ଫେରନ୍ତୁ B2400;
	ସ୍ଥିତି 4800:
		ଫେରନ୍ତୁ B4800;
	ସ୍ଥିତି 9600:
		ଫେରନ୍ତୁ B9600;

#ifdef B19200
	ସ୍ଥିତି 19200:
		ଫେରନ୍ତୁ B19200;
#ଅନ୍ୟଥା /* B19200 */
#ifdef EXTA
	ସ୍ଥିତି 19200:
		ଫେରନ୍ତୁ EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	ସ୍ଥିତି 38400:
		ଫେରନ୍ତୁ B38400;
#ଅନ୍ୟଥା /* B38400 */
#ifdef EXTB
	ସ୍ଥିତି 38400:
		ଫେରନ୍ତୁ EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	ସ୍ଥିତି 7200:
		ଫେରନ୍ତୁ B7200;
#endif /* B7200 */
#ifdef B14400
	ସ୍ଥିତି 14400:
		ଫେରନ୍ତୁ B14400;
#endif /* B14400 */
#ifdef B28800
	ସ୍ଥିତି 28800:
		ଫେରନ୍ତୁ B28800;
#endif /* B28800 */
#ifdef B57600
	ସ୍ଥିତି 57600:
		ଫେରନ୍ତୁ B57600;
#endif /* B57600 */
#ifdef B76800
	ସ୍ଥିତି 76800:
		ଫେରନ୍ତୁ B76800;
#endif /* B76800 */
#ifdef B115200
	ସ୍ଥିତି 115200:
		ଫେରନ୍ତୁ B115200;
#endif /* B115200 */
#ifdef B230400
	ସ୍ଥିତି 230400:
		ଫେରନ୍ତୁ B230400;
#endif /* B230400 */
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
ସ୍ଥିର u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	ଯଦି (c == _POSIX_VDISABLE)
		ଫେରନ୍ତୁ 255;
#endif /* _POSIX_VDISABLE */
	ଫେରନ୍ତୁ c;
}

/*
 * Decode a special character from SSH line format.
 */
ସ୍ଥିର cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	ଯଦି (c == 255)
		ଫେରନ୍ତୁ _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	ଫେରନ୍ତୁ c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
ଶୂନ୍ୟ
ssh_tty_make_modes(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା termios *tiop)
{
	ସଂରଚନା termios tio;
	ସଂରଚନା sshbuf *buf;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ibaud, obaud;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");

	ଯଦି (tiop == ଖାଲି) {
		ଯଦି (fd == -1) {
			debug_f("no fd or tio");
			ଯାଅ end;
		}
		ଯଦି (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			ଯାଅ end;
		}
	} ଅନ୍ୟଥା
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	ଯଦି ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	ଯଦି ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	ଯଦି (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} ଅନ୍ୟଥା ଯଦି ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#ଅନ୍ତର୍ଭାଵ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	ଯଦି ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
ଶୂନ୍ୟ
ssh_tty_parse_modes(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା termios tio;
	ସଂରଚନା sshbuf *buf;
	ଅଚଳ u_char *data;
	u_char opcode;
	u_int baud, u;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, failure = 0;
	size_t len;

	ଯଦି ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (len == 0)
		ଫେରନ୍ତୁ;
	ଯଦି ((buf = sshbuf_from(data, len)) == ଖାଲି) {
		error_f("sshbuf_from failed");
		ଫେରନ୍ତୁ;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	ଯଦି (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	ଯେତେବେଳେ (sshbuf_len(buf) > 0) {
		ଯଦି ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		ବାଛ (opcode) {
		ସ୍ଥିତି TTY_OP_END:
			ଯାଅ set;

		ସ୍ଥିତି TTY_OP_ISPEED:
			ଯଦି ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			ଯଦି (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			ଭାଙ୍ଗ;

		ସ୍ଥିତି TTY_OP_OSPEED:
			ଯଦି ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			ଯଦି (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			ଭାଙ୍ଗ;

#define TTYCHAR(NAME, OP) \
		ସ୍ଥିତି OP: \
			ଯଦି ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			ଭାଙ୍ଗ;
#define TTYMODE(NAME, FIELD, OP) \
		ସ୍ଥିତି OP: \
			ଯଦି ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			ଯଦି (u) \
				tio.FIELD |= NAME; \
			ଅନ୍ୟଥା \
				tio.FIELD &= ~NAME; \
			ଭାଙ୍ଗ;

#ଅନ୍ତର୍ଭାଵ "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			ଯଦି (opcode > 0 && opcode < 160) {
				ଯଦି ((r = sshbuf_get_u32(buf, ଖାଲି)) != 0)
					fatal_fr(r, "parse arg");
				ଭାଙ୍ଗ;
			} ଅନ୍ୟଥା {
				logit_f("unknown opcode %d", opcode);
				ଯାଅ set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	ଯଦି (len > 0) {
		logit_f("%zu bytes left", len);
		ଫେରନ୍ତୁ;		/* Don't process bytes passed */
	}
	ଯଦି (failure == -1)
		ଫେରନ୍ତୁ;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	ଯଦି (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
