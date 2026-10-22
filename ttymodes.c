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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <errno.h>
#ضمن <string.h>
#ضمن <termios.h>
#ضمن <stdarg.h>

#ضمن "packet.h"
#ضمن "log.h"
#ضمن "compat.h"
#ضمن "sshbuf.h"

#وصف_ڪريو TTY_OP_پڇاڙي		0
/*
 * uint32 (u_int) follows speed.
 */
#وصف_ڪريو TTY_OP_ISPEED	128
#وصف_ڪريو TTY_OP_OSPEED	129

/*
 * Converts POSIX speed_t to a baud rate.  The values of the
 * constants for speed_t are not themselves portable.
 */
ساكن صحيح
رفتار_منزل_baud(speed_t رفتار)
{
	بدل (رفتار) {
	حالة B0:
		أرجع 0;
	حالة B50:
		أرجع 50;
	حالة B75:
		أرجع 75;
	حالة B110:
		أرجع 110;
	حالة B134:
		أرجع 134;
	حالة B150:
		أرجع 150;
	حالة B200:
		أرجع 200;
	حالة B300:
		أرجع 300;
	حالة B600:
		أرجع 600;
	حالة B1200:
		أرجع 1200;
	حالة B1800:
		أرجع 1800;
	حالة B2400:
		أرجع 2400;
	حالة B4800:
		أرجع 4800;
	حالة B9600:
		أرجع 9600;

#جيڪڏهن_وصف_ٿيل B19200
	حالة B19200:
		أرجع 19200;
#وإلا /* B19200 */
#جيڪڏهن_وصف_ٿيل EXTA
	حالة EXTA:
		أرجع 19200;
#جيڪڏهن_پورو /* EXTA */
#جيڪڏهن_پورو /* B19200 */

#جيڪڏهن_وصف_ٿيل B38400
	حالة B38400:
		أرجع 38400;
#وإلا /* B38400 */
#جيڪڏهن_وصف_ٿيل EXTB
	حالة EXTB:
		أرجع 38400;
#جيڪڏهن_پورو /* EXTB */
#جيڪڏهن_پورو /* B38400 */

#جيڪڏهن_وصف_ٿيل B7200
	حالة B7200:
		أرجع 7200;
#جيڪڏهن_پورو /* B7200 */
#جيڪڏهن_وصف_ٿيل B14400
	حالة B14400:
		أرجع 14400;
#جيڪڏهن_پورو /* B14400 */
#جيڪڏهن_وصف_ٿيل B28800
	حالة B28800:
		أرجع 28800;
#جيڪڏهن_پورو /* B28800 */
#جيڪڏهن_وصف_ٿيل B57600
	حالة B57600:
		أرجع 57600;
#جيڪڏهن_پورو /* B57600 */
#جيڪڏهن_وصف_ٿيل B76800
	حالة B76800:
		أرجع 76800;
#جيڪڏهن_پورو /* B76800 */
#جيڪڏهن_وصف_ٿيل B115200
	حالة B115200:
		أرجع 115200;
#جيڪڏهن_پورو /* B115200 */
#جيڪڏهن_وصف_ٿيل B230400
	حالة B230400:
		أرجع 230400;
#جيڪڏهن_پورو /* B230400 */
	افتراضي:
		أرجع 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
ساكن speed_t
baud_منزل_رفتار(صحيح baud)
{
	بدل (baud) {
	حالة 0:
		أرجع B0;
	حالة 50:
		أرجع B50;
	حالة 75:
		أرجع B75;
	حالة 110:
		أرجع B110;
	حالة 134:
		أرجع B134;
	حالة 150:
		أرجع B150;
	حالة 200:
		أرجع B200;
	حالة 300:
		أرجع B300;
	حالة 600:
		أرجع B600;
	حالة 1200:
		أرجع B1200;
	حالة 1800:
		أرجع B1800;
	حالة 2400:
		أرجع B2400;
	حالة 4800:
		أرجع B4800;
	حالة 9600:
		أرجع B9600;

#جيڪڏهن_وصف_ٿيل B19200
	حالة 19200:
		أرجع B19200;
#وإلا /* B19200 */
#جيڪڏهن_وصف_ٿيل EXTA
	حالة 19200:
		أرجع EXTA;
#جيڪڏهن_پورو /* EXTA */
#جيڪڏهن_پورو /* B19200 */

#جيڪڏهن_وصف_ٿيل B38400
	حالة 38400:
		أرجع B38400;
#وإلا /* B38400 */
#جيڪڏهن_وصف_ٿيل EXTB
	حالة 38400:
		أرجع EXTB;
#جيڪڏهن_پورو /* EXTB */
#جيڪڏهن_پورو /* B38400 */

#جيڪڏهن_وصف_ٿيل B7200
	حالة 7200:
		أرجع B7200;
#جيڪڏهن_پورو /* B7200 */
#جيڪڏهن_وصف_ٿيل B14400
	حالة 14400:
		أرجع B14400;
#جيڪڏهن_پورو /* B14400 */
#جيڪڏهن_وصف_ٿيل B28800
	حالة 28800:
		أرجع B28800;
#جيڪڏهن_پورو /* B28800 */
#جيڪڏهن_وصف_ٿيل B57600
	حالة 57600:
		أرجع B57600;
#جيڪڏهن_پورو /* B57600 */
#جيڪڏهن_وصف_ٿيل B76800
	حالة 76800:
		أرجع B76800;
#جيڪڏهن_پورو /* B76800 */
#جيڪڏهن_وصف_ٿيل B115200
	حالة 115200:
		أرجع B115200;
#جيڪڏهن_پورو /* B115200 */
#جيڪڏهن_وصف_ٿيل B230400
	حالة 230400:
		أرجع B230400;
#جيڪڏهن_پورو /* B230400 */
	افتراضي:
		أرجع B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
ساكن u_int
special_char_encode(cc_t c)
{
#جيڪڏهن_وصف_ٿيل _POSIX_VDISABLE
	إذا (c == _POSIX_VDISABLE)
		أرجع 255;
#جيڪڏهن_پورو /* _POSIX_VDISABLE */
	أرجع c;
}

/*
 * Decode a special character from SSH line format.
 */
ساكن cc_t
special_char_decode(u_int c)
{
#جيڪڏهن_وصف_ٿيل _POSIX_VDISABLE
	إذا (c == 255)
		أرجع _POSIX_VDISABLE;
#جيڪڏهن_پورو /* _POSIX_VDISABLE */
	أرجع c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
فراغ
ssh_tty_make_modes(بنية ssh *ssh, صحيح fd, بنية termios *tiop)
{
	بنية termios tio;
	بنية sshbuf *buf;
	صحيح r, ibaud, obaud;

	إذا ((buf = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");

	إذا (tiop == عدم) {
		إذا (fd == -1) {
			debug_f("no fd or tio");
			اذهب پڇاڙي;
		}
		إذا (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			اذهب پڇاڙي;
		}
	} وإلا
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = رفتار_منزل_baud(cfgetospeed(&tio));
	ibaud = رفتار_منزل_baud(cfgetispeed(&tio));
	إذا ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#وصف_ڪريو TTYCHAR(NAME, OP) \
	إذا ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#وصف_ڪريو SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#وصف_ڪريو TTYMODE(NAME, ميدان_2, OP) \
	إذا (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} وإلا إذا ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.ميدان_2 & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#ضمن "ttymodes.h"

#وصف_رد TTYCHAR
#وصف_رد TTYMODE

پڇاڙي:
	/* Mark end of mode data. */
	إذا ((r = sshbuf_put_u8(buf, TTY_OP_پڇاڙي)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
فراغ
ssh_tty_parse_modes(بنية ssh *ssh, صحيح fd)
{
	بنية termios tio;
	بنية sshbuf *buf;
	ثابت u_char *معلومات;
	u_char opcode;
	u_int baud, u;
	صحيح r, failure = 0;
	سائيز_t len;

	إذا ((r = sshpkt_get_string_سڌو(ssh, &معلومات, &len)) != 0)
		fatal_fr(r, "parse");
	إذا (len == 0)
		أرجع;
	إذا ((buf = sshbuf_from(معلومات, len)) == عدم) {
		error_f("sshbuf_from failed");
		أرجع;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	إذا (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	طالما (sshbuf_len(buf) > 0) {
		إذا ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		بدل (opcode) {
		حالة TTY_OP_پڇاڙي:
			اذهب سيٽ;

		حالة TTY_OP_ISPEED:
			إذا ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			إذا (failure != -1 &&
			    cfsetispeed(&tio, baud_منزل_رفتار(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			اكسر;

		حالة TTY_OP_OSPEED:
			إذا ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			إذا (failure != -1 &&
			    cfsetospeed(&tio, baud_منزل_رفتار(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			اكسر;

#وصف_ڪريو TTYCHAR(NAME, OP) \
		حالة OP: \
			إذا ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			اكسر;
#وصف_ڪريو TTYMODE(NAME, ميدان_2, OP) \
		حالة OP: \
			إذا ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			إذا (u) \
				tio.ميدان_2 |= NAME; \
			وإلا \
				tio.ميدان_2 &= ~NAME; \
			اكسر;

#ضمن "ttymodes.h"

#وصف_رد TTYCHAR
#وصف_رد TTYMODE

		افتراضي:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			إذا (opcode > 0 && opcode < 160) {
				إذا ((r = sshbuf_get_u32(buf, عدم)) != 0)
					fatal_fr(r, "parse arg");
				اكسر;
			} وإلا {
				logit_f("unknown opcode %d", opcode);
				اذهب سيٽ;
			}
		}
	}

سيٽ:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	إذا (len > 0) {
		logit_f("%zu bytes left", len);
		أرجع;		/* Don't process bytes passed */
	}
	إذا (failure == -1)
		أرجع;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	إذا (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
