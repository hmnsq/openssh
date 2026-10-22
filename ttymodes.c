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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <termios.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "sshbuf.h"

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
স্থির পূর্ণসংখ্যা
speed_to_baud(speed_t speed)
{
	নির্বাচন (speed) {
	ক্ষেত্র B0:
		ফেরত 0;
	ক্ষেত্র B50:
		ফেরত 50;
	ক্ষেত্র B75:
		ফেরত 75;
	ক্ষেত্র B110:
		ফেরত 110;
	ক্ষেত্র B134:
		ফেরত 134;
	ক্ষেত্র B150:
		ফেরত 150;
	ক্ষেত্র B200:
		ফেরত 200;
	ক্ষেত্র B300:
		ফেরত 300;
	ক্ষেত্র B600:
		ফেরত 600;
	ক্ষেত্র B1200:
		ফেরত 1200;
	ক্ষেত্র B1800:
		ফেরত 1800;
	ক্ষেত্র B2400:
		ফেরত 2400;
	ক্ষেত্র B4800:
		ফেরত 4800;
	ক্ষেত্র B9600:
		ফেরত 9600;

#ifdef B19200
	ক্ষেত্র B19200:
		ফেরত 19200;
#অন্যথা /* B19200 */
#ifdef EXTA
	ক্ষেত্র EXTA:
		ফেরত 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	ক্ষেত্র B38400:
		ফেরত 38400;
#অন্যথা /* B38400 */
#ifdef EXTB
	ক্ষেত্র EXTB:
		ফেরত 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	ক্ষেত্র B7200:
		ফেরত 7200;
#endif /* B7200 */
#ifdef B14400
	ক্ষেত্র B14400:
		ফেরত 14400;
#endif /* B14400 */
#ifdef B28800
	ক্ষেত্র B28800:
		ফেরত 28800;
#endif /* B28800 */
#ifdef B57600
	ক্ষেত্র B57600:
		ফেরত 57600;
#endif /* B57600 */
#ifdef B76800
	ক্ষেত্র B76800:
		ফেরত 76800;
#endif /* B76800 */
#ifdef B115200
	ক্ষেত্র B115200:
		ফেরত 115200;
#endif /* B115200 */
#ifdef B230400
	ক্ষেত্র B230400:
		ফেরত 230400;
#endif /* B230400 */
	পূর্বনির্ধারিত:
		ফেরত 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
স্থির speed_t
baud_to_speed(পূর্ণসংখ্যা baud)
{
	নির্বাচন (baud) {
	ক্ষেত্র 0:
		ফেরত B0;
	ক্ষেত্র 50:
		ফেরত B50;
	ক্ষেত্র 75:
		ফেরত B75;
	ক্ষেত্র 110:
		ফেরত B110;
	ক্ষেত্র 134:
		ফেরত B134;
	ক্ষেত্র 150:
		ফেরত B150;
	ক্ষেত্র 200:
		ফেরত B200;
	ক্ষেত্র 300:
		ফেরত B300;
	ক্ষেত্র 600:
		ফেরত B600;
	ক্ষেত্র 1200:
		ফেরত B1200;
	ক্ষেত্র 1800:
		ফেরত B1800;
	ক্ষেত্র 2400:
		ফেরত B2400;
	ক্ষেত্র 4800:
		ফেরত B4800;
	ক্ষেত্র 9600:
		ফেরত B9600;

#ifdef B19200
	ক্ষেত্র 19200:
		ফেরত B19200;
#অন্যথা /* B19200 */
#ifdef EXTA
	ক্ষেত্র 19200:
		ফেরত EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	ক্ষেত্র 38400:
		ফেরত B38400;
#অন্যথা /* B38400 */
#ifdef EXTB
	ক্ষেত্র 38400:
		ফেরত EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	ক্ষেত্র 7200:
		ফেরত B7200;
#endif /* B7200 */
#ifdef B14400
	ক্ষেত্র 14400:
		ফেরত B14400;
#endif /* B14400 */
#ifdef B28800
	ক্ষেত্র 28800:
		ফেরত B28800;
#endif /* B28800 */
#ifdef B57600
	ক্ষেত্র 57600:
		ফেরত B57600;
#endif /* B57600 */
#ifdef B76800
	ক্ষেত্র 76800:
		ফেরত B76800;
#endif /* B76800 */
#ifdef B115200
	ক্ষেত্র 115200:
		ফেরত B115200;
#endif /* B115200 */
#ifdef B230400
	ক্ষেত্র 230400:
		ফেরত B230400;
#endif /* B230400 */
	পূর্বনির্ধারিত:
		ফেরত B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
স্থির u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	যদি (c == _POSIX_VDISABLE)
		ফেরত 255;
#endif /* _POSIX_VDISABLE */
	ফেরত c;
}

/*
 * Decode a special character from SSH line format.
 */
স্থির cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	যদি (c == 255)
		ফেরত _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	ফেরত c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
শূন্য
ssh_tty_make_modes(কাঠামো ssh *ssh, পূর্ণসংখ্যা fd, কাঠামো termios *tiop)
{
	কাঠামো termios tio;
	কাঠামো sshbuf *buf;
	পূর্ণসংখ্যা r, ibaud, obaud;

	যদি ((buf = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");

	যদি (tiop == ফাঁকা) {
		যদি (fd == -1) {
			debug_f("no fd or tio");
			যাও end;
		}
		যদি (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", strerror(errno));
			যাও end;
		}
	} অন্যথা
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	যদি ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	যদি ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	যদি (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} অন্যথা যদি ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#অন্তর্ভাব "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	যদি ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
শূন্য
ssh_tty_parse_modes(কাঠামো ssh *ssh, পূর্ণসংখ্যা fd)
{
	কাঠামো termios tio;
	কাঠামো sshbuf *buf;
	ধ্রুবক u_char *তথ্য;
	u_char opcode;
	u_int baud, u;
	পূর্ণসংখ্যা r, failure = 0;
	আকার_t len;

	যদি ((r = sshpkt_get_string_direct(ssh, &তথ্য, &len)) != 0)
		fatal_fr(r, "parse");
	যদি (len == 0)
		ফেরত;
	যদি ((buf = sshbuf_from(তথ্য, len)) == ফাঁকা) {
		error_f("sshbuf_from failed");
		ফেরত;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	যদি (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", strerror(errno));
		failure = -1;
	}

	যখন (sshbuf_len(buf) > 0) {
		যদি ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		নির্বাচন (opcode) {
		ক্ষেত্র TTY_OP_END:
			যাও set;

		ক্ষেত্র TTY_OP_ISPEED:
			যদি ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			যদি (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			বিরতি;

		ক্ষেত্র TTY_OP_OSPEED:
			যদি ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			যদি (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			বিরতি;

#define TTYCHAR(NAME, OP) \
		ক্ষেত্র OP: \
			যদি ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			বিরতি;
#define TTYMODE(NAME, FIELD, OP) \
		ক্ষেত্র OP: \
			যদি ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			যদি (u) \
				tio.FIELD |= NAME; \
			অন্যথা \
				tio.FIELD &= ~NAME; \
			বিরতি;

#অন্তর্ভাব "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		পূর্বনির্ধারিত:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			যদি (opcode > 0 && opcode < 160) {
				যদি ((r = sshbuf_get_u32(buf, ফাঁকা)) != 0)
					fatal_fr(r, "parse arg");
				বিরতি;
			} অন্যথা {
				logit_f("unknown opcode %d", opcode);
				যাও set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	যদি (len > 0) {
		logit_f("%zu bytes left", len);
		ফেরত;		/* Don't process bytes passed */
	}
	যদি (failure == -1)
		ফেরত;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	যদি (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", strerror(errno));
}
