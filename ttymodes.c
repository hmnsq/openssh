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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <termios.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "packet.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "sshbuf.h"

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
स्थिर पूर्णांक
speed_to_baud(speed_t speed)
{
	निवड (speed) {
	स्थिती B0:
		परत 0;
	स्थिती B50:
		परत 50;
	स्थिती B75:
		परत 75;
	स्थिती B110:
		परत 110;
	स्थिती B134:
		परत 134;
	स्थिती B150:
		परत 150;
	स्थिती B200:
		परत 200;
	स्थिती B300:
		परत 300;
	स्थिती B600:
		परत 600;
	स्थिती B1200:
		परत 1200;
	स्थिती B1800:
		परत 1800;
	स्थिती B2400:
		परत 2400;
	स्थिती B4800:
		परत 4800;
	स्थिती B9600:
		परत 9600;

#ifdef B19200
	स्थिती B19200:
		परत 19200;
#अन्यथा /* B19200 */
#ifdef EXTA
	स्थिती EXTA:
		परत 19200;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	स्थिती B38400:
		परत 38400;
#अन्यथा /* B38400 */
#ifdef EXTB
	स्थिती EXTB:
		परत 38400;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	स्थिती B7200:
		परत 7200;
#endif /* B7200 */
#ifdef B14400
	स्थिती B14400:
		परत 14400;
#endif /* B14400 */
#ifdef B28800
	स्थिती B28800:
		परत 28800;
#endif /* B28800 */
#ifdef B57600
	स्थिती B57600:
		परत 57600;
#endif /* B57600 */
#ifdef B76800
	स्थिती B76800:
		परत 76800;
#endif /* B76800 */
#ifdef B115200
	स्थिती B115200:
		परत 115200;
#endif /* B115200 */
#ifdef B230400
	स्थिती B230400:
		परत 230400;
#endif /* B230400 */
	पूर्वनिर्धारित:
		परत 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
स्थिर speed_t
baud_to_speed(पूर्णांक baud)
{
	निवड (baud) {
	स्थिती 0:
		परत B0;
	स्थिती 50:
		परत B50;
	स्थिती 75:
		परत B75;
	स्थिती 110:
		परत B110;
	स्थिती 134:
		परत B134;
	स्थिती 150:
		परत B150;
	स्थिती 200:
		परत B200;
	स्थिती 300:
		परत B300;
	स्थिती 600:
		परत B600;
	स्थिती 1200:
		परत B1200;
	स्थिती 1800:
		परत B1800;
	स्थिती 2400:
		परत B2400;
	स्थिती 4800:
		परत B4800;
	स्थिती 9600:
		परत B9600;

#ifdef B19200
	स्थिती 19200:
		परत B19200;
#अन्यथा /* B19200 */
#ifdef EXTA
	स्थिती 19200:
		परत EXTA;
#endif /* EXTA */
#endif /* B19200 */

#ifdef B38400
	स्थिती 38400:
		परत B38400;
#अन्यथा /* B38400 */
#ifdef EXTB
	स्थिती 38400:
		परत EXTB;
#endif /* EXTB */
#endif /* B38400 */

#ifdef B7200
	स्थिती 7200:
		परत B7200;
#endif /* B7200 */
#ifdef B14400
	स्थिती 14400:
		परत B14400;
#endif /* B14400 */
#ifdef B28800
	स्थिती 28800:
		परत B28800;
#endif /* B28800 */
#ifdef B57600
	स्थिती 57600:
		परत B57600;
#endif /* B57600 */
#ifdef B76800
	स्थिती 76800:
		परत B76800;
#endif /* B76800 */
#ifdef B115200
	स्थिती 115200:
		परत B115200;
#endif /* B115200 */
#ifdef B230400
	स्थिती 230400:
		परत B230400;
#endif /* B230400 */
	पूर्वनिर्धारित:
		परत B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
स्थिर u_int
special_char_encode(cc_t c)
{
#ifdef _POSIX_VDISABLE
	जर (c == _POSIX_VDISABLE)
		परत 255;
#endif /* _POSIX_VDISABLE */
	परत c;
}

/*
 * Decode a special character from SSH line format.
 */
स्थिर cc_t
special_char_decode(u_int c)
{
#ifdef _POSIX_VDISABLE
	जर (c == 255)
		परत _POSIX_VDISABLE;
#endif /* _POSIX_VDISABLE */
	परत c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
शून्य
ssh_tty_make_modes(संरचना ssh *ssh, पूर्णांक fd, संरचना termios *tiop)
{
	संरचना termios tio;
	संरचना sshbuf *buf;
	पूर्णांक r, ibaud, obaud;

	जर ((buf = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");

	जर (tiop == रिक्त) {
		जर (fd == -1) {
			debug_f("no fd or tio");
			जा end;
		}
		जर (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", म_त्रुटि(त्रुटि_सं));
			जा end;
		}
	} अन्यथा
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	जर ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#define TTYCHAR(NAME, OP) \
	जर ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#define SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#define TTYMODE(NAME, FIELD, OP) \
	जर (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} अन्यथा जर ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#अन्तर्भाव "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

end:
	/* Mark end of mode data. */
	जर ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
शून्य
ssh_tty_parse_modes(संरचना ssh *ssh, पूर्णांक fd)
{
	संरचना termios tio;
	संरचना sshbuf *buf;
	स्थिरांक u_char *data;
	u_char opcode;
	u_int baud, u;
	पूर्णांक r, failure = 0;
	माप_प्रकार len;

	जर ((r = sshpkt_get_string_direct(ssh, &data, &len)) != 0)
		fatal_fr(r, "parse");
	जर (len == 0)
		परत;
	जर ((buf = sshbuf_from(data, len)) == रिक्त) {
		error_f("sshbuf_from failed");
		परत;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	जर (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", म_त्रुटि(त्रुटि_सं));
		failure = -1;
	}

	पर्यंत (sshbuf_len(buf) > 0) {
		जर ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		निवड (opcode) {
		स्थिती TTY_OP_END:
			जा set;

		स्थिती TTY_OP_ISPEED:
			जर ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			जर (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			थांबा;

		स्थिती TTY_OP_OSPEED:
			जर ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			जर (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			थांबा;

#define TTYCHAR(NAME, OP) \
		स्थिती OP: \
			जर ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			थांबा;
#define TTYMODE(NAME, FIELD, OP) \
		स्थिती OP: \
			जर ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			जर (u) \
				tio.FIELD |= NAME; \
			अन्यथा \
				tio.FIELD &= ~NAME; \
			थांबा;

#अन्तर्भाव "ttymodes.h"

#undef TTYCHAR
#undef TTYMODE

		पूर्वनिर्धारित:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			जर (opcode > 0 && opcode < 160) {
				जर ((r = sshbuf_get_u32(buf, रिक्त)) != 0)
					fatal_fr(r, "parse arg");
				थांबा;
			} अन्यथा {
				logit_f("unknown opcode %d", opcode);
				जा set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	जर (len > 0) {
		logit_f("%zu bytes left", len);
		परत;		/* Don't process bytes passed */
	}
	जर (failure == -1)
		परत;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	जर (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", म_त्रुटि(त्रुटि_सं));
}
