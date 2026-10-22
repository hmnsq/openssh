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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <errno.h>
#समावेश <string.h>
#समावेश <termios.h>
#समावेश <stdarg.h>

#समावेश "packet.h"
#समावेश "log.h"
#समावेश "compat.h"
#समावेश "sshbuf.h"

#घोषणा TTY_OP_END		0
/*
 * uint32 (u_int) follows speed.
 */
#घोषणा TTY_OP_ISPEED	128
#घोषणा TTY_OP_OSPEED	129

/*
 * Converts POSIX speed_t to a baud rate.  The values of the
 * constants for speed_t are not themselves portable.
 */
अटल पूर्णांक
speed_to_baud(speed_t speed)
{
	चयन (speed) {
	हाल B0:
		वापस 0;
	हाल B50:
		वापस 50;
	हाल B75:
		वापस 75;
	हाल B110:
		वापस 110;
	हाल B134:
		वापस 134;
	हाल B150:
		वापस 150;
	हाल B200:
		वापस 200;
	हाल B300:
		वापस 300;
	हाल B600:
		वापस 600;
	हाल B1200:
		वापस 1200;
	हाल B1800:
		वापस 1800;
	हाल B2400:
		वापस 2400;
	हाल B4800:
		वापस 4800;
	हाल B9600:
		वापस 9600;

#अगर_घोषित B19200
	हाल B19200:
		वापस 19200;
#अन्यथा /* B19200 */
#अगर_घोषित EXTA
	हाल EXTA:
		वापस 19200;
#पूर्ण_अगर /* EXTA */
#पूर्ण_अगर /* B19200 */

#अगर_घोषित B38400
	हाल B38400:
		वापस 38400;
#अन्यथा /* B38400 */
#अगर_घोषित EXTB
	हाल EXTB:
		वापस 38400;
#पूर्ण_अगर /* EXTB */
#पूर्ण_अगर /* B38400 */

#अगर_घोषित B7200
	हाल B7200:
		वापस 7200;
#पूर्ण_अगर /* B7200 */
#अगर_घोषित B14400
	हाल B14400:
		वापस 14400;
#पूर्ण_अगर /* B14400 */
#अगर_घोषित B28800
	हाल B28800:
		वापस 28800;
#पूर्ण_अगर /* B28800 */
#अगर_घोषित B57600
	हाल B57600:
		वापस 57600;
#पूर्ण_अगर /* B57600 */
#अगर_घोषित B76800
	हाल B76800:
		वापस 76800;
#पूर्ण_अगर /* B76800 */
#अगर_घोषित B115200
	हाल B115200:
		वापस 115200;
#पूर्ण_अगर /* B115200 */
#अगर_घोषित B230400
	हाल B230400:
		वापस 230400;
#पूर्ण_अगर /* B230400 */
	शेष:
		वापस 9600;
	}
}

/*
 * Converts a numeric baud rate to a POSIX speed_t.
 */
अटल speed_t
baud_to_speed(पूर्णांक baud)
{
	चयन (baud) {
	हाल 0:
		वापस B0;
	हाल 50:
		वापस B50;
	हाल 75:
		वापस B75;
	हाल 110:
		वापस B110;
	हाल 134:
		वापस B134;
	हाल 150:
		वापस B150;
	हाल 200:
		वापस B200;
	हाल 300:
		वापस B300;
	हाल 600:
		वापस B600;
	हाल 1200:
		वापस B1200;
	हाल 1800:
		वापस B1800;
	हाल 2400:
		वापस B2400;
	हाल 4800:
		वापस B4800;
	हाल 9600:
		वापस B9600;

#अगर_घोषित B19200
	हाल 19200:
		वापस B19200;
#अन्यथा /* B19200 */
#अगर_घोषित EXTA
	हाल 19200:
		वापस EXTA;
#पूर्ण_अगर /* EXTA */
#पूर्ण_अगर /* B19200 */

#अगर_घोषित B38400
	हाल 38400:
		वापस B38400;
#अन्यथा /* B38400 */
#अगर_घोषित EXTB
	हाल 38400:
		वापस EXTB;
#पूर्ण_अगर /* EXTB */
#पूर्ण_अगर /* B38400 */

#अगर_घोषित B7200
	हाल 7200:
		वापस B7200;
#पूर्ण_अगर /* B7200 */
#अगर_घोषित B14400
	हाल 14400:
		वापस B14400;
#पूर्ण_अगर /* B14400 */
#अगर_घोषित B28800
	हाल 28800:
		वापस B28800;
#पूर्ण_अगर /* B28800 */
#अगर_घोषित B57600
	हाल 57600:
		वापस B57600;
#पूर्ण_अगर /* B57600 */
#अगर_घोषित B76800
	हाल 76800:
		वापस B76800;
#पूर्ण_अगर /* B76800 */
#अगर_घोषित B115200
	हाल 115200:
		वापस B115200;
#पूर्ण_अगर /* B115200 */
#अगर_घोषित B230400
	हाल 230400:
		वापस B230400;
#पूर्ण_अगर /* B230400 */
	शेष:
		वापस B9600;
	}
}

/*
 * Encode a special character into SSH line format.
 */
अटल u_int
special_char_encode(cc_t c)
{
#अगर_घोषित _POSIX_VDISABLE
	अगर (c == _POSIX_VDISABLE)
		वापस 255;
#पूर्ण_अगर /* _POSIX_VDISABLE */
	वापस c;
}

/*
 * Decode a special character from SSH line format.
 */
अटल cc_t
special_char_decode(u_int c)
{
#अगर_घोषित _POSIX_VDISABLE
	अगर (c == 255)
		वापस _POSIX_VDISABLE;
#पूर्ण_अगर /* _POSIX_VDISABLE */
	वापस c;
}

/*
 * Encodes terminal modes for the terminal referenced by fd
 * or tiop in a portable manner, and appends the modes to a packet
 * being constructed.
 */
व्योम
ssh_tty_make_modes(काष्ठा ssh *ssh, पूर्णांक fd, काष्ठा termios *tiop)
{
	काष्ठा termios tio;
	काष्ठा sshbuf *buf;
	पूर्णांक r, ibaud, obaud;

	अगर ((buf = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");

	अगर (tiop == शून्य) {
		अगर (fd == -1) {
			debug_f("no fd or tio");
			जाओ end;
		}
		अगर (tcgetattr(fd, &tio) == -1) {
			logit("tcgetattr: %.100s", म_त्रुटि(त्रुटि_सं));
			जाओ end;
		}
	} अन्यथा
		tio = *tiop;

	/* Store input and output baud rates. */
	obaud = speed_to_baud(cfgetospeed(&tio));
	ibaud = speed_to_baud(cfgetispeed(&tio));
	अगर ((r = sshbuf_put_u8(buf, TTY_OP_OSPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, obaud)) != 0 ||
	    (r = sshbuf_put_u8(buf, TTY_OP_ISPEED)) != 0 ||
	    (r = sshbuf_put_u32(buf, ibaud)) != 0)
		fatal_fr(r, "compose");

	/* Store values of mode flags. */
#घोषणा TTYCHAR(NAME, OP) \
	अगर ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, \
	    special_char_encode(tio.c_cc[NAME]))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#घोषणा SSH_TTYMODE_IUTF8 42  /* for SSH_BUG_UTF8TTYMODE */

#घोषणा TTYMODE(NAME, FIELD, OP) \
	अगर (OP == SSH_TTYMODE_IUTF8 && (ssh->compat & SSH_BUG_UTF8TTYMODE)) { \
		debug3_f("SSH_BUG_UTF8TTYMODE"); \
	} अन्यथा अगर ((r = sshbuf_put_u8(buf, OP)) != 0 || \
	    (r = sshbuf_put_u32(buf, ((tio.FIELD & NAME) != 0))) != 0) \
		fatal_fr(r, "compose %s", #NAME);

#समावेश "ttymodes.h"

#अघोषित TTYCHAR
#अघोषित TTYMODE

end:
	/* Mark end of mode data. */
	अगर ((r = sshbuf_put_u8(buf, TTY_OP_END)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, buf)) != 0)
		fatal_fr(r, "compose end");
	sshbuf_free(buf);
}

/*
 * Decodes terminal modes for the terminal referenced by fd in a portable
 * manner from a packet being read.
 */
व्योम
ssh_tty_parse_modes(काष्ठा ssh *ssh, पूर्णांक fd)
{
	काष्ठा termios tio;
	काष्ठा sshbuf *buf;
	स्थिर u_char *तथ्य;
	u_char opcode;
	u_int baud, u;
	पूर्णांक r, failure = 0;
	माप_प्रकार len;

	अगर ((r = sshpkt_get_string_direct(ssh, &तथ्य, &len)) != 0)
		fatal_fr(r, "parse");
	अगर (len == 0)
		वापस;
	अगर ((buf = sshbuf_from(तथ्य, len)) == शून्य) {
		error_f("sshbuf_from failed");
		वापस;
	}

	/*
	 * Get old attributes for the terminal.  We will modify these
	 * flags. I am hoping that if there are any machine-specific
	 * modes, they will initially have reasonable values.
	 */
	अगर (tcgetattr(fd, &tio) == -1) {
		logit("tcgetattr: %.100s", म_त्रुटि(त्रुटि_सं));
		failure = -1;
	}

	जबतक (sshbuf_len(buf) > 0) {
		अगर ((r = sshbuf_get_u8(buf, &opcode)) != 0)
			fatal_fr(r, "parse opcode");
		चयन (opcode) {
		हाल TTY_OP_END:
			जाओ set;

		हाल TTY_OP_ISPEED:
			अगर ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ispeed");
			अगर (failure != -1 &&
			    cfsetispeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetispeed failed for %d", baud);
			अवरोध;

		हाल TTY_OP_OSPEED:
			अगर ((r = sshbuf_get_u32(buf, &baud)) != 0)
				fatal_fr(r, "parse ospeed");
			अगर (failure != -1 &&
			    cfsetospeed(&tio, baud_to_speed(baud)) == -1)
				error("cfsetospeed failed for %d", baud);
			अवरोध;

#घोषणा TTYCHAR(NAME, OP) \
		हाल OP: \
			अगर ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			tio.c_cc[NAME] = special_char_decode(u); \
			अवरोध;
#घोषणा TTYMODE(NAME, FIELD, OP) \
		हाल OP: \
			अगर ((r = sshbuf_get_u32(buf, &u)) != 0) \
				fatal_fr(r, "parse %s", #NAME); \
			अगर (u) \
				tio.FIELD |= NAME; \
			अन्यथा \
				tio.FIELD &= ~NAME; \
			अवरोध;

#समावेश "ttymodes.h"

#अघोषित TTYCHAR
#अघोषित TTYMODE

		शेष:
			debug("Ignoring unsupported tty mode opcode %d (0x%x)",
			    opcode, opcode);
			/*
			 * SSH2:
			 * Opcodes 1 to 159 are defined to have a uint32
			 * argument.
			 * Opcodes 160 to 255 are undefined and cause parsing
			 * to stop.
			 */
			अगर (opcode > 0 && opcode < 160) {
				अगर ((r = sshbuf_get_u32(buf, शून्य)) != 0)
					fatal_fr(r, "parse arg");
				अवरोध;
			} अन्यथा {
				logit_f("unknown opcode %d", opcode);
				जाओ set;
			}
		}
	}

set:
	len = sshbuf_len(buf);
	sshbuf_free(buf);
	अगर (len > 0) {
		logit_f("%zu bytes left", len);
		वापस;		/* Don't process bytes passed */
	}
	अगर (failure == -1)
		वापस;		/* Packet parsed ok but tcgetattr() failed */

	/* Set the new modes for the terminal. */
	अगर (tcsetattr(fd, TCSANOW, &tio) == -1)
		logit("Setting tty modes failed: %.100s", म_त्रुटि(त्रुटि_सं));
}
