/* $OpenBSD: modpipe.c,v 1.9 2026/03/06 07:06:45 dtucker Exp $ */

/*
 * Copyright (c) 2012 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <unistd.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <errno.h>
#अगर_घोषित HAVE_ERR_H
# include <err.h>
#पूर्ण_अगर
#समावेश "openbsd-compat/getopt_long.c"

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	ख_लिखो(मानक_त्रुटि, "modspec is one of:\n");
	ख_लिखो(मानक_त्रुटि, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	ख_लिखो(मानक_त्रुटि, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	निकास(1);
}

#घोषणा MAX_MODIFICATIONS 256
काष्ठा modification {
	क्रमागत { MOD_XOR, MOD_AND_OR } what;
	अचिन्हित दीर्घ दीर्घ offset;
	uint8_t m1, m2;
};

अटल व्योम
parse_modification(स्थिर अक्षर *s, काष्ठा modification *m)
{
	अक्षर what[16+1];
	पूर्णांक n, m1, m2;

	bzero(m, माप(*m));
	अगर ((n = माला_पूछो(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	अगर (strcasecmp(what, "xor") == 0) {
		अगर (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		अगर (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} अन्यथा अगर (strcasecmp(what, "andor") == 0) {
		अगर (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		अगर (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		अगर (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} अन्यथा
		errx(1, "Invalid modification type \"%s\"", what);
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक ch;
	u_char buf[8192];
	माप_प्रकार योग_2;
	ssize_t r, s, o;
	काष्ठा modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, अंक_mods = 0;

	जबतक ((ch = getopt(argc, argv, "wm:")) != -1) {
		चयन (ch) {
		हाल 'm':
			अगर (अंक_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[अंक_mods++]));
			अवरोध;
		हाल 'w':
			wflag = 1;
			अवरोध;
		शेष:
			usage();
			/* NOTREACHED */
		}
	}
	क्रम (योग_2 = 0;;) {
		r = s = पढ़ो(STDIN_FILENO, buf, माप(buf));
		अगर (r == 0)
			अवरोध;
		अगर (r < 0) {
			अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
				जारी;
			err(1, "read");
		}
		क्रम (i = 0; i < अंक_mods; i++) {
			अगर (mods[i].offset < योग_2 ||
			    mods[i].offset >= योग_2 + s)
				जारी;
			चयन (mods[i].what) {
			हाल MOD_XOR:
				buf[mods[i].offset - योग_2] ^= mods[i].m1;
				अवरोध;
			हाल MOD_AND_OR:
				buf[mods[i].offset - योग_2] &= mods[i].m1;
				buf[mods[i].offset - योग_2] |= mods[i].m2;
				अवरोध;
			}
		}
		क्रम (o = 0; o < s; o += r) {
			r = ग_लिखो(STDOUT_FILENO, buf + o, s - o);
			अगर (r == 0)
				अवरोध;
			अगर (r < 0) {
				अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
					जारी;
				err(1, "write");
			}
		}
		योग_2 += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	क्रम (i = 0; wflag && i < अंक_mods; i++) {
		अगर (mods[i].offset < योग_2)
			जारी;
		r = 1;
		ख_लिखो(मानक_त्रुटि, "modpipe: warning - mod %u not reached\n", i);
	}
	वापस r;
}
