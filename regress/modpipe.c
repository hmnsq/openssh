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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#अन्तर्भाव "openbsd-compat/getopt_long.c"

स्थिर शून्य
usage(शून्य)
{
	ख_लिखो(मानक_त्रुटि, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	ख_लिखो(मानक_त्रुटि, "modspec is one of:\n");
	ख_लिखो(मानक_त्रुटि, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	ख_लिखो(मानक_त्रुटि, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	निकास(1);
}

#define MAX_MODIFICATIONS 256
संरचना modification {
	गणना { MOD_XOR, MOD_AND_OR } what;
	अचिन्हित दीर्घ दीर्घ offset;
	uint8_t m1, m2;
};

स्थिर शून्य
parse_modification(स्थिरांक अक्षर *s, संरचना modification *m)
{
	अक्षर what[16+1];
	पूर्णांक n, m1, m2;

	bzero(m, आकार(*m));
	जर ((n = माला_पूछो(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	जर (strcasecmp(what, "xor") == 0) {
		जर (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		जर (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} अन्यथा जर (strcasecmp(what, "andor") == 0) {
		जर (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		जर (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		जर (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} अन्यथा
		errx(1, "Invalid modification type \"%s\"", what);
}

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक ch;
	u_char buf[8192];
	माप_प्रकार total;
	ssize_t r, s, o;
	संरचना modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, अंक_mods = 0;

	पर्यंत ((ch = getopt(argc, argv, "wm:")) != -1) {
		निवड (ch) {
		स्थिती 'm':
			जर (अंक_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[अंक_mods++]));
			थांबा;
		स्थिती 'w':
			wflag = 1;
			थांबा;
		पूर्वनिर्धारित:
			usage();
			/* NOTREACHED */
		}
	}
	साठी (total = 0;;) {
		r = s = पठ(STDIN_FILENO, buf, आकार(buf));
		जर (r == 0)
			थांबा;
		जर (r < 0) {
			जर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
				सुरूठेवा;
			err(1, "read");
		}
		साठी (i = 0; i < अंक_mods; i++) {
			जर (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				सुरूठेवा;
			निवड (mods[i].what) {
			स्थिती MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				थांबा;
			स्थिती MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				थांबा;
			}
		}
		साठी (o = 0; o < s; o += r) {
			r = लिख(STDOUT_FILENO, buf + o, s - o);
			जर (r == 0)
				थांबा;
			जर (r < 0) {
				जर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
					सुरूठेवा;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	साठी (i = 0; wflag && i < अंक_mods; i++) {
		जर (mods[i].offset < total)
			सुरूठेवा;
		r = 1;
		ख_लिखो(मानक_त्रुटि, "modpipe: warning - mod %u not reached\n", i);
	}
	परत r;
}
