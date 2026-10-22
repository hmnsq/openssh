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
parse_modification(अचर वर्ण *s, संरचना modification *m)
{
	वर्ण what[16+1];
	पूर्णाङ्क n, m1, m2;

	bzero(m, परिमाण(*m));
	यदि ((n = माला_पूछो(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	यदि (strcasecmp(what, "xor") == 0) {
		यदि (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		यदि (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} अन्यथा यदि (strcasecmp(what, "andor") == 0) {
		यदि (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		यदि (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		यदि (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} अन्यथा
		errx(1, "Invalid modification type \"%s\"", what);
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क ch;
	u_char buf[8192];
	माप_प्रकार total;
	ssize_t r, s, o;
	संरचना modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, अङ्क_mods = 0;

	जबसम्म ((ch = getopt(argc, argv, "wm:")) != -1) {
		विकल्प (ch) {
		पक्ष 'm':
			यदि (अङ्क_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[अङ्क_mods++]));
			रोक;
		पक्ष 'w':
			wflag = 1;
			रोक;
		स्वभाव:
			usage();
			/* NOTREACHED */
		}
	}
	लागि (total = 0;;) {
		r = s = पठ(STDIN_FILENO, buf, परिमाण(buf));
		यदि (r == 0)
			रोक;
		यदि (r < 0) {
			यदि (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
				जारी;
			err(1, "read");
		}
		लागि (i = 0; i < अङ्क_mods; i++) {
			यदि (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				जारी;
			विकल्प (mods[i].what) {
			पक्ष MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				रोक;
			पक्ष MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				रोक;
			}
		}
		लागि (o = 0; o < s; o += r) {
			r = लिख(STDOUT_FILENO, buf + o, s - o);
			यदि (r == 0)
				रोक;
			यदि (r < 0) {
				यदि (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
					जारी;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	लागि (i = 0; wflag && i < अङ्क_mods; i++) {
		यदि (mods[i].offset < total)
			जारी;
		r = 1;
		ख_लिखो(मानक_त्रुटि, "modpipe: warning - mod %u not reached\n", i);
	}
	फर्काऊ r;
}
