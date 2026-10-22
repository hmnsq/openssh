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
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
संरचना modification {
	गणना { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

स्थिर शून्य
parse_modification(ध्रुव वर्ण *s, संरचना modification *m)
{
	वर्ण what[16+1];
	पूर्णाङ्क n, m1, m2;

	bzero(m, परिमाण(*m));
	सचे ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	सचे (strcasecmp(what, "xor") == 0) {
		सचे (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		सचे (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} अञ्ञथा सचे (strcasecmp(what, "andor") == 0) {
		सचे (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		सचे (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		सचे (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} अञ्ञथा
		errx(1, "Invalid modification type \"%s\"", what);
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	संरचना modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, अङ्कः_mods = 0;

	याव ((ch = getopt(argc, argv, "wm:")) != -1) {
		विकल्प (ch) {
		पक्ष 'm':
			सचे (अङ्कः_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[अङ्कः_mods++]));
			भङ्ग;
		पक्ष 'w':
			wflag = 1;
			भङ्ग;
		स्वभाव:
			usage();
			/* NOTREACHED */
		}
	}
	अत्थाय (total = 0;;) {
		r = s = पठ(STDIN_FILENO, buf, परिमाण(buf));
		सचे (r == 0)
			भङ्ग;
		सचे (r < 0) {
			सचे (errno == EAGAIN || errno == EINTR)
				अनुवर्त;
			err(1, "read");
		}
		अत्थाय (i = 0; i < अङ्कः_mods; i++) {
			सचे (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				अनुवर्त;
			विकल्प (mods[i].what) {
			पक्ष MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				भङ्ग;
			पक्ष MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				भङ्ग;
			}
		}
		अत्थाय (o = 0; o < s; o += r) {
			r = लिख(STDOUT_FILENO, buf + o, s - o);
			सचे (r == 0)
				भङ्ग;
			सचे (r < 0) {
				सचे (errno == EAGAIN || errno == EINTR)
					अनुवर्त;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	अत्थाय (i = 0; wflag && i < अङ्कः_mods; i++) {
		सचे (mods[i].offset < total)
			अनुवर्त;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	पटिनिवत्त r;
}
