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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <unistd.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#ضمن "openbsd-compat/getopt_long.c"

ساكن فراغ
usage(فراغ)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
بنية modification {
	تعداد { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

ساكن فراغ
parse_modification(ثابت حرف *s, بنية modification *m)
{
	حرف what[16+1];
	صحيح n, m1, m2;

	bzero(m, حجم(*m));
	إذا ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	إذا (strcasecmp(what, "xor") == 0) {
		إذا (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		إذا (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} وإلا إذا (strcasecmp(what, "andor") == 0) {
		إذا (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		إذا (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		إذا (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} وإلا
		errx(1, "Invalid modification type \"%s\"", what);
}

صحيح
main(صحيح argc, حرف **argv)
{
	صحيح ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	بنية modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, عدد_mods = 0;

	طالما ((ch = getopt(argc, argv, "wm:")) != -1) {
		بدل (ch) {
		حالة 'm':
			إذا (عدد_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[عدد_mods++]));
			اكسر;
		حالة 'w':
			wflag = 1;
			اكسر;
		افتراضي:
			usage();
			/* NOTREACHED */
		}
	}
	لكل (total = 0;;) {
		r = s = اقرأ(STDIN_FILENO, buf, حجم(buf));
		إذا (r == 0)
			اكسر;
		إذا (r < 0) {
			إذا (errno == EAGAIN || errno == EINTR)
				استمر;
			err(1, "read");
		}
		لكل (i = 0; i < عدد_mods; i++) {
			إذا (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				استمر;
			بدل (mods[i].what) {
			حالة MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				اكسر;
			حالة MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				اكسر;
			}
		}
		لكل (o = 0; o < s; o += r) {
			r = اكتب(STDOUT_FILENO, buf + o, s - o);
			إذا (r == 0)
				اكسر;
			إذا (r < 0) {
				إذا (errno == EAGAIN || errno == EINTR)
					استمر;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	لكل (i = 0; wflag && i < عدد_mods; i++) {
		إذا (mods[i].offset < total)
			استمر;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	أرجع r;
}
