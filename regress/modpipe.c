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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <unistd.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#شامل "openbsd-compat/getopt_long.c"

ایستا تهی
usage(تهی)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
ساختار modification {
	شمارش { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

ایستا تهی
parse_modification(ثابت نویسه *s, ساختار modification *m)
{
	نویسه what[16+1];
	صحیح n, m1, m2;

	bzero(m, اندازه(*m));
	اگر ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	اگر (strcasecmp(what, "xor") == 0) {
		اگر (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		اگر (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} وگرنه اگر (strcasecmp(what, "andor") == 0) {
		اگر (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		اگر (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		اگر (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} وگرنه
		errx(1, "Invalid modification type \"%s\"", what);
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	صحیح ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	ساختار modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, رقم_mods = 0;

	وقتی ((ch = getopt(argc, argv, "wm:")) != -1) {
		انتخاب (ch) {
		حالت 'm':
			اگر (رقم_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[رقم_mods++]));
			بشکن;
		حالت 'w':
			wflag = 1;
			بشکن;
		پیشفرض:
			usage();
			/* NOTREACHED */
		}
	}
	برای (total = 0;;) {
		r = s = اقرأ(STDIN_FILENO, buf, اندازه(buf));
		اگر (r == 0)
			بشکن;
		اگر (r < 0) {
			اگر (errno == EAGAIN || errno == EINTR)
				ادامه;
			err(1, "read");
		}
		برای (i = 0; i < رقم_mods; i++) {
			اگر (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				ادامه;
			انتخاب (mods[i].what) {
			حالت MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				بشکن;
			حالت MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				بشکن;
			}
		}
		برای (o = 0; o < s; o += r) {
			r = اكتب(STDOUT_FILENO, buf + o, s - o);
			اگر (r == 0)
				بشکن;
			اگر (r < 0) {
				اگر (errno == EAGAIN || errno == EINTR)
					ادامه;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	برای (i = 0; wflag && i < رقم_mods; i++) {
		اگر (mods[i].offset < total)
			ادامه;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	بازگشت r;
}
