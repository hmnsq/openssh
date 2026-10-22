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
#اگر_تعریف_شدہ HAVE_ERR_H
# include <err.h>
#اگر_ختم
#شامل "openbsd-compat/getopt_long.c"

ساکن خالی
usage(خالی)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	باہر_نکلو(1);
}

#تعریف_کرو MAX_MODIFICATIONS 256
ساخت modification {
	شمار { MOD_XOR, MOD_AND_OR } what;
	غیرعلامتی طویل طویل انحراف;
	uint8_t m1, m2;
};

ساکن خالی
parse_modification(ثابت حرف *s, ساخت modification *m)
{
	حرف what[16+1];
	صحیح n, m1, m2;

	bzero(m, حجم(*m));
	اگر ((n = لڑی_سے_پڑھو(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->انحراف, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	اگر (strcasecmp(what, "xor") == 0) {
		اگر (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		اگر (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} ورنہ اگر (strcasecmp(what, "andor") == 0) {
		اگر (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		اگر (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		اگر (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} ورنہ
		errx(1, "Invalid modification type \"%s\"", what);
}

صحیح
مین(صحیح argc, حرف **argv)
{
	صحیح ch;
	u_char buf[8192];
	سائز_t کل;
	ssize_t r, s, o;
	ساخت modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, عدد_mods = 0;

	جب ((ch = getopt(argc, argv, "wm:")) != -1) {
		انتخاب (ch) {
		حالت 'm':
			اگر (عدد_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[عدد_mods++]));
			توڑو;
		حالت 'w':
			wflag = 1;
			توڑو;
		طےشدہ:
			usage();
			/* NOTREACHED */
		}
	}
	برائے (کل = 0;;) {
		r = s = اقرأ(STDIN_FILENO, buf, حجم(buf));
		اگر (r == 0)
			توڑو;
		اگر (r < 0) {
			اگر (errno == EAGAIN || errno == EINTR)
				جاری;
			err(1, "read");
		}
		برائے (i = 0; i < عدد_mods; i++) {
			اگر (mods[i].انحراف < کل ||
			    mods[i].انحراف >= کل + s)
				جاری;
			انتخاب (mods[i].what) {
			حالت MOD_XOR:
				buf[mods[i].انحراف - کل] ^= mods[i].m1;
				توڑو;
			حالت MOD_AND_OR:
				buf[mods[i].انحراف - کل] &= mods[i].m1;
				buf[mods[i].انحراف - کل] |= mods[i].m2;
				توڑو;
			}
		}
		برائے (o = 0; o < s; o += r) {
			r = اكتب(STDOUT_FILENO, buf + o, s - o);
			اگر (r == 0)
				توڑو;
			اگر (r < 0) {
				اگر (errno == EAGAIN || errno == EINTR)
					جاری;
				err(1, "write");
			}
		}
		کل += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	برائے (i = 0; wflag && i < عدد_mods; i++) {
		اگر (mods[i].انحراف < کل)
			جاری;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	واپس r;
}
