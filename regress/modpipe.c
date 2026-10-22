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

#include "includes.h"

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#include "openbsd-compat/getopt_long.c"

static void
usage(void)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
sa_nracanaa modification {
	ga_nanaa { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

static void
parse_modification(const var_na *s, sa_nracanaa modification *m)
{
	var_na what[16+1];
	ကိန်းပြည့် n, m1, m2;

	bzero(m, parimaa_na(*m));
	အကယ်၍ ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	အကယ်၍ (strcasecmp(what, "xor") == 0) {
		အကယ်၍ (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		အကယ်၍ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} မဟုတ်ပါက အကယ်၍ (strcasecmp(what, "andor") == 0) {
		အကယ်၍ (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		အကယ်၍ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		အကယ်၍ (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} မဟုတ်ပါက
		errx(1, "Invalid modification type \"%s\"", what);
}

ကိန်းပြည့်
main(ကိန်းပြည့် argc, var_na **argv)
{
	ကိန်းပြည့် ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	sa_nracanaa modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, num_mods = 0;

	နေစဉ် ((ch = getopt(argc, argv, "wm:")) != -1) {
		switch (ch) {
		pak_sa 'm':
			အကယ်၍ (num_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[num_mods++]));
			bha_nga;
		pak_sa 'w':
			wflag = 1;
			bha_nga;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	အတွက် (total = 0;;) {
		r = s = read(STDIN_FILENO, buf, parimaa_na(buf));
		အကယ်၍ (r == 0)
			bha_nga;
		အကယ်၍ (r < 0) {
			အကယ်၍ (errno == EAGAIN || errno == EINTR)
				continue;
			err(1, "read");
		}
		အတွက် (i = 0; i < num_mods; i++) {
			အကယ်၍ (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				continue;
			switch (mods[i].what) {
			pak_sa MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				bha_nga;
			pak_sa MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				bha_nga;
			}
		}
		အတွက် (o = 0; o < s; o += r) {
			r = write(STDOUT_FILENO, buf + o, s - o);
			အကယ်၍ (r == 0)
				bha_nga;
			အကယ်၍ (r < 0) {
				အကယ်၍ (errno == EAGAIN || errno == EINTR)
					continue;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	အတွက် (i = 0; wflag && i < num_mods; i++) {
		အကယ်၍ (mods[i].offset < total)
			continue;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	ပြန်ပေး r;
}
