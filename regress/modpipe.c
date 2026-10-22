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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <errno.h>
#నిర్వచితమైతే HAVE_ERR_H
# include <err.h>
#అయితే_ముగింపు
#అన్తర్భావ "openbsd-compat/getopt_long.c"

స్థిర శూన్య
usage(శూన్య)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	నిష్క్రమించు(1);
}

#నిర్వచించు MAX_MODIFICATIONS 256
నిర్మాణం modification {
	గణన { MOD_XOR, MOD_AND_OR } what;
	గుర్తులేని దీర్ఘ దీర్ఘ స్థానభ్రంశం;
	uint8_t m1, m2;
};

స్థిర శూన్య
parse_modification(స్థిరరాశి అక్షరం *s, నిర్మాణం modification *m)
{
	అక్షరం what[16+1];
	పూర్ణాంకం n, m1, m2;

	bzero(m, పరిమాణం(*m));
	ఒకవేళ ((n = అక్షరశ్రేణి_చదువు(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->స్థానభ్రంశం, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	ఒకవేళ (strcasecmp(what, "xor") == 0) {
		ఒకవేళ (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		ఒకవేళ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} లేకపోతే ఒకవేళ (strcasecmp(what, "andor") == 0) {
		ఒకవేళ (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		ఒకవేళ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		ఒకవేళ (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} లేకపోతే
		errx(1, "Invalid modification type \"%s\"", what);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	పూర్ణాంకం ch;
	u_char buf[8192];
	కొలత_t మొత్తం;
	ssize_t r, s, o;
	నిర్మాణం modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, అంకె_mods = 0;

	అయితే ((ch = getopt(argc, argv, "wm:")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'm':
			ఒకవేళ (అంకె_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[అంకె_mods++]));
			ఆపు;
		స్థితి 'w':
			wflag = 1;
			ఆపు;
		అప్రమేయ:
			usage();
			/* NOTREACHED */
		}
	}
	కొరకు (మొత్తం = 0;;) {
		r = s = పఠ(STDIN_FILENO, buf, పరిమాణం(buf));
		ఒకవేళ (r == 0)
			ఆపు;
		ఒకవేళ (r < 0) {
			ఒకవేళ (errno == EAGAIN || errno == EINTR)
				కొనసాగు;
			err(1, "read");
		}
		కొరకు (i = 0; i < అంకె_mods; i++) {
			ఒకవేళ (mods[i].స్థానభ్రంశం < మొత్తం ||
			    mods[i].స్థానభ్రంశం >= మొత్తం + s)
				కొనసాగు;
			ఎంపిక (mods[i].what) {
			స్థితి MOD_XOR:
				buf[mods[i].స్థానభ్రంశం - మొత్తం] ^= mods[i].m1;
				ఆపు;
			స్థితి MOD_AND_OR:
				buf[mods[i].స్థానభ్రంశం - మొత్తం] &= mods[i].m1;
				buf[mods[i].స్థానభ్రంశం - మొత్తం] |= mods[i].m2;
				ఆపు;
			}
		}
		కొరకు (o = 0; o < s; o += r) {
			r = లిఖ(STDOUT_FILENO, buf + o, s - o);
			ఒకవేళ (r == 0)
				ఆపు;
			ఒకవేళ (r < 0) {
				ఒకవేళ (errno == EAGAIN || errno == EINTR)
					కొనసాగు;
				err(1, "write");
			}
		}
		మొత్తం += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	కొరకు (i = 0; wflag && i < అంకె_mods; i++) {
		ఒకవేళ (mods[i].స్థానభ్రంశం < మొత్తం)
			కొనసాగు;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	తిరిగి r;
}
