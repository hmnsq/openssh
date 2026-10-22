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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/getopt_long.c"

ସ୍ଥିର ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
ସଂରଚନା modification {
	ଗଣନା { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

ସ୍ଥିର ଶୂନ୍ୟ
parse_modification(ଅଚଳ ଅକ୍ଷର *s, ସଂରଚନା modification *m)
{
	ଅକ୍ଷର what[16+1];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା n, m1, m2;

	bzero(m, ଆକାର(*m));
	ଯଦି ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	ଯଦି (strcasecmp(what, "xor") == 0) {
		ଯଦି (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		ଯଦି (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} ଅନ୍ୟଥା ଯଦି (strcasecmp(what, "andor") == 0) {
		ଯଦି (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		ଯଦି (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		ଯଦି (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} ଅନ୍ୟଥା
		errx(1, "Invalid modification type \"%s\"", what);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	ସଂରଚନା modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, ଅଙ୍କ_mods = 0;

	ଯେତେବେଳେ ((ch = getopt(argc, argv, "wm:")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'm':
			ଯଦି (ଅଙ୍କ_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[ଅଙ୍କ_mods++]));
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'w':
			wflag = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
			/* NOTREACHED */
		}
	}
	ପାଇଁ (total = 0;;) {
		r = s = ପଠ(STDIN_FILENO, buf, ଆକାର(buf));
		ଯଦି (r == 0)
			ଭାଙ୍ଗ;
		ଯଦି (r < 0) {
			ଯଦି (errno == EAGAIN || errno == EINTR)
				ଜାରି;
			err(1, "read");
		}
		ପାଇଁ (i = 0; i < ଅଙ୍କ_mods; i++) {
			ଯଦି (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				ଜାରି;
			ବାଛ (mods[i].what) {
			ସ୍ଥିତି MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				ଭାଙ୍ଗ;
			}
		}
		ପାଇଁ (o = 0; o < s; o += r) {
			r = ଲିଖ(STDOUT_FILENO, buf + o, s - o);
			ଯଦି (r == 0)
				ଭାଙ୍ଗ;
			ଯଦି (r < 0) {
				ଯଦି (errno == EAGAIN || errno == EINTR)
					ଜାରି;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	ପାଇଁ (i = 0; wflag && i < ଅଙ୍କ_mods; i++) {
		ଯଦି (mods[i].offset < total)
			ଜାରି;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	ଫେରନ୍ତୁ r;
}
