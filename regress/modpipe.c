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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#அந்தர்பாவ "openbsd-compat/getopt_long.c"

நிலையான வெறுமை
usage(வெறுமை)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
கட்டமைப்பு modification {
	எண்ணிக்கை { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

நிலையான வெறுமை
parse_modification(மாறிலி எழுத்து *s, கட்டமைப்பு modification *m)
{
	எழுத்து what[16+1];
	முழு n, m1, m2;

	bzero(m, அளவு(*m));
	எனில் ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	எனில் (strcasecmp(what, "xor") == 0) {
		எனில் (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		எனில் (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} இல்லையெனில் எனில் (strcasecmp(what, "andor") == 0) {
		எனில் (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		எனில் (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		எனில் (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} இல்லையெனில்
		errx(1, "Invalid modification type \"%s\"", what);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	முழு ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	கட்டமைப்பு modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, இலக்கம்_mods = 0;

	போது ((ch = getopt(argc, argv, "wm:")) != -1) {
		தேர்வு (ch) {
		நிலை 'm':
			எனில் (இலக்கம்_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[இலக்கம்_mods++]));
			நிறுத்து;
		நிலை 'w':
			wflag = 1;
			நிறுத்து;
		இயல்பு:
			usage();
			/* NOTREACHED */
		}
	}
	க்கு (total = 0;;) {
		r = s = பட(STDIN_FILENO, buf, அளவு(buf));
		எனில் (r == 0)
			நிறுத்து;
		எனில் (r < 0) {
			எனில் (errno == EAGAIN || errno == EINTR)
				தொடர்;
			err(1, "read");
		}
		க்கு (i = 0; i < இலக்கம்_mods; i++) {
			எனில் (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				தொடர்;
			தேர்வு (mods[i].what) {
			நிலை MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				நிறுத்து;
			நிலை MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				நிறுத்து;
			}
		}
		க்கு (o = 0; o < s; o += r) {
			r = லிக(STDOUT_FILENO, buf + o, s - o);
			எனில் (r == 0)
				நிறுத்து;
			எனில் (r < 0) {
				எனில் (errno == EAGAIN || errno == EINTR)
					தொடர்;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	க்கு (i = 0; wflag && i < இலக்கம்_mods; i++) {
		எனில் (mods[i].offset < total)
			தொடர்;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	திரும்பு r;
}
