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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#ಅನ್ತರ್ಭಾವ "openbsd-compat/getopt_long.c"

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
ಸಂರಚನಾ modification {
	ಗಣನಾ { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

ಸ್ಥಿರ ಶೂನ್ಯ
parse_modification(ಧ್ರುವ ವರ್ಣ *s, ಸಂರಚನಾ modification *m)
{
	ವರ್ಣ what[16+1];
	ಪೂರ್ಣಾಙ್ಕ n, m1, m2;

	bzero(m, ಪರಿಮಾಣ(*m));
	ಯದಿ ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	ಯದಿ (strcasecmp(what, "xor") == 0) {
		ಯದಿ (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		ಯದಿ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(what, "andor") == 0) {
		ಯದಿ (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		ಯದಿ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		ಯದಿ (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} ಅನ್ಯಥಾ
		errx(1, "Invalid modification type \"%s\"", what);
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಪೂರ್ಣಾಙ್ಕ ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	ಸಂರಚನಾ modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, ಅಂಕೆ_mods = 0;

	ಯಾವತ್ ((ch = getopt(argc, argv, "wm:")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'm':
			ಯದಿ (ಅಂಕೆ_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[ಅಂಕೆ_mods++]));
			ಭಙ್ಗ;
		ಪಕ್ಷ 'w':
			wflag = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			usage();
			/* NOTREACHED */
		}
	}
	ಪ್ರತಿ (total = 0;;) {
		r = s = ಪಠ(STDIN_FILENO, buf, ಪರಿಮಾಣ(buf));
		ಯದಿ (r == 0)
			ಭಙ್ಗ;
		ಯದಿ (r < 0) {
			ಯದಿ (errno == EAGAIN || errno == EINTR)
				ಅನುವರ್ತ;
			err(1, "read");
		}
		ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_mods; i++) {
			ಯದಿ (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				ಅನುವರ್ತ;
			ವಿಕಲ್ಪ (mods[i].what) {
			ಪಕ್ಷ MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				ಭಙ್ಗ;
			ಪಕ್ಷ MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				ಭಙ್ಗ;
			}
		}
		ಪ್ರತಿ (o = 0; o < s; o += r) {
			r = ಲಿಖ(STDOUT_FILENO, buf + o, s - o);
			ಯದಿ (r == 0)
				ಭಙ್ಗ;
			ಯದಿ (r < 0) {
				ಯದಿ (errno == EAGAIN || errno == EINTR)
					ಅನುವರ್ತ;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	ಪ್ರತಿ (i = 0; wflag && i < ಅಂಕೆ_mods; i++) {
		ಯದಿ (mods[i].offset < total)
			ಅನುವರ್ತ;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	ಪ್ರತ್ಯಾಗಮ r;
}
