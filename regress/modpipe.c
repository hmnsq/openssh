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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_ERR_H
# include <err.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "openbsd-compat/getopt_long.c"

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	ನಿರ್ಗಮಿಸು(1);
}

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_MODIFICATIONS 256
ರಚನೆ modification {
	ಎಣಿಕೆ { MOD_XOR, MOD_AND_OR } what;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ ಸ್ಥಾನಾಂತರ;
	uint8_t m1, m2;
};

ಸ್ಥಿರ ಶೂನ್ಯ
parse_modification(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ರಚನೆ modification *m)
{
	ಅಕ್ಷರ what[16+1];
	ಪೂರ್ಣಾಂಕ n, m1, m2;

	bzero(m, ಗಾತ್ರ(*m));
	ಆದರೆ ((n = ಅಕ್ಷರಸರಣಿ_ಓದು(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->ಸ್ಥಾನಾಂತರ, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	ಆದರೆ (strcasecmp(what, "xor") == 0) {
		ಆದರೆ (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		ಆದರೆ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(what, "andor") == 0) {
		ಆದರೆ (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		ಆದರೆ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		ಆದರೆ (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} ಇಲ್ಲದಿದ್ದರೆ
		errx(1, "Invalid modification type \"%s\"", what);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಪೂರ್ಣಾಂಕ ch;
	u_char buf[8192];
	ಗಾತ್ರ_t ಒಟ್ಟು;
	ssize_t r, s, o;
	ರಚನೆ modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, ಅಂಕೆ_mods = 0;

	ಆಗ ((ch = getopt(argc, argv, "wm:")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'm':
			ಆದರೆ (ಅಂಕೆ_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[ಅಂಕೆ_mods++]));
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'w':
			wflag = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
			/* NOTREACHED */
		}
	}
	ಗಾಗಿ (ಒಟ್ಟು = 0;;) {
		r = s = ಪಠ(STDIN_FILENO, buf, ಗಾತ್ರ(buf));
		ಆದರೆ (r == 0)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (r < 0) {
			ಆದರೆ (errno == EAGAIN || errno == EINTR)
				ಮುಂದುವರಿ;
			err(1, "read");
		}
		ಗಾಗಿ (i = 0; i < ಅಂಕೆ_mods; i++) {
			ಆದರೆ (mods[i].ಸ್ಥಾನಾಂತರ < ಒಟ್ಟು ||
			    mods[i].ಸ್ಥಾನಾಂತರ >= ಒಟ್ಟು + s)
				ಮುಂದುವರಿ;
			ಆಯ್ಕೆ (mods[i].what) {
			ಸ್ಥಿತಿ MOD_XOR:
				buf[mods[i].ಸ್ಥಾನಾಂತರ - ಒಟ್ಟು] ^= mods[i].m1;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ MOD_AND_OR:
				buf[mods[i].ಸ್ಥಾನಾಂತರ - ಒಟ್ಟು] &= mods[i].m1;
				buf[mods[i].ಸ್ಥಾನಾಂತರ - ಒಟ್ಟು] |= mods[i].m2;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಗಾಗಿ (o = 0; o < s; o += r) {
			r = ಲಿಖ(STDOUT_FILENO, buf + o, s - o);
			ಆದರೆ (r == 0)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (r < 0) {
				ಆದರೆ (errno == EAGAIN || errno == EINTR)
					ಮುಂದುವರಿ;
				err(1, "write");
			}
		}
		ಒಟ್ಟು += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	ಗಾಗಿ (i = 0; wflag && i < ಅಂಕೆ_mods; i++) {
		ಆದರೆ (mods[i].ಸ್ಥಾನಾಂತರ < ಒಟ್ಟು)
			ಮುಂದುವರಿ;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	ಹಿಂತಿರುಗಿ r;
}
