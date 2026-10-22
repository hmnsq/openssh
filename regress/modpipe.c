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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#অন্তর্ভাৱ "openbsd-compat/getopt_long.c"

স্থির শূন্য
usage(শূন্য)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
সংরচনা modification {
	গণনা { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

স্থির শূন্য
parse_modification(ধ্রুৱ ৱর্ণ *s, সংরচনা modification *m)
{
	ৱর্ণ what[16+1];
	পূর্ণাঙ্ক n, m1, m2;

	bzero(m, পরিমাণ(*m));
	যদি ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	যদি (strcasecmp(what, "xor") == 0) {
		যদি (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		যদি (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} অন্যথা যদি (strcasecmp(what, "andor") == 0) {
		যদি (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		যদি (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		যদি (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} অন্যথা
		errx(1, "Invalid modification type \"%s\"", what);
}

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, ৱর্ণ **argv)
{
	পূর্ণাঙ্ক ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	সংরচনা modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, অঙ্ক_mods = 0;

	যেতিয়ালৈ ((ch = getopt(argc, argv, "wm:")) != -1) {
		ৱিকল্প (ch) {
		পক্ষ 'm':
			যদি (অঙ্ক_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[অঙ্ক_mods++]));
			ভঙ্গ;
		পক্ষ 'w':
			wflag = 1;
			ভঙ্গ;
		স্ৱভাৱ:
			usage();
			/* NOTREACHED */
		}
	}
	বাবে (total = 0;;) {
		r = s = পঠ(STDIN_FILENO, buf, পরিমাণ(buf));
		যদি (r == 0)
			ভঙ্গ;
		যদি (r < 0) {
			যদি (errno == EAGAIN || errno == EINTR)
				অনুৱর্ত;
			err(1, "read");
		}
		বাবে (i = 0; i < অঙ্ক_mods; i++) {
			যদি (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				অনুৱর্ত;
			ৱিকল্প (mods[i].what) {
			পক্ষ MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				ভঙ্গ;
			পক্ষ MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				ভঙ্গ;
			}
		}
		বাবে (o = 0; o < s; o += r) {
			r = লিখ(STDOUT_FILENO, buf + o, s - o);
			যদি (r == 0)
				ভঙ্গ;
			যদি (r < 0) {
				যদি (errno == EAGAIN || errno == EINTR)
					অনুৱর্ত;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	বাবে (i = 0; wflag && i < অঙ্ক_mods; i++) {
		যদি (mods[i].offset < total)
			অনুৱর্ত;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	ঘূৰাই r;
}
