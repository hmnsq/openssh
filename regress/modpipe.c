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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_ERR_H
# include <err.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/getopt_long.c"

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_MODIFICATIONS 256
ਬਣਤਰ modification {
	ਗਿਣਤੀ { MOD_XOR, MOD_AND_OR } what;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ ਵਿੱਥ;
	uint8_t m1, m2;
};

ਸਥਿਰ ਖਾਲੀ
parse_modification(ਅਚਲ ਅੱਖਰ *s, ਬਣਤਰ modification *m)
{
	ਅੱਖਰ what[16+1];
	ਪੂਰਨ n, m1, m2;

	bzero(m, ਆਕਾਰ(*m));
	ਜੇ ((n = ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->ਵਿੱਥ, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	ਜੇ (strcasecmp(what, "xor") == 0) {
		ਜੇ (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		ਜੇ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(what, "andor") == 0) {
		ਜੇ (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		ਜੇ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		ਜੇ (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} ਨਹੀਂਤਾਂ
		errx(1, "Invalid modification type \"%s\"", what);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਪੂਰਨ ch;
	u_char buf[8192];
	ਮਾਪ_t ਕੁੱਲ;
	ssize_t r, s, o;
	ਬਣਤਰ modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, ਅੰਕ_mods = 0;

	ਜਦੋਂ ((ch = getopt(argc, argv, "wm:")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'm':
			ਜੇ (ਅੰਕ_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[ਅੰਕ_mods++]));
			ਰੋਕੋ;
		ਹਾਲਤ 'w':
			wflag = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			usage();
			/* NOTREACHED */
		}
	}
	ਲਈ (ਕੁੱਲ = 0;;) {
		r = s = ਪਠ(STDIN_FILENO, buf, ਆਕਾਰ(buf));
		ਜੇ (r == 0)
			ਰੋਕੋ;
		ਜੇ (r < 0) {
			ਜੇ (errno == EAGAIN || errno == EINTR)
				ਜਾਰੀ;
			err(1, "read");
		}
		ਲਈ (i = 0; i < ਅੰਕ_mods; i++) {
			ਜੇ (mods[i].ਵਿੱਥ < ਕੁੱਲ ||
			    mods[i].ਵਿੱਥ >= ਕੁੱਲ + s)
				ਜਾਰੀ;
			ਚੋਣ (mods[i].what) {
			ਹਾਲਤ MOD_XOR:
				buf[mods[i].ਵਿੱਥ - ਕੁੱਲ] ^= mods[i].m1;
				ਰੋਕੋ;
			ਹਾਲਤ MOD_AND_OR:
				buf[mods[i].ਵਿੱਥ - ਕੁੱਲ] &= mods[i].m1;
				buf[mods[i].ਵਿੱਥ - ਕੁੱਲ] |= mods[i].m2;
				ਰੋਕੋ;
			}
		}
		ਲਈ (o = 0; o < s; o += r) {
			r = ਲਿਖ(STDOUT_FILENO, buf + o, s - o);
			ਜੇ (r == 0)
				ਰੋਕੋ;
			ਜੇ (r < 0) {
				ਜੇ (errno == EAGAIN || errno == EINTR)
					ਜਾਰੀ;
				err(1, "write");
			}
		}
		ਕੁੱਲ += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	ਲਈ (i = 0; wflag && i < ਅੰਕ_mods; i++) {
		ਜੇ (mods[i].ਵਿੱਥ < ਕੁੱਲ)
			ਜਾਰੀ;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	ਵਾਪਸ r;
}
