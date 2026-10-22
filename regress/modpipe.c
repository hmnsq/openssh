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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#અન્તર્ભાવ "openbsd-compat/getopt_long.c"

સ્થિર શૂન્ય
usage(શૂન્ય)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
સંરચના modification {
	ગણના { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

સ્થિર શૂન્ય
parse_modification(અચલ અક્ષર *s, સંરચના modification *m)
{
	અક્ષર what[16+1];
	પૂર્ણાંક n, m1, m2;

	bzero(m, કદ(*m));
	જો ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	જો (strcasecmp(what, "xor") == 0) {
		જો (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		જો (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} નહીંતર જો (strcasecmp(what, "andor") == 0) {
		જો (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		જો (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		જો (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} નહીંતર
		errx(1, "Invalid modification type \"%s\"", what);
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	પૂર્ણાંક ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	સંરચના modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, અંક_mods = 0;

	જ્યારે ((ch = getopt(argc, argv, "wm:")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'm':
			જો (અંક_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[અંક_mods++]));
			તોડો;
		સ્થિતિ 'w':
			wflag = 1;
			તોડો;
		મૂળભૂત:
			usage();
			/* NOTREACHED */
		}
	}
	માટે (total = 0;;) {
		r = s = પઠ(STDIN_FILENO, buf, કદ(buf));
		જો (r == 0)
			તોડો;
		જો (r < 0) {
			જો (errno == EAGAIN || errno == EINTR)
				ચાલુ;
			err(1, "read");
		}
		માટે (i = 0; i < અંક_mods; i++) {
			જો (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				ચાલુ;
			પસંદગી (mods[i].what) {
			સ્થિતિ MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				તોડો;
			સ્થિતિ MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				તોડો;
			}
		}
		માટે (o = 0; o < s; o += r) {
			r = લિખ(STDOUT_FILENO, buf + o, s - o);
			જો (r == 0)
				તોડો;
			જો (r < 0) {
				જો (errno == EAGAIN || errno == EINTR)
					ચાલુ;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	માટે (i = 0; wflag && i < અંક_mods; i++) {
		જો (mods[i].offset < total)
			ચાલુ;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	પાછા r;
}
