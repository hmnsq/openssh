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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <errno.h>
#ifdef HAVE_ERR_H
# include <err.h>
#endif
#അന്തര്ഭാവ "openbsd-compat/getopt_long.c"

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
{
	fprintf(stderr, "Usage: modpipe -w [-m modspec ...] < in > out\n");
	fprintf(stderr, "modspec is one of:\n");
	fprintf(stderr, "    xor:offset:value       - XOR \"value\" at \"offset\"\n");
	fprintf(stderr, "    andor:offset:val1:val2 - AND \"val1\" then OR \"val2\" at \"offset\"\n");
	exit(1);
}

#define MAX_MODIFICATIONS 256
ഘടന modification {
	എണ്ണൽ { MOD_XOR, MOD_AND_OR } what;
	unsigned long long offset;
	uint8_t m1, m2;
};

സ്ഥിതം ശൂന്യം
parse_modification(സ്ഥിരം അക്ഷരം *s, ഘടന modification *m)
{
	അക്ഷരം what[16+1];
	പൂർണ്ണസംഖ്യ n, m1, m2;

	bzero(m, വലുപ്പം(*m));
	എങ്കിൽ ((n = sscanf(s, "%16[^:]%*[:]%llu%*[:]%i%*[:]%i",
	    what, &m->offset, &m1, &m2)) < 3)
		errx(1, "Invalid modification spec \"%s\"", s);
	എങ്കിൽ (strcasecmp(what, "xor") == 0) {
		എങ്കിൽ (n > 3)
			errx(1, "Invalid modification spec \"%s\"", s);
		എങ്കിൽ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid XOR modification value");
		m->what = MOD_XOR;
		m->m1 = m1;
	} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(what, "andor") == 0) {
		എങ്കിൽ (n != 4)
			errx(1, "Invalid modification spec \"%s\"", s);
		എങ്കിൽ (m1 < 0 || m1 > 0xff)
			errx(1, "Invalid AND modification value");
		എങ്കിൽ (m2 < 0 || m2 > 0xff)
			errx(1, "Invalid OR modification value");
		m->what = MOD_AND_OR;
		m->m1 = m1;
		m->m2 = m2;
	} അല്ലെങ്കിൽ
		errx(1, "Invalid modification type \"%s\"", what);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	പൂർണ്ണസംഖ്യ ch;
	u_char buf[8192];
	size_t total;
	ssize_t r, s, o;
	ഘടന modification mods[MAX_MODIFICATIONS];
	u_int i, wflag = 0, അക്കം_mods = 0;

	ആകുമ്പോൾ ((ch = getopt(argc, argv, "wm:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'm':
			എങ്കിൽ (അക്കം_mods >= MAX_MODIFICATIONS)
				errx(1, "Too many modifications");
			parse_modification(optarg, &(mods[അക്കം_mods++]));
			നിർത്തുക;
		അവസ്ഥ 'w':
			wflag = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			usage();
			/* NOTREACHED */
		}
	}
	വേണ്ടി (total = 0;;) {
		r = s = പഠ(STDIN_FILENO, buf, വലുപ്പം(buf));
		എങ്കിൽ (r == 0)
			നിർത്തുക;
		എങ്കിൽ (r < 0) {
			എങ്കിൽ (errno == EAGAIN || errno == EINTR)
				തുടരുക;
			err(1, "read");
		}
		വേണ്ടി (i = 0; i < അക്കം_mods; i++) {
			എങ്കിൽ (mods[i].offset < total ||
			    mods[i].offset >= total + s)
				തുടരുക;
			തിരഞ്ഞെടുപ്പ് (mods[i].what) {
			അവസ്ഥ MOD_XOR:
				buf[mods[i].offset - total] ^= mods[i].m1;
				നിർത്തുക;
			അവസ്ഥ MOD_AND_OR:
				buf[mods[i].offset - total] &= mods[i].m1;
				buf[mods[i].offset - total] |= mods[i].m2;
				നിർത്തുക;
			}
		}
		വേണ്ടി (o = 0; o < s; o += r) {
			r = ലിഖ(STDOUT_FILENO, buf + o, s - o);
			എങ്കിൽ (r == 0)
				നിർത്തുക;
			എങ്കിൽ (r < 0) {
				എങ്കിൽ (errno == EAGAIN || errno == EINTR)
					തുടരുക;
				err(1, "write");
			}
		}
		total += s;
	}
	/* Warn if modifications not reached in input stream */
	r = 0;
	വേണ്ടി (i = 0; wflag && i < അക്കം_mods; i++) {
		എങ്കിൽ (mods[i].offset < total)
			തുടരുക;
		r = 1;
		fprintf(stderr, "modpipe: warning - mod %u not reached\n", i);
	}
	തിരികെ r;
}
