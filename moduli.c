/* $OpenBSD: moduli.c,v 1.41 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright 1994 Phil Karn <karn@qualcomm.com>
 * Copyright 1996-1998, 2003 William Allen Simpson <wsimpson@greendragon.com>
 * Copyright 2000 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Two-step process to generate safe primes for DHGEX
 *
 *  Sieve candidates for "safe" primes,
 *  suitable for use as Diffie-Hellman moduli;
 *  that is, where q = (p-1)/2 is also prime.
 *
 * First step: generate candidate primes (memory intensive)
 * Second step: test primes' safety (processor intensive)
 */

#അന്തര്ഭാവ "includes.h"

#ifdef WITH_OPENSSL

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/dh.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "dh.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"

#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

/*
 * File output defines
 */

/* need line long enough for largest moduli plus headers */
#define QLINESIZE		(100+8192)

/*
 * Size: decimal.
 * Specifies the number of the most significant bit (0 to M).
 * WARNING: internally, usually 1 to N.
 */
#define QSIZE_MINIMUM		(511)

/*
 * Prime sieving defines
 */

/* Constant: assuming 8 bit bytes and 32 bit words */
#define SHIFT_BIT	(3)
#define SHIFT_BYTE	(2)
#define SHIFT_WORD	(SHIFT_BIT+SHIFT_BYTE)
#define SHIFT_MEGABYTE	(20)
#define SHIFT_MEGAWORD	(SHIFT_MEGABYTE-SHIFT_BYTE)

/*
 * Do not increase this number beyond the unsigned integer bit size.
 * Due to a multiple of 4, it must be LESS than 128 (yielding 2**30 bits).
 */
#define LARGE_MAXIMUM	(127UL)	/* megabytes */

/*
 * Constant: when used with 32-bit integers, the largest sieve prime
 * has to be less than 2**32.
 */
#define SMALL_MAXIMUM	(0xffffffffUL)

/* Constant: can sieve all primes less than 2**32, as 65537**2 > 2**32-1. */
#define TINY_സംഖ്യ	(1UL<<16)

/* Ensure enough bit space for testing 2*q. */
#define TEST_MAXIMUM	(1UL<<16)
#define TEST_MINIMUM	(QSIZE_MINIMUM + 1)
/* real TEST_MINIMUM	(1UL << (SHIFT_WORD - TEST_POWER)) */
#define TEST_POWER	(3)	/* 2**n, n < SHIFT_WORD */

/* bit operations on 32-bit words */
#define BIT_CLEAR(a,n)	((a)[(n)>>SHIFT_WORD] &= ~(1L << ((n) & 31)))
#define BIT_SET(a,n)	((a)[(n)>>SHIFT_WORD] |= (1L << ((n) & 31)))
#define BIT_TEST(a,n)	((a)[(n)>>SHIFT_WORD] & (1L << ((n) & 31)))

/*
 * Prime testing defines
 */

/* Minimum number of primality tests to perform */
#define TRIAL_MINIMUM	(4)

/*
 * Sieving data (XXX - move to struct)
 */

/* sieve 2**16 */
സ്ഥിതം uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
സ്ഥിതം uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
സ്ഥിതം uint32_t *LargeSieve, largewords, largetries, largenumbers;
സ്ഥിതം uint32_t largebits, largememory;	/* megabytes */
സ്ഥിതം BIGNUM *largebase;

പൂർണ്ണസംഖ്യ gen_candidates(FILE *, uint32_t, BIGNUM *);
പൂർണ്ണസംഖ്യ അഭാജ്യം_test(FILE *, FILE *, uint32_t, uint32_t, അക്ഷരം *, unsigned long,
    unsigned long);

/*
 * print moduli out in consistent form,
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	ഘടന tm *gtm;
	time_t time_now;
	പൂർണ്ണസംഖ്യ res;

	time(&time_now);
	gtm = gmtime(&time_now);
	എങ്കിൽ (gtm == ശൂന്യ)
		തിരികെ -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	എങ്കിൽ (res < 0)
		തിരികെ (-1);

	എങ്കിൽ (BN_print_fp(ofile, omodulus) < 1)
		തിരികെ (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	തിരികെ (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
സ്ഥിതം ശൂന്യം
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_word(largebase, s32);
	എങ്കിൽ (r == 0)
		u = 0; /* s divides into largebase exactly */
	അല്ലെങ്കിൽ
		u = s - r; /* largebase+u is first entry divisible by s */

	എങ്കിൽ (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		എങ്കിൽ (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		വേണ്ടി (u /= 2; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	എങ്കിൽ (r == 0)
		u = 0; /* s divides p exactly */
	അല്ലെങ്കിൽ
		u = s - r; /* p+u is first entry divisible by s */

	എങ്കിൽ (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		ആകുമ്പോൾ (u & 0x3) {
			എങ്കിൽ (SMALL_MAXIMUM - u < s)
				തിരികെ;
			u += s;
		}

		/* Mark all multiples of 4*s */
		വേണ്ടി (u /= 4; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
പൂർണ്ണസംഖ്യ
gen_candidates(FILE *out, uint32_t power, BIGNUM *start)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_സംഖ്യ >> 6;
	uint32_t tinywords = TINY_സംഖ്യ >> 6;
	time_t time_start, time_stop;
	uint32_t i;
	പൂർണ്ണസംഖ്യ ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	എങ്കിൽ (power > TEST_MAXIMUM) {
		error("Too many bits: %u > %lu", power, TEST_MAXIMUM);
		തിരികെ (-1);
	} അല്ലെങ്കിൽ എങ്കിൽ (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		തിരികെ (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_MAXIMUM;
	largewords = (largememory << SHIFT_MEGAWORD);

	TinySieve = xcalloc(tinywords, വലുപ്പം(uint32_t));
	tinybits = tinywords << SHIFT_WORD;

	SmallSieve = xcalloc(smallwords, വലുപ്പം(uint32_t));
	smallbits = smallwords << SHIFT_WORD;

	LargeSieve = xcalloc(largewords, വലുപ്പം(uint32_t));
	largebits = largewords << SHIFT_WORD;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	എങ്കിൽ ((q = BN_new()) == ശൂന്യ)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	എങ്കിൽ ((largebase = BN_new()) == ശൂന്യ)
		fatal("BN_new failed");
	എങ്കിൽ (start == ശൂന്യ) {
		എങ്കിൽ (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (BN_copy(largebase, start) == ശൂന്യ)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	എങ്കിൽ (BN_set_bit(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&time_start);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&time_start),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	വേണ്ടി (i = 0; i < tinybits; i++) {
		എങ്കിൽ (BIT_TEST(TinySieve, i))
			തുടരുക; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		വേണ്ടി (j = i + t; j < tinybits; j += t)
			BIT_SET(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	വേണ്ടി (smallbase = TINY_സംഖ്യ + 3;
	    smallbase < (SMALL_MAXIMUM - TINY_സംഖ്യ);
	    smallbase += TINY_സംഖ്യ) {
		വേണ്ടി (i = 0; i < tinybits; i++) {
			എങ്കിൽ (BIT_TEST(TinySieve, i))
				തുടരുക; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			എങ്കിൽ (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} അല്ലെങ്കിൽ {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			എങ്കിൽ (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			വേണ്ടി (s /= 2; s < smallbits; s += t)
				BIT_SET(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		വേണ്ടി (i = 0; i < smallbits; i++) {
			എങ്കിൽ (BIT_TEST(SmallSieve, i))
				തുടരുക; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << SHIFT_BYTE);
	}

	time(&time_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&time_stop), largetries, (long long)(time_stop - time_start));

	വേണ്ടി (j = r = 0; j < largebits; j++) {
		എങ്കിൽ (BIT_TEST(LargeSieve, j))
			തുടരുക; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		എങ്കിൽ (BN_set_word(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		എങ്കിൽ (BN_add(q, q, largebase) == 0)
			fatal("BN_add failed");
		എങ്കിൽ (qfileout(out, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			നിർത്തുക;
		}

		r++; /* count q */
	}

	time(&time_stop);

	സ്വതന്ത്രം(LargeSieve);
	സ്വതന്ത്രം(SmallSieve);
	സ്വതന്ത്രം(TinySieve);

	logit("%.24s Found %u candidates", ctime(&time_stop), r);

	തിരികെ (ret);
}

സ്ഥിതം ശൂന്യം
write_checkpoint(അക്ഷരം *cpfile, uint32_t lineno)
{
	FILE *fp;
	അക്ഷരം tmp[PATH_MAX];
	പൂർണ്ണസംഖ്യ r, writeok, closeok;

	r = snprintf(tmp, വലുപ്പം(tmp), "%s.XXXXXXXXXX", cpfile);
	എങ്കിൽ (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		തിരികെ;
	}
	എങ്കിൽ ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		തിരികെ;
	}
	എങ്കിൽ ((fp = fdopen(r, "w")) == ശൂന്യ) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		തിരികെ;
	}
	writeok = (fprintf(fp, "%lu\n", (unsigned long)lineno) > 0);
	closeok = (fclose(fp) == 0);
	എങ്കിൽ (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (unsigned long)lineno, cpfile);
	} അല്ലെങ്കിൽ {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(ശൂന്യം)unlink(tmp);
	}
}

സ്ഥിതം unsigned long
read_checkpoint(അക്ഷരം *cpfile)
{
	FILE *fp;
	unsigned long lineno = 0;

	എങ്കിൽ ((fp = fopen(cpfile, "r")) == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	അല്ലെങ്കിൽ
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	തിരികെ lineno;
}

സ്ഥിതം unsigned long
എണ്ണം_വരികൾ(FILE *f)
{
	unsigned long എണ്ണം = 0;
	അക്ഷരം lp[QLINESIZE + 1];

	എങ്കിൽ (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		തിരികെ ULONG_MAX;
	}
	ആകുമ്പോൾ (fgets(lp, QLINESIZE + 1, f) != ശൂന്യ)
		എണ്ണം++;
	rewind(f);
	debug("input file has %lu lines", എണ്ണം);
	തിരികെ എണ്ണം;
}

സ്ഥിതം അക്ഷരം *
fmt_time(time_t seconds)
{
	പൂർണ്ണസംഖ്യ day, hr, min;
	സ്ഥിതം അക്ഷരം buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	എങ്കിൽ (day > 0)
		snprintf(buf, വലുപ്പം buf, "%dd %d:%02d", day, hr, min);
	അല്ലെങ്കിൽ
		snprintf(buf, വലുപ്പം buf, "%d:%02d", hr, min);
	തിരികെ buf;
}

സ്ഥിതം ശൂന്യം
print_progress(unsigned long start_lineno, unsigned long current_lineno,
    unsigned long end_lineno)
{
	സ്ഥിതം time_t time_start, time_prev;
	time_t time_now, elapsed;
	unsigned long അക്കം_to_process, processed, remaining, percent, eta;
	ഇരട്ട time_per_വരി;
	അക്ഷരം *eta_str;

	time_now = monotime();
	എങ്കിൽ (time_start == 0) {
		time_start = time_prev = time_now;
		തിരികെ;
	}
	/* print progress after 1m then once per 5m */
	എങ്കിൽ (time_now - time_prev < 5 * 60)
		തിരികെ;
	time_prev = time_now;
	elapsed = time_now - time_start;
	processed = current_lineno - start_lineno;
	remaining = end_lineno - current_lineno;
	അക്കം_to_process = end_lineno - start_lineno;
	time_per_വരി = (ഇരട്ട)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&time_now);
	എങ്കിൽ (end_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&time_now),
		    processed, fmt_time(elapsed));
		തിരികെ;
	}
	percent = 100 * processed / അക്കം_to_process;
	eta = time_per_വരി * remaining;
	eta_str = xstrdup(fmt_time(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&time_now), processed, അക്കം_to_process, percent,
	    fmt_time(elapsed), eta_str);
	സ്വതന്ത്രം(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
പൂർണ്ണസംഖ്യ
അഭാജ്യം_test(FILE *in, FILE *out, uint32_t trials, uint32_t generator_wanted,
    അക്ഷരം *checkpoint_file, unsigned long start_lineno, unsigned long അക്കം_വരികൾ)
{
	BIGNUM *q, *p, *a;
	അക്ഷരം *cp, *lp;
	uint32_t എണ്ണം_in = 0, എണ്ണം_out = 0, എണ്ണം_possible = 0;
	uint32_t generator_known, in_tests, in_tries, in_type, in_size;
	unsigned long last_processed = 0, end_lineno;
	time_t time_start, time_stop;
	പൂർണ്ണസംഖ്യ res, is_അഭാജ്യം;

	എങ്കിൽ (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		തിരികെ (-1);
	}

	എങ്കിൽ (അക്കം_വരികൾ == 0)
		end_lineno = എണ്ണം_വരികൾ(in);
	അല്ലെങ്കിൽ
		end_lineno = start_lineno + അക്കം_വരികൾ;

	time(&time_start);

	എങ്കിൽ ((p = BN_new()) == ശൂന്യ)
		fatal("BN_new failed");
	എങ്കിൽ ((q = BN_new()) == ശൂന്യ)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&time_start), trials, generator_wanted);

	എങ്കിൽ (checkpoint_file != ശൂന്യ)
		last_processed = read_checkpoint(checkpoint_file);
	last_processed = start_lineno = MAXIMUM(last_processed, start_lineno);
	എങ്കിൽ (end_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", last_processed);
	അല്ലെങ്കിൽ
		debug("process from line %lu to line %lu", last_processed,
		    end_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	ആകുമ്പോൾ (fgets(lp, QLINESIZE + 1, in) != ശൂന്യ && എണ്ണം_in < end_lineno) {
		എണ്ണം_in++;
		എങ്കിൽ (എണ്ണം_in <= last_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", എണ്ണം_in);
			തുടരുക;
		}
		എങ്കിൽ (checkpoint_file != ശൂന്യ)
			write_checkpoint(checkpoint_file, എണ്ണം_in);
		print_progress(start_lineno, എണ്ണം_in, end_lineno);
		എങ്കിൽ (strlen(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", എണ്ണം_in);
			തുടരുക;
		}

		/* XXX - fragile parser */
		/* time */
		cp = &lp[14];	/* (skip) */

		/* type */
		in_type = strtoul(cp, &cp, 10);

		/* tests */
		in_tests = strtoul(cp, &cp, 10);

		എങ്കിൽ (in_tests & MODULI_TESTS_COMPOSITE) {
			debug2("%10u: known composite", എണ്ണം_in);
			തുടരുക;
		}

		/* tries */
		in_tries = strtoul(cp, &cp, 10);

		/* size (most significant bit) */
		in_size = strtoul(cp, &cp, 10);

		/* generator (hex) */
		generator_known = strtoul(cp, &cp, 16);

		/* Skip white space */
		cp += strspn(cp, " ");

		/* modulus (hex) */
		തിരഞ്ഞെടുപ്പ് (in_type) {
		അവസ്ഥ MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", എണ്ണം_in, in_type);
			a = q;
			എങ്കിൽ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			എങ്കിൽ (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			എങ്കിൽ (BN_add_word(p, 1) == 0)
				fatal("BN_add_word failed");
			in_size += 1;
			generator_known = 0;
			നിർത്തുക;
		അവസ്ഥ MODULI_TYPE_UNSTRUCTURED:
		അവസ്ഥ MODULI_TYPE_SAFE:
		അവസ്ഥ MODULI_TYPE_SCHNORR:
		അവസ്ഥ MODULI_TYPE_STRONG:
		അവസ്ഥ MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", എണ്ണം_in, in_type);
			a = p;
			എങ്കിൽ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			എങ്കിൽ (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			debug2("Unknown prime type");
			നിർത്തുക;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		എങ്കിൽ ((uint32_t)BN_അക്കം_bits(p) != (in_size + 1)) {
			debug2("%10u: bit size %u mismatch", എണ്ണം_in, in_size);
			തുടരുക;
		}
		എങ്കിൽ (in_size < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", എണ്ണം_in, in_size);
			തുടരുക;
		}

		എങ്കിൽ (in_tests & MODULI_TESTS_MILLER_RABIN)
			in_tries += trials;
		അല്ലെങ്കിൽ
			in_tries = trials;

		/*
		 * guess unknown generator
		 */
		എങ്കിൽ (generator_known == 0) {
			എങ്കിൽ (BN_mod_word(p, 24) == 11)
				generator_known = 2;
			അല്ലെങ്കിൽ {
				uint32_t r = BN_mod_word(p, 10);

				എങ്കിൽ (r == 3 || r == 7)
					generator_known = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		എങ്കിൽ (generator_wanted > 0 &&
		    generator_wanted != generator_known) {
			debug2("%10u: generator %d != %d",
			    എണ്ണം_in, generator_known, generator_wanted);
			തുടരുക;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		എങ്കിൽ (generator_known == 0) {
			debug2("%10u: no known generator", എണ്ണം_in);
			തുടരുക;
		}

		എണ്ണം_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_അഭാജ്യം = BN_is_അഭാജ്യം_ex(q, 1, ശൂന്യ, ശൂന്യ);
		എങ്കിൽ (is_അഭാജ്യം < 0)
			fatal("BN_is_prime_ex failed");
		എങ്കിൽ (is_അഭാജ്യം == 0) {
			debug("%10u: q failed first possible prime test",
			    എണ്ണം_in);
			തുടരുക;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_അഭാജ്യം = BN_is_അഭാജ്യം_ex(p, trials, ശൂന്യ, ശൂന്യ);
		എങ്കിൽ (is_അഭാജ്യം < 0)
			fatal("BN_is_prime_ex failed");
		എങ്കിൽ (is_അഭാജ്യം == 0) {
			debug("%10u: p is not prime", എണ്ണം_in);
			തുടരുക;
		}
		debug("%10u: p is almost certainly prime", എണ്ണം_in);

		/* recheck q more rigorously */
		is_അഭാജ്യം = BN_is_അഭാജ്യം_ex(q, trials - 1, ശൂന്യ, ശൂന്യ);
		എങ്കിൽ (is_അഭാജ്യം < 0)
			fatal("BN_is_prime_ex failed");
		എങ്കിൽ (is_അഭാജ്യം == 0) {
			debug("%10u: q is not prime", എണ്ണം_in);
			തുടരുക;
		}
		debug("%10u: q is almost certainly prime", എണ്ണം_in);

		എങ്കിൽ (qfileout(out, MODULI_TYPE_SAFE,
		    in_tests | MODULI_TESTS_MILLER_RABIN,
		    in_tries, in_size, generator_known, p)) {
			res = -1;
			നിർത്തുക;
		}

		എണ്ണം_out++;
	}

	time(&time_stop);
	സ്വതന്ത്രം(lp);
	BN_free(p);
	BN_free(q);

	എങ്കിൽ (checkpoint_file != ശൂന്യ)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&time_stop), എണ്ണം_out, എണ്ണം_possible,
	    (long) (time_stop - time_start));

	തിരികെ (res);
}

#endif /* WITH_OPENSSL */
