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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "dh.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

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
#define TINY_ಸಂಖ್ಯೆ	(1UL<<16)

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
ಸ್ಥಿರ uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
ಸ್ಥಿರ uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
ಸ್ಥಿರ uint32_t *LargeSieve, largewords, largetries, largenumbers;
ಸ್ಥಿರ uint32_t largebits, largememory;	/* megabytes */
ಸ್ಥಿರ BIGNUM *largebase;

ಪೂರ್ಣಾಙ್ಕ gen_candidates(FILE *, uint32_t, BIGNUM *);
ಪೂರ್ಣಾಙ್ಕ ಅವಿಭಾಜ್ಯ_test(FILE *, FILE *, uint32_t, uint32_t, ವರ್ಣ *, unsigned long,
    unsigned long);

/*
 * print moduli out in consistent form,
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	ಸಂರಚನಾ tm *gtm;
	time_t time_now;
	ಪೂರ್ಣಾಙ್ಕ res;

	time(&time_now);
	gtm = gmtime(&time_now);
	ಯದಿ (gtm == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	ಯದಿ (res < 0)
		ಪ್ರತ್ಯಾಗಮ (-1);

	ಯದಿ (BN_print_fp(ofile, omodulus) < 1)
		ಪ್ರತ್ಯಾಗಮ (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	ಪ್ರತ್ಯಾಗಮ (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
ಸ್ಥಿರ ಶೂನ್ಯ
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_word(largebase, s32);
	ಯದಿ (r == 0)
		u = 0; /* s divides into largebase exactly */
	ಅನ್ಯಥಾ
		u = s - r; /* largebase+u is first entry divisible by s */

	ಯದಿ (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		ಯದಿ (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		ಪ್ರತಿ (u /= 2; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	ಯದಿ (r == 0)
		u = 0; /* s divides p exactly */
	ಅನ್ಯಥಾ
		u = s - r; /* p+u is first entry divisible by s */

	ಯದಿ (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		ಯಾವತ್ (u & 0x3) {
			ಯದಿ (SMALL_MAXIMUM - u < s)
				ಪ್ರತ್ಯಾಗಮ;
			u += s;
		}

		/* Mark all multiples of 4*s */
		ಪ್ರತಿ (u /= 4; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
ಪೂರ್ಣಾಙ್ಕ
gen_candidates(FILE *out, uint32_t power, BIGNUM *start)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_ಸಂಖ್ಯೆ >> 6;
	uint32_t tinywords = TINY_ಸಂಖ್ಯೆ >> 6;
	time_t time_start, time_stop;
	uint32_t i;
	ಪೂರ್ಣಾಙ್ಕ ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	ಯದಿ (power > TEST_MAXIMUM) {
		error("Too many bits: %u > %lu", power, TEST_MAXIMUM);
		ಪ್ರತ್ಯಾಗಮ (-1);
	} ಅನ್ಯಥಾ ಯದಿ (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_MAXIMUM;
	largewords = (largememory << SHIFT_MEGAWORD);

	TinySieve = xcalloc(tinywords, ಪರಿಮಾಣ(uint32_t));
	tinybits = tinywords << SHIFT_WORD;

	SmallSieve = xcalloc(smallwords, ಪರಿಮಾಣ(uint32_t));
	smallbits = smallwords << SHIFT_WORD;

	LargeSieve = xcalloc(largewords, ಪರಿಮಾಣ(uint32_t));
	largebits = largewords << SHIFT_WORD;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	ಯದಿ ((q = BN_new()) == ರಿಕ್ತ)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	ಯದಿ ((largebase = BN_new()) == ರಿಕ್ತ)
		fatal("BN_new failed");
	ಯದಿ (start == ರಿಕ್ತ) {
		ಯದಿ (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} ಅನ್ಯಥಾ {
		ಯದಿ (BN_copy(largebase, start) == ರಿಕ್ತ)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	ಯದಿ (BN_set_bit(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&time_start);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&time_start),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	ಪ್ರತಿ (i = 0; i < tinybits; i++) {
		ಯದಿ (BIT_TEST(TinySieve, i))
			ಅನುವರ್ತ; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		ಪ್ರತಿ (j = i + t; j < tinybits; j += t)
			BIT_SET(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	ಪ್ರತಿ (smallbase = TINY_ಸಂಖ್ಯೆ + 3;
	    smallbase < (SMALL_MAXIMUM - TINY_ಸಂಖ್ಯೆ);
	    smallbase += TINY_ಸಂಖ್ಯೆ) {
		ಪ್ರತಿ (i = 0; i < tinybits; i++) {
			ಯದಿ (BIT_TEST(TinySieve, i))
				ಅನುವರ್ತ; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			ಯದಿ (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} ಅನ್ಯಥಾ {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			ಯದಿ (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			ಪ್ರತಿ (s /= 2; s < smallbits; s += t)
				BIT_SET(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		ಪ್ರತಿ (i = 0; i < smallbits; i++) {
			ಯದಿ (BIT_TEST(SmallSieve, i))
				ಅನುವರ್ತ; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << SHIFT_BYTE);
	}

	time(&time_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&time_stop), largetries, (long long)(time_stop - time_start));

	ಪ್ರತಿ (j = r = 0; j < largebits; j++) {
		ಯದಿ (BIT_TEST(LargeSieve, j))
			ಅನುವರ್ತ; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		ಯದಿ (BN_set_word(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		ಯದಿ (BN_add(q, q, largebase) == 0)
			fatal("BN_add failed");
		ಯದಿ (qfileout(out, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			ಭಙ್ಗ;
		}

		r++; /* count q */
	}

	time(&time_stop);

	ಮುಕ್ತ(LargeSieve);
	ಮುಕ್ತ(SmallSieve);
	ಮುಕ್ತ(TinySieve);

	logit("%.24s Found %u candidates", ctime(&time_stop), r);

	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ
write_checkpoint(ವರ್ಣ *cpfile, uint32_t lineno)
{
	FILE *fp;
	ವರ್ಣ tmp[PATH_MAX];
	ಪೂರ್ಣಾಙ್ಕ r, writeok, closeok;

	r = snprintf(tmp, ಪರಿಮಾಣ(tmp), "%s.XXXXXXXXXX", cpfile);
	ಯದಿ (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((fp = fdopen(r, "w")) == ರಿಕ್ತ) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		ಪ್ರತ್ಯಾಗಮ;
	}
	writeok = (fprintf(fp, "%lu\n", (unsigned long)lineno) > 0);
	closeok = (fclose(fp) == 0);
	ಯದಿ (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (unsigned long)lineno, cpfile);
	} ಅನ್ಯಥಾ {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(ಶೂನ್ಯ)unlink(tmp);
	}
}

ಸ್ಥಿರ unsigned long
read_checkpoint(ವರ್ಣ *cpfile)
{
	FILE *fp;
	unsigned long lineno = 0;

	ಯದಿ ((fp = fopen(cpfile, "r")) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	ಅನ್ಯಥಾ
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	ಪ್ರತ್ಯಾಗಮ lineno;
}

ಸ್ಥಿರ unsigned long
ಎಣಿಕೆ_ಸಾಲುಗಳು(FILE *f)
{
	unsigned long ಎಣಿಕೆ = 0;
	ವರ್ಣ lp[QLINESIZE + 1];

	ಯದಿ (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		ಪ್ರತ್ಯಾಗಮ ULONG_MAX;
	}
	ಯಾವತ್ (fgets(lp, QLINESIZE + 1, f) != ರಿಕ್ತ)
		ಎಣಿಕೆ++;
	rewind(f);
	debug("input file has %lu lines", ಎಣಿಕೆ);
	ಪ್ರತ್ಯಾಗಮ ಎಣಿಕೆ;
}

ಸ್ಥಿರ ವರ್ಣ *
fmt_time(time_t seconds)
{
	ಪೂರ್ಣಾಙ್ಕ day, hr, min;
	ಸ್ಥಿರ ವರ್ಣ buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	ಯದಿ (day > 0)
		snprintf(buf, ಪರಿಮಾಣ buf, "%dd %d:%02d", day, hr, min);
	ಅನ್ಯಥಾ
		snprintf(buf, ಪರಿಮಾಣ buf, "%d:%02d", hr, min);
	ಪ್ರತ್ಯಾಗಮ buf;
}

ಸ್ಥಿರ ಶೂನ್ಯ
print_progress(unsigned long start_lineno, unsigned long current_lineno,
    unsigned long end_lineno)
{
	ಸ್ಥಿರ time_t time_start, time_prev;
	time_t time_now, elapsed;
	unsigned long ಅಂಕೆ_to_process, processed, remaining, percent, eta;
	ದ್ವಿಗುಣ time_per_ಸಾಲು;
	ವರ್ಣ *eta_str;

	time_now = monotime();
	ಯದಿ (time_start == 0) {
		time_start = time_prev = time_now;
		ಪ್ರತ್ಯಾಗಮ;
	}
	/* print progress after 1m then once per 5m */
	ಯದಿ (time_now - time_prev < 5 * 60)
		ಪ್ರತ್ಯಾಗಮ;
	time_prev = time_now;
	elapsed = time_now - time_start;
	processed = current_lineno - start_lineno;
	remaining = end_lineno - current_lineno;
	ಅಂಕೆ_to_process = end_lineno - start_lineno;
	time_per_ಸಾಲು = (ದ್ವಿಗುಣ)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&time_now);
	ಯದಿ (end_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&time_now),
		    processed, fmt_time(elapsed));
		ಪ್ರತ್ಯಾಗಮ;
	}
	percent = 100 * processed / ಅಂಕೆ_to_process;
	eta = time_per_ಸಾಲು * remaining;
	eta_str = xstrdup(fmt_time(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&time_now), processed, ಅಂಕೆ_to_process, percent,
	    fmt_time(elapsed), eta_str);
	ಮುಕ್ತ(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
ಪೂರ್ಣಾಙ್ಕ
ಅವಿಭಾಜ್ಯ_test(FILE *in, FILE *out, uint32_t trials, uint32_t generator_wanted,
    ವರ್ಣ *checkpoint_file, unsigned long start_lineno, unsigned long ಅಂಕೆ_ಸಾಲುಗಳು)
{
	BIGNUM *q, *p, *a;
	ವರ್ಣ *cp, *lp;
	uint32_t ಎಣಿಕೆ_in = 0, ಎಣಿಕೆ_out = 0, ಎಣಿಕೆ_possible = 0;
	uint32_t generator_known, in_tests, in_tries, in_type, in_size;
	unsigned long last_processed = 0, end_lineno;
	time_t time_start, time_stop;
	ಪೂರ್ಣಾಙ್ಕ res, is_ಅವಿಭಾಜ್ಯ;

	ಯದಿ (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	ಯದಿ (ಅಂಕೆ_ಸಾಲುಗಳು == 0)
		end_lineno = ಎಣಿಕೆ_ಸಾಲುಗಳು(in);
	ಅನ್ಯಥಾ
		end_lineno = start_lineno + ಅಂಕೆ_ಸಾಲುಗಳು;

	time(&time_start);

	ಯದಿ ((p = BN_new()) == ರಿಕ್ತ)
		fatal("BN_new failed");
	ಯದಿ ((q = BN_new()) == ರಿಕ್ತ)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&time_start), trials, generator_wanted);

	ಯದಿ (checkpoint_file != ರಿಕ್ತ)
		last_processed = read_checkpoint(checkpoint_file);
	last_processed = start_lineno = MAXIMUM(last_processed, start_lineno);
	ಯದಿ (end_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", last_processed);
	ಅನ್ಯಥಾ
		debug("process from line %lu to line %lu", last_processed,
		    end_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	ಯಾವತ್ (fgets(lp, QLINESIZE + 1, in) != ರಿಕ್ತ && ಎಣಿಕೆ_in < end_lineno) {
		ಎಣಿಕೆ_in++;
		ಯದಿ (ಎಣಿಕೆ_in <= last_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", ಎಣಿಕೆ_in);
			ಅನುವರ್ತ;
		}
		ಯದಿ (checkpoint_file != ರಿಕ್ತ)
			write_checkpoint(checkpoint_file, ಎಣಿಕೆ_in);
		print_progress(start_lineno, ಎಣಿಕೆ_in, end_lineno);
		ಯದಿ (strlen(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", ಎಣಿಕೆ_in);
			ಅನುವರ್ತ;
		}

		/* XXX - fragile parser */
		/* time */
		cp = &lp[14];	/* (skip) */

		/* type */
		in_type = strtoul(cp, &cp, 10);

		/* tests */
		in_tests = strtoul(cp, &cp, 10);

		ಯದಿ (in_tests & MODULI_TESTS_COMPOSITE) {
			debug2("%10u: known composite", ಎಣಿಕೆ_in);
			ಅನುವರ್ತ;
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
		ವಿಕಲ್ಪ (in_type) {
		ಪಕ್ಷ MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", ಎಣಿಕೆ_in, in_type);
			a = q;
			ಯದಿ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			ಯದಿ (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			ಯದಿ (BN_add_word(p, 1) == 0)
				fatal("BN_add_word failed");
			in_size += 1;
			generator_known = 0;
			ಭಙ್ಗ;
		ಪಕ್ಷ MODULI_TYPE_UNSTRUCTURED:
		ಪಕ್ಷ MODULI_TYPE_SAFE:
		ಪಕ್ಷ MODULI_TYPE_SCHNORR:
		ಪಕ್ಷ MODULI_TYPE_STRONG:
		ಪಕ್ಷ MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", ಎಣಿಕೆ_in, in_type);
			a = p;
			ಯದಿ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			ಯದಿ (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			debug2("Unknown prime type");
			ಭಙ್ಗ;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		ಯದಿ ((uint32_t)BN_ಅಂಕೆ_bits(p) != (in_size + 1)) {
			debug2("%10u: bit size %u mismatch", ಎಣಿಕೆ_in, in_size);
			ಅನುವರ್ತ;
		}
		ಯದಿ (in_size < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", ಎಣಿಕೆ_in, in_size);
			ಅನುವರ್ತ;
		}

		ಯದಿ (in_tests & MODULI_TESTS_MILLER_RABIN)
			in_tries += trials;
		ಅನ್ಯಥಾ
			in_tries = trials;

		/*
		 * guess unknown generator
		 */
		ಯದಿ (generator_known == 0) {
			ಯದಿ (BN_mod_word(p, 24) == 11)
				generator_known = 2;
			ಅನ್ಯಥಾ {
				uint32_t r = BN_mod_word(p, 10);

				ಯದಿ (r == 3 || r == 7)
					generator_known = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		ಯದಿ (generator_wanted > 0 &&
		    generator_wanted != generator_known) {
			debug2("%10u: generator %d != %d",
			    ಎಣಿಕೆ_in, generator_known, generator_wanted);
			ಅನುವರ್ತ;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		ಯದಿ (generator_known == 0) {
			debug2("%10u: no known generator", ಎಣಿಕೆ_in);
			ಅನುವರ್ತ;
		}

		ಎಣಿಕೆ_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_ಅವಿಭಾಜ್ಯ = BN_is_ಅವಿಭಾಜ್ಯ_ex(q, 1, ರಿಕ್ತ, ರಿಕ್ತ);
		ಯದಿ (is_ಅವಿಭಾಜ್ಯ < 0)
			fatal("BN_is_prime_ex failed");
		ಯದಿ (is_ಅವಿಭಾಜ್ಯ == 0) {
			debug("%10u: q failed first possible prime test",
			    ಎಣಿಕೆ_in);
			ಅನುವರ್ತ;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_ಅವಿಭಾಜ್ಯ = BN_is_ಅವಿಭಾಜ್ಯ_ex(p, trials, ರಿಕ್ತ, ರಿಕ್ತ);
		ಯದಿ (is_ಅವಿಭಾಜ್ಯ < 0)
			fatal("BN_is_prime_ex failed");
		ಯದಿ (is_ಅವಿಭಾಜ್ಯ == 0) {
			debug("%10u: p is not prime", ಎಣಿಕೆ_in);
			ಅನುವರ್ತ;
		}
		debug("%10u: p is almost certainly prime", ಎಣಿಕೆ_in);

		/* recheck q more rigorously */
		is_ಅವಿಭಾಜ್ಯ = BN_is_ಅವಿಭಾಜ್ಯ_ex(q, trials - 1, ರಿಕ್ತ, ರಿಕ್ತ);
		ಯದಿ (is_ಅವಿಭಾಜ್ಯ < 0)
			fatal("BN_is_prime_ex failed");
		ಯದಿ (is_ಅವಿಭಾಜ್ಯ == 0) {
			debug("%10u: q is not prime", ಎಣಿಕೆ_in);
			ಅನುವರ್ತ;
		}
		debug("%10u: q is almost certainly prime", ಎಣಿಕೆ_in);

		ಯದಿ (qfileout(out, MODULI_TYPE_SAFE,
		    in_tests | MODULI_TESTS_MILLER_RABIN,
		    in_tries, in_size, generator_known, p)) {
			res = -1;
			ಭಙ್ಗ;
		}

		ಎಣಿಕೆ_out++;
	}

	time(&time_stop);
	ಮುಕ್ತ(lp);
	BN_free(p);
	BN_free(q);

	ಯದಿ (checkpoint_file != ರಿಕ್ತ)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&time_stop), ಎಣಿಕೆ_out, ಎಣಿಕೆ_possible,
	    (long) (time_stop - time_start));

	ಪ್ರತ್ಯಾಗಮ (res);
}

#endif /* WITH_OPENSSL */
