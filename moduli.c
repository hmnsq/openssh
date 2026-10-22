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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL

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
#ವ್ಯಾಖ್ಯಾನಿಸು QLINESIZE		(100+8192)

/*
 * Size: decimal.
 * Specifies the number of the most significant bit (0 to M).
 * WARNING: internally, usually 1 to N.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು QSIZE_MINIMUM		(511)

/*
 * Prime sieving defines
 */

/* Constant: assuming 8 bit bytes and 32 bit words */
#ವ್ಯಾಖ್ಯಾನಿಸು ಸರಿಸು_ಬಿಟ್	(3)
#ವ್ಯಾಖ್ಯಾನಿಸು ಸರಿಸು_BYTE	(2)
#ವ್ಯಾಖ್ಯಾನಿಸು ಸರಿಸು_ಶಬ್ದ	(ಸರಿಸು_ಬಿಟ್+ಸರಿಸು_BYTE)
#ವ್ಯಾಖ್ಯಾನಿಸು ಸರಿಸು_MEGABYTE	(20)
#ವ್ಯಾಖ್ಯಾನಿಸು ಸರಿಸು_MEGAWORD	(ಸರಿಸು_MEGABYTE-ಸರಿಸು_BYTE)

/*
 * Do not increase this number beyond the unsigned integer bit size.
 * Due to a multiple of 4, it must be LESS than 128 (yielding 2**30 bits).
 */
#ವ್ಯಾಖ್ಯಾನಿಸು LARGE_ಗರಿಷ್ಠ	(127UL)	/* megabytes */

/*
 * Constant: when used with 32-bit integers, the largest sieve prime
 * has to be less than 2**32.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SMALL_ಗರಿಷ್ಠ	(0xffffffffUL)

/* Constant: can sieve all primes less than 2**32, as 65537**2 > 2**32-1. */
#ವ್ಯಾಖ್ಯಾನಿಸು TINY_ಸಂಖ್ಯೆ	(1UL<<16)

/* Ensure enough bit space for testing 2*q. */
#ವ್ಯಾಖ್ಯಾನಿಸು TEST_ಗರಿಷ್ಠ	(1UL<<16)
#ವ್ಯಾಖ್ಯಾನಿಸು TEST_MINIMUM	(QSIZE_MINIMUM + 1)
/* real TEST_MINIMUM	(1UL << (SHIFT_WORD - TEST_POWER)) */
#ವ್ಯಾಖ್ಯಾನಿಸು TEST_POWER	(3)	/* 2**n, n < SHIFT_WORD */

/* bit operations on 32-bit words */
#ವ್ಯಾಖ್ಯಾನಿಸು ಬಿಟ್_CLEAR(a,n)	((a)[(n)>>ಸರಿಸು_ಶಬ್ದ] &= ~(1L << ((n) & 31)))
#ವ್ಯಾಖ್ಯಾನಿಸು ಬಿಟ್_ಗಣ(a,n)	((a)[(n)>>ಸರಿಸು_ಶಬ್ದ] |= (1L << ((n) & 31)))
#ವ್ಯಾಖ್ಯಾನಿಸು ಬಿಟ್_TEST(a,n)	((a)[(n)>>ಸರಿಸು_ಶಬ್ದ] & (1L << ((n) & 31)))

/*
 * Prime testing defines
 */

/* Minimum number of primality tests to perform */
#ವ್ಯಾಖ್ಯಾನಿಸು TRIAL_MINIMUM	(4)

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

ಪೂರ್ಣಾಂಕ gen_candidates(FILE *, uint32_t, BIGNUM *);
ಪೂರ್ಣಾಂಕ ಅವಿಭಾಜ್ಯ_test(FILE *, FILE *, uint32_t, uint32_t, ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ,
    ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ);

/*
 * print moduli out in consistent form,
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	ರಚನೆ tm *gtm;
	time_t ಸಮಯ_now;
	ಪೂರ್ಣಾಂಕ res;

	time(&ಸಮಯ_now);
	gtm = gmtime(&ಸಮಯ_now);
	ಆದರೆ (gtm == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	ಆದರೆ (res < 0)
		ಹಿಂತಿರುಗಿ (-1);

	ಆದರೆ (BN_print_fp(ofile, omodulus) < 1)
		ಹಿಂತಿರುಗಿ (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	ಹಿಂತಿರುಗಿ (res > 0 ? 0 : -1);
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
	r = BN_mod_ಶಬ್ದ(largebase, s32);
	ಆದರೆ (r == 0)
		u = 0; /* s divides into largebase exactly */
	ಇಲ್ಲದಿದ್ದರೆ
		u = s - r; /* largebase+u is first entry divisible by s */

	ಆದರೆ (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		ಆದರೆ (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		ಗಾಗಿ (u /= 2; u < largebits; u += s)
			ಬಿಟ್_ಗಣ(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	ಆದರೆ (r == 0)
		u = 0; /* s divides p exactly */
	ಇಲ್ಲದಿದ್ದರೆ
		u = s - r; /* p+u is first entry divisible by s */

	ಆದರೆ (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		ಆಗ (u & 0x3) {
			ಆದರೆ (SMALL_ಗರಿಷ್ಠ - u < s)
				ಹಿಂತಿರುಗಿ;
			u += s;
		}

		/* Mark all multiples of 4*s */
		ಗಾಗಿ (u /= 4; u < largebits; u += s)
			ಬಿಟ್_ಗಣ(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
ಪೂರ್ಣಾಂಕ
gen_candidates(FILE *ಹೊರಹೋಗು, uint32_t power, BIGNUM *ಆರಂಭ)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_ಸಂಖ್ಯೆ >> 6;
	uint32_t tinywords = TINY_ಸಂಖ್ಯೆ >> 6;
	time_t ಸಮಯ_ಆರಂಭ, ಸಮಯ_stop;
	uint32_t i;
	ಪೂರ್ಣಾಂಕ ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	ಆದರೆ (power > TEST_ಗರಿಷ್ಠ) {
		error("Too many bits: %u > %lu", power, TEST_ಗರಿಷ್ಠ);
		ಹಿಂತಿರುಗಿ (-1);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		ಹಿಂತಿರುಗಿ (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_ಗರಿಷ್ಠ;
	largewords = (largememory << ಸರಿಸು_MEGAWORD);

	TinySieve = xcalloc(tinywords, ಗಾತ್ರ(uint32_t));
	tinybits = tinywords << ಸರಿಸು_ಶಬ್ದ;

	SmallSieve = xcalloc(smallwords, ಗಾತ್ರ(uint32_t));
	smallbits = smallwords << ಸರಿಸು_ಶಬ್ದ;

	LargeSieve = xcalloc(largewords, ಗಾತ್ರ(uint32_t));
	largebits = largewords << ಸರಿಸು_ಶಬ್ದ;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	ಆದರೆ ((q = BN_new()) == ಖಾಲಿ)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	ಆದರೆ ((largebase = BN_new()) == ಖಾಲಿ)
		fatal("BN_new failed");
	ಆದರೆ (ಆರಂಭ == ಖಾಲಿ) {
		ಆದರೆ (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (BN_copy(largebase, ಆರಂಭ) == ಖಾಲಿ)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	ಆದರೆ (BN_ಗಣ_ಬಿಟ್(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&ಸಮಯ_ಆರಂಭ);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&ಸಮಯ_ಆರಂಭ),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	ಗಾಗಿ (i = 0; i < tinybits; i++) {
		ಆದರೆ (ಬಿಟ್_TEST(TinySieve, i))
			ಮುಂದುವರಿ; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		ಗಾಗಿ (j = i + t; j < tinybits; j += t)
			ಬಿಟ್_ಗಣ(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	ಗಾಗಿ (smallbase = TINY_ಸಂಖ್ಯೆ + 3;
	    smallbase < (SMALL_ಗರಿಷ್ಠ - TINY_ಸಂಖ್ಯೆ);
	    smallbase += TINY_ಸಂಖ್ಯೆ) {
		ಗಾಗಿ (i = 0; i < tinybits; i++) {
			ಆದರೆ (ಬಿಟ್_TEST(TinySieve, i))
				ಮುಂದುವರಿ; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			ಆದರೆ (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} ಇಲ್ಲದಿದ್ದರೆ {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			ಆದರೆ (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			ಗಾಗಿ (s /= 2; s < smallbits; s += t)
				ಬಿಟ್_ಗಣ(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		ಗಾಗಿ (i = 0; i < smallbits; i++) {
			ಆದರೆ (ಬಿಟ್_TEST(SmallSieve, i))
				ಮುಂದುವರಿ; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << ಸರಿಸು_BYTE);
	}

	time(&ಸಮಯ_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&ಸಮಯ_stop), largetries, (ದೀರ್ಘ ದೀರ್ಘ)(ಸಮಯ_stop - ಸಮಯ_ಆರಂಭ));

	ಗಾಗಿ (j = r = 0; j < largebits; j++) {
		ಆದರೆ (ಬಿಟ್_TEST(LargeSieve, j))
			ಮುಂದುವರಿ; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		ಆದರೆ (BN_ಗಣ_ಶಬ್ದ(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		ಆದರೆ (BN_ಕೂಡಿಸು(q, q, largebase) == 0)
			fatal("BN_add failed");
		ಆದರೆ (qfileout(ಹೊರಹೋಗು, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			ನಿಲ್ಲಿಸು;
		}

		r++; /* count q */
	}

	time(&ಸಮಯ_stop);

	ಬಿಡುಗಡೆ(LargeSieve);
	ಬಿಡುಗಡೆ(SmallSieve);
	ಬಿಡುಗಡೆ(TinySieve);

	logit("%.24s Found %u candidates", ctime(&ಸಮಯ_stop), r);

	ಹಿಂತಿರುಗಿ (ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ
write_checkpoint(ಅಕ್ಷರ *cpfile, uint32_t lineno)
{
	FILE *fp;
	ಅಕ್ಷರ tmp[PATH_MAX];
	ಪೂರ್ಣಾಂಕ r, writeok, closeok;

	r = snprintf(tmp, ಗಾತ್ರ(tmp), "%s.XXXXXXXXXX", cpfile);
	ಆದರೆ (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((fp = fdopen(r, "w")) == ಖಾಲಿ) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		ಹಿಂತಿರುಗಿ;
	}
	writeok = (fprintf(fp, "%lu\n", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)lineno) > 0);
	closeok = (fclose(fp) == 0);
	ಆದರೆ (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)lineno, cpfile);
	} ಇಲ್ಲದಿದ್ದರೆ {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(ಶೂನ್ಯ)unlink(tmp);
	}
}

ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ
read_checkpoint(ಅಕ್ಷರ *cpfile)
{
	FILE *fp;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ lineno = 0;

	ಆದರೆ ((fp = fopen(cpfile, "r")) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	ಇಲ್ಲದಿದ್ದರೆ
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	ಹಿಂತಿರುಗಿ lineno;
}

ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ
ಎಣಿಕೆ_ಸಾಲುಗಳು(FILE *f)
{
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಎಣಿಕೆ_2 = 0;
	ಅಕ್ಷರ lp[QLINESIZE + 1];

	ಆದರೆ (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		ಹಿಂತಿರುಗಿ ULONG_MAX;
	}
	ಆಗ (fgets(lp, QLINESIZE + 1, f) != ಖಾಲಿ)
		ಎಣಿಕೆ_2++;
	rewind(f);
	debug("input file has %lu lines", ಎಣಿಕೆ_2);
	ಹಿಂತಿರುಗಿ ಎಣಿಕೆ_2;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
fmt_ಸಮಯ(time_t seconds)
{
	ಪೂರ್ಣಾಂಕ day, hr, min;
	ಸ್ಥಿರ ಅಕ್ಷರ buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	ಆದರೆ (day > 0)
		snprintf(buf, ಗಾತ್ರ buf, "%dd %d:%02d", day, hr, min);
	ಇಲ್ಲದಿದ್ದರೆ
		snprintf(buf, ಗಾತ್ರ buf, "%d:%02d", hr, min);
	ಹಿಂತಿರುಗಿ buf;
}

ಸ್ಥಿರ ಶೂನ್ಯ
print_ಪ್ರಗತಿ(ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಆರಂಭ_lineno, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ current_lineno,
    ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಕೊನೆ_lineno)
{
	ಸ್ಥಿರ time_t ಸಮಯ_ಆರಂಭ, ಸಮಯ_prev;
	time_t ಸಮಯ_now, elapsed;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಅಂಕೆ_ಗಮ್ಯ_process, processed, ಉಳಿದ, percent, eta;
	ದ್ವಿಗುಣ ಸಮಯ_ಪ್ರತಿ_ಸಾಲು;
	ಅಕ್ಷರ *eta_str;

	ಸಮಯ_now = monotime();
	ಆದರೆ (ಸಮಯ_ಆರಂಭ == 0) {
		ಸಮಯ_ಆರಂಭ = ಸಮಯ_prev = ಸಮಯ_now;
		ಹಿಂತಿರುಗಿ;
	}
	/* print progress after 1m then once per 5m */
	ಆದರೆ (ಸಮಯ_now - ಸಮಯ_prev < 5 * 60)
		ಹಿಂತಿರುಗಿ;
	ಸಮಯ_prev = ಸಮಯ_now;
	elapsed = ಸಮಯ_now - ಸಮಯ_ಆರಂಭ;
	processed = current_lineno - ಆರಂಭ_lineno;
	ಉಳಿದ = ಕೊನೆ_lineno - current_lineno;
	ಅಂಕೆ_ಗಮ್ಯ_process = ಕೊನೆ_lineno - ಆರಂಭ_lineno;
	ಸಮಯ_ಪ್ರತಿ_ಸಾಲು = (ದ್ವಿಗುಣ)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&ಸಮಯ_now);
	ಆದರೆ (ಕೊನೆ_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&ಸಮಯ_now),
		    processed, fmt_ಸಮಯ(elapsed));
		ಹಿಂತಿರುಗಿ;
	}
	percent = 100 * processed / ಅಂಕೆ_ಗಮ್ಯ_process;
	eta = ಸಮಯ_ಪ್ರತಿ_ಸಾಲು * ಉಳಿದ;
	eta_str = xstrdup(fmt_ಸಮಯ(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&ಸಮಯ_now), processed, ಅಂಕೆ_ಗಮ್ಯ_process, percent,
	    fmt_ಸಮಯ(elapsed), eta_str);
	ಬಿಡುಗಡೆ(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
ಪೂರ್ಣಾಂಕ
ಅವಿಭಾಜ್ಯ_test(FILE *ಒಳ, FILE *ಹೊರಹೋಗು, uint32_t trials, uint32_t generator_wanted,
    ಅಕ್ಷರ *checkpoint_file, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಆರಂಭ_lineno, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಅಂಕೆ_ಸಾಲುಗಳು)
{
	BIGNUM *q, *p, *a;
	ಅಕ್ಷರ *cp, *lp;
	uint32_t ಎಣಿಕೆ_ಒಳ = 0, ಎಣಿಕೆ_ಹೊರಹೋಗು = 0, ಎಣಿಕೆ_possible = 0;
	uint32_t generator_ತಿಳಿದ, ಒಳ_tests, ಒಳ_tries, ಒಳ_type, ಒಳ_ಗಾತ್ರ;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಕೊನೆಯ_processed = 0, ಕೊನೆ_lineno;
	time_t ಸಮಯ_ಆರಂಭ, ಸಮಯ_stop;
	ಪೂರ್ಣಾಂಕ res, is_ಅವಿಭಾಜ್ಯ;

	ಆದರೆ (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		ಹಿಂತಿರುಗಿ (-1);
	}

	ಆದರೆ (ಅಂಕೆ_ಸಾಲುಗಳು == 0)
		ಕೊನೆ_lineno = ಎಣಿಕೆ_ಸಾಲುಗಳು(ಒಳ);
	ಇಲ್ಲದಿದ್ದರೆ
		ಕೊನೆ_lineno = ಆರಂಭ_lineno + ಅಂಕೆ_ಸಾಲುಗಳು;

	time(&ಸಮಯ_ಆರಂಭ);

	ಆದರೆ ((p = BN_new()) == ಖಾಲಿ)
		fatal("BN_new failed");
	ಆದರೆ ((q = BN_new()) == ಖಾಲಿ)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&ಸಮಯ_ಆರಂಭ), trials, generator_wanted);

	ಆದರೆ (checkpoint_file != ಖಾಲಿ)
		ಕೊನೆಯ_processed = read_checkpoint(checkpoint_file);
	ಕೊನೆಯ_processed = ಆರಂಭ_lineno = ಗರಿಷ್ಠ(ಕೊನೆಯ_processed, ಆರಂಭ_lineno);
	ಆದರೆ (ಕೊನೆ_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", ಕೊನೆಯ_processed);
	ಇಲ್ಲದಿದ್ದರೆ
		debug("process from line %lu to line %lu", ಕೊನೆಯ_processed,
		    ಕೊನೆ_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	ಆಗ (fgets(lp, QLINESIZE + 1, ಒಳ) != ಖಾಲಿ && ಎಣಿಕೆ_ಒಳ < ಕೊನೆ_lineno) {
		ಎಣಿಕೆ_ಒಳ++;
		ಆದರೆ (ಎಣಿಕೆ_ಒಳ <= ಕೊನೆಯ_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", ಎಣಿಕೆ_ಒಳ);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (checkpoint_file != ಖಾಲಿ)
			write_checkpoint(checkpoint_file, ಎಣಿಕೆ_ಒಳ);
		print_ಪ್ರಗತಿ(ಆರಂಭ_lineno, ಎಣಿಕೆ_ಒಳ, ಕೊನೆ_lineno);
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", ಎಣಿಕೆ_ಒಳ);
			ಮುಂದುವರಿ;
		}

		/* XXX - fragile parser */
		/*ಸಮಯ*/
		cp = &lp[14];	/* (skip) */

		/* type */
		ಒಳ_type = strtoul(cp, &cp, 10);

		/* tests */
		ಒಳ_tests = strtoul(cp, &cp, 10);

		ಆದರೆ (ಒಳ_tests & MODULI_TESTS_ಸಂಯುಕ್ತ) {
			debug2("%10u: known composite", ಎಣಿಕೆ_ಒಳ);
			ಮುಂದುವರಿ;
		}

		/* tries */
		ಒಳ_tries = strtoul(cp, &cp, 10);

		/* size (most significant bit) */
		ಒಳ_ಗಾತ್ರ = strtoul(cp, &cp, 10);

		/* generator (hex) */
		generator_ತಿಳಿದ = strtoul(cp, &cp, 16);

		/* Skip white space */
		cp += strspn(cp, " ");

		/* modulus (hex) */
		ಆಯ್ಕೆ (ಒಳ_type) {
		ಸ್ಥಿತಿ MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", ಎಣಿಕೆ_ಒಳ, ಒಳ_type);
			a = q;
			ಆದರೆ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			ಆದರೆ (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			ಆದರೆ (BN_ಕೂಡಿಸು_ಶಬ್ದ(p, 1) == 0)
				fatal("BN_add_word failed");
			ಒಳ_ಗಾತ್ರ += 1;
			generator_ತಿಳಿದ = 0;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ MODULI_TYPE_UNSTRUCTURED:
		ಸ್ಥಿತಿ MODULI_TYPE_ಸುರಕ್ಷಿತ:
		ಸ್ಥಿತಿ MODULI_TYPE_SCHNORR:
		ಸ್ಥಿತಿ MODULI_TYPE_STRONG:
		ಸ್ಥಿತಿ MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", ಎಣಿಕೆ_ಒಳ, ಒಳ_type);
			a = p;
			ಆದರೆ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			ಆದರೆ (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			debug2("Unknown prime type");
			ನಿಲ್ಲಿಸು;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		ಆದರೆ ((uint32_t)BN_ಅಂಕೆ_ಬಿಟ್ಟುಗಳು(p) != (ಒಳ_ಗಾತ್ರ + 1)) {
			debug2("%10u: bit size %u mismatch", ಎಣಿಕೆ_ಒಳ, ಒಳ_ಗಾತ್ರ);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (ಒಳ_ಗಾತ್ರ < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", ಎಣಿಕೆ_ಒಳ, ಒಳ_ಗಾತ್ರ);
			ಮುಂದುವರಿ;
		}

		ಆದರೆ (ಒಳ_tests & MODULI_TESTS_MILLER_RABIN)
			ಒಳ_tries += trials;
		ಇಲ್ಲದಿದ್ದರೆ
			ಒಳ_tries = trials;

		/*
		 * guess unknown generator
		 */
		ಆದರೆ (generator_ತಿಳಿದ == 0) {
			ಆದರೆ (BN_mod_ಶಬ್ದ(p, 24) == 11)
				generator_ತಿಳಿದ = 2;
			ಇಲ್ಲದಿದ್ದರೆ {
				uint32_t r = BN_mod_ಶಬ್ದ(p, 10);

				ಆದರೆ (r == 3 || r == 7)
					generator_ತಿಳಿದ = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		ಆದರೆ (generator_wanted > 0 &&
		    generator_wanted != generator_ತಿಳಿದ) {
			debug2("%10u: generator %d != %d",
			    ಎಣಿಕೆ_ಒಳ, generator_ತಿಳಿದ, generator_wanted);
			ಮುಂದುವರಿ;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		ಆದರೆ (generator_ತಿಳಿದ == 0) {
			debug2("%10u: no known generator", ಎಣಿಕೆ_ಒಳ);
			ಮುಂದುವರಿ;
		}

		ಎಣಿಕೆ_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_ಅವಿಭಾಜ್ಯ = BN_is_ಅವಿಭಾಜ್ಯ_ex(q, 1, ಖಾಲಿ, ಖಾಲಿ);
		ಆದರೆ (is_ಅವಿಭಾಜ್ಯ < 0)
			fatal("BN_is_prime_ex failed");
		ಆದರೆ (is_ಅವಿಭಾಜ್ಯ == 0) {
			debug("%10u: q failed first possible prime test",
			    ಎಣಿಕೆ_ಒಳ);
			ಮುಂದುವರಿ;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_ಅವಿಭಾಜ್ಯ = BN_is_ಅವಿಭಾಜ್ಯ_ex(p, trials, ಖಾಲಿ, ಖಾಲಿ);
		ಆದರೆ (is_ಅವಿಭಾಜ್ಯ < 0)
			fatal("BN_is_prime_ex failed");
		ಆದರೆ (is_ಅವಿಭಾಜ್ಯ == 0) {
			debug("%10u: p is not prime", ಎಣಿಕೆ_ಒಳ);
			ಮುಂದುವರಿ;
		}
		debug("%10u: p is almost certainly prime", ಎಣಿಕೆ_ಒಳ);

		/* recheck q more rigorously */
		is_ಅವಿಭಾಜ್ಯ = BN_is_ಅವಿಭಾಜ್ಯ_ex(q, trials - 1, ಖಾಲಿ, ಖಾಲಿ);
		ಆದರೆ (is_ಅವಿಭಾಜ್ಯ < 0)
			fatal("BN_is_prime_ex failed");
		ಆದರೆ (is_ಅವಿಭಾಜ್ಯ == 0) {
			debug("%10u: q is not prime", ಎಣಿಕೆ_ಒಳ);
			ಮುಂದುವರಿ;
		}
		debug("%10u: q is almost certainly prime", ಎಣಿಕೆ_ಒಳ);

		ಆದರೆ (qfileout(ಹೊರಹೋಗು, MODULI_TYPE_ಸುರಕ್ಷಿತ,
		    ಒಳ_tests | MODULI_TESTS_MILLER_RABIN,
		    ಒಳ_tries, ಒಳ_ಗಾತ್ರ, generator_ತಿಳಿದ, p)) {
			res = -1;
			ನಿಲ್ಲಿಸು;
		}

		ಎಣಿಕೆ_ಹೊರಹೋಗು++;
	}

	time(&ಸಮಯ_stop);
	ಬಿಡುಗಡೆ(lp);
	BN_free(p);
	BN_free(q);

	ಆದರೆ (checkpoint_file != ಖಾಲಿ)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&ಸಮಯ_stop), ಎಣಿಕೆ_ಹೊರಹೋಗು, ಎಣಿಕೆ_possible,
	    (ದೀರ್ಘ) (ಸಮಯ_stop - ಸಮಯ_ಆರಂಭ));

	ಹಿಂತಿರುಗಿ (res);
}

#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
