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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/dh.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

/*
 * File output defines
 */

/* need line long enough for largest moduli plus headers */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ QLINESIZE		(100+8192)

/*
 * Size: decimal.
 * Specifies the number of the most significant bit (0 to M).
 * WARNING: internally, usually 1 to N.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ QSIZE_MINIMUM		(511)

/*
 * Prime sieving defines
 */

/* Constant: assuming 8 bit bytes and 32 bit words */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਖਿਸਕਾਓ_ਦੋਆਧਾਰੀ_ਅੰਕ	(3)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਖਿਸਕਾਓ_BYTE	(2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਖਿਸਕਾਓ_ਸ਼ਬਦ	(ਖਿਸਕਾਓ_ਦੋਆਧਾਰੀ_ਅੰਕ+ਖਿਸਕਾਓ_BYTE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਖਿਸਕਾਓ_MEGABYTE	(20)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਖਿਸਕਾਓ_MEGAWORD	(ਖਿਸਕਾਓ_MEGABYTE-ਖਿਸਕਾਓ_BYTE)

/*
 * Do not increase this number beyond the unsigned integer bit size.
 * Due to a multiple of 4, it must be LESS than 128 (yielding 2**30 bits).
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LARGE_ਵੱਧ_ਤੋਂ_ਵੱਧ	(127UL)	/* megabytes */

/*
 * Constant: when used with 32-bit integers, the largest sieve prime
 * has to be less than 2**32.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SMALL_ਵੱਧ_ਤੋਂ_ਵੱਧ	(0xffffffffUL)

/* Constant: can sieve all primes less than 2**32, as 65537**2 > 2**32-1. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TINY_ਸੰਖਿਆ	(1UL<<16)

/* Ensure enough bit space for testing 2*q. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TEST_ਵੱਧ_ਤੋਂ_ਵੱਧ	(1UL<<16)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TEST_MINIMUM	(QSIZE_MINIMUM + 1)
/* real TEST_MINIMUM	(1UL << (SHIFT_WORD - TEST_POWER)) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TEST_POWER	(3)	/* 2**n, n < SHIFT_WORD */

/* bit operations on 32-bit words */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਦੋਆਧਾਰੀ_ਅੰਕ_CLEAR(a,n)	((a)[(n)>>ਖਿਸਕਾਓ_ਸ਼ਬਦ] &= ~(1L << ((n) & 31)))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਦੋਆਧਾਰੀ_ਅੰਕ_ਸੈੱਟ(a,n)	((a)[(n)>>ਖਿਸਕਾਓ_ਸ਼ਬਦ] |= (1L << ((n) & 31)))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਦੋਆਧਾਰੀ_ਅੰਕ_TEST(a,n)	((a)[(n)>>ਖਿਸਕਾਓ_ਸ਼ਬਦ] & (1L << ((n) & 31)))

/*
 * Prime testing defines
 */

/* Minimum number of primality tests to perform */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TRIAL_MINIMUM	(4)

/*
 * Sieving data (XXX - move to struct)
 */

/* sieve 2**16 */
ਸਥਿਰ uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
ਸਥਿਰ uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
ਸਥਿਰ uint32_t *LargeSieve, largewords, largetries, largenumbers;
ਸਥਿਰ uint32_t largebits, largememory;	/* megabytes */
ਸਥਿਰ BIGNUM *largebase;

ਪੂਰਨ gen_candidates(FILE *, uint32_t, BIGNUM *);
ਪੂਰਨ ਅਭਾਜ_test(FILE *, FILE *, uint32_t, uint32_t, ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ);

/*
 * print moduli out in consistent form,
 */
ਸਥਿਰ ਪੂਰਨ
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	ਬਣਤਰ tm *gtm;
	time_t ਸਮਾਂ_now;
	ਪੂਰਨ res;

	time(&ਸਮਾਂ_now);
	gtm = gmtime(&ਸਮਾਂ_now);
	ਜੇ (gtm == ਨਿਰਾ)
		ਵਾਪਸ -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	ਜੇ (res < 0)
		ਵਾਪਸ (-1);

	ਜੇ (BN_print_fp(ofile, omodulus) < 1)
		ਵਾਪਸ (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	ਵਾਪਸ (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
ਸਥਿਰ ਖਾਲੀ
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_ਸ਼ਬਦ(largebase, s32);
	ਜੇ (r == 0)
		u = 0; /* s divides into largebase exactly */
	ਨਹੀਂਤਾਂ
		u = s - r; /* largebase+u is first entry divisible by s */

	ਜੇ (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		ਜੇ (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		ਲਈ (u /= 2; u < largebits; u += s)
			ਦੋਆਧਾਰੀ_ਅੰਕ_ਸੈੱਟ(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	ਜੇ (r == 0)
		u = 0; /* s divides p exactly */
	ਨਹੀਂਤਾਂ
		u = s - r; /* p+u is first entry divisible by s */

	ਜੇ (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		ਜਦੋਂ (u & 0x3) {
			ਜੇ (SMALL_ਵੱਧ_ਤੋਂ_ਵੱਧ - u < s)
				ਵਾਪਸ;
			u += s;
		}

		/* Mark all multiples of 4*s */
		ਲਈ (u /= 4; u < largebits; u += s)
			ਦੋਆਧਾਰੀ_ਅੰਕ_ਸੈੱਟ(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
ਪੂਰਨ
gen_candidates(FILE *ਬਾਹਰਲਾ, uint32_t power, BIGNUM *ਸ਼ੁਰੂ)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_ਸੰਖਿਆ >> 6;
	uint32_t tinywords = TINY_ਸੰਖਿਆ >> 6;
	time_t ਸਮਾਂ_ਸ਼ੁਰੂ, ਸਮਾਂ_stop;
	uint32_t i;
	ਪੂਰਨ ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	ਜੇ (power > TEST_ਵੱਧ_ਤੋਂ_ਵੱਧ) {
		error("Too many bits: %u > %lu", power, TEST_ਵੱਧ_ਤੋਂ_ਵੱਧ);
		ਵਾਪਸ (-1);
	} ਨਹੀਂਤਾਂ ਜੇ (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		ਵਾਪਸ (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_ਵੱਧ_ਤੋਂ_ਵੱਧ;
	largewords = (largememory << ਖਿਸਕਾਓ_MEGAWORD);

	TinySieve = xcalloc(tinywords, ਆਕਾਰ(uint32_t));
	tinybits = tinywords << ਖਿਸਕਾਓ_ਸ਼ਬਦ;

	SmallSieve = xcalloc(smallwords, ਆਕਾਰ(uint32_t));
	smallbits = smallwords << ਖਿਸਕਾਓ_ਸ਼ਬਦ;

	LargeSieve = xcalloc(largewords, ਆਕਾਰ(uint32_t));
	largebits = largewords << ਖਿਸਕਾਓ_ਸ਼ਬਦ;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	ਜੇ ((q = BN_new()) == ਨਿਰਾ)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	ਜੇ ((largebase = BN_new()) == ਨਿਰਾ)
		fatal("BN_new failed");
	ਜੇ (ਸ਼ੁਰੂ == ਨਿਰਾ) {
		ਜੇ (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} ਨਹੀਂਤਾਂ {
		ਜੇ (BN_copy(largebase, ਸ਼ੁਰੂ) == ਨਿਰਾ)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	ਜੇ (BN_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&ਸਮਾਂ_ਸ਼ੁਰੂ);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&ਸਮਾਂ_ਸ਼ੁਰੂ),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	ਲਈ (i = 0; i < tinybits; i++) {
		ਜੇ (ਦੋਆਧਾਰੀ_ਅੰਕ_TEST(TinySieve, i))
			ਜਾਰੀ; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		ਲਈ (j = i + t; j < tinybits; j += t)
			ਦੋਆਧਾਰੀ_ਅੰਕ_ਸੈੱਟ(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	ਲਈ (smallbase = TINY_ਸੰਖਿਆ + 3;
	    smallbase < (SMALL_ਵੱਧ_ਤੋਂ_ਵੱਧ - TINY_ਸੰਖਿਆ);
	    smallbase += TINY_ਸੰਖਿਆ) {
		ਲਈ (i = 0; i < tinybits; i++) {
			ਜੇ (ਦੋਆਧਾਰੀ_ਅੰਕ_TEST(TinySieve, i))
				ਜਾਰੀ; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			ਜੇ (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} ਨਹੀਂਤਾਂ {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			ਜੇ (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			ਲਈ (s /= 2; s < smallbits; s += t)
				ਦੋਆਧਾਰੀ_ਅੰਕ_ਸੈੱਟ(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		ਲਈ (i = 0; i < smallbits; i++) {
			ਜੇ (ਦੋਆਧਾਰੀ_ਅੰਕ_TEST(SmallSieve, i))
				ਜਾਰੀ; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << ਖਿਸਕਾਓ_BYTE);
	}

	time(&ਸਮਾਂ_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&ਸਮਾਂ_stop), largetries, (ਲੰਮਾ ਲੰਮਾ)(ਸਮਾਂ_stop - ਸਮਾਂ_ਸ਼ੁਰੂ));

	ਲਈ (j = r = 0; j < largebits; j++) {
		ਜੇ (ਦੋਆਧਾਰੀ_ਅੰਕ_TEST(LargeSieve, j))
			ਜਾਰੀ; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		ਜੇ (BN_ਸੈੱਟ_ਸ਼ਬਦ(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		ਜੇ (BN_ਜੋੜੋ(q, q, largebase) == 0)
			fatal("BN_add failed");
		ਜੇ (qfileout(ਬਾਹਰਲਾ, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			ਰੋਕੋ;
		}

		r++; /* count q */
	}

	time(&ਸਮਾਂ_stop);

	ਮੁਕਤ(LargeSieve);
	ਮੁਕਤ(SmallSieve);
	ਮੁਕਤ(TinySieve);

	logit("%.24s Found %u candidates", ctime(&ਸਮਾਂ_stop), r);

	ਵਾਪਸ (ret);
}

ਸਥਿਰ ਖਾਲੀ
write_checkpoint(ਅੱਖਰ *cpfile, uint32_t lineno)
{
	FILE *fp;
	ਅੱਖਰ tmp[PATH_MAX];
	ਪੂਰਨ r, writeok, closeok;

	r = snprintf(tmp, ਆਕਾਰ(tmp), "%s.XXXXXXXXXX", cpfile);
	ਜੇ (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		ਵਾਪਸ;
	}
	ਜੇ ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		ਵਾਪਸ;
	}
	ਜੇ ((fp = fdopen(r, "w")) == ਨਿਰਾ) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		ਵਾਪਸ;
	}
	writeok = (fprintf(fp, "%lu\n", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)lineno) > 0);
	closeok = (fclose(fp) == 0);
	ਜੇ (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)lineno, cpfile);
	} ਨਹੀਂਤਾਂ {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(ਖਾਲੀ)unlink(tmp);
	}
}

ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ
read_checkpoint(ਅੱਖਰ *cpfile)
{
	FILE *fp;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ lineno = 0;

	ਜੇ ((fp = fopen(cpfile, "r")) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	ਨਹੀਂਤਾਂ
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	ਵਾਪਸ lineno;
}

ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ
ਗਿਣਤੀ_ਸਤਰਾਂ(FILE *f)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਗਿਣਤੀ_2 = 0;
	ਅੱਖਰ lp[QLINESIZE + 1];

	ਜੇ (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		ਵਾਪਸ ULONG_MAX;
	}
	ਜਦੋਂ (fgets(lp, QLINESIZE + 1, f) != ਨਿਰਾ)
		ਗਿਣਤੀ_2++;
	rewind(f);
	debug("input file has %lu lines", ਗਿਣਤੀ_2);
	ਵਾਪਸ ਗਿਣਤੀ_2;
}

ਸਥਿਰ ਅੱਖਰ *
fmt_ਸਮਾਂ(time_t seconds)
{
	ਪੂਰਨ day, hr, min;
	ਸਥਿਰ ਅੱਖਰ buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	ਜੇ (day > 0)
		snprintf(buf, ਆਕਾਰ buf, "%dd %d:%02d", day, hr, min);
	ਨਹੀਂਤਾਂ
		snprintf(buf, ਆਕਾਰ buf, "%d:%02d", hr, min);
	ਵਾਪਸ buf;
}

ਸਥਿਰ ਖਾਲੀ
print_ਤਰੱਕੀ(ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਸ਼ੁਰੂ_lineno, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ current_lineno,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਸਿਰਾ_lineno)
{
	ਸਥਿਰ time_t ਸਮਾਂ_ਸ਼ੁਰੂ, ਸਮਾਂ_prev;
	time_t ਸਮਾਂ_now, elapsed;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕ_ਮੰਜ਼ਿਲ_process, processed, ਬਚਿਆ, percent, eta;
	ਦੁੱਗਣਾ ਸਮਾਂ_ਪ੍ਰਤੀ_ਸਤਰ;
	ਅੱਖਰ *eta_str;

	ਸਮਾਂ_now = monotime();
	ਜੇ (ਸਮਾਂ_ਸ਼ੁਰੂ == 0) {
		ਸਮਾਂ_ਸ਼ੁਰੂ = ਸਮਾਂ_prev = ਸਮਾਂ_now;
		ਵਾਪਸ;
	}
	/* print progress after 1m then once per 5m */
	ਜੇ (ਸਮਾਂ_now - ਸਮਾਂ_prev < 5 * 60)
		ਵਾਪਸ;
	ਸਮਾਂ_prev = ਸਮਾਂ_now;
	elapsed = ਸਮਾਂ_now - ਸਮਾਂ_ਸ਼ੁਰੂ;
	processed = current_lineno - ਸ਼ੁਰੂ_lineno;
	ਬਚਿਆ = ਸਿਰਾ_lineno - current_lineno;
	ਅੰਕ_ਮੰਜ਼ਿਲ_process = ਸਿਰਾ_lineno - ਸ਼ੁਰੂ_lineno;
	ਸਮਾਂ_ਪ੍ਰਤੀ_ਸਤਰ = (ਦੁੱਗਣਾ)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&ਸਮਾਂ_now);
	ਜੇ (ਸਿਰਾ_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&ਸਮਾਂ_now),
		    processed, fmt_ਸਮਾਂ(elapsed));
		ਵਾਪਸ;
	}
	percent = 100 * processed / ਅੰਕ_ਮੰਜ਼ਿਲ_process;
	eta = ਸਮਾਂ_ਪ੍ਰਤੀ_ਸਤਰ * ਬਚਿਆ;
	eta_str = xstrdup(fmt_ਸਮਾਂ(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&ਸਮਾਂ_now), processed, ਅੰਕ_ਮੰਜ਼ਿਲ_process, percent,
	    fmt_ਸਮਾਂ(elapsed), eta_str);
	ਮੁਕਤ(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
ਪੂਰਨ
ਅਭਾਜ_test(FILE *ਵਿੱਚ, FILE *ਬਾਹਰਲਾ, uint32_t trials, uint32_t generator_wanted,
    ਅੱਖਰ *checkpoint_file, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਸ਼ੁਰੂ_lineno, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕ_ਸਤਰਾਂ)
{
	BIGNUM *q, *p, *a;
	ਅੱਖਰ *cp, *lp;
	uint32_t ਗਿਣਤੀ_ਵਿੱਚ = 0, ਗਿਣਤੀ_ਬਾਹਰਲਾ = 0, ਗਿਣਤੀ_possible = 0;
	uint32_t generator_ਗਿਆਤ, ਵਿੱਚ_tests, ਵਿੱਚ_tries, ਵਿੱਚ_type, ਵਿੱਚ_ਮਾਪ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਆਖਰੀ_processed = 0, ਸਿਰਾ_lineno;
	time_t ਸਮਾਂ_ਸ਼ੁਰੂ, ਸਮਾਂ_stop;
	ਪੂਰਨ res, is_ਅਭਾਜ;

	ਜੇ (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		ਵਾਪਸ (-1);
	}

	ਜੇ (ਅੰਕ_ਸਤਰਾਂ == 0)
		ਸਿਰਾ_lineno = ਗਿਣਤੀ_ਸਤਰਾਂ(ਵਿੱਚ);
	ਨਹੀਂਤਾਂ
		ਸਿਰਾ_lineno = ਸ਼ੁਰੂ_lineno + ਅੰਕ_ਸਤਰਾਂ;

	time(&ਸਮਾਂ_ਸ਼ੁਰੂ);

	ਜੇ ((p = BN_new()) == ਨਿਰਾ)
		fatal("BN_new failed");
	ਜੇ ((q = BN_new()) == ਨਿਰਾ)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&ਸਮਾਂ_ਸ਼ੁਰੂ), trials, generator_wanted);

	ਜੇ (checkpoint_file != ਨਿਰਾ)
		ਆਖਰੀ_processed = read_checkpoint(checkpoint_file);
	ਆਖਰੀ_processed = ਸ਼ੁਰੂ_lineno = ਵੱਧ_ਤੋਂ_ਵੱਧ(ਆਖਰੀ_processed, ਸ਼ੁਰੂ_lineno);
	ਜੇ (ਸਿਰਾ_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", ਆਖਰੀ_processed);
	ਨਹੀਂਤਾਂ
		debug("process from line %lu to line %lu", ਆਖਰੀ_processed,
		    ਸਿਰਾ_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	ਜਦੋਂ (fgets(lp, QLINESIZE + 1, ਵਿੱਚ) != ਨਿਰਾ && ਗਿਣਤੀ_ਵਿੱਚ < ਸਿਰਾ_lineno) {
		ਗਿਣਤੀ_ਵਿੱਚ++;
		ਜੇ (ਗਿਣਤੀ_ਵਿੱਚ <= ਆਖਰੀ_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", ਗਿਣਤੀ_ਵਿੱਚ);
			ਜਾਰੀ;
		}
		ਜੇ (checkpoint_file != ਨਿਰਾ)
			write_checkpoint(checkpoint_file, ਗਿਣਤੀ_ਵਿੱਚ);
		print_ਤਰੱਕੀ(ਸ਼ੁਰੂ_lineno, ਗਿਣਤੀ_ਵਿੱਚ, ਸਿਰਾ_lineno);
		ਜੇ (ਲੜੀ_ਲੰਬਾਈ(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", ਗਿਣਤੀ_ਵਿੱਚ);
			ਜਾਰੀ;
		}

		/* XXX - fragile parser */
		/*ਸਮਾਂ*/
		cp = &lp[14];	/* (skip) */

		/* type */
		ਵਿੱਚ_type = strtoul(cp, &cp, 10);

		/* tests */
		ਵਿੱਚ_tests = strtoul(cp, &cp, 10);

		ਜੇ (ਵਿੱਚ_tests & MODULI_TESTS_ਸੰਯੁਕਤ) {
			debug2("%10u: known composite", ਗਿਣਤੀ_ਵਿੱਚ);
			ਜਾਰੀ;
		}

		/* tries */
		ਵਿੱਚ_tries = strtoul(cp, &cp, 10);

		/* size (most significant bit) */
		ਵਿੱਚ_ਮਾਪ = strtoul(cp, &cp, 10);

		/* generator (hex) */
		generator_ਗਿਆਤ = strtoul(cp, &cp, 16);

		/* Skip white space */
		cp += strspn(cp, " ");

		/* modulus (hex) */
		ਚੋਣ (ਵਿੱਚ_type) {
		ਹਾਲਤ MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", ਗਿਣਤੀ_ਵਿੱਚ, ਵਿੱਚ_type);
			a = q;
			ਜੇ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			ਜੇ (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			ਜੇ (BN_ਜੋੜੋ_ਸ਼ਬਦ(p, 1) == 0)
				fatal("BN_add_word failed");
			ਵਿੱਚ_ਮਾਪ += 1;
			generator_ਗਿਆਤ = 0;
			ਰੋਕੋ;
		ਹਾਲਤ MODULI_TYPE_UNSTRUCTURED:
		ਹਾਲਤ MODULI_TYPE_ਸੁਰੱਖਿਅਤ:
		ਹਾਲਤ MODULI_TYPE_SCHNORR:
		ਹਾਲਤ MODULI_TYPE_STRONG:
		ਹਾਲਤ MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", ਗਿਣਤੀ_ਵਿੱਚ, ਵਿੱਚ_type);
			a = p;
			ਜੇ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			ਜੇ (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			ਰੋਕੋ;
		ਮੂਲ:
			debug2("Unknown prime type");
			ਰੋਕੋ;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		ਜੇ ((uint32_t)BN_ਅੰਕ_ਬਿੱਟ(p) != (ਵਿੱਚ_ਮਾਪ + 1)) {
			debug2("%10u: bit size %u mismatch", ਗਿਣਤੀ_ਵਿੱਚ, ਵਿੱਚ_ਮਾਪ);
			ਜਾਰੀ;
		}
		ਜੇ (ਵਿੱਚ_ਮਾਪ < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", ਗਿਣਤੀ_ਵਿੱਚ, ਵਿੱਚ_ਮਾਪ);
			ਜਾਰੀ;
		}

		ਜੇ (ਵਿੱਚ_tests & MODULI_TESTS_MILLER_RABIN)
			ਵਿੱਚ_tries += trials;
		ਨਹੀਂਤਾਂ
			ਵਿੱਚ_tries = trials;

		/*
		 * guess unknown generator
		 */
		ਜੇ (generator_ਗਿਆਤ == 0) {
			ਜੇ (BN_mod_ਸ਼ਬਦ(p, 24) == 11)
				generator_ਗਿਆਤ = 2;
			ਨਹੀਂਤਾਂ {
				uint32_t r = BN_mod_ਸ਼ਬਦ(p, 10);

				ਜੇ (r == 3 || r == 7)
					generator_ਗਿਆਤ = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		ਜੇ (generator_wanted > 0 &&
		    generator_wanted != generator_ਗਿਆਤ) {
			debug2("%10u: generator %d != %d",
			    ਗਿਣਤੀ_ਵਿੱਚ, generator_ਗਿਆਤ, generator_wanted);
			ਜਾਰੀ;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		ਜੇ (generator_ਗਿਆਤ == 0) {
			debug2("%10u: no known generator", ਗਿਣਤੀ_ਵਿੱਚ);
			ਜਾਰੀ;
		}

		ਗਿਣਤੀ_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_ਅਭਾਜ = BN_is_ਅਭਾਜ_ex(q, 1, ਨਿਰਾ, ਨਿਰਾ);
		ਜੇ (is_ਅਭਾਜ < 0)
			fatal("BN_is_prime_ex failed");
		ਜੇ (is_ਅਭਾਜ == 0) {
			debug("%10u: q failed first possible prime test",
			    ਗਿਣਤੀ_ਵਿੱਚ);
			ਜਾਰੀ;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_ਅਭਾਜ = BN_is_ਅਭਾਜ_ex(p, trials, ਨਿਰਾ, ਨਿਰਾ);
		ਜੇ (is_ਅਭਾਜ < 0)
			fatal("BN_is_prime_ex failed");
		ਜੇ (is_ਅਭਾਜ == 0) {
			debug("%10u: p is not prime", ਗਿਣਤੀ_ਵਿੱਚ);
			ਜਾਰੀ;
		}
		debug("%10u: p is almost certainly prime", ਗਿਣਤੀ_ਵਿੱਚ);

		/* recheck q more rigorously */
		is_ਅਭਾਜ = BN_is_ਅਭਾਜ_ex(q, trials - 1, ਨਿਰਾ, ਨਿਰਾ);
		ਜੇ (is_ਅਭਾਜ < 0)
			fatal("BN_is_prime_ex failed");
		ਜੇ (is_ਅਭਾਜ == 0) {
			debug("%10u: q is not prime", ਗਿਣਤੀ_ਵਿੱਚ);
			ਜਾਰੀ;
		}
		debug("%10u: q is almost certainly prime", ਗਿਣਤੀ_ਵਿੱਚ);

		ਜੇ (qfileout(ਬਾਹਰਲਾ, MODULI_TYPE_ਸੁਰੱਖਿਅਤ,
		    ਵਿੱਚ_tests | MODULI_TESTS_MILLER_RABIN,
		    ਵਿੱਚ_tries, ਵਿੱਚ_ਮਾਪ, generator_ਗਿਆਤ, p)) {
			res = -1;
			ਰੋਕੋ;
		}

		ਗਿਣਤੀ_ਬਾਹਰਲਾ++;
	}

	time(&ਸਮਾਂ_stop);
	ਮੁਕਤ(lp);
	BN_free(p);
	BN_free(q);

	ਜੇ (checkpoint_file != ਨਿਰਾ)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&ਸਮਾਂ_stop), ਗਿਣਤੀ_ਬਾਹਰਲਾ, ਗਿਣਤੀ_possible,
	    (ਲੰਮਾ) (ਸਮਾਂ_stop - ਸਮਾਂ_ਸ਼ੁਰੂ));

	ਵਾਪਸ (res);
}

#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
