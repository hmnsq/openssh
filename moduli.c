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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే WITH_OPENSSL

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/dh.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "dh.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

/*
 * File output defines
 */

/* need line long enough for largest moduli plus headers */
#నిర్వచించు QLINESIZE		(100+8192)

/*
 * Size: decimal.
 * Specifies the number of the most significant bit (0 to M).
 * WARNING: internally, usually 1 to N.
 */
#నిర్వచించు QSIZE_MINIMUM		(511)

/*
 * Prime sieving defines
 */

/* Constant: assuming 8 bit bytes and 32 bit words */
#నిర్వచించు జరుపు_బిట్టు	(3)
#నిర్వచించు జరుపు_BYTE	(2)
#నిర్వచించు జరుపు_మాట	(జరుపు_బిట్టు+జరుపు_BYTE)
#నిర్వచించు జరుపు_MEGABYTE	(20)
#నిర్వచించు జరుపు_MEGAWORD	(జరుపు_MEGABYTE-జరుపు_BYTE)

/*
 * Do not increase this number beyond the unsigned integer bit size.
 * Due to a multiple of 4, it must be LESS than 128 (yielding 2**30 bits).
 */
#నిర్వచించు LARGE_గరిష్ఠ	(127UL)	/* megabytes */

/*
 * Constant: when used with 32-bit integers, the largest sieve prime
 * has to be less than 2**32.
 */
#నిర్వచించు SMALL_గరిష్ఠ	(0xffffffffUL)

/* Constant: can sieve all primes less than 2**32, as 65537**2 > 2**32-1. */
#నిర్వచించు TINY_సంఖ్య	(1UL<<16)

/* Ensure enough bit space for testing 2*q. */
#నిర్వచించు TEST_గరిష్ఠ	(1UL<<16)
#నిర్వచించు TEST_MINIMUM	(QSIZE_MINIMUM + 1)
/* real TEST_MINIMUM	(1UL << (SHIFT_WORD - TEST_POWER)) */
#నిర్వచించు TEST_POWER	(3)	/* 2**n, n < SHIFT_WORD */

/* bit operations on 32-bit words */
#నిర్వచించు బిట్టు_CLEAR(a,n)	((a)[(n)>>జరుపు_మాట] &= ~(1L << ((n) & 31)))
#నిర్వచించు బిట్టు_సమితి(a,n)	((a)[(n)>>జరుపు_మాట] |= (1L << ((n) & 31)))
#నిర్వచించు బిట్టు_TEST(a,n)	((a)[(n)>>జరుపు_మాట] & (1L << ((n) & 31)))

/*
 * Prime testing defines
 */

/* Minimum number of primality tests to perform */
#నిర్వచించు TRIAL_MINIMUM	(4)

/*
 * Sieving data (XXX - move to struct)
 */

/* sieve 2**16 */
స్థిర uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
స్థిర uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
స్థిర uint32_t *LargeSieve, largewords, largetries, largenumbers;
స్థిర uint32_t largebits, largememory;	/* megabytes */
స్థిర BIGNUM *largebase;

పూర్ణాంకం gen_candidates(FILE *, uint32_t, BIGNUM *);
పూర్ణాంకం ప్రధానసంఖ్య_test(FILE *, FILE *, uint32_t, uint32_t, అక్షరం *, గుర్తులేని దీర్ఘ,
    గుర్తులేని దీర్ఘ);

/*
 * print moduli out in consistent form,
 */
స్థిర పూర్ణాంకం
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	నిర్మాణం tm *gtm;
	time_t సమయం_now;
	పూర్ణాంకం res;

	time(&సమయం_now);
	gtm = gmtime(&సమయం_now);
	ఒకవేళ (gtm == ఖాళీ)
		తిరిగి -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	ఒకవేళ (res < 0)
		తిరిగి (-1);

	ఒకవేళ (BN_print_fp(ofile, omodulus) < 1)
		తిరిగి (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	తిరిగి (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
స్థిర శూన్య
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_మాట(largebase, s32);
	ఒకవేళ (r == 0)
		u = 0; /* s divides into largebase exactly */
	లేకపోతే
		u = s - r; /* largebase+u is first entry divisible by s */

	ఒకవేళ (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		ఒకవేళ (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		కొరకు (u /= 2; u < largebits; u += s)
			బిట్టు_సమితి(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	ఒకవేళ (r == 0)
		u = 0; /* s divides p exactly */
	లేకపోతే
		u = s - r; /* p+u is first entry divisible by s */

	ఒకవేళ (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		అయితే (u & 0x3) {
			ఒకవేళ (SMALL_గరిష్ఠ - u < s)
				తిరిగి;
			u += s;
		}

		/* Mark all multiples of 4*s */
		కొరకు (u /= 4; u < largebits; u += s)
			బిట్టు_సమితి(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
పూర్ణాంకం
gen_candidates(FILE *బహిర్గతం, uint32_t power, BIGNUM *ప్రారంభం)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_సంఖ్య >> 6;
	uint32_t tinywords = TINY_సంఖ్య >> 6;
	time_t సమయం_ప్రారంభం, సమయం_stop;
	uint32_t i;
	పూర్ణాంకం ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	ఒకవేళ (power > TEST_గరిష్ఠ) {
		error("Too many bits: %u > %lu", power, TEST_గరిష్ఠ);
		తిరిగి (-1);
	} లేకపోతే ఒకవేళ (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		తిరిగి (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_గరిష్ఠ;
	largewords = (largememory << జరుపు_MEGAWORD);

	TinySieve = xcalloc(tinywords, పరిమాణం(uint32_t));
	tinybits = tinywords << జరుపు_మాట;

	SmallSieve = xcalloc(smallwords, పరిమాణం(uint32_t));
	smallbits = smallwords << జరుపు_మాట;

	LargeSieve = xcalloc(largewords, పరిమాణం(uint32_t));
	largebits = largewords << జరుపు_మాట;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	ఒకవేళ ((q = BN_new()) == ఖాళీ)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	ఒకవేళ ((largebase = BN_new()) == ఖాళీ)
		fatal("BN_new failed");
	ఒకవేళ (ప్రారంభం == ఖాళీ) {
		ఒకవేళ (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} లేకపోతే {
		ఒకవేళ (BN_copy(largebase, ప్రారంభం) == ఖాళీ)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	ఒకవేళ (BN_సమితి_బిట్టు(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&సమయం_ప్రారంభం);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&సమయం_ప్రారంభం),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	కొరకు (i = 0; i < tinybits; i++) {
		ఒకవేళ (బిట్టు_TEST(TinySieve, i))
			కొనసాగు; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		కొరకు (j = i + t; j < tinybits; j += t)
			బిట్టు_సమితి(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	కొరకు (smallbase = TINY_సంఖ్య + 3;
	    smallbase < (SMALL_గరిష్ఠ - TINY_సంఖ్య);
	    smallbase += TINY_సంఖ్య) {
		కొరకు (i = 0; i < tinybits; i++) {
			ఒకవేళ (బిట్టు_TEST(TinySieve, i))
				కొనసాగు; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			ఒకవేళ (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} లేకపోతే {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			ఒకవేళ (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			కొరకు (s /= 2; s < smallbits; s += t)
				బిట్టు_సమితి(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		కొరకు (i = 0; i < smallbits; i++) {
			ఒకవేళ (బిట్టు_TEST(SmallSieve, i))
				కొనసాగు; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << జరుపు_BYTE);
	}

	time(&సమయం_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&సమయం_stop), largetries, (దీర్ఘ దీర్ఘ)(సమయం_stop - సమయం_ప్రారంభం));

	కొరకు (j = r = 0; j < largebits; j++) {
		ఒకవేళ (బిట్టు_TEST(LargeSieve, j))
			కొనసాగు; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		ఒకవేళ (BN_సమితి_మాట(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		ఒకవేళ (BN_కూడు(q, q, largebase) == 0)
			fatal("BN_add failed");
		ఒకవేళ (qfileout(బహిర్గతం, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			ఆపు;
		}

		r++; /* count q */
	}

	time(&సమయం_stop);

	విడుదల(LargeSieve);
	విడుదల(SmallSieve);
	విడుదల(TinySieve);

	logit("%.24s Found %u candidates", ctime(&సమయం_stop), r);

	తిరిగి (ret);
}

స్థిర శూన్య
write_checkpoint(అక్షరం *cpfile, uint32_t lineno)
{
	FILE *fp;
	అక్షరం tmp[PATH_MAX];
	పూర్ణాంకం r, writeok, closeok;

	r = snprintf(tmp, పరిమాణం(tmp), "%s.XXXXXXXXXX", cpfile);
	ఒకవేళ (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		తిరిగి;
	}
	ఒకవేళ ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		తిరిగి;
	}
	ఒకవేళ ((fp = fdopen(r, "w")) == ఖాళీ) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		తిరిగి;
	}
	writeok = (fprintf(fp, "%lu\n", (గుర్తులేని దీర్ఘ)lineno) > 0);
	closeok = (fclose(fp) == 0);
	ఒకవేళ (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (గుర్తులేని దీర్ఘ)lineno, cpfile);
	} లేకపోతే {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(శూన్య)unlink(tmp);
	}
}

స్థిర గుర్తులేని దీర్ఘ
read_checkpoint(అక్షరం *cpfile)
{
	FILE *fp;
	గుర్తులేని దీర్ఘ lineno = 0;

	ఒకవేళ ((fp = fopen(cpfile, "r")) == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	లేకపోతే
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	తిరిగి lineno;
}

స్థిర గుర్తులేని దీర్ఘ
లెక్క_పంక్తులు(FILE *f)
{
	గుర్తులేని దీర్ఘ లెక్క = 0;
	అక్షరం lp[QLINESIZE + 1];

	ఒకవేళ (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		తిరిగి ULONG_MAX;
	}
	అయితే (fgets(lp, QLINESIZE + 1, f) != ఖాళీ)
		లెక్క++;
	rewind(f);
	debug("input file has %lu lines", లెక్క);
	తిరిగి లెక్క;
}

స్థిర అక్షరం *
fmt_సమయం(time_t seconds)
{
	పూర్ణాంకం day, hr, min;
	స్థిర అక్షరం buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	ఒకవేళ (day > 0)
		snprintf(buf, పరిమాణం buf, "%dd %d:%02d", day, hr, min);
	లేకపోతే
		snprintf(buf, పరిమాణం buf, "%d:%02d", hr, min);
	తిరిగి buf;
}

స్థిర శూన్య
print_పురోగతి(గుర్తులేని దీర్ఘ ప్రారంభం_lineno, గుర్తులేని దీర్ఘ current_lineno,
    గుర్తులేని దీర్ఘ చివర_lineno)
{
	స్థిర time_t సమయం_ప్రారంభం, సమయం_prev;
	time_t సమయం_now, elapsed;
	గుర్తులేని దీర్ఘ అంకె_గమ్యం_process, processed, మిగిలిన, percent, eta;
	ద్విగుణ సమయం_చొప్పున_పంక్తి;
	అక్షరం *eta_str;

	సమయం_now = monotime();
	ఒకవేళ (సమయం_ప్రారంభం == 0) {
		సమయం_ప్రారంభం = సమయం_prev = సమయం_now;
		తిరిగి;
	}
	/* print progress after 1m then once per 5m */
	ఒకవేళ (సమయం_now - సమయం_prev < 5 * 60)
		తిరిగి;
	సమయం_prev = సమయం_now;
	elapsed = సమయం_now - సమయం_ప్రారంభం;
	processed = current_lineno - ప్రారంభం_lineno;
	మిగిలిన = చివర_lineno - current_lineno;
	అంకె_గమ్యం_process = చివర_lineno - ప్రారంభం_lineno;
	సమయం_చొప్పున_పంక్తి = (ద్విగుణ)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&సమయం_now);
	ఒకవేళ (చివర_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&సమయం_now),
		    processed, fmt_సమయం(elapsed));
		తిరిగి;
	}
	percent = 100 * processed / అంకె_గమ్యం_process;
	eta = సమయం_చొప్పున_పంక్తి * మిగిలిన;
	eta_str = xstrdup(fmt_సమయం(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&సమయం_now), processed, అంకె_గమ్యం_process, percent,
	    fmt_సమయం(elapsed), eta_str);
	విడుదల(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
పూర్ణాంకం
ప్రధానసంఖ్య_test(FILE *లోపల, FILE *బహిర్గతం, uint32_t trials, uint32_t generator_wanted,
    అక్షరం *checkpoint_file, గుర్తులేని దీర్ఘ ప్రారంభం_lineno, గుర్తులేని దీర్ఘ అంకె_పంక్తులు)
{
	BIGNUM *q, *p, *a;
	అక్షరం *cp, *lp;
	uint32_t లెక్క_లోపల = 0, లెక్క_బహిర్గతం = 0, లెక్క_possible = 0;
	uint32_t generator_తెలిసిన, లోపల_tests, లోపల_tries, లోపల_type, లోపల_కొలత;
	గుర్తులేని దీర్ఘ చివరి_processed = 0, చివర_lineno;
	time_t సమయం_ప్రారంభం, సమయం_stop;
	పూర్ణాంకం res, is_ప్రధానసంఖ్య;

	ఒకవేళ (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		తిరిగి (-1);
	}

	ఒకవేళ (అంకె_పంక్తులు == 0)
		చివర_lineno = లెక్క_పంక్తులు(లోపల);
	లేకపోతే
		చివర_lineno = ప్రారంభం_lineno + అంకె_పంక్తులు;

	time(&సమయం_ప్రారంభం);

	ఒకవేళ ((p = BN_new()) == ఖాళీ)
		fatal("BN_new failed");
	ఒకవేళ ((q = BN_new()) == ఖాళీ)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&సమయం_ప్రారంభం), trials, generator_wanted);

	ఒకవేళ (checkpoint_file != ఖాళీ)
		చివరి_processed = read_checkpoint(checkpoint_file);
	చివరి_processed = ప్రారంభం_lineno = గరిష్ఠ(చివరి_processed, ప్రారంభం_lineno);
	ఒకవేళ (చివర_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", చివరి_processed);
	లేకపోతే
		debug("process from line %lu to line %lu", చివరి_processed,
		    చివర_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	అయితే (fgets(lp, QLINESIZE + 1, లోపల) != ఖాళీ && లెక్క_లోపల < చివర_lineno) {
		లెక్క_లోపల++;
		ఒకవేళ (లెక్క_లోపల <= చివరి_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", లెక్క_లోపల);
			కొనసాగు;
		}
		ఒకవేళ (checkpoint_file != ఖాళీ)
			write_checkpoint(checkpoint_file, లెక్క_లోపల);
		print_పురోగతి(ప్రారంభం_lineno, లెక్క_లోపల, చివర_lineno);
		ఒకవేళ (అక్షరశ్రేణి_పొడవు(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", లెక్క_లోపల);
			కొనసాగు;
		}

		/* XXX - fragile parser */
		/*సమయం*/
		cp = &lp[14];	/* (skip) */

		/* type */
		లోపల_type = strtoul(cp, &cp, 10);

		/* tests */
		లోపల_tests = strtoul(cp, &cp, 10);

		ఒకవేళ (లోపల_tests & MODULI_TESTS_సంయుక్త) {
			debug2("%10u: known composite", లెక్క_లోపల);
			కొనసాగు;
		}

		/* tries */
		లోపల_tries = strtoul(cp, &cp, 10);

		/* size (most significant bit) */
		లోపల_కొలత = strtoul(cp, &cp, 10);

		/* generator (hex) */
		generator_తెలిసిన = strtoul(cp, &cp, 16);

		/* Skip white space */
		cp += strspn(cp, " ");

		/* modulus (hex) */
		ఎంపిక (లోపల_type) {
		స్థితి MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", లెక్క_లోపల, లోపల_type);
			a = q;
			ఒకవేళ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			ఒకవేళ (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			ఒకవేళ (BN_కూడు_మాట(p, 1) == 0)
				fatal("BN_add_word failed");
			లోపల_కొలత += 1;
			generator_తెలిసిన = 0;
			ఆపు;
		స్థితి MODULI_TYPE_UNSTRUCTURED:
		స్థితి MODULI_TYPE_సురక్షిత:
		స్థితి MODULI_TYPE_SCHNORR:
		స్థితి MODULI_TYPE_STRONG:
		స్థితి MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", లెక్క_లోపల, లోపల_type);
			a = p;
			ఒకవేళ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			ఒకవేళ (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			ఆపు;
		అప్రమేయ:
			debug2("Unknown prime type");
			ఆపు;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		ఒకవేళ ((uint32_t)BN_అంకె_బిట్లు(p) != (లోపల_కొలత + 1)) {
			debug2("%10u: bit size %u mismatch", లెక్క_లోపల, లోపల_కొలత);
			కొనసాగు;
		}
		ఒకవేళ (లోపల_కొలత < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", లెక్క_లోపల, లోపల_కొలత);
			కొనసాగు;
		}

		ఒకవేళ (లోపల_tests & MODULI_TESTS_MILLER_RABIN)
			లోపల_tries += trials;
		లేకపోతే
			లోపల_tries = trials;

		/*
		 * guess unknown generator
		 */
		ఒకవేళ (generator_తెలిసిన == 0) {
			ఒకవేళ (BN_mod_మాట(p, 24) == 11)
				generator_తెలిసిన = 2;
			లేకపోతే {
				uint32_t r = BN_mod_మాట(p, 10);

				ఒకవేళ (r == 3 || r == 7)
					generator_తెలిసిన = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		ఒకవేళ (generator_wanted > 0 &&
		    generator_wanted != generator_తెలిసిన) {
			debug2("%10u: generator %d != %d",
			    లెక్క_లోపల, generator_తెలిసిన, generator_wanted);
			కొనసాగు;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		ఒకవేళ (generator_తెలిసిన == 0) {
			debug2("%10u: no known generator", లెక్క_లోపల);
			కొనసాగు;
		}

		లెక్క_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_ప్రధానసంఖ్య = BN_is_ప్రధానసంఖ్య_ex(q, 1, ఖాళీ, ఖాళీ);
		ఒకవేళ (is_ప్రధానసంఖ్య < 0)
			fatal("BN_is_prime_ex failed");
		ఒకవేళ (is_ప్రధానసంఖ్య == 0) {
			debug("%10u: q failed first possible prime test",
			    లెక్క_లోపల);
			కొనసాగు;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_ప్రధానసంఖ్య = BN_is_ప్రధానసంఖ్య_ex(p, trials, ఖాళీ, ఖాళీ);
		ఒకవేళ (is_ప్రధానసంఖ్య < 0)
			fatal("BN_is_prime_ex failed");
		ఒకవేళ (is_ప్రధానసంఖ్య == 0) {
			debug("%10u: p is not prime", లెక్క_లోపల);
			కొనసాగు;
		}
		debug("%10u: p is almost certainly prime", లెక్క_లోపల);

		/* recheck q more rigorously */
		is_ప్రధానసంఖ్య = BN_is_ప్రధానసంఖ్య_ex(q, trials - 1, ఖాళీ, ఖాళీ);
		ఒకవేళ (is_ప్రధానసంఖ్య < 0)
			fatal("BN_is_prime_ex failed");
		ఒకవేళ (is_ప్రధానసంఖ్య == 0) {
			debug("%10u: q is not prime", లెక్క_లోపల);
			కొనసాగు;
		}
		debug("%10u: q is almost certainly prime", లెక్క_లోపల);

		ఒకవేళ (qfileout(బహిర్గతం, MODULI_TYPE_సురక్షిత,
		    లోపల_tests | MODULI_TESTS_MILLER_RABIN,
		    లోపల_tries, లోపల_కొలత, generator_తెలిసిన, p)) {
			res = -1;
			ఆపు;
		}

		లెక్క_బహిర్గతం++;
	}

	time(&సమయం_stop);
	విడుదల(lp);
	BN_free(p);
	BN_free(q);

	ఒకవేళ (checkpoint_file != ఖాళీ)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&సమయం_stop), లెక్క_బహిర్గతం, లెక్క_possible,
	    (దీర్ఘ) (సమయం_stop - సమయం_ప్రారంభం));

	తిరిగి (res);
}

#అయితే_ముగింపు /* WITH_OPENSSL */
