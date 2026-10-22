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

#அந்தர்பாவ "includes.h"

#ifdef WITH_OPENSSL

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/dh.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "dh.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

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
#define TINY_எண்	(1UL<<16)

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
நிலையான uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
நிலையான uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
நிலையான uint32_t *LargeSieve, largewords, largetries, largenumbers;
நிலையான uint32_t largebits, largememory;	/* megabytes */
நிலையான BIGNUM *largebase;

முழு gen_candidates(FILE *, uint32_t, BIGNUM *);
முழு பகாஎண்_test(FILE *, FILE *, uint32_t, uint32_t, எழுத்து *, unsigned long,
    unsigned long);

/*
 * print moduli out in consistent form,
 */
நிலையான முழு
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	கட்டமைப்பு tm *gtm;
	time_t time_now;
	முழு res;

	time(&time_now);
	gtm = gmtime(&time_now);
	எனில் (gtm == வெற்று)
		திரும்பு -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	எனில் (res < 0)
		திரும்பு (-1);

	எனில் (BN_print_fp(ofile, omodulus) < 1)
		திரும்பு (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	திரும்பு (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
நிலையான வெறுமை
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_word(largebase, s32);
	எனில் (r == 0)
		u = 0; /* s divides into largebase exactly */
	இல்லையெனில்
		u = s - r; /* largebase+u is first entry divisible by s */

	எனில் (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		எனில் (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		க்கு (u /= 2; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	எனில் (r == 0)
		u = 0; /* s divides p exactly */
	இல்லையெனில்
		u = s - r; /* p+u is first entry divisible by s */

	எனில் (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		போது (u & 0x3) {
			எனில் (SMALL_MAXIMUM - u < s)
				திரும்பு;
			u += s;
		}

		/* Mark all multiples of 4*s */
		க்கு (u /= 4; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
முழு
gen_candidates(FILE *out, uint32_t power, BIGNUM *start)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_எண் >> 6;
	uint32_t tinywords = TINY_எண் >> 6;
	time_t time_start, time_stop;
	uint32_t i;
	முழு ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	எனில் (power > TEST_MAXIMUM) {
		error("Too many bits: %u > %lu", power, TEST_MAXIMUM);
		திரும்பு (-1);
	} இல்லையெனில் எனில் (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		திரும்பு (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_MAXIMUM;
	largewords = (largememory << SHIFT_MEGAWORD);

	TinySieve = xcalloc(tinywords, அளவு(uint32_t));
	tinybits = tinywords << SHIFT_WORD;

	SmallSieve = xcalloc(smallwords, அளவு(uint32_t));
	smallbits = smallwords << SHIFT_WORD;

	LargeSieve = xcalloc(largewords, அளவு(uint32_t));
	largebits = largewords << SHIFT_WORD;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	எனில் ((q = BN_new()) == வெற்று)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	எனில் ((largebase = BN_new()) == வெற்று)
		fatal("BN_new failed");
	எனில் (start == வெற்று) {
		எனில் (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} இல்லையெனில் {
		எனில் (BN_copy(largebase, start) == வெற்று)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	எனில் (BN_set_bit(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&time_start);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&time_start),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	க்கு (i = 0; i < tinybits; i++) {
		எனில் (BIT_TEST(TinySieve, i))
			தொடர்; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		க்கு (j = i + t; j < tinybits; j += t)
			BIT_SET(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	க்கு (smallbase = TINY_எண் + 3;
	    smallbase < (SMALL_MAXIMUM - TINY_எண்);
	    smallbase += TINY_எண்) {
		க்கு (i = 0; i < tinybits; i++) {
			எனில் (BIT_TEST(TinySieve, i))
				தொடர்; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			எனில் (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} இல்லையெனில் {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			எனில் (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			க்கு (s /= 2; s < smallbits; s += t)
				BIT_SET(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		க்கு (i = 0; i < smallbits; i++) {
			எனில் (BIT_TEST(SmallSieve, i))
				தொடர்; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << SHIFT_BYTE);
	}

	time(&time_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&time_stop), largetries, (long long)(time_stop - time_start));

	க்கு (j = r = 0; j < largebits; j++) {
		எனில் (BIT_TEST(LargeSieve, j))
			தொடர்; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		எனில் (BN_set_word(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		எனில் (BN_add(q, q, largebase) == 0)
			fatal("BN_add failed");
		எனில் (qfileout(out, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			நிறுத்து;
		}

		r++; /* count q */
	}

	time(&time_stop);

	விடுவி(LargeSieve);
	விடுவி(SmallSieve);
	விடுவி(TinySieve);

	logit("%.24s Found %u candidates", ctime(&time_stop), r);

	திரும்பு (ret);
}

நிலையான வெறுமை
write_checkpoint(எழுத்து *cpfile, uint32_t lineno)
{
	FILE *fp;
	எழுத்து tmp[PATH_MAX];
	முழு r, writeok, closeok;

	r = snprintf(tmp, அளவு(tmp), "%s.XXXXXXXXXX", cpfile);
	எனில் (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		திரும்பு;
	}
	எனில் ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		திரும்பு;
	}
	எனில் ((fp = fdopen(r, "w")) == வெற்று) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		திரும்பு;
	}
	writeok = (fprintf(fp, "%lu\n", (unsigned long)lineno) > 0);
	closeok = (fclose(fp) == 0);
	எனில் (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (unsigned long)lineno, cpfile);
	} இல்லையெனில் {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(வெறுமை)unlink(tmp);
	}
}

நிலையான unsigned long
read_checkpoint(எழுத்து *cpfile)
{
	FILE *fp;
	unsigned long lineno = 0;

	எனில் ((fp = fopen(cpfile, "r")) == வெற்று)
		திரும்பு 0;
	எனில் (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	இல்லையெனில்
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	திரும்பு lineno;
}

நிலையான unsigned long
மொத்தம்_வரிகள்(FILE *f)
{
	unsigned long மொத்தம் = 0;
	எழுத்து lp[QLINESIZE + 1];

	எனில் (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		திரும்பு ULONG_MAX;
	}
	போது (fgets(lp, QLINESIZE + 1, f) != வெற்று)
		மொத்தம்++;
	rewind(f);
	debug("input file has %lu lines", மொத்தம்);
	திரும்பு மொத்தம்;
}

நிலையான எழுத்து *
fmt_time(time_t seconds)
{
	முழு day, hr, min;
	நிலையான எழுத்து buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	எனில் (day > 0)
		snprintf(buf, அளவு buf, "%dd %d:%02d", day, hr, min);
	இல்லையெனில்
		snprintf(buf, அளவு buf, "%d:%02d", hr, min);
	திரும்பு buf;
}

நிலையான வெறுமை
print_progress(unsigned long start_lineno, unsigned long current_lineno,
    unsigned long end_lineno)
{
	நிலையான time_t time_start, time_prev;
	time_t time_now, elapsed;
	unsigned long இலக்கம்_to_process, processed, remaining, percent, eta;
	இரட்டை time_per_வரி;
	எழுத்து *eta_str;

	time_now = monotime();
	எனில் (time_start == 0) {
		time_start = time_prev = time_now;
		திரும்பு;
	}
	/* print progress after 1m then once per 5m */
	எனில் (time_now - time_prev < 5 * 60)
		திரும்பு;
	time_prev = time_now;
	elapsed = time_now - time_start;
	processed = current_lineno - start_lineno;
	remaining = end_lineno - current_lineno;
	இலக்கம்_to_process = end_lineno - start_lineno;
	time_per_வரி = (இரட்டை)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&time_now);
	எனில் (end_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&time_now),
		    processed, fmt_time(elapsed));
		திரும்பு;
	}
	percent = 100 * processed / இலக்கம்_to_process;
	eta = time_per_வரி * remaining;
	eta_str = xstrdup(fmt_time(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&time_now), processed, இலக்கம்_to_process, percent,
	    fmt_time(elapsed), eta_str);
	விடுவி(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
முழு
பகாஎண்_test(FILE *in, FILE *out, uint32_t trials, uint32_t generator_wanted,
    எழுத்து *checkpoint_file, unsigned long start_lineno, unsigned long இலக்கம்_வரிகள்)
{
	BIGNUM *q, *p, *a;
	எழுத்து *cp, *lp;
	uint32_t மொத்தம்_in = 0, மொத்தம்_out = 0, மொத்தம்_possible = 0;
	uint32_t generator_known, in_tests, in_tries, in_type, in_size;
	unsigned long last_processed = 0, end_lineno;
	time_t time_start, time_stop;
	முழு res, is_பகாஎண்;

	எனில் (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		திரும்பு (-1);
	}

	எனில் (இலக்கம்_வரிகள் == 0)
		end_lineno = மொத்தம்_வரிகள்(in);
	இல்லையெனில்
		end_lineno = start_lineno + இலக்கம்_வரிகள்;

	time(&time_start);

	எனில் ((p = BN_new()) == வெற்று)
		fatal("BN_new failed");
	எனில் ((q = BN_new()) == வெற்று)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&time_start), trials, generator_wanted);

	எனில் (checkpoint_file != வெற்று)
		last_processed = read_checkpoint(checkpoint_file);
	last_processed = start_lineno = MAXIMUM(last_processed, start_lineno);
	எனில் (end_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", last_processed);
	இல்லையெனில்
		debug("process from line %lu to line %lu", last_processed,
		    end_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	போது (fgets(lp, QLINESIZE + 1, in) != வெற்று && மொத்தம்_in < end_lineno) {
		மொத்தம்_in++;
		எனில் (மொத்தம்_in <= last_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", மொத்தம்_in);
			தொடர்;
		}
		எனில் (checkpoint_file != வெற்று)
			write_checkpoint(checkpoint_file, மொத்தம்_in);
		print_progress(start_lineno, மொத்தம்_in, end_lineno);
		எனில் (strlen(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", மொத்தம்_in);
			தொடர்;
		}

		/* XXX - fragile parser */
		/* time */
		cp = &lp[14];	/* (skip) */

		/* type */
		in_type = strtoul(cp, &cp, 10);

		/* tests */
		in_tests = strtoul(cp, &cp, 10);

		எனில் (in_tests & MODULI_TESTS_COMPOSITE) {
			debug2("%10u: known composite", மொத்தம்_in);
			தொடர்;
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
		தேர்வு (in_type) {
		நிலை MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", மொத்தம்_in, in_type);
			a = q;
			எனில் (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			எனில் (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			எனில் (BN_add_word(p, 1) == 0)
				fatal("BN_add_word failed");
			in_size += 1;
			generator_known = 0;
			நிறுத்து;
		நிலை MODULI_TYPE_UNSTRUCTURED:
		நிலை MODULI_TYPE_SAFE:
		நிலை MODULI_TYPE_SCHNORR:
		நிலை MODULI_TYPE_STRONG:
		நிலை MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", மொத்தம்_in, in_type);
			a = p;
			எனில் (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			எனில் (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			நிறுத்து;
		இயல்பு:
			debug2("Unknown prime type");
			நிறுத்து;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		எனில் ((uint32_t)BN_இலக்கம்_bits(p) != (in_size + 1)) {
			debug2("%10u: bit size %u mismatch", மொத்தம்_in, in_size);
			தொடர்;
		}
		எனில் (in_size < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", மொத்தம்_in, in_size);
			தொடர்;
		}

		எனில் (in_tests & MODULI_TESTS_MILLER_RABIN)
			in_tries += trials;
		இல்லையெனில்
			in_tries = trials;

		/*
		 * guess unknown generator
		 */
		எனில் (generator_known == 0) {
			எனில் (BN_mod_word(p, 24) == 11)
				generator_known = 2;
			இல்லையெனில் {
				uint32_t r = BN_mod_word(p, 10);

				எனில் (r == 3 || r == 7)
					generator_known = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		எனில் (generator_wanted > 0 &&
		    generator_wanted != generator_known) {
			debug2("%10u: generator %d != %d",
			    மொத்தம்_in, generator_known, generator_wanted);
			தொடர்;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		எனில் (generator_known == 0) {
			debug2("%10u: no known generator", மொத்தம்_in);
			தொடர்;
		}

		மொத்தம்_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_பகாஎண் = BN_is_பகாஎண்_ex(q, 1, வெற்று, வெற்று);
		எனில் (is_பகாஎண் < 0)
			fatal("BN_is_prime_ex failed");
		எனில் (is_பகாஎண் == 0) {
			debug("%10u: q failed first possible prime test",
			    மொத்தம்_in);
			தொடர்;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_பகாஎண் = BN_is_பகாஎண்_ex(p, trials, வெற்று, வெற்று);
		எனில் (is_பகாஎண் < 0)
			fatal("BN_is_prime_ex failed");
		எனில் (is_பகாஎண் == 0) {
			debug("%10u: p is not prime", மொத்தம்_in);
			தொடர்;
		}
		debug("%10u: p is almost certainly prime", மொத்தம்_in);

		/* recheck q more rigorously */
		is_பகாஎண் = BN_is_பகாஎண்_ex(q, trials - 1, வெற்று, வெற்று);
		எனில் (is_பகாஎண் < 0)
			fatal("BN_is_prime_ex failed");
		எனில் (is_பகாஎண் == 0) {
			debug("%10u: q is not prime", மொத்தம்_in);
			தொடர்;
		}
		debug("%10u: q is almost certainly prime", மொத்தம்_in);

		எனில் (qfileout(out, MODULI_TYPE_SAFE,
		    in_tests | MODULI_TESTS_MILLER_RABIN,
		    in_tries, in_size, generator_known, p)) {
			res = -1;
			நிறுத்து;
		}

		மொத்தம்_out++;
	}

	time(&time_stop);
	விடுவி(lp);
	BN_free(p);
	BN_free(q);

	எனில் (checkpoint_file != வெற்று)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&time_stop), மொத்தம்_out, மொத்தம்_possible,
	    (long) (time_stop - time_start));

	திரும்பு (res);
}

#endif /* WITH_OPENSSL */
