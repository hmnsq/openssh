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

#ضمن "includes.h"

#ifdef WITH_OPENSSL

#ضمن <sys/types.h>

#ضمن <openssl/bn.h>
#ضمن <openssl/dh.h>

#ضمن <errno.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <time.h>
#ضمن <unistd.h>
#ضمن <limits.h>

#ضمن "xmalloc.h"
#ضمن "dh.h"
#ضمن "log.h"
#ضمن "misc.h"

#ضمن "openbsd-compat/openssl-compat.h"

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
#define TINY_NUMBER	(1UL<<16)

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
ساكن uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
ساكن uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
ساكن uint32_t *LargeSieve, largewords, largetries, largenumbers;
ساكن uint32_t largebits, largememory;	/* megabytes */
ساكن BIGNUM *largebase;

صحيح gen_candidates(FILE *, uint32_t, BIGNUM *);
صحيح prime_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, unsigned long,
    unsigned long);

/*
 * print moduli out in consistent form,
 */
ساكن صحيح
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	بنية tm *gtm;
	time_t time_now;
	صحيح res;

	time(&time_now);
	gtm = gmtime(&time_now);
	ܐܢ (gtm == عدم)
		ܦܢܐ -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	ܐܢ (res < 0)
		ܦܢܐ (-1);

	ܐܢ (BN_print_fp(ofile, omodulus) < 1)
		ܦܢܐ (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	ܦܢܐ (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
ساكن فراغ
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_word(largebase, s32);
	ܐܢ (r == 0)
		u = 0; /* s divides into largebase exactly */
	ܐܚܪܢܐ
		u = s - r; /* largebase+u is first entry divisible by s */

	ܐܢ (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		ܐܢ (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		لكل (u /= 2; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	ܐܢ (r == 0)
		u = 0; /* s divides p exactly */
	ܐܚܪܢܐ
		u = s - r; /* p+u is first entry divisible by s */

	ܐܢ (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		ܟܡܐ (u & 0x3) {
			ܐܢ (SMALL_MAXIMUM - u < s)
				ܦܢܐ;
			u += s;
		}

		/* Mark all multiples of 4*s */
		لكل (u /= 4; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
صحيح
gen_candidates(FILE *out, uint32_t power, BIGNUM *start)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_NUMBER >> 6;
	uint32_t tinywords = TINY_NUMBER >> 6;
	time_t time_start, time_stop;
	uint32_t i;
	صحيح ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	ܐܢ (power > TEST_MAXIMUM) {
		error("Too many bits: %u > %lu", power, TEST_MAXIMUM);
		ܦܢܐ (-1);
	} ܐܚܪܢܐ ܐܢ (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		ܦܢܐ (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_MAXIMUM;
	largewords = (largememory << SHIFT_MEGAWORD);

	TinySieve = xcalloc(tinywords, حجم(uint32_t));
	tinybits = tinywords << SHIFT_WORD;

	SmallSieve = xcalloc(smallwords, حجم(uint32_t));
	smallbits = smallwords << SHIFT_WORD;

	LargeSieve = xcalloc(largewords, حجم(uint32_t));
	largebits = largewords << SHIFT_WORD;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	ܐܢ ((q = BN_new()) == عدم)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	ܐܢ ((largebase = BN_new()) == عدم)
		fatal("BN_new failed");
	ܐܢ (start == عدم) {
		ܐܢ (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} ܐܚܪܢܐ {
		ܐܢ (BN_copy(largebase, start) == عدم)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	ܐܢ (BN_set_bit(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&time_start);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&time_start),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	لكل (i = 0; i < tinybits; i++) {
		ܐܢ (BIT_TEST(TinySieve, i))
			استمر; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		لكل (j = i + t; j < tinybits; j += t)
			BIT_SET(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	لكل (smallbase = TINY_NUMBER + 3;
	    smallbase < (SMALL_MAXIMUM - TINY_NUMBER);
	    smallbase += TINY_NUMBER) {
		لكل (i = 0; i < tinybits; i++) {
			ܐܢ (BIT_TEST(TinySieve, i))
				استمر; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			ܐܢ (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} ܐܚܪܢܐ {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			ܐܢ (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			لكل (s /= 2; s < smallbits; s += t)
				BIT_SET(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		لكل (i = 0; i < smallbits; i++) {
			ܐܢ (BIT_TEST(SmallSieve, i))
				استمر; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << SHIFT_BYTE);
	}

	time(&time_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&time_stop), largetries, (long long)(time_stop - time_start));

	لكل (j = r = 0; j < largebits; j++) {
		ܐܢ (BIT_TEST(LargeSieve, j))
			استمر; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		ܐܢ (BN_set_word(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		ܐܢ (BN_add(q, q, largebase) == 0)
			fatal("BN_add failed");
		ܐܢ (qfileout(out, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			اكسر;
		}

		r++; /* count q */
	}

	time(&time_stop);

	حرر(LargeSieve);
	حرر(SmallSieve);
	حرر(TinySieve);

	logit("%.24s Found %u candidates", ctime(&time_stop), r);

	ܦܢܐ (ret);
}

ساكن فراغ
write_checkpoint(حرف *cpfile, uint32_t lineno)
{
	FILE *fp;
	حرف tmp[PATH_MAX];
	صحيح r, writeok, closeok;

	r = snprintf(tmp, حجم(tmp), "%s.XXXXXXXXXX", cpfile);
	ܐܢ (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		ܦܢܐ;
	}
	ܐܢ ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		ܦܢܐ;
	}
	ܐܢ ((fp = fdopen(r, "w")) == عدم) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		ܦܢܐ;
	}
	writeok = (fprintf(fp, "%lu\n", (unsigned long)lineno) > 0);
	closeok = (fclose(fp) == 0);
	ܐܢ (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (unsigned long)lineno, cpfile);
	} ܐܚܪܢܐ {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(فراغ)unlink(tmp);
	}
}

ساكن unsigned long
read_checkpoint(حرف *cpfile)
{
	FILE *fp;
	unsigned long lineno = 0;

	ܐܢ ((fp = fopen(cpfile, "r")) == عدم)
		ܦܢܐ 0;
	ܐܢ (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	ܐܚܪܢܐ
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	ܦܢܐ lineno;
}

ساكن unsigned long
count_lines(FILE *f)
{
	unsigned long count = 0;
	حرف lp[QLINESIZE + 1];

	ܐܢ (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		ܦܢܐ ULONG_MAX;
	}
	ܟܡܐ (fgets(lp, QLINESIZE + 1, f) != عدم)
		count++;
	rewind(f);
	debug("input file has %lu lines", count);
	ܦܢܐ count;
}

ساكن حرف *
fmt_time(time_t seconds)
{
	صحيح day, hr, min;
	ساكن حرف buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	ܐܢ (day > 0)
		snprintf(buf, حجم buf, "%dd %d:%02d", day, hr, min);
	ܐܚܪܢܐ
		snprintf(buf, حجم buf, "%d:%02d", hr, min);
	ܦܢܐ buf;
}

ساكن فراغ
print_progress(unsigned long start_lineno, unsigned long current_lineno,
    unsigned long end_lineno)
{
	ساكن time_t time_start, time_prev;
	time_t time_now, elapsed;
	unsigned long num_to_process, processed, remaining, percent, eta;
	مزدوج time_per_line;
	حرف *eta_str;

	time_now = monotime();
	ܐܢ (time_start == 0) {
		time_start = time_prev = time_now;
		ܦܢܐ;
	}
	/* print progress after 1m then once per 5m */
	ܐܢ (time_now - time_prev < 5 * 60)
		ܦܢܐ;
	time_prev = time_now;
	elapsed = time_now - time_start;
	processed = current_lineno - start_lineno;
	remaining = end_lineno - current_lineno;
	num_to_process = end_lineno - start_lineno;
	time_per_line = (مزدوج)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&time_now);
	ܐܢ (end_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&time_now),
		    processed, fmt_time(elapsed));
		ܦܢܐ;
	}
	percent = 100 * processed / num_to_process;
	eta = time_per_line * remaining;
	eta_str = xstrdup(fmt_time(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&time_now), processed, num_to_process, percent,
	    fmt_time(elapsed), eta_str);
	حرر(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
صحيح
prime_test(FILE *in, FILE *out, uint32_t trials, uint32_t generator_wanted,
    حرف *checkpoint_file, unsigned long start_lineno, unsigned long num_lines)
{
	BIGNUM *q, *p, *a;
	حرف *cp, *lp;
	uint32_t count_in = 0, count_out = 0, count_possible = 0;
	uint32_t generator_known, in_tests, in_tries, in_type, in_size;
	unsigned long last_processed = 0, end_lineno;
	time_t time_start, time_stop;
	صحيح res, is_prime;

	ܐܢ (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		ܦܢܐ (-1);
	}

	ܐܢ (num_lines == 0)
		end_lineno = count_lines(in);
	ܐܚܪܢܐ
		end_lineno = start_lineno + num_lines;

	time(&time_start);

	ܐܢ ((p = BN_new()) == عدم)
		fatal("BN_new failed");
	ܐܢ ((q = BN_new()) == عدم)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&time_start), trials, generator_wanted);

	ܐܢ (checkpoint_file != عدم)
		last_processed = read_checkpoint(checkpoint_file);
	last_processed = start_lineno = MAXIMUM(last_processed, start_lineno);
	ܐܢ (end_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", last_processed);
	ܐܚܪܢܐ
		debug("process from line %lu to line %lu", last_processed,
		    end_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	ܟܡܐ (fgets(lp, QLINESIZE + 1, in) != عدم && count_in < end_lineno) {
		count_in++;
		ܐܢ (count_in <= last_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", count_in);
			استمر;
		}
		ܐܢ (checkpoint_file != عدم)
			write_checkpoint(checkpoint_file, count_in);
		print_progress(start_lineno, count_in, end_lineno);
		ܐܢ (strlen(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", count_in);
			استمر;
		}

		/* XXX - fragile parser */
		/* time */
		cp = &lp[14];	/* (skip) */

		/* type */
		in_type = strtoul(cp, &cp, 10);

		/* tests */
		in_tests = strtoul(cp, &cp, 10);

		ܐܢ (in_tests & MODULI_TESTS_COMPOSITE) {
			debug2("%10u: known composite", count_in);
			استمر;
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
		بدل (in_type) {
		حالة MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", count_in, in_type);
			a = q;
			ܐܢ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			ܐܢ (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			ܐܢ (BN_add_word(p, 1) == 0)
				fatal("BN_add_word failed");
			in_size += 1;
			generator_known = 0;
			اكسر;
		حالة MODULI_TYPE_UNSTRUCTURED:
		حالة MODULI_TYPE_SAFE:
		حالة MODULI_TYPE_SCHNORR:
		حالة MODULI_TYPE_STRONG:
		حالة MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", count_in, in_type);
			a = p;
			ܐܢ (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			ܐܢ (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			اكسر;
		افتراضي:
			debug2("Unknown prime type");
			اكسر;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		ܐܢ ((uint32_t)BN_num_bits(p) != (in_size + 1)) {
			debug2("%10u: bit size %u mismatch", count_in, in_size);
			استمر;
		}
		ܐܢ (in_size < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", count_in, in_size);
			استمر;
		}

		ܐܢ (in_tests & MODULI_TESTS_MILLER_RABIN)
			in_tries += trials;
		ܐܚܪܢܐ
			in_tries = trials;

		/*
		 * guess unknown generator
		 */
		ܐܢ (generator_known == 0) {
			ܐܢ (BN_mod_word(p, 24) == 11)
				generator_known = 2;
			ܐܚܪܢܐ {
				uint32_t r = BN_mod_word(p, 10);

				ܐܢ (r == 3 || r == 7)
					generator_known = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		ܐܢ (generator_wanted > 0 &&
		    generator_wanted != generator_known) {
			debug2("%10u: generator %d != %d",
			    count_in, generator_known, generator_wanted);
			استمر;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		ܐܢ (generator_known == 0) {
			debug2("%10u: no known generator", count_in);
			استمر;
		}

		count_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_prime = BN_is_prime_ex(q, 1, عدم, عدم);
		ܐܢ (is_prime < 0)
			fatal("BN_is_prime_ex failed");
		ܐܢ (is_prime == 0) {
			debug("%10u: q failed first possible prime test",
			    count_in);
			استمر;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_prime = BN_is_prime_ex(p, trials, عدم, عدم);
		ܐܢ (is_prime < 0)
			fatal("BN_is_prime_ex failed");
		ܐܢ (is_prime == 0) {
			debug("%10u: p is not prime", count_in);
			استمر;
		}
		debug("%10u: p is almost certainly prime", count_in);

		/* recheck q more rigorously */
		is_prime = BN_is_prime_ex(q, trials - 1, عدم, عدم);
		ܐܢ (is_prime < 0)
			fatal("BN_is_prime_ex failed");
		ܐܢ (is_prime == 0) {
			debug("%10u: q is not prime", count_in);
			استمر;
		}
		debug("%10u: q is almost certainly prime", count_in);

		ܐܢ (qfileout(out, MODULI_TYPE_SAFE,
		    in_tests | MODULI_TESTS_MILLER_RABIN,
		    in_tries, in_size, generator_known, p)) {
			res = -1;
			اكسر;
		}

		count_out++;
	}

	time(&time_stop);
	حرر(lp);
	BN_free(p);
	BN_free(q);

	ܐܢ (checkpoint_file != عدم)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&time_stop), count_out, count_possible,
	    (long) (time_stop - time_start));

	ܦܢܐ (res);
}

#endif /* WITH_OPENSSL */
