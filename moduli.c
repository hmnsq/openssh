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

#অন্তর্ভাব "includes.h"

#ifdef WITH_OPENSSL

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/dh.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "dh.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

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
#define TINY_সংখ্যা	(1UL<<16)

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
স্থির uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
স্থির uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
স্থির uint32_t *LargeSieve, largewords, largetries, largenumbers;
স্থির uint32_t largebits, largememory;	/* megabytes */
স্থির BIGNUM *largebase;

পূর্ণসংখ্যা gen_candidates(FILE *, uint32_t, BIGNUM *);
পূর্ণসংখ্যা মৌলিক_test(FILE *, FILE *, uint32_t, uint32_t, অক্ষর *, unsigned long,
    unsigned long);

/*
 * print moduli out in consistent form,
 */
স্থির পূর্ণসংখ্যা
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	কাঠামো tm *gtm;
	time_t time_now;
	পূর্ণসংখ্যা res;

	time(&time_now);
	gtm = gmtime(&time_now);
	যদি (gtm == ফাঁকা)
		ফেরত -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	যদি (res < 0)
		ফেরত (-1);

	যদি (BN_print_fp(ofile, omodulus) < 1)
		ফেরত (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	ফেরত (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
স্থির শূন্য
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_word(largebase, s32);
	যদি (r == 0)
		u = 0; /* s divides into largebase exactly */
	অন্যথা
		u = s - r; /* largebase+u is first entry divisible by s */

	যদি (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		যদি (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		জন্য (u /= 2; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	যদি (r == 0)
		u = 0; /* s divides p exactly */
	অন্যথা
		u = s - r; /* p+u is first entry divisible by s */

	যদি (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		যখন (u & 0x3) {
			যদি (SMALL_MAXIMUM - u < s)
				ফেরত;
			u += s;
		}

		/* Mark all multiples of 4*s */
		জন্য (u /= 4; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
পূর্ণসংখ্যা
gen_candidates(FILE *out, uint32_t power, BIGNUM *start)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_সংখ্যা >> 6;
	uint32_t tinywords = TINY_সংখ্যা >> 6;
	time_t time_start, time_stop;
	uint32_t i;
	পূর্ণসংখ্যা ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	যদি (power > TEST_MAXIMUM) {
		error("Too many bits: %u > %lu", power, TEST_MAXIMUM);
		ফেরত (-1);
	} অন্যথা যদি (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		ফেরত (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_MAXIMUM;
	largewords = (largememory << SHIFT_MEGAWORD);

	TinySieve = xcalloc(tinywords, আকার(uint32_t));
	tinybits = tinywords << SHIFT_WORD;

	SmallSieve = xcalloc(smallwords, আকার(uint32_t));
	smallbits = smallwords << SHIFT_WORD;

	LargeSieve = xcalloc(largewords, আকার(uint32_t));
	largebits = largewords << SHIFT_WORD;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	যদি ((q = BN_new()) == ফাঁকা)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	যদি ((largebase = BN_new()) == ফাঁকা)
		fatal("BN_new failed");
	যদি (start == ফাঁকা) {
		যদি (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} অন্যথা {
		যদি (BN_copy(largebase, start) == ফাঁকা)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	যদি (BN_set_bit(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&time_start);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&time_start),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	জন্য (i = 0; i < tinybits; i++) {
		যদি (BIT_TEST(TinySieve, i))
			চালু; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		জন্য (j = i + t; j < tinybits; j += t)
			BIT_SET(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	জন্য (smallbase = TINY_সংখ্যা + 3;
	    smallbase < (SMALL_MAXIMUM - TINY_সংখ্যা);
	    smallbase += TINY_সংখ্যা) {
		জন্য (i = 0; i < tinybits; i++) {
			যদি (BIT_TEST(TinySieve, i))
				চালু; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			যদি (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} অন্যথা {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			যদি (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			জন্য (s /= 2; s < smallbits; s += t)
				BIT_SET(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		জন্য (i = 0; i < smallbits; i++) {
			যদি (BIT_TEST(SmallSieve, i))
				চালু; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << SHIFT_BYTE);
	}

	time(&time_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&time_stop), largetries, (long long)(time_stop - time_start));

	জন্য (j = r = 0; j < largebits; j++) {
		যদি (BIT_TEST(LargeSieve, j))
			চালু; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		যদি (BN_set_word(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		যদি (BN_add(q, q, largebase) == 0)
			fatal("BN_add failed");
		যদি (qfileout(out, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			বিরতি;
		}

		r++; /* count q */
	}

	time(&time_stop);

	মুক্ত(LargeSieve);
	মুক্ত(SmallSieve);
	মুক্ত(TinySieve);

	logit("%.24s Found %u candidates", ctime(&time_stop), r);

	ফেরত (ret);
}

স্থির শূন্য
write_checkpoint(অক্ষর *cpfile, uint32_t lineno)
{
	FILE *fp;
	অক্ষর tmp[PATH_MAX];
	পূর্ণসংখ্যা r, writeok, closeok;

	r = snprintf(tmp, আকার(tmp), "%s.XXXXXXXXXX", cpfile);
	যদি (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		ফেরত;
	}
	যদি ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		ফেরত;
	}
	যদি ((fp = fdopen(r, "w")) == ফাঁকা) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		ফেরত;
	}
	writeok = (fprintf(fp, "%lu\n", (unsigned long)lineno) > 0);
	closeok = (fclose(fp) == 0);
	যদি (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (unsigned long)lineno, cpfile);
	} অন্যথা {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(শূন্য)unlink(tmp);
	}
}

স্থির unsigned long
read_checkpoint(অক্ষর *cpfile)
{
	FILE *fp;
	unsigned long lineno = 0;

	যদি ((fp = fopen(cpfile, "r")) == ফাঁকা)
		ফেরত 0;
	যদি (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	অন্যথা
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	ফেরত lineno;
}

স্থির unsigned long
গুনতি_সারিগুলি(FILE *f)
{
	unsigned long গুনতি = 0;
	অক্ষর lp[QLINESIZE + 1];

	যদি (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		ফেরত ULONG_MAX;
	}
	যখন (fgets(lp, QLINESIZE + 1, f) != ফাঁকা)
		গুনতি++;
	rewind(f);
	debug("input file has %lu lines", গুনতি);
	ফেরত গুনতি;
}

স্থির অক্ষর *
fmt_time(time_t seconds)
{
	পূর্ণসংখ্যা day, hr, min;
	স্থির অক্ষর buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	যদি (day > 0)
		snprintf(buf, আকার buf, "%dd %d:%02d", day, hr, min);
	অন্যথা
		snprintf(buf, আকার buf, "%d:%02d", hr, min);
	ফেরত buf;
}

স্থির শূন্য
print_progress(unsigned long start_lineno, unsigned long current_lineno,
    unsigned long end_lineno)
{
	স্থির time_t time_start, time_পূর্ব;
	time_t time_now, elapsed;
	unsigned long অঙ্ক_to_process, processed, remaining, percent, eta;
	দ্বিগুণ time_per_সারি;
	অক্ষর *eta_str;

	time_now = monotime();
	যদি (time_start == 0) {
		time_start = time_পূর্ব = time_now;
		ফেরত;
	}
	/* print progress after 1m then once per 5m */
	যদি (time_now - time_পূর্ব < 5 * 60)
		ফেরত;
	time_পূর্ব = time_now;
	elapsed = time_now - time_start;
	processed = current_lineno - start_lineno;
	remaining = end_lineno - current_lineno;
	অঙ্ক_to_process = end_lineno - start_lineno;
	time_per_সারি = (দ্বিগুণ)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&time_now);
	যদি (end_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&time_now),
		    processed, fmt_time(elapsed));
		ফেরত;
	}
	percent = 100 * processed / অঙ্ক_to_process;
	eta = time_per_সারি * remaining;
	eta_str = xstrdup(fmt_time(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&time_now), processed, অঙ্ক_to_process, percent,
	    fmt_time(elapsed), eta_str);
	মুক্ত(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
পূর্ণসংখ্যা
মৌলিক_test(FILE *in, FILE *out, uint32_t trials, uint32_t generator_wanted,
    অক্ষর *checkpoint_file, unsigned long start_lineno, unsigned long অঙ্ক_সারিগুলি)
{
	BIGNUM *q, *p, *a;
	অক্ষর *cp, *lp;
	uint32_t গুনতি_in = 0, গুনতি_out = 0, গুনতি_possible = 0;
	uint32_t generator_known, in_tests, in_tries, in_type, in_আকার;
	unsigned long last_processed = 0, end_lineno;
	time_t time_start, time_stop;
	পূর্ণসংখ্যা res, is_মৌলিক;

	যদি (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		ফেরত (-1);
	}

	যদি (অঙ্ক_সারিগুলি == 0)
		end_lineno = গুনতি_সারিগুলি(in);
	অন্যথা
		end_lineno = start_lineno + অঙ্ক_সারিগুলি;

	time(&time_start);

	যদি ((p = BN_new()) == ফাঁকা)
		fatal("BN_new failed");
	যদি ((q = BN_new()) == ফাঁকা)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&time_start), trials, generator_wanted);

	যদি (checkpoint_file != ফাঁকা)
		last_processed = read_checkpoint(checkpoint_file);
	last_processed = start_lineno = MAXIMUM(last_processed, start_lineno);
	যদি (end_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", last_processed);
	অন্যথা
		debug("process from line %lu to line %lu", last_processed,
		    end_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	যখন (fgets(lp, QLINESIZE + 1, in) != ফাঁকা && গুনতি_in < end_lineno) {
		গুনতি_in++;
		যদি (গুনতি_in <= last_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", গুনতি_in);
			চালু;
		}
		যদি (checkpoint_file != ফাঁকা)
			write_checkpoint(checkpoint_file, গুনতি_in);
		print_progress(start_lineno, গুনতি_in, end_lineno);
		যদি (strlen(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", গুনতি_in);
			চালু;
		}

		/* XXX - fragile parser */
		/* time */
		cp = &lp[14];	/* (skip) */

		/* type */
		in_type = strtoul(cp, &cp, 10);

		/* tests */
		in_tests = strtoul(cp, &cp, 10);

		যদি (in_tests & MODULI_TESTS_COMPOSITE) {
			debug2("%10u: known composite", গুনতি_in);
			চালু;
		}

		/* tries */
		in_tries = strtoul(cp, &cp, 10);

		/* size (most significant bit) */
		in_আকার = strtoul(cp, &cp, 10);

		/* generator (hex) */
		generator_known = strtoul(cp, &cp, 16);

		/* Skip white space */
		cp += strspn(cp, " ");

		/* modulus (hex) */
		নির্বাচন (in_type) {
		ক্ষেত্র MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", গুনতি_in, in_type);
			a = q;
			যদি (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			যদি (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			যদি (BN_add_word(p, 1) == 0)
				fatal("BN_add_word failed");
			in_আকার += 1;
			generator_known = 0;
			বিরতি;
		ক্ষেত্র MODULI_TYPE_UNSTRUCTURED:
		ক্ষেত্র MODULI_TYPE_SAFE:
		ক্ষেত্র MODULI_TYPE_SCHNORR:
		ক্ষেত্র MODULI_TYPE_STRONG:
		ক্ষেত্র MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", গুনতি_in, in_type);
			a = p;
			যদি (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			যদি (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			বিরতি;
		পূর্বনির্ধারিত:
			debug2("Unknown prime type");
			বিরতি;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		যদি ((uint32_t)BN_অঙ্ক_bits(p) != (in_আকার + 1)) {
			debug2("%10u: bit size %u mismatch", গুনতি_in, in_আকার);
			চালু;
		}
		যদি (in_আকার < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", গুনতি_in, in_আকার);
			চালু;
		}

		যদি (in_tests & MODULI_TESTS_MILLER_RABIN)
			in_tries += trials;
		অন্যথা
			in_tries = trials;

		/*
		 * guess unknown generator
		 */
		যদি (generator_known == 0) {
			যদি (BN_mod_word(p, 24) == 11)
				generator_known = 2;
			অন্যথা {
				uint32_t r = BN_mod_word(p, 10);

				যদি (r == 3 || r == 7)
					generator_known = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		যদি (generator_wanted > 0 &&
		    generator_wanted != generator_known) {
			debug2("%10u: generator %d != %d",
			    গুনতি_in, generator_known, generator_wanted);
			চালু;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		যদি (generator_known == 0) {
			debug2("%10u: no known generator", গুনতি_in);
			চালু;
		}

		গুনতি_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_মৌলিক = BN_is_মৌলিক_ex(q, 1, ফাঁকা, ফাঁকা);
		যদি (is_মৌলিক < 0)
			fatal("BN_is_prime_ex failed");
		যদি (is_মৌলিক == 0) {
			debug("%10u: q failed first possible prime test",
			    গুনতি_in);
			চালু;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_মৌলিক = BN_is_মৌলিক_ex(p, trials, ফাঁকা, ফাঁকা);
		যদি (is_মৌলিক < 0)
			fatal("BN_is_prime_ex failed");
		যদি (is_মৌলিক == 0) {
			debug("%10u: p is not prime", গুনতি_in);
			চালু;
		}
		debug("%10u: p is almost certainly prime", গুনতি_in);

		/* recheck q more rigorously */
		is_মৌলিক = BN_is_মৌলিক_ex(q, trials - 1, ফাঁকা, ফাঁকা);
		যদি (is_মৌলিক < 0)
			fatal("BN_is_prime_ex failed");
		যদি (is_মৌলিক == 0) {
			debug("%10u: q is not prime", গুনতি_in);
			চালু;
		}
		debug("%10u: q is almost certainly prime", গুনতি_in);

		যদি (qfileout(out, MODULI_TYPE_SAFE,
		    in_tests | MODULI_TESTS_MILLER_RABIN,
		    in_tries, in_আকার, generator_known, p)) {
			res = -1;
			বিরতি;
		}

		গুনতি_out++;
	}

	time(&time_stop);
	মুক্ত(lp);
	BN_free(p);
	BN_free(q);

	যদি (checkpoint_file != ফাঁকা)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&time_stop), গুনতি_out, গুনতি_possible,
	    (long) (time_stop - time_start));

	ফেরত (res);
}

#endif /* WITH_OPENSSL */
