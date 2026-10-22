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

#અન્તર્ભાવ "includes.h"

#ifdef WITH_OPENSSL

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/dh.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "dh.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

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
#define TINY_સંખ્યા	(1UL<<16)

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
સ્થિર uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
સ્થિર uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
સ્થિર uint32_t *LargeSieve, largewords, largetries, largenumbers;
સ્થિર uint32_t largebits, largememory;	/* megabytes */
સ્થિર BIGNUM *largebase;

પૂર્ણાંક gen_candidates(FILE *, uint32_t, BIGNUM *);
પૂર્ણાંક અવિભાજ્ય_test(FILE *, FILE *, uint32_t, uint32_t, અક્ષર *, unsigned long,
    unsigned long);

/*
 * print moduli out in consistent form,
 */
સ્થિર પૂર્ણાંક
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	સંરચના tm *gtm;
	time_t time_now;
	પૂર્ણાંક res;

	time(&time_now);
	gtm = gmtime(&time_now);
	જો (gtm == ખાલી)
		પાછા -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	જો (res < 0)
		પાછા (-1);

	જો (BN_print_fp(ofile, omodulus) < 1)
		પાછા (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	પાછા (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
સ્થિર શૂન્ય
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_word(largebase, s32);
	જો (r == 0)
		u = 0; /* s divides into largebase exactly */
	નહીંતર
		u = s - r; /* largebase+u is first entry divisible by s */

	જો (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		જો (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		માટે (u /= 2; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	જો (r == 0)
		u = 0; /* s divides p exactly */
	નહીંતર
		u = s - r; /* p+u is first entry divisible by s */

	જો (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		જ્યારે (u & 0x3) {
			જો (SMALL_MAXIMUM - u < s)
				પાછા;
			u += s;
		}

		/* Mark all multiples of 4*s */
		માટે (u /= 4; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
પૂર્ણાંક
gen_candidates(FILE *out, uint32_t power, BIGNUM *start)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_સંખ્યા >> 6;
	uint32_t tinywords = TINY_સંખ્યા >> 6;
	time_t time_start, time_stop;
	uint32_t i;
	પૂર્ણાંક ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	જો (power > TEST_MAXIMUM) {
		error("Too many bits: %u > %lu", power, TEST_MAXIMUM);
		પાછા (-1);
	} નહીંતર જો (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		પાછા (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_MAXIMUM;
	largewords = (largememory << SHIFT_MEGAWORD);

	TinySieve = xcalloc(tinywords, કદ(uint32_t));
	tinybits = tinywords << SHIFT_WORD;

	SmallSieve = xcalloc(smallwords, કદ(uint32_t));
	smallbits = smallwords << SHIFT_WORD;

	LargeSieve = xcalloc(largewords, કદ(uint32_t));
	largebits = largewords << SHIFT_WORD;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	જો ((q = BN_new()) == ખાલી)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	જો ((largebase = BN_new()) == ખાલી)
		fatal("BN_new failed");
	જો (start == ખાલી) {
		જો (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} નહીંતર {
		જો (BN_copy(largebase, start) == ખાલી)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	જો (BN_set_bit(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&time_start);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&time_start),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	માટે (i = 0; i < tinybits; i++) {
		જો (BIT_TEST(TinySieve, i))
			ચાલુ; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		માટે (j = i + t; j < tinybits; j += t)
			BIT_SET(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	માટે (smallbase = TINY_સંખ્યા + 3;
	    smallbase < (SMALL_MAXIMUM - TINY_સંખ્યા);
	    smallbase += TINY_સંખ્યા) {
		માટે (i = 0; i < tinybits; i++) {
			જો (BIT_TEST(TinySieve, i))
				ચાલુ; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			જો (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} નહીંતર {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			જો (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			માટે (s /= 2; s < smallbits; s += t)
				BIT_SET(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		માટે (i = 0; i < smallbits; i++) {
			જો (BIT_TEST(SmallSieve, i))
				ચાલુ; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << SHIFT_BYTE);
	}

	time(&time_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&time_stop), largetries, (long long)(time_stop - time_start));

	માટે (j = r = 0; j < largebits; j++) {
		જો (BIT_TEST(LargeSieve, j))
			ચાલુ; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		જો (BN_set_word(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		જો (BN_add(q, q, largebase) == 0)
			fatal("BN_add failed");
		જો (qfileout(out, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			તોડો;
		}

		r++; /* count q */
	}

	time(&time_stop);

	મુક્ત(LargeSieve);
	મુક્ત(SmallSieve);
	મુક્ત(TinySieve);

	logit("%.24s Found %u candidates", ctime(&time_stop), r);

	પાછા (ret);
}

સ્થિર શૂન્ય
write_checkpoint(અક્ષર *cpfile, uint32_t lineno)
{
	FILE *fp;
	અક્ષર tmp[PATH_MAX];
	પૂર્ણાંક r, writeok, closeok;

	r = snprintf(tmp, કદ(tmp), "%s.XXXXXXXXXX", cpfile);
	જો (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		પાછા;
	}
	જો ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		પાછા;
	}
	જો ((fp = fdopen(r, "w")) == ખાલી) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		પાછા;
	}
	writeok = (fprintf(fp, "%lu\n", (unsigned long)lineno) > 0);
	closeok = (fclose(fp) == 0);
	જો (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (unsigned long)lineno, cpfile);
	} નહીંતર {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(શૂન્ય)unlink(tmp);
	}
}

સ્થિર unsigned long
read_checkpoint(અક્ષર *cpfile)
{
	FILE *fp;
	unsigned long lineno = 0;

	જો ((fp = fopen(cpfile, "r")) == ખાલી)
		પાછા 0;
	જો (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	નહીંતર
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	પાછા lineno;
}

સ્થિર unsigned long
ગણતરી_લીટીઓ(FILE *f)
{
	unsigned long ગણતરી = 0;
	અક્ષર lp[QLINESIZE + 1];

	જો (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		પાછા ULONG_MAX;
	}
	જ્યારે (fgets(lp, QLINESIZE + 1, f) != ખાલી)
		ગણતરી++;
	rewind(f);
	debug("input file has %lu lines", ગણતરી);
	પાછા ગણતરી;
}

સ્થિર અક્ષર *
fmt_time(time_t seconds)
{
	પૂર્ણાંક day, hr, min;
	સ્થિર અક્ષર buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	જો (day > 0)
		snprintf(buf, કદ buf, "%dd %d:%02d", day, hr, min);
	નહીંતર
		snprintf(buf, કદ buf, "%d:%02d", hr, min);
	પાછા buf;
}

સ્થિર શૂન્ય
print_progress(unsigned long start_lineno, unsigned long current_lineno,
    unsigned long end_lineno)
{
	સ્થિર time_t time_start, time_prev;
	time_t time_now, elapsed;
	unsigned long અંક_to_process, processed, remaining, percent, eta;
	દ્વિગુણ time_per_લીટી;
	અક્ષર *eta_str;

	time_now = monotime();
	જો (time_start == 0) {
		time_start = time_prev = time_now;
		પાછા;
	}
	/* print progress after 1m then once per 5m */
	જો (time_now - time_prev < 5 * 60)
		પાછા;
	time_prev = time_now;
	elapsed = time_now - time_start;
	processed = current_lineno - start_lineno;
	remaining = end_lineno - current_lineno;
	અંક_to_process = end_lineno - start_lineno;
	time_per_લીટી = (દ્વિગુણ)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&time_now);
	જો (end_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&time_now),
		    processed, fmt_time(elapsed));
		પાછા;
	}
	percent = 100 * processed / અંક_to_process;
	eta = time_per_લીટી * remaining;
	eta_str = xstrdup(fmt_time(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&time_now), processed, અંક_to_process, percent,
	    fmt_time(elapsed), eta_str);
	મુક્ત(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
પૂર્ણાંક
અવિભાજ્ય_test(FILE *in, FILE *out, uint32_t trials, uint32_t generator_wanted,
    અક્ષર *checkpoint_file, unsigned long start_lineno, unsigned long અંક_લીટીઓ)
{
	BIGNUM *q, *p, *a;
	અક્ષર *cp, *lp;
	uint32_t ગણતરી_in = 0, ગણતરી_out = 0, ગણતરી_possible = 0;
	uint32_t generator_known, in_tests, in_tries, in_type, in_size;
	unsigned long last_processed = 0, end_lineno;
	time_t time_start, time_stop;
	પૂર્ણાંક res, is_અવિભાજ્ય;

	જો (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		પાછા (-1);
	}

	જો (અંક_લીટીઓ == 0)
		end_lineno = ગણતરી_લીટીઓ(in);
	નહીંતર
		end_lineno = start_lineno + અંક_લીટીઓ;

	time(&time_start);

	જો ((p = BN_new()) == ખાલી)
		fatal("BN_new failed");
	જો ((q = BN_new()) == ખાલી)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&time_start), trials, generator_wanted);

	જો (checkpoint_file != ખાલી)
		last_processed = read_checkpoint(checkpoint_file);
	last_processed = start_lineno = MAXIMUM(last_processed, start_lineno);
	જો (end_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", last_processed);
	નહીંતર
		debug("process from line %lu to line %lu", last_processed,
		    end_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	જ્યારે (fgets(lp, QLINESIZE + 1, in) != ખાલી && ગણતરી_in < end_lineno) {
		ગણતરી_in++;
		જો (ગણતરી_in <= last_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", ગણતરી_in);
			ચાલુ;
		}
		જો (checkpoint_file != ખાલી)
			write_checkpoint(checkpoint_file, ગણતરી_in);
		print_progress(start_lineno, ગણતરી_in, end_lineno);
		જો (strlen(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", ગણતરી_in);
			ચાલુ;
		}

		/* XXX - fragile parser */
		/* time */
		cp = &lp[14];	/* (skip) */

		/* type */
		in_type = strtoul(cp, &cp, 10);

		/* tests */
		in_tests = strtoul(cp, &cp, 10);

		જો (in_tests & MODULI_TESTS_COMPOSITE) {
			debug2("%10u: known composite", ગણતરી_in);
			ચાલુ;
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
		પસંદગી (in_type) {
		સ્થિતિ MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", ગણતરી_in, in_type);
			a = q;
			જો (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			જો (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			જો (BN_add_word(p, 1) == 0)
				fatal("BN_add_word failed");
			in_size += 1;
			generator_known = 0;
			તોડો;
		સ્થિતિ MODULI_TYPE_UNSTRUCTURED:
		સ્થિતિ MODULI_TYPE_SAFE:
		સ્થિતિ MODULI_TYPE_SCHNORR:
		સ્થિતિ MODULI_TYPE_STRONG:
		સ્થિતિ MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", ગણતરી_in, in_type);
			a = p;
			જો (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			જો (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			તોડો;
		મૂળભૂત:
			debug2("Unknown prime type");
			તોડો;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		જો ((uint32_t)BN_અંક_bits(p) != (in_size + 1)) {
			debug2("%10u: bit size %u mismatch", ગણતરી_in, in_size);
			ચાલુ;
		}
		જો (in_size < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", ગણતરી_in, in_size);
			ચાલુ;
		}

		જો (in_tests & MODULI_TESTS_MILLER_RABIN)
			in_tries += trials;
		નહીંતર
			in_tries = trials;

		/*
		 * guess unknown generator
		 */
		જો (generator_known == 0) {
			જો (BN_mod_word(p, 24) == 11)
				generator_known = 2;
			નહીંતર {
				uint32_t r = BN_mod_word(p, 10);

				જો (r == 3 || r == 7)
					generator_known = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		જો (generator_wanted > 0 &&
		    generator_wanted != generator_known) {
			debug2("%10u: generator %d != %d",
			    ગણતરી_in, generator_known, generator_wanted);
			ચાલુ;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		જો (generator_known == 0) {
			debug2("%10u: no known generator", ગણતરી_in);
			ચાલુ;
		}

		ગણતરી_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_અવિભાજ્ય = BN_is_અવિભાજ્ય_ex(q, 1, ખાલી, ખાલી);
		જો (is_અવિભાજ્ય < 0)
			fatal("BN_is_prime_ex failed");
		જો (is_અવિભાજ્ય == 0) {
			debug("%10u: q failed first possible prime test",
			    ગણતરી_in);
			ચાલુ;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_અવિભાજ્ય = BN_is_અવિભાજ્ય_ex(p, trials, ખાલી, ખાલી);
		જો (is_અવિભાજ્ય < 0)
			fatal("BN_is_prime_ex failed");
		જો (is_અવિભાજ્ય == 0) {
			debug("%10u: p is not prime", ગણતરી_in);
			ચાલુ;
		}
		debug("%10u: p is almost certainly prime", ગણતરી_in);

		/* recheck q more rigorously */
		is_અવિભાજ્ય = BN_is_અવિભાજ્ય_ex(q, trials - 1, ખાલી, ખાલી);
		જો (is_અવિભાજ્ય < 0)
			fatal("BN_is_prime_ex failed");
		જો (is_અવિભાજ્ય == 0) {
			debug("%10u: q is not prime", ગણતરી_in);
			ચાલુ;
		}
		debug("%10u: q is almost certainly prime", ગણતરી_in);

		જો (qfileout(out, MODULI_TYPE_SAFE,
		    in_tests | MODULI_TESTS_MILLER_RABIN,
		    in_tries, in_size, generator_known, p)) {
			res = -1;
			તોડો;
		}

		ગણતરી_out++;
	}

	time(&time_stop);
	મુક્ત(lp);
	BN_free(p);
	BN_free(q);

	જો (checkpoint_file != ખાલી)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&time_stop), ગણતરી_out, ગણતરી_possible,
	    (long) (time_stop - time_start));

	પાછા (res);
}

#endif /* WITH_OPENSSL */
