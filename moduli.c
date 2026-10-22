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

#अन्तर्भाव "includes.h"

#ifdef WITH_OPENSSL

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/dh.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "dh.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

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
#define TINY_सङ्ख्या	(1UL<<16)

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
स्थिर uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
स्थिर uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
स्थिर uint32_t *LargeSieve, largewords, largetries, largenumbers;
स्थिर uint32_t largebits, largememory;	/* megabytes */
स्थिर BIGNUM *largebase;

पूर्णाङ्क gen_candidates(FILE *, uint32_t, BIGNUM *);
पूर्णाङ्क अविभाज्यः_test(FILE *, FILE *, uint32_t, uint32_t, वर्ण *, unsigned long,
    unsigned long);

/*
 * print moduli out in consistent form,
 */
स्थिर पूर्णाङ्क
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	संरचना tm *gtm;
	time_t time_now;
	पूर्णाङ्क res;

	time(&time_now);
	gtm = gmtime(&time_now);
	सचे (gtm == रिक्त)
		पटिनिवत्त -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	सचे (res < 0)
		पटिनिवत्त (-1);

	सचे (BN_print_fp(ofile, omodulus) < 1)
		पटिनिवत्त (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	पटिनिवत्त (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
स्थिर शून्य
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_word(largebase, s32);
	सचे (r == 0)
		u = 0; /* s divides into largebase exactly */
	अञ्ञथा
		u = s - r; /* largebase+u is first entry divisible by s */

	सचे (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		सचे (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		अत्थाय (u /= 2; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	सचे (r == 0)
		u = 0; /* s divides p exactly */
	अञ्ञथा
		u = s - r; /* p+u is first entry divisible by s */

	सचे (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		याव (u & 0x3) {
			सचे (SMALL_MAXIMUM - u < s)
				पटिनिवत्त;
			u += s;
		}

		/* Mark all multiples of 4*s */
		अत्थाय (u /= 4; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
पूर्णाङ्क
gen_candidates(FILE *out, uint32_t power, BIGNUM *start)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_सङ्ख्या >> 6;
	uint32_t tinywords = TINY_सङ्ख्या >> 6;
	time_t time_start, time_stop;
	uint32_t i;
	पूर्णाङ्क ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	सचे (power > TEST_MAXIMUM) {
		error("Too many bits: %u > %lu", power, TEST_MAXIMUM);
		पटिनिवत्त (-1);
	} अञ्ञथा सचे (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		पटिनिवत्त (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_MAXIMUM;
	largewords = (largememory << SHIFT_MEGAWORD);

	TinySieve = xcalloc(tinywords, परिमाण(uint32_t));
	tinybits = tinywords << SHIFT_WORD;

	SmallSieve = xcalloc(smallwords, परिमाण(uint32_t));
	smallbits = smallwords << SHIFT_WORD;

	LargeSieve = xcalloc(largewords, परिमाण(uint32_t));
	largebits = largewords << SHIFT_WORD;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	सचे ((q = BN_new()) == रिक्त)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	सचे ((largebase = BN_new()) == रिक्त)
		fatal("BN_new failed");
	सचे (start == रिक्त) {
		सचे (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} अञ्ञथा {
		सचे (BN_copy(largebase, start) == रिक्त)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	सचे (BN_set_bit(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&time_start);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&time_start),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	अत्थाय (i = 0; i < tinybits; i++) {
		सचे (BIT_TEST(TinySieve, i))
			अनुवर्त; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		अत्थाय (j = i + t; j < tinybits; j += t)
			BIT_SET(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	अत्थाय (smallbase = TINY_सङ्ख्या + 3;
	    smallbase < (SMALL_MAXIMUM - TINY_सङ्ख्या);
	    smallbase += TINY_सङ्ख्या) {
		अत्थाय (i = 0; i < tinybits; i++) {
			सचे (BIT_TEST(TinySieve, i))
				अनुवर्त; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			सचे (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} अञ्ञथा {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			सचे (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			अत्थाय (s /= 2; s < smallbits; s += t)
				BIT_SET(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		अत्थाय (i = 0; i < smallbits; i++) {
			सचे (BIT_TEST(SmallSieve, i))
				अनुवर्त; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << SHIFT_BYTE);
	}

	time(&time_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&time_stop), largetries, (long long)(time_stop - time_start));

	अत्थाय (j = r = 0; j < largebits; j++) {
		सचे (BIT_TEST(LargeSieve, j))
			अनुवर्त; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		सचे (BN_set_word(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		सचे (BN_add(q, q, largebase) == 0)
			fatal("BN_add failed");
		सचे (qfileout(out, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			भङ्ग;
		}

		r++; /* count q */
	}

	time(&time_stop);

	मुक्त(LargeSieve);
	मुक्त(SmallSieve);
	मुक्त(TinySieve);

	logit("%.24s Found %u candidates", ctime(&time_stop), r);

	पटिनिवत्त (ret);
}

स्थिर शून्य
write_checkpoint(वर्ण *cpfile, uint32_t lineno)
{
	FILE *fp;
	वर्ण tmp[PATH_MAX];
	पूर्णाङ्क r, writeok, closeok;

	r = snprintf(tmp, परिमाण(tmp), "%s.XXXXXXXXXX", cpfile);
	सचे (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		पटिनिवत्त;
	}
	सचे ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		पटिनिवत्त;
	}
	सचे ((fp = fdopen(r, "w")) == रिक्त) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		पटिनिवत्त;
	}
	writeok = (fprintf(fp, "%lu\n", (unsigned long)lineno) > 0);
	closeok = (fclose(fp) == 0);
	सचे (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (unsigned long)lineno, cpfile);
	} अञ्ञथा {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(शून्य)unlink(tmp);
	}
}

स्थिर unsigned long
read_checkpoint(वर्ण *cpfile)
{
	FILE *fp;
	unsigned long lineno = 0;

	सचे ((fp = fopen(cpfile, "r")) == रिक्त)
		पटिनिवत्त 0;
	सचे (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	अञ्ञथा
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	पटिनिवत्त lineno;
}

स्थिर unsigned long
गणनम्_पङ्क्तयः(FILE *f)
{
	unsigned long गणनम् = 0;
	वर्ण lp[QLINESIZE + 1];

	सचे (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		पटिनिवत्त ULONG_MAX;
	}
	याव (fgets(lp, QLINESIZE + 1, f) != रिक्त)
		गणनम्++;
	rewind(f);
	debug("input file has %lu lines", गणनम्);
	पटिनिवत्त गणनम्;
}

स्थिर वर्ण *
fmt_time(time_t seconds)
{
	पूर्णाङ्क day, hr, min;
	स्थिर वर्ण buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	सचे (day > 0)
		snprintf(buf, परिमाण buf, "%dd %d:%02d", day, hr, min);
	अञ्ञथा
		snprintf(buf, परिमाण buf, "%d:%02d", hr, min);
	पटिनिवत्त buf;
}

स्थिर शून्य
print_progress(unsigned long start_lineno, unsigned long current_lineno,
    unsigned long end_lineno)
{
	स्थिर time_t time_start, time_prev;
	time_t time_now, elapsed;
	unsigned long अङ्कः_to_process, processed, remaining, percent, eta;
	द्विगुण time_per_पङ्क्तिः;
	वर्ण *eta_str;

	time_now = monotime();
	सचे (time_start == 0) {
		time_start = time_prev = time_now;
		पटिनिवत्त;
	}
	/* print progress after 1m then once per 5m */
	सचे (time_now - time_prev < 5 * 60)
		पटिनिवत्त;
	time_prev = time_now;
	elapsed = time_now - time_start;
	processed = current_lineno - start_lineno;
	remaining = end_lineno - current_lineno;
	अङ्कः_to_process = end_lineno - start_lineno;
	time_per_पङ्क्तिः = (द्विगुण)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&time_now);
	सचे (end_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&time_now),
		    processed, fmt_time(elapsed));
		पटिनिवत्त;
	}
	percent = 100 * processed / अङ्कः_to_process;
	eta = time_per_पङ्क्तिः * remaining;
	eta_str = xstrdup(fmt_time(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&time_now), processed, अङ्कः_to_process, percent,
	    fmt_time(elapsed), eta_str);
	मुक्त(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
पूर्णाङ्क
अविभाज्यः_test(FILE *in, FILE *out, uint32_t trials, uint32_t generator_wanted,
    वर्ण *checkpoint_file, unsigned long start_lineno, unsigned long अङ्कः_पङ्क्तयः)
{
	BIGNUM *q, *p, *a;
	वर्ण *cp, *lp;
	uint32_t गणनम्_in = 0, गणनम्_out = 0, गणनम्_possible = 0;
	uint32_t generator_known, in_tests, in_tries, in_type, in_size;
	unsigned long last_processed = 0, end_lineno;
	time_t time_start, time_stop;
	पूर्णाङ्क res, is_अविभाज्यः;

	सचे (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		पटिनिवत्त (-1);
	}

	सचे (अङ्कः_पङ्क्तयः == 0)
		end_lineno = गणनम्_पङ्क्तयः(in);
	अञ्ञथा
		end_lineno = start_lineno + अङ्कः_पङ्क्तयः;

	time(&time_start);

	सचे ((p = BN_new()) == रिक्त)
		fatal("BN_new failed");
	सचे ((q = BN_new()) == रिक्त)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&time_start), trials, generator_wanted);

	सचे (checkpoint_file != रिक्त)
		last_processed = read_checkpoint(checkpoint_file);
	last_processed = start_lineno = MAXIMUM(last_processed, start_lineno);
	सचे (end_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", last_processed);
	अञ्ञथा
		debug("process from line %lu to line %lu", last_processed,
		    end_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	याव (fgets(lp, QLINESIZE + 1, in) != रिक्त && गणनम्_in < end_lineno) {
		गणनम्_in++;
		सचे (गणनम्_in <= last_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", गणनम्_in);
			अनुवर्त;
		}
		सचे (checkpoint_file != रिक्त)
			write_checkpoint(checkpoint_file, गणनम्_in);
		print_progress(start_lineno, गणनम्_in, end_lineno);
		सचे (strlen(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", गणनम्_in);
			अनुवर्त;
		}

		/* XXX - fragile parser */
		/* time */
		cp = &lp[14];	/* (skip) */

		/* type */
		in_type = strtoul(cp, &cp, 10);

		/* tests */
		in_tests = strtoul(cp, &cp, 10);

		सचे (in_tests & MODULI_TESTS_COMPOSITE) {
			debug2("%10u: known composite", गणनम्_in);
			अनुवर्त;
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
		विकल्प (in_type) {
		पक्ष MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", गणनम्_in, in_type);
			a = q;
			सचे (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			सचे (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			सचे (BN_add_word(p, 1) == 0)
				fatal("BN_add_word failed");
			in_size += 1;
			generator_known = 0;
			भङ्ग;
		पक्ष MODULI_TYPE_UNSTRUCTURED:
		पक्ष MODULI_TYPE_SAFE:
		पक्ष MODULI_TYPE_SCHNORR:
		पक्ष MODULI_TYPE_STRONG:
		पक्ष MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", गणनम्_in, in_type);
			a = p;
			सचे (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			सचे (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			भङ्ग;
		स्वभाव:
			debug2("Unknown prime type");
			भङ्ग;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		सचे ((uint32_t)BN_अङ्कः_bits(p) != (in_size + 1)) {
			debug2("%10u: bit size %u mismatch", गणनम्_in, in_size);
			अनुवर्त;
		}
		सचे (in_size < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", गणनम्_in, in_size);
			अनुवर्त;
		}

		सचे (in_tests & MODULI_TESTS_MILLER_RABIN)
			in_tries += trials;
		अञ्ञथा
			in_tries = trials;

		/*
		 * guess unknown generator
		 */
		सचे (generator_known == 0) {
			सचे (BN_mod_word(p, 24) == 11)
				generator_known = 2;
			अञ्ञथा {
				uint32_t r = BN_mod_word(p, 10);

				सचे (r == 3 || r == 7)
					generator_known = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		सचे (generator_wanted > 0 &&
		    generator_wanted != generator_known) {
			debug2("%10u: generator %d != %d",
			    गणनम्_in, generator_known, generator_wanted);
			अनुवर्त;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		सचे (generator_known == 0) {
			debug2("%10u: no known generator", गणनम्_in);
			अनुवर्त;
		}

		गणनम्_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_अविभाज्यः = BN_is_अविभाज्यः_ex(q, 1, रिक्त, रिक्त);
		सचे (is_अविभाज्यः < 0)
			fatal("BN_is_prime_ex failed");
		सचे (is_अविभाज्यः == 0) {
			debug("%10u: q failed first possible prime test",
			    गणनम्_in);
			अनुवर्त;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_अविभाज्यः = BN_is_अविभाज्यः_ex(p, trials, रिक्त, रिक्त);
		सचे (is_अविभाज्यः < 0)
			fatal("BN_is_prime_ex failed");
		सचे (is_अविभाज्यः == 0) {
			debug("%10u: p is not prime", गणनम्_in);
			अनुवर्त;
		}
		debug("%10u: p is almost certainly prime", गणनम्_in);

		/* recheck q more rigorously */
		is_अविभाज्यः = BN_is_अविभाज्यः_ex(q, trials - 1, रिक्त, रिक्त);
		सचे (is_अविभाज्यः < 0)
			fatal("BN_is_prime_ex failed");
		सचे (is_अविभाज्यः == 0) {
			debug("%10u: q is not prime", गणनम्_in);
			अनुवर्त;
		}
		debug("%10u: q is almost certainly prime", गणनम्_in);

		सचे (qfileout(out, MODULI_TYPE_SAFE,
		    in_tests | MODULI_TESTS_MILLER_RABIN,
		    in_tries, in_size, generator_known, p)) {
			res = -1;
			भङ्ग;
		}

		गणनम्_out++;
	}

	time(&time_stop);
	मुक्त(lp);
	BN_free(p);
	BN_free(q);

	सचे (checkpoint_file != रिक्त)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&time_stop), गणनम्_out, गणनम्_possible,
	    (long) (time_stop - time_start));

	पटिनिवत्त (res);
}

#endif /* WITH_OPENSSL */
