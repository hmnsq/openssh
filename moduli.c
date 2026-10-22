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
#define TINY_संख्या	(1UL<<16)

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

पूर्णांक gen_candidates(खाता *, uint32_t, BIGNUM *);
पूर्णांक मूळसंख्या_test(खाता *, खाता *, uint32_t, uint32_t, अक्षर *, अचिन्हित दीर्घ,
    अचिन्हित दीर्घ);

/*
 * print moduli out in consistent form,
 */
स्थिर पूर्णांक
qfileout(खाता * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	संरचना पंचांग *gtm;
	समय_प्रकार time_now;
	पूर्णांक res;

	समय(&time_now);
	gtm = स_जमट(&time_now);
	जर (gtm == रिक्त)
		परत -1;

	res = ख_लिखो(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	जर (res < 0)
		परत (-1);

	जर (BN_print_fp(ofile, omodulus) < 1)
		परत (-1);

	res = ख_लिखो(ofile, "\n");
	ख_साफ(ofile);

	परत (res > 0 ? 0 : -1);
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
	जर (r == 0)
		u = 0; /* s divides into largebase exactly */
	अन्यथा
		u = s - r; /* largebase+u is first entry divisible by s */

	जर (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		जर (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		साठी (u /= 2; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	जर (r == 0)
		u = 0; /* s divides p exactly */
	अन्यथा
		u = s - r; /* p+u is first entry divisible by s */

	जर (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		पर्यंत (u & 0x3) {
			जर (SMALL_MAXIMUM - u < s)
				परत;
			u += s;
		}

		/* Mark all multiples of 4*s */
		साठी (u /= 4; u < largebits; u += s)
			BIT_SET(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
पूर्णांक
gen_candidates(खाता *out, uint32_t power, BIGNUM *start)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_संख्या >> 6;
	uint32_t tinywords = TINY_संख्या >> 6;
	समय_प्रकार time_start, time_stop;
	uint32_t i;
	पूर्णांक ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	जर (power > TEST_MAXIMUM) {
		error("Too many bits: %u > %lu", power, TEST_MAXIMUM);
		परत (-1);
	} अन्यथा जर (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		परत (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_MAXIMUM;
	largewords = (largememory << SHIFT_MEGAWORD);

	TinySieve = xcalloc(tinywords, आकार(uint32_t));
	tinybits = tinywords << SHIFT_WORD;

	SmallSieve = xcalloc(smallwords, आकार(uint32_t));
	smallbits = smallwords << SHIFT_WORD;

	LargeSieve = xcalloc(largewords, आकार(uint32_t));
	largebits = largewords << SHIFT_WORD;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	जर ((q = BN_new()) == रिक्त)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	जर ((largebase = BN_new()) == रिक्त)
		fatal("BN_new failed");
	जर (start == रिक्त) {
		जर (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} अन्यथा {
		जर (BN_copy(largebase, start) == रिक्त)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	जर (BN_set_bit(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	समय(&time_start);

	logit("%.24s Sieve next %u plus %u-bit", स_समय(&time_start),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	साठी (i = 0; i < tinybits; i++) {
		जर (BIT_TEST(TinySieve, i))
			सुरूठेवा; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		साठी (j = i + t; j < tinybits; j += t)
			BIT_SET(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	साठी (smallbase = TINY_संख्या + 3;
	    smallbase < (SMALL_MAXIMUM - TINY_संख्या);
	    smallbase += TINY_संख्या) {
		साठी (i = 0; i < tinybits; i++) {
			जर (BIT_TEST(TinySieve, i))
				सुरूठेवा; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			जर (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} अन्यथा {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			जर (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			साठी (s /= 2; s < smallbits; s += t)
				BIT_SET(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		साठी (i = 0; i < smallbits; i++) {
			जर (BIT_TEST(SmallSieve, i))
				सुरूठेवा; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		स_रखो(SmallSieve, 0, smallwords << SHIFT_BYTE);
	}

	समय(&time_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    स_समय(&time_stop), largetries, (दीर्घ दीर्घ)(time_stop - time_start));

	साठी (j = r = 0; j < largebits; j++) {
		जर (BIT_TEST(LargeSieve, j))
			सुरूठेवा; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		जर (BN_set_word(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		जर (BN_add(q, q, largebase) == 0)
			fatal("BN_add failed");
		जर (qfileout(out, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			थांबा;
		}

		r++; /* count q */
	}

	समय(&time_stop);

	मुक्त(LargeSieve);
	मुक्त(SmallSieve);
	मुक्त(TinySieve);

	logit("%.24s Found %u candidates", स_समय(&time_stop), r);

	परत (ret);
}

स्थिर शून्य
write_checkpoint(अक्षर *cpfile, uint32_t lineno)
{
	खाता *fp;
	अक्षर tmp[PATH_MAX];
	पूर्णांक r, writeok, closeok;

	r = snprintf(tmp, आकार(tmp), "%s.XXXXXXXXXX", cpfile);
	जर (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		परत;
	}
	जर ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, म_त्रुटि(त्रुटि_सं));
		परत;
	}
	जर ((fp = fdopen(r, "w")) == रिक्त) {
		logit("write_checkpoint: fdopen: %s", म_त्रुटि(त्रुटि_सं));
		unlink(tmp);
		बंद(r);
		परत;
	}
	writeok = (ख_लिखो(fp, "%lu\n", (अचिन्हित दीर्घ)lineno) > 0);
	closeok = (ख_बंद(fp) == 0);
	जर (writeok && closeok && नाम(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (अचिन्हित दीर्घ)lineno, cpfile);
	} अन्यथा {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    म_त्रुटि(त्रुटि_सं));
		(शून्य)unlink(tmp);
	}
}

स्थिर अचिन्हित दीर्घ
read_checkpoint(अक्षर *cpfile)
{
	खाता *fp;
	अचिन्हित दीर्घ lineno = 0;

	जर ((fp = ख_खोलो(cpfile, "r")) == रिक्त)
		परत 0;
	जर (ख_पूछो(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	अन्यथा
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	ख_बंद(fp);
	परत lineno;
}

स्थिर अचिन्हित दीर्घ
मोजणी_ओळी(खाता *f)
{
	अचिन्हित दीर्घ मोजणी = 0;
	अक्षर lp[QLINESIZE + 1];

	जर (ख_जाओ(f, 0, शुरू_से) != 0) {
		debug("input file is not seekable");
		परत अच_दीर्घ_उच्च;
	}
	पर्यंत (ख_माला_लो(lp, QLINESIZE + 1, f) != रिक्त)
		मोजणी++;
	शुरुआत(f);
	debug("input file has %lu lines", मोजणी);
	परत मोजणी;
}

स्थिर अक्षर *
fmt_time(समय_प्रकार seconds)
{
	पूर्णांक day, hr, min;
	स्थिर अक्षर buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	जर (day > 0)
		snprintf(buf, आकार buf, "%dd %d:%02d", day, hr, min);
	अन्यथा
		snprintf(buf, आकार buf, "%d:%02d", hr, min);
	परत buf;
}

स्थिर शून्य
print_progress(अचिन्हित दीर्घ start_lineno, अचिन्हित दीर्घ current_lineno,
    अचिन्हित दीर्घ end_lineno)
{
	स्थिर समय_प्रकार time_start, time_prev;
	समय_प्रकार time_now, elapsed;
	अचिन्हित दीर्घ अंक_to_process, processed, remaining, percent, eta;
	द्विगुण time_per_ओळ;
	अक्षर *eta_str;

	time_now = monotime();
	जर (time_start == 0) {
		time_start = time_prev = time_now;
		परत;
	}
	/* print progress after 1m then once per 5m */
	जर (time_now - time_prev < 5 * 60)
		परत;
	time_prev = time_now;
	elapsed = time_now - time_start;
	processed = current_lineno - start_lineno;
	remaining = end_lineno - current_lineno;
	अंक_to_process = end_lineno - start_lineno;
	time_per_ओळ = (द्विगुण)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	समय(&time_now);
	जर (end_lineno == अच_दीर्घ_उच्च) {
		logit("%.24s processed %lu in %s", स_समय(&time_now),
		    processed, fmt_time(elapsed));
		परत;
	}
	percent = 100 * processed / अंक_to_process;
	eta = time_per_ओळ * remaining;
	eta_str = xstrdup(fmt_time(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    स_समय(&time_now), processed, अंक_to_process, percent,
	    fmt_time(elapsed), eta_str);
	मुक्त(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
पूर्णांक
मूळसंख्या_test(खाता *in, खाता *out, uint32_t trials, uint32_t generator_wanted,
    अक्षर *checkpoint_file, अचिन्हित दीर्घ start_lineno, अचिन्हित दीर्घ अंक_ओळी)
{
	BIGNUM *q, *p, *a;
	अक्षर *cp, *lp;
	uint32_t मोजणी_in = 0, मोजणी_out = 0, मोजणी_possible = 0;
	uint32_t generator_known, in_tests, in_tries, in_type, in_size;
	अचिन्हित दीर्घ last_processed = 0, end_lineno;
	समय_प्रकार time_start, time_stop;
	पूर्णांक res, is_मूळसंख्या;

	जर (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		परत (-1);
	}

	जर (अंक_ओळी == 0)
		end_lineno = मोजणी_ओळी(in);
	अन्यथा
		end_lineno = start_lineno + अंक_ओळी;

	समय(&time_start);

	जर ((p = BN_new()) == रिक्त)
		fatal("BN_new failed");
	जर ((q = BN_new()) == रिक्त)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    स_समय(&time_start), trials, generator_wanted);

	जर (checkpoint_file != रिक्त)
		last_processed = read_checkpoint(checkpoint_file);
	last_processed = start_lineno = MAXIMUM(last_processed, start_lineno);
	जर (end_lineno == अच_दीर्घ_उच्च)
		debug("process from line %lu from pipe", last_processed);
	अन्यथा
		debug("process from line %lu to line %lu", last_processed,
		    end_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	पर्यंत (ख_माला_लो(lp, QLINESIZE + 1, in) != रिक्त && मोजणी_in < end_lineno) {
		मोजणी_in++;
		जर (मोजणी_in <= last_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", मोजणी_in);
			सुरूठेवा;
		}
		जर (checkpoint_file != रिक्त)
			write_checkpoint(checkpoint_file, मोजणी_in);
		print_progress(start_lineno, मोजणी_in, end_lineno);
		जर (म_माप(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", मोजणी_in);
			सुरूठेवा;
		}

		/* XXX - fragile parser */
		/* time */
		cp = &lp[14];	/* (skip) */

		/* type */
		in_type = म_से_अदीर्घ(cp, &cp, 10);

		/* tests */
		in_tests = म_से_अदीर्घ(cp, &cp, 10);

		जर (in_tests & MODULI_TESTS_COMPOSITE) {
			debug2("%10u: known composite", मोजणी_in);
			सुरूठेवा;
		}

		/* tries */
		in_tries = म_से_अदीर्घ(cp, &cp, 10);

		/* size (most significant bit) */
		in_size = म_से_अदीर्घ(cp, &cp, 10);

		/* generator (hex) */
		generator_known = म_से_अदीर्घ(cp, &cp, 16);

		/* Skip white space */
		cp += म_अखोज(cp, " ");

		/* modulus (hex) */
		निवड (in_type) {
		स्थिती MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", मोजणी_in, in_type);
			a = q;
			जर (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			जर (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			जर (BN_add_word(p, 1) == 0)
				fatal("BN_add_word failed");
			in_size += 1;
			generator_known = 0;
			थांबा;
		स्थिती MODULI_TYPE_UNSTRUCTURED:
		स्थिती MODULI_TYPE_SAFE:
		स्थिती MODULI_TYPE_SCHNORR:
		स्थिती MODULI_TYPE_STRONG:
		स्थिती MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", मोजणी_in, in_type);
			a = p;
			जर (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			जर (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			थांबा;
		पूर्वनिर्धारित:
			debug2("Unknown prime type");
			थांबा;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		जर ((uint32_t)BN_अंक_bits(p) != (in_size + 1)) {
			debug2("%10u: bit size %u mismatch", मोजणी_in, in_size);
			सुरूठेवा;
		}
		जर (in_size < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", मोजणी_in, in_size);
			सुरूठेवा;
		}

		जर (in_tests & MODULI_TESTS_MILLER_RABIN)
			in_tries += trials;
		अन्यथा
			in_tries = trials;

		/*
		 * guess unknown generator
		 */
		जर (generator_known == 0) {
			जर (BN_mod_word(p, 24) == 11)
				generator_known = 2;
			अन्यथा {
				uint32_t r = BN_mod_word(p, 10);

				जर (r == 3 || r == 7)
					generator_known = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		जर (generator_wanted > 0 &&
		    generator_wanted != generator_known) {
			debug2("%10u: generator %d != %d",
			    मोजणी_in, generator_known, generator_wanted);
			सुरूठेवा;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		जर (generator_known == 0) {
			debug2("%10u: no known generator", मोजणी_in);
			सुरूठेवा;
		}

		मोजणी_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_मूळसंख्या = BN_is_मूळसंख्या_ex(q, 1, रिक्त, रिक्त);
		जर (is_मूळसंख्या < 0)
			fatal("BN_is_prime_ex failed");
		जर (is_मूळसंख्या == 0) {
			debug("%10u: q failed first possible prime test",
			    मोजणी_in);
			सुरूठेवा;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_मूळसंख्या = BN_is_मूळसंख्या_ex(p, trials, रिक्त, रिक्त);
		जर (is_मूळसंख्या < 0)
			fatal("BN_is_prime_ex failed");
		जर (is_मूळसंख्या == 0) {
			debug("%10u: p is not prime", मोजणी_in);
			सुरूठेवा;
		}
		debug("%10u: p is almost certainly prime", मोजणी_in);

		/* recheck q more rigorously */
		is_मूळसंख्या = BN_is_मूळसंख्या_ex(q, trials - 1, रिक्त, रिक्त);
		जर (is_मूळसंख्या < 0)
			fatal("BN_is_prime_ex failed");
		जर (is_मूळसंख्या == 0) {
			debug("%10u: q is not prime", मोजणी_in);
			सुरूठेवा;
		}
		debug("%10u: q is almost certainly prime", मोजणी_in);

		जर (qfileout(out, MODULI_TYPE_SAFE,
		    in_tests | MODULI_TESTS_MILLER_RABIN,
		    in_tries, in_size, generator_known, p)) {
			res = -1;
			थांबा;
		}

		मोजणी_out++;
	}

	समय(&time_stop);
	मुक्त(lp);
	BN_free(p);
	BN_free(q);

	जर (checkpoint_file != रिक्त)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    स_समय(&time_stop), मोजणी_out, मोजणी_possible,
	    (दीर्घ) (time_stop - time_start));

	परत (res);
}

#endif /* WITH_OPENSSL */
