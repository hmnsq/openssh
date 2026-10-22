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

#اگر_تعریف_شده WITH_OPENSSL

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
#تعریف_کن QLINESIZE		(100+8192)

/*
 * Size: decimal.
 * Specifies the number of the most significant bit (0 to M).
 * WARNING: internally, usually 1 to N.
 */
#تعریف_کن QSIZE_MINIMUM		(511)

/*
 * Prime sieving defines
 */

/* Constant: assuming 8 bit bytes and 32 bit words */
#تعریف_کن لغزش_بیت	(3)
#تعریف_کن لغزش_BYTE	(2)
#تعریف_کن لغزش_کلمه	(لغزش_بیت+لغزش_BYTE)
#تعریف_کن لغزش_MEGABYTE	(20)
#تعریف_کن لغزش_MEGAWORD	(لغزش_MEGABYTE-لغزش_BYTE)

/*
 * Do not increase this number beyond the unsigned integer bit size.
 * Due to a multiple of 4, it must be LESS than 128 (yielding 2**30 bits).
 */
#تعریف_کن LARGE_بیشینه	(127UL)	/* megabytes */

/*
 * Constant: when used with 32-bit integers, the largest sieve prime
 * has to be less than 2**32.
 */
#تعریف_کن SMALL_بیشینه	(0xffffffffUL)

/* Constant: can sieve all primes less than 2**32, as 65537**2 > 2**32-1. */
#تعریف_کن TINY_عدد	(1UL<<16)

/* Ensure enough bit space for testing 2*q. */
#تعریف_کن TEST_بیشینه	(1UL<<16)
#تعریف_کن TEST_MINIMUM	(QSIZE_MINIMUM + 1)
/* real TEST_MINIMUM	(1UL << (SHIFT_WORD - TEST_POWER)) */
#تعریف_کن TEST_POWER	(3)	/* 2**n, n < SHIFT_WORD */

/* bit operations on 32-bit words */
#تعریف_کن بیت_CLEAR(a,n)	((a)[(n)>>لغزش_کلمه] &= ~(1L << ((n) & 31)))
#تعریف_کن بیت_مجموعه(a,n)	((a)[(n)>>لغزش_کلمه] |= (1L << ((n) & 31)))
#تعریف_کن بیت_TEST(a,n)	((a)[(n)>>لغزش_کلمه] & (1L << ((n) & 31)))

/*
 * Prime testing defines
 */

/* Minimum number of primality tests to perform */
#تعریف_کن TRIAL_MINIMUM	(4)

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
صحيح اول_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, بیعلامت دراز,
    بیعلامت دراز);

/*
 * print moduli out in consistent form,
 */
ساكن صحيح
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	بنية tm *gtm;
	time_t زمان_now;
	صحيح res;

	time(&زمان_now);
	gtm = gmtime(&زمان_now);
	إذا (gtm == عدم)
		أرجع -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	إذا (res < 0)
		أرجع (-1);

	إذا (BN_print_fp(ofile, omodulus) < 1)
		أرجع (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	أرجع (res > 0 ? 0 : -1);
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
	r = BN_mod_کلمه(largebase, s32);
	إذا (r == 0)
		u = 0; /* s divides into largebase exactly */
	وإلا
		u = s - r; /* largebase+u is first entry divisible by s */

	إذا (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		إذا (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		لكل (u /= 2; u < largebits; u += s)
			بیت_مجموعه(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	إذا (r == 0)
		u = 0; /* s divides p exactly */
	وإلا
		u = s - r; /* p+u is first entry divisible by s */

	إذا (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		طالما (u & 0x3) {
			إذا (SMALL_بیشینه - u < s)
				أرجع;
			u += s;
		}

		/* Mark all multiples of 4*s */
		لكل (u /= 4; u < largebits; u += s)
			بیت_مجموعه(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
صحيح
gen_candidates(FILE *بیرون, uint32_t power, BIGNUM *شروع)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_عدد >> 6;
	uint32_t tinywords = TINY_عدد >> 6;
	time_t زمان_شروع, زمان_stop;
	uint32_t i;
	صحيح ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	إذا (power > TEST_بیشینه) {
		error("Too many bits: %u > %lu", power, TEST_بیشینه);
		أرجع (-1);
	} وإلا إذا (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		أرجع (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_بیشینه;
	largewords = (largememory << لغزش_MEGAWORD);

	TinySieve = xcalloc(tinywords, حجم(uint32_t));
	tinybits = tinywords << لغزش_کلمه;

	SmallSieve = xcalloc(smallwords, حجم(uint32_t));
	smallbits = smallwords << لغزش_کلمه;

	LargeSieve = xcalloc(largewords, حجم(uint32_t));
	largebits = largewords << لغزش_کلمه;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	إذا ((q = BN_new()) == عدم)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	إذا ((largebase = BN_new()) == عدم)
		fatal("BN_new failed");
	إذا (شروع == عدم) {
		إذا (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} وإلا {
		إذا (BN_copy(largebase, شروع) == عدم)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	إذا (BN_مجموعه_بیت(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&زمان_شروع);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&زمان_شروع),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	لكل (i = 0; i < tinybits; i++) {
		إذا (بیت_TEST(TinySieve, i))
			استمر; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		لكل (j = i + t; j < tinybits; j += t)
			بیت_مجموعه(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	لكل (smallbase = TINY_عدد + 3;
	    smallbase < (SMALL_بیشینه - TINY_عدد);
	    smallbase += TINY_عدد) {
		لكل (i = 0; i < tinybits; i++) {
			إذا (بیت_TEST(TinySieve, i))
				استمر; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			إذا (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} وإلا {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			إذا (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			لكل (s /= 2; s < smallbits; s += t)
				بیت_مجموعه(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		لكل (i = 0; i < smallbits; i++) {
			إذا (بیت_TEST(SmallSieve, i))
				استمر; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << لغزش_BYTE);
	}

	time(&زمان_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&زمان_stop), largetries, (دراز دراز)(زمان_stop - زمان_شروع));

	لكل (j = r = 0; j < largebits; j++) {
		إذا (بیت_TEST(LargeSieve, j))
			استمر; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		إذا (BN_مجموعه_کلمه(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		إذا (BN_جمع_کن(q, q, largebase) == 0)
			fatal("BN_add failed");
		إذا (qfileout(بیرون, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			اكسر;
		}

		r++; /* count q */
	}

	time(&زمان_stop);

	حرر(LargeSieve);
	حرر(SmallSieve);
	حرر(TinySieve);

	logit("%.24s Found %u candidates", ctime(&زمان_stop), r);

	أرجع (ret);
}

ساكن فراغ
write_checkpoint(حرف *cpfile, uint32_t lineno)
{
	FILE *fp;
	حرف tmp[PATH_MAX];
	صحيح r, writeok, closeok;

	r = snprintf(tmp, حجم(tmp), "%s.XXXXXXXXXX", cpfile);
	إذا (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		أرجع;
	}
	إذا ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		أرجع;
	}
	إذا ((fp = fdopen(r, "w")) == عدم) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		أرجع;
	}
	writeok = (fprintf(fp, "%lu\n", (بیعلامت دراز)lineno) > 0);
	closeok = (fclose(fp) == 0);
	إذا (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (بیعلامت دراز)lineno, cpfile);
	} وإلا {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(فراغ)unlink(tmp);
	}
}

ساكن بیعلامت دراز
read_checkpoint(حرف *cpfile)
{
	FILE *fp;
	بیعلامت دراز lineno = 0;

	إذا ((fp = fopen(cpfile, "r")) == عدم)
		أرجع 0;
	إذا (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	وإلا
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	أرجع lineno;
}

ساكن بیعلامت دراز
شمار_سطرها(FILE *f)
{
	بیعلامت دراز شمار = 0;
	حرف lp[QLINESIZE + 1];

	إذا (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		أرجع ULONG_MAX;
	}
	طالما (fgets(lp, QLINESIZE + 1, f) != عدم)
		شمار++;
	rewind(f);
	debug("input file has %lu lines", شمار);
	أرجع شمار;
}

ساكن حرف *
fmt_زمان(time_t seconds)
{
	صحيح day, hr, min;
	ساكن حرف buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	إذا (day > 0)
		snprintf(buf, حجم buf, "%dd %d:%02d", day, hr, min);
	وإلا
		snprintf(buf, حجم buf, "%d:%02d", hr, min);
	أرجع buf;
}

ساكن فراغ
print_پیشرفت(بیعلامت دراز شروع_lineno, بیعلامت دراز current_lineno,
    بیعلامت دراز انتها_lineno)
{
	ساكن time_t زمان_شروع, زمان_prev;
	time_t زمان_now, elapsed;
	بیعلامت دراز رقم_مقصد_process, processed, مانده, percent, eta;
	مزدوج زمان_در_هر_سطر;
	حرف *eta_str;

	زمان_now = monotime();
	إذا (زمان_شروع == 0) {
		زمان_شروع = زمان_prev = زمان_now;
		أرجع;
	}
	/* print progress after 1m then once per 5m */
	إذا (زمان_now - زمان_prev < 5 * 60)
		أرجع;
	زمان_prev = زمان_now;
	elapsed = زمان_now - زمان_شروع;
	processed = current_lineno - شروع_lineno;
	مانده = انتها_lineno - current_lineno;
	رقم_مقصد_process = انتها_lineno - شروع_lineno;
	زمان_در_هر_سطر = (مزدوج)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&زمان_now);
	إذا (انتها_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&زمان_now),
		    processed, fmt_زمان(elapsed));
		أرجع;
	}
	percent = 100 * processed / رقم_مقصد_process;
	eta = زمان_در_هر_سطر * مانده;
	eta_str = xstrdup(fmt_زمان(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&زمان_now), processed, رقم_مقصد_process, percent,
	    fmt_زمان(elapsed), eta_str);
	حرر(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
صحيح
اول_test(FILE *درون, FILE *بیرون, uint32_t trials, uint32_t generator_wanted,
    حرف *checkpoint_file, بیعلامت دراز شروع_lineno, بیعلامت دراز رقم_سطرها)
{
	BIGNUM *q, *p, *a;
	حرف *cp, *lp;
	uint32_t شمار_درون = 0, شمار_بیرون = 0, شمار_possible = 0;
	uint32_t generator_معلوم, درون_tests, درون_tries, درون_type, درون_اندازه;
	بیعلامت دراز آخرین_processed = 0, انتها_lineno;
	time_t زمان_شروع, زمان_stop;
	صحيح res, is_اول;

	إذا (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		أرجع (-1);
	}

	إذا (رقم_سطرها == 0)
		انتها_lineno = شمار_سطرها(درون);
	وإلا
		انتها_lineno = شروع_lineno + رقم_سطرها;

	time(&زمان_شروع);

	إذا ((p = BN_new()) == عدم)
		fatal("BN_new failed");
	إذا ((q = BN_new()) == عدم)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&زمان_شروع), trials, generator_wanted);

	إذا (checkpoint_file != عدم)
		آخرین_processed = read_checkpoint(checkpoint_file);
	آخرین_processed = شروع_lineno = بیشینه(آخرین_processed, شروع_lineno);
	إذا (انتها_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", آخرین_processed);
	وإلا
		debug("process from line %lu to line %lu", آخرین_processed,
		    انتها_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	طالما (fgets(lp, QLINESIZE + 1, درون) != عدم && شمار_درون < انتها_lineno) {
		شمار_درون++;
		إذا (شمار_درون <= آخرین_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", شمار_درون);
			استمر;
		}
		إذا (checkpoint_file != عدم)
			write_checkpoint(checkpoint_file, شمار_درون);
		print_پیشرفت(شروع_lineno, شمار_درون, انتها_lineno);
		إذا (طول_رشته(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", شمار_درون);
			استمر;
		}

		/* XXX - fragile parser */
		/*زمان*/
		cp = &lp[14];	/* (skip) */

		/* type */
		درون_type = strtoul(cp, &cp, 10);

		/* tests */
		درون_tests = strtoul(cp, &cp, 10);

		إذا (درون_tests & MODULI_TESTS_مرکب) {
			debug2("%10u: known composite", شمار_درون);
			استمر;
		}

		/* tries */
		درون_tries = strtoul(cp, &cp, 10);

		/* size (most significant bit) */
		درون_اندازه = strtoul(cp, &cp, 10);

		/* generator (hex) */
		generator_معلوم = strtoul(cp, &cp, 16);

		/* Skip white space */
		cp += strspn(cp, " ");

		/* modulus (hex) */
		بدل (درون_type) {
		حالة MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", شمار_درون, درون_type);
			a = q;
			إذا (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			إذا (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			إذا (BN_جمع_کن_کلمه(p, 1) == 0)
				fatal("BN_add_word failed");
			درون_اندازه += 1;
			generator_معلوم = 0;
			اكسر;
		حالة MODULI_TYPE_UNSTRUCTURED:
		حالة MODULI_TYPE_امن:
		حالة MODULI_TYPE_SCHNORR:
		حالة MODULI_TYPE_STRONG:
		حالة MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", شمار_درون, درون_type);
			a = p;
			إذا (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			إذا (BN_rshift(q, p, 1) == 0)
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
		إذا ((uint32_t)BN_رقم_بیتها(p) != (درون_اندازه + 1)) {
			debug2("%10u: bit size %u mismatch", شمار_درون, درون_اندازه);
			استمر;
		}
		إذا (درون_اندازه < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", شمار_درون, درون_اندازه);
			استمر;
		}

		إذا (درون_tests & MODULI_TESTS_MILLER_RABIN)
			درون_tries += trials;
		وإلا
			درون_tries = trials;

		/*
		 * guess unknown generator
		 */
		إذا (generator_معلوم == 0) {
			إذا (BN_mod_کلمه(p, 24) == 11)
				generator_معلوم = 2;
			وإلا {
				uint32_t r = BN_mod_کلمه(p, 10);

				إذا (r == 3 || r == 7)
					generator_معلوم = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		إذا (generator_wanted > 0 &&
		    generator_wanted != generator_معلوم) {
			debug2("%10u: generator %d != %d",
			    شمار_درون, generator_معلوم, generator_wanted);
			استمر;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		إذا (generator_معلوم == 0) {
			debug2("%10u: no known generator", شمار_درون);
			استمر;
		}

		شمار_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_اول = BN_is_اول_ex(q, 1, عدم, عدم);
		إذا (is_اول < 0)
			fatal("BN_is_prime_ex failed");
		إذا (is_اول == 0) {
			debug("%10u: q failed first possible prime test",
			    شمار_درون);
			استمر;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_اول = BN_is_اول_ex(p, trials, عدم, عدم);
		إذا (is_اول < 0)
			fatal("BN_is_prime_ex failed");
		إذا (is_اول == 0) {
			debug("%10u: p is not prime", شمار_درون);
			استمر;
		}
		debug("%10u: p is almost certainly prime", شمار_درون);

		/* recheck q more rigorously */
		is_اول = BN_is_اول_ex(q, trials - 1, عدم, عدم);
		إذا (is_اول < 0)
			fatal("BN_is_prime_ex failed");
		إذا (is_اول == 0) {
			debug("%10u: q is not prime", شمار_درون);
			استمر;
		}
		debug("%10u: q is almost certainly prime", شمار_درون);

		إذا (qfileout(بیرون, MODULI_TYPE_امن,
		    درون_tests | MODULI_TESTS_MILLER_RABIN,
		    درون_tries, درون_اندازه, generator_معلوم, p)) {
			res = -1;
			اكسر;
		}

		شمار_بیرون++;
	}

	time(&زمان_stop);
	حرر(lp);
	BN_free(p);
	BN_free(q);

	إذا (checkpoint_file != عدم)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&زمان_stop), شمار_بیرون, شمار_possible,
	    (دراز) (زمان_stop - زمان_شروع));

	أرجع (res);
}

#پایان_اگر /* WITH_OPENSSL */
