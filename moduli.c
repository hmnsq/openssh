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

#شامل "includes.h"

#اگر_تعریف_شدہ WITH_OPENSSL

#شامل <sys/types.h>

#شامل <openssl/bn.h>
#شامل <openssl/dh.h>

#شامل <errno.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <limits.h>

#شامل "xmalloc.h"
#شامل "dh.h"
#شامل "log.h"
#شامل "misc.h"

#شامل "openbsd-compat/openssl-compat.h"

/*
 * File output defines
 */

/* need line long enough for largest moduli plus headers */
#تعریف_کرو QLINESIZE		(100+8192)

/*
 * Size: decimal.
 * Specifies the number of the most significant bit (0 to M).
 * WARNING: internally, usually 1 to N.
 */
#تعریف_کرو QSIZE_MINIMUM		(511)

/*
 * Prime sieving defines
 */

/* Constant: assuming 8 bit bytes and 32 bit words */
#تعریف_کرو سرکاؤ_ثنائی_ہندسہ	(3)
#تعریف_کرو سرکاؤ_BYTE	(2)
#تعریف_کرو سرکاؤ_لفظ	(سرکاؤ_ثنائی_ہندسہ+سرکاؤ_BYTE)
#تعریف_کرو سرکاؤ_MEGABYTE	(20)
#تعریف_کرو سرکاؤ_MEGAWORD	(سرکاؤ_MEGABYTE-سرکاؤ_BYTE)

/*
 * Do not increase this number beyond the unsigned integer bit size.
 * Due to a multiple of 4, it must be LESS than 128 (yielding 2**30 bits).
 */
#تعریف_کرو LARGE_زیادہ_سے_زیادہ	(127UL)	/* megabytes */

/*
 * Constant: when used with 32-bit integers, the largest sieve prime
 * has to be less than 2**32.
 */
#تعریف_کرو SMALL_زیادہ_سے_زیادہ	(0xffffffffUL)

/* Constant: can sieve all primes less than 2**32, as 65537**2 > 2**32-1. */
#تعریف_کرو TINY_نمبر	(1UL<<16)

/* Ensure enough bit space for testing 2*q. */
#تعریف_کرو TEST_زیادہ_سے_زیادہ	(1UL<<16)
#تعریف_کرو TEST_MINIMUM	(QSIZE_MINIMUM + 1)
/* real TEST_MINIMUM	(1UL << (SHIFT_WORD - TEST_POWER)) */
#تعریف_کرو TEST_POWER	(3)	/* 2**n, n < SHIFT_WORD */

/* bit operations on 32-bit words */
#تعریف_کرو ثنائی_ہندسہ_CLEAR(a,n)	((a)[(n)>>سرکاؤ_لفظ] &= ~(1L << ((n) & 31)))
#تعریف_کرو ثنائی_ہندسہ_سیٹ(a,n)	((a)[(n)>>سرکاؤ_لفظ] |= (1L << ((n) & 31)))
#تعریف_کرو ثنائی_ہندسہ_TEST(a,n)	((a)[(n)>>سرکاؤ_لفظ] & (1L << ((n) & 31)))

/*
 * Prime testing defines
 */

/* Minimum number of primality tests to perform */
#تعریف_کرو TRIAL_MINIMUM	(4)

/*
 * Sieving data (XXX - move to struct)
 */

/* sieve 2**16 */
ساکن uint32_t *TinySieve, tinybits;

/* sieve 2**30 in 2**16 parts */
ساکن uint32_t *SmallSieve, smallbits, smallbase;

/* sieve relative to the initial value */
ساکن uint32_t *LargeSieve, largewords, largetries, largenumbers;
ساکن uint32_t largebits, largememory;	/* megabytes */
ساکن BIGNUM *largebase;

صحیح gen_candidates(FILE *, uint32_t, BIGNUM *);
صحیح مفرد_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, غیرعلامتی طویل,
    غیرعلامتی طویل);

/*
 * print moduli out in consistent form,
 */
ساکن صحیح
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	ساخت tm *gtm;
	time_t وقت_now;
	صحیح res;

	time(&وقت_now);
	gtm = gmtime(&وقت_now);
	اگر (gtm == تہی)
		واپس -1;

	res = fprintf(ofile, "%04d%02d%02d%02d%02d%02d %u %u %u %u %x ",
	    gtm->tm_year + 1900, gtm->tm_mon + 1, gtm->tm_mday,
	    gtm->tm_hour, gtm->tm_min, gtm->tm_sec,
	    otype, otests, otries, osize, ogenerator);

	اگر (res < 0)
		واپس (-1);

	اگر (BN_print_fp(ofile, omodulus) < 1)
		واپس (-1);

	res = fprintf(ofile, "\n");
	fflush(ofile);

	واپس (res > 0 ? 0 : -1);
}


/*
 ** Sieve p's and q's with small factors
 */
ساکن خالی
sieve_large(uint32_t s32)
{
	uint64_t r, u, s = s32;

	debug3("sieve_large %u", s32);
	largetries++;
	/* r = largebase mod s */
	r = BN_mod_لفظ(largebase, s32);
	اگر (r == 0)
		u = 0; /* s divides into largebase exactly */
	ورنہ
		u = s - r; /* largebase+u is first entry divisible by s */

	اگر (u < largebits * 2ULL) {
		/*
		 * The sieve omits p's and q's divisible by 2, so ensure that
		 * largebase+u is odd. Then, step through the sieve in
		 * increments of 2*s
		 */
		اگر (u & 0x1)
			u += s; /* Make largebase+u odd, and u even */

		/* Mark all multiples of 2*s */
		برائے (u /= 2; u < largebits; u += s)
			ثنائی_ہندسہ_سیٹ(LargeSieve, u);
	}

	/* r = p mod s */
	r = (2 * r + 1) % s;
	اگر (r == 0)
		u = 0; /* s divides p exactly */
	ورنہ
		u = s - r; /* p+u is first entry divisible by s */

	اگر (u < largebits * 4ULL) {
		/*
		 * The sieve omits p's divisible by 4, so ensure that
		 * largebase+u is not. Then, step through the sieve in
		 * increments of 4*s
		 */
		جب (u & 0x3) {
			اگر (SMALL_زیادہ_سے_زیادہ - u < s)
				واپس;
			u += s;
		}

		/* Mark all multiples of 4*s */
		برائے (u /= 4; u < largebits; u += s)
			ثنائی_ہندسہ_سیٹ(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
صحیح
gen_candidates(FILE *برآمد, uint32_t power, BIGNUM *آغاز)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_نمبر >> 6;
	uint32_t tinywords = TINY_نمبر >> 6;
	time_t وقت_آغاز, وقت_stop;
	uint32_t i;
	صحیح ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	اگر (power > TEST_زیادہ_سے_زیادہ) {
		error("Too many bits: %u > %lu", power, TEST_زیادہ_سے_زیادہ);
		واپس (-1);
	} ورنہ اگر (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		واپس (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_زیادہ_سے_زیادہ;
	largewords = (largememory << سرکاؤ_MEGAWORD);

	TinySieve = xcalloc(tinywords, حجم(uint32_t));
	tinybits = tinywords << سرکاؤ_لفظ;

	SmallSieve = xcalloc(smallwords, حجم(uint32_t));
	smallbits = smallwords << سرکاؤ_لفظ;

	LargeSieve = xcalloc(largewords, حجم(uint32_t));
	largebits = largewords << سرکاؤ_لفظ;
	largenumbers = largebits * 2;	/* even numbers excluded */

	/* validation check: count the number of primes tried */
	largetries = 0;
	اگر ((q = BN_new()) == تہی)
		fatal("BN_new failed");

	/*
	 * Generate random starting point for subprime search, or use
	 * specified parameter.
	 */
	اگر ((largebase = BN_new()) == تہی)
		fatal("BN_new failed");
	اگر (آغاز == تہی) {
		اگر (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} ورنہ {
		اگر (BN_copy(largebase, آغاز) == تہی)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	اگر (BN_سیٹ_ثنائی_ہندسہ(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&وقت_آغاز);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&وقت_آغاز),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	برائے (i = 0; i < tinybits; i++) {
		اگر (ثنائی_ہندسہ_TEST(TinySieve, i))
			جاری; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		برائے (j = i + t; j < tinybits; j += t)
			ثنائی_ہندسہ_سیٹ(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	برائے (smallbase = TINY_نمبر + 3;
	    smallbase < (SMALL_زیادہ_سے_زیادہ - TINY_نمبر);
	    smallbase += TINY_نمبر) {
		برائے (i = 0; i < tinybits; i++) {
			اگر (ثنائی_ہندسہ_TEST(TinySieve, i))
				جاری; /* 2*i+3 is composite */

			/* The next tiny prime */
			t = 2 * i + 3;
			r = smallbase % t;

			اگر (r == 0) {
				s = 0; /* t divides into smallbase exactly */
			} ورنہ {
				/* smallbase+s is first entry divisible by t */
				s = t - r;
			}

			/*
			 * The sieve omits even numbers, so ensure that
			 * smallbase+s is odd. Then, step through the sieve
			 * in increments of 2*t
			 */
			اگر (s & 1)
				s += t; /* Make smallbase+s odd, and s even */

			/* Mark all multiples of 2*t */
			برائے (s /= 2; s < smallbits; s += t)
				ثنائی_ہندسہ_سیٹ(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		برائے (i = 0; i < smallbits; i++) {
			اگر (ثنائی_ہندسہ_TEST(SmallSieve, i))
				جاری; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << سرکاؤ_BYTE);
	}

	time(&وقت_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&وقت_stop), largetries, (طویل طویل)(وقت_stop - وقت_آغاز));

	برائے (j = r = 0; j < largebits; j++) {
		اگر (ثنائی_ہندسہ_TEST(LargeSieve, j))
			جاری; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		اگر (BN_سیٹ_لفظ(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		اگر (BN_جوڑو(q, q, largebase) == 0)
			fatal("BN_add failed");
		اگر (qfileout(برآمد, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			توڑو;
		}

		r++; /* count q */
	}

	time(&وقت_stop);

	آزاد(LargeSieve);
	آزاد(SmallSieve);
	آزاد(TinySieve);

	logit("%.24s Found %u candidates", ctime(&وقت_stop), r);

	واپس (ret);
}

ساکن خالی
write_checkpoint(حرف *cpfile, uint32_t lineno)
{
	FILE *fp;
	حرف tmp[PATH_MAX];
	صحیح r, writeok, closeok;

	r = snprintf(tmp, حجم(tmp), "%s.XXXXXXXXXX", cpfile);
	اگر (r < 0 || r >= PATH_MAX) {
		logit("write_checkpoint: temp pathname too long");
		واپس;
	}
	اگر ((r = mkstemp(tmp)) == -1) {
		logit("mkstemp(%s): %s", tmp, strerror(errno));
		واپس;
	}
	اگر ((fp = fdopen(r, "w")) == تہی) {
		logit("write_checkpoint: fdopen: %s", strerror(errno));
		unlink(tmp);
		close(r);
		واپس;
	}
	writeok = (fprintf(fp, "%lu\n", (غیرعلامتی طویل)lineno) > 0);
	closeok = (fclose(fp) == 0);
	اگر (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (غیرعلامتی طویل)lineno, cpfile);
	} ورنہ {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(خالی)unlink(tmp);
	}
}

ساکن غیرعلامتی طویل
read_checkpoint(حرف *cpfile)
{
	FILE *fp;
	غیرعلامتی طویل lineno = 0;

	اگر ((fp = fopen(cpfile, "r")) == تہی)
		واپس 0;
	اگر (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	ورنہ
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	واپس lineno;
}

ساکن غیرعلامتی طویل
گنتی_سطریں(FILE *f)
{
	غیرعلامتی طویل گنتی = 0;
	حرف lp[QLINESIZE + 1];

	اگر (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		واپس ULONG_MAX;
	}
	جب (fgets(lp, QLINESIZE + 1, f) != تہی)
		گنتی++;
	rewind(f);
	debug("input file has %lu lines", گنتی);
	واپس گنتی;
}

ساکن حرف *
fmt_وقت(time_t seconds)
{
	صحیح day, hr, min;
	ساکن حرف buf[128];

	min = (seconds / 60) % 60;
	hr = (seconds / 60 / 60) % 24;
	day = seconds / 60 / 60 / 24;
	اگر (day > 0)
		snprintf(buf, حجم buf, "%dd %d:%02d", day, hr, min);
	ورنہ
		snprintf(buf, حجم buf, "%d:%02d", hr, min);
	واپس buf;
}

ساکن خالی
print_پیش_رفت(غیرعلامتی طویل آغاز_lineno, غیرعلامتی طویل current_lineno,
    غیرعلامتی طویل انتہا_lineno)
{
	ساکن time_t وقت_آغاز, وقت_پچھلا;
	time_t وقت_now, elapsed;
	غیرعلامتی طویل عدد_مقصد_process, processed, بقایا, percent, eta;
	دوہرا وقت_فی_سطر;
	حرف *eta_str;

	وقت_now = monotime();
	اگر (وقت_آغاز == 0) {
		وقت_آغاز = وقت_پچھلا = وقت_now;
		واپس;
	}
	/* print progress after 1m then once per 5m */
	اگر (وقت_now - وقت_پچھلا < 5 * 60)
		واپس;
	وقت_پچھلا = وقت_now;
	elapsed = وقت_now - وقت_آغاز;
	processed = current_lineno - آغاز_lineno;
	بقایا = انتہا_lineno - current_lineno;
	عدد_مقصد_process = انتہا_lineno - آغاز_lineno;
	وقت_فی_سطر = (دوہرا)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&وقت_now);
	اگر (انتہا_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&وقت_now),
		    processed, fmt_وقت(elapsed));
		واپس;
	}
	percent = 100 * processed / عدد_مقصد_process;
	eta = وقت_فی_سطر * بقایا;
	eta_str = xstrdup(fmt_وقت(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&وقت_now), processed, عدد_مقصد_process, percent,
	    fmt_وقت(elapsed), eta_str);
	آزاد(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
صحیح
مفرد_test(FILE *اندر, FILE *برآمد, uint32_t trials, uint32_t generator_wanted,
    حرف *checkpoint_file, غیرعلامتی طویل آغاز_lineno, غیرعلامتی طویل عدد_سطریں)
{
	BIGNUM *q, *p, *a;
	حرف *cp, *lp;
	uint32_t گنتی_اندر = 0, گنتی_برآمد = 0, گنتی_possible = 0;
	uint32_t generator_معلوم, اندر_tests, اندر_tries, اندر_type, اندر_سائز;
	غیرعلامتی طویل آخری_processed = 0, انتہا_lineno;
	time_t وقت_آغاز, وقت_stop;
	صحیح res, is_مفرد;

	اگر (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		واپس (-1);
	}

	اگر (عدد_سطریں == 0)
		انتہا_lineno = گنتی_سطریں(اندر);
	ورنہ
		انتہا_lineno = آغاز_lineno + عدد_سطریں;

	time(&وقت_آغاز);

	اگر ((p = BN_new()) == تہی)
		fatal("BN_new failed");
	اگر ((q = BN_new()) == تہی)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&وقت_آغاز), trials, generator_wanted);

	اگر (checkpoint_file != تہی)
		آخری_processed = read_checkpoint(checkpoint_file);
	آخری_processed = آغاز_lineno = زیادہ_سے_زیادہ(آخری_processed, آغاز_lineno);
	اگر (انتہا_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", آخری_processed);
	ورنہ
		debug("process from line %lu to line %lu", آخری_processed,
		    انتہا_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	جب (fgets(lp, QLINESIZE + 1, اندر) != تہی && گنتی_اندر < انتہا_lineno) {
		گنتی_اندر++;
		اگر (گنتی_اندر <= آخری_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", گنتی_اندر);
			جاری;
		}
		اگر (checkpoint_file != تہی)
			write_checkpoint(checkpoint_file, گنتی_اندر);
		print_پیش_رفت(آغاز_lineno, گنتی_اندر, انتہا_lineno);
		اگر (لڑی_لمبائی(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", گنتی_اندر);
			جاری;
		}

		/* XXX - fragile parser */
		/*وقت*/
		cp = &lp[14];	/* (skip) */

		/* type */
		اندر_type = strtoul(cp, &cp, 10);

		/* tests */
		اندر_tests = strtoul(cp, &cp, 10);

		اگر (اندر_tests & MODULI_TESTS_مرکب) {
			debug2("%10u: known composite", گنتی_اندر);
			جاری;
		}

		/* tries */
		اندر_tries = strtoul(cp, &cp, 10);

		/* size (most significant bit) */
		اندر_سائز = strtoul(cp, &cp, 10);

		/* generator (hex) */
		generator_معلوم = strtoul(cp, &cp, 16);

		/* Skip white space */
		cp += strspn(cp, " ");

		/* modulus (hex) */
		انتخاب (اندر_type) {
		حالت MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", گنتی_اندر, اندر_type);
			a = q;
			اگر (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			اگر (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			اگر (BN_جوڑو_لفظ(p, 1) == 0)
				fatal("BN_add_word failed");
			اندر_سائز += 1;
			generator_معلوم = 0;
			توڑو;
		حالت MODULI_TYPE_UNSTRUCTURED:
		حالت MODULI_TYPE_محفوظ:
		حالت MODULI_TYPE_SCHNORR:
		حالت MODULI_TYPE_STRONG:
		حالت MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", گنتی_اندر, اندر_type);
			a = p;
			اگر (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* q = (p-1) / 2 */
			اگر (BN_rshift(q, p, 1) == 0)
				fatal("BN_rshift failed");
			توڑو;
		طےشدہ:
			debug2("Unknown prime type");
			توڑو;
		}

		/*
		 * due to earlier inconsistencies in interpretation, check
		 * the proposed bit size.
		 */
		اگر ((uint32_t)BN_عدد_بٹ(p) != (اندر_سائز + 1)) {
			debug2("%10u: bit size %u mismatch", گنتی_اندر, اندر_سائز);
			جاری;
		}
		اگر (اندر_سائز < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", گنتی_اندر, اندر_سائز);
			جاری;
		}

		اگر (اندر_tests & MODULI_TESTS_MILLER_RABIN)
			اندر_tries += trials;
		ورنہ
			اندر_tries = trials;

		/*
		 * guess unknown generator
		 */
		اگر (generator_معلوم == 0) {
			اگر (BN_mod_لفظ(p, 24) == 11)
				generator_معلوم = 2;
			ورنہ {
				uint32_t r = BN_mod_لفظ(p, 10);

				اگر (r == 3 || r == 7)
					generator_معلوم = 5;
			}
		}
		/*
		 * skip tests when desired generator doesn't match
		 */
		اگر (generator_wanted > 0 &&
		    generator_wanted != generator_معلوم) {
			debug2("%10u: generator %d != %d",
			    گنتی_اندر, generator_معلوم, generator_wanted);
			جاری;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		اگر (generator_معلوم == 0) {
			debug2("%10u: no known generator", گنتی_اندر);
			جاری;
		}

		گنتی_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_مفرد = BN_is_مفرد_ex(q, 1, تہی, تہی);
		اگر (is_مفرد < 0)
			fatal("BN_is_prime_ex failed");
		اگر (is_مفرد == 0) {
			debug("%10u: q failed first possible prime test",
			    گنتی_اندر);
			جاری;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_مفرد = BN_is_مفرد_ex(p, trials, تہی, تہی);
		اگر (is_مفرد < 0)
			fatal("BN_is_prime_ex failed");
		اگر (is_مفرد == 0) {
			debug("%10u: p is not prime", گنتی_اندر);
			جاری;
		}
		debug("%10u: p is almost certainly prime", گنتی_اندر);

		/* recheck q more rigorously */
		is_مفرد = BN_is_مفرد_ex(q, trials - 1, تہی, تہی);
		اگر (is_مفرد < 0)
			fatal("BN_is_prime_ex failed");
		اگر (is_مفرد == 0) {
			debug("%10u: q is not prime", گنتی_اندر);
			جاری;
		}
		debug("%10u: q is almost certainly prime", گنتی_اندر);

		اگر (qfileout(برآمد, MODULI_TYPE_محفوظ,
		    اندر_tests | MODULI_TESTS_MILLER_RABIN,
		    اندر_tries, اندر_سائز, generator_معلوم, p)) {
			res = -1;
			توڑو;
		}

		گنتی_برآمد++;
	}

	time(&وقت_stop);
	آزاد(lp);
	BN_free(p);
	BN_free(q);

	اگر (checkpoint_file != تہی)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&وقت_stop), گنتی_برآمد, گنتی_possible,
	    (طویل) (وقت_stop - وقت_آغاز));

	واپس (res);
}

#اگر_ختم /* WITH_OPENSSL */
