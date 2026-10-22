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

#جے_تعریف_شدہ WITH_OPENSSL

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
#تعریف_کرو کھسکاؤ_ثنائی_ہندسہ	(3)
#تعریف_کرو کھسکاؤ_BYTE	(2)
#تعریف_کرو کھسکاؤ_لفظ	(کھسکاؤ_ثنائی_ہندسہ+کھسکاؤ_BYTE)
#تعریف_کرو کھسکاؤ_MEGABYTE	(20)
#تعریف_کرو کھسکاؤ_MEGAWORD	(کھسکاؤ_MEGABYTE-کھسکاؤ_BYTE)

/*
 * Do not increase this number beyond the unsigned integer bit size.
 * Due to a multiple of 4, it must be LESS than 128 (yielding 2**30 bits).
 */
#تعریف_کرو LARGE_ودھ_توں_ودھ	(127UL)	/* megabytes */

/*
 * Constant: when used with 32-bit integers, the largest sieve prime
 * has to be less than 2**32.
 */
#تعریف_کرو SMALL_ودھ_توں_ودھ	(0xffffffffUL)

/* Constant: can sieve all primes less than 2**32, as 65537**2 > 2**32-1. */
#تعریف_کرو TINY_نمبر	(1UL<<16)

/* Ensure enough bit space for testing 2*q. */
#تعریف_کرو TEST_ودھ_توں_ودھ	(1UL<<16)
#تعریف_کرو TEST_MINIMUM	(QSIZE_MINIMUM + 1)
/* real TEST_MINIMUM	(1UL << (SHIFT_WORD - TEST_POWER)) */
#تعریف_کرو TEST_POWER	(3)	/* 2**n, n < SHIFT_WORD */

/* bit operations on 32-bit words */
#تعریف_کرو ثنائی_ہندسہ_CLEAR(a,n)	((a)[(n)>>کھسکاؤ_لفظ] &= ~(1L << ((n) & 31)))
#تعریف_کرو ثنائی_ہندسہ_سیٹ(a,n)	((a)[(n)>>کھسکاؤ_لفظ] |= (1L << ((n) & 31)))
#تعریف_کرو ثنائی_ہندسہ_TEST(a,n)	((a)[(n)>>کھسکاؤ_لفظ] & (1L << ((n) & 31)))

/*
 * Prime testing defines
 */

/* Minimum number of primality tests to perform */
#تعریف_کرو TRIAL_MINIMUM	(4)

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
صحيح مفرد_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, بنانشانی لما,
    بنانشانی لما);

/*
 * print moduli out in consistent form,
 */
ساكن صحيح
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	بنية tm *gtm;
	time_t ویلا_now;
	صحيح res;

	time(&ویلا_now);
	gtm = gmtime(&ویلا_now);
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
	r = BN_mod_لفظ(largebase, s32);
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
			ثنائی_ہندسہ_سیٹ(LargeSieve, u);
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
			إذا (SMALL_ودھ_توں_ودھ - u < s)
				أرجع;
			u += s;
		}

		/* Mark all multiples of 4*s */
		لكل (u /= 4; u < largebits; u += s)
			ثنائی_ہندسہ_سیٹ(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
صحيح
gen_candidates(FILE *باہرلا, uint32_t power, BIGNUM *شروع)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_نمبر >> 6;
	uint32_t tinywords = TINY_نمبر >> 6;
	time_t ویلا_شروع, ویلا_stop;
	uint32_t i;
	صحيح ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	إذا (power > TEST_ودھ_توں_ودھ) {
		error("Too many bits: %u > %lu", power, TEST_ودھ_توں_ودھ);
		أرجع (-1);
	} وإلا إذا (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		أرجع (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_ودھ_توں_ودھ;
	largewords = (largememory << کھسکاؤ_MEGAWORD);

	TinySieve = xcalloc(tinywords, حجم(uint32_t));
	tinybits = tinywords << کھسکاؤ_لفظ;

	SmallSieve = xcalloc(smallwords, حجم(uint32_t));
	smallbits = smallwords << کھسکاؤ_لفظ;

	LargeSieve = xcalloc(largewords, حجم(uint32_t));
	largebits = largewords << کھسکاؤ_لفظ;
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
	إذا (BN_سیٹ_ثنائی_ہندسہ(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&ویلا_شروع);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&ویلا_شروع),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	لكل (i = 0; i < tinybits; i++) {
		إذا (ثنائی_ہندسہ_TEST(TinySieve, i))
			استمر; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		لكل (j = i + t; j < tinybits; j += t)
			ثنائی_ہندسہ_سیٹ(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	لكل (smallbase = TINY_نمبر + 3;
	    smallbase < (SMALL_ودھ_توں_ودھ - TINY_نمبر);
	    smallbase += TINY_نمبر) {
		لكل (i = 0; i < tinybits; i++) {
			إذا (ثنائی_ہندسہ_TEST(TinySieve, i))
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
				ثنائی_ہندسہ_سیٹ(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		لكل (i = 0; i < smallbits; i++) {
			إذا (ثنائی_ہندسہ_TEST(SmallSieve, i))
				استمر; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << کھسکاؤ_BYTE);
	}

	time(&ویلا_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&ویلا_stop), largetries, (لما لما)(ویلا_stop - ویلا_شروع));

	لكل (j = r = 0; j < largebits; j++) {
		إذا (ثنائی_ہندسہ_TEST(LargeSieve, j))
			استمر; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		إذا (BN_سیٹ_لفظ(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		إذا (BN_جوڑو(q, q, largebase) == 0)
			fatal("BN_add failed");
		إذا (qfileout(باہرلا, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			اكسر;
		}

		r++; /* count q */
	}

	time(&ویلا_stop);

	حرر(LargeSieve);
	حرر(SmallSieve);
	حرر(TinySieve);

	logit("%.24s Found %u candidates", ctime(&ویلا_stop), r);

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
	writeok = (fprintf(fp, "%lu\n", (بنانشانی لما)lineno) > 0);
	closeok = (fclose(fp) == 0);
	إذا (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (بنانشانی لما)lineno, cpfile);
	} وإلا {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(فراغ)unlink(tmp);
	}
}

ساكن بنانشانی لما
read_checkpoint(حرف *cpfile)
{
	FILE *fp;
	بنانشانی لما lineno = 0;

	إذا ((fp = fopen(cpfile, "r")) == عدم)
		أرجع 0;
	إذا (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	وإلا
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	أرجع lineno;
}

ساكن بنانشانی لما
گنتی_سطریں(FILE *f)
{
	بنانشانی لما گنتی = 0;
	حرف lp[QLINESIZE + 1];

	إذا (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		أرجع ULONG_MAX;
	}
	طالما (fgets(lp, QLINESIZE + 1, f) != عدم)
		گنتی++;
	rewind(f);
	debug("input file has %lu lines", گنتی);
	أرجع گنتی;
}

ساكن حرف *
fmt_ویلا(time_t seconds)
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
print_ترقی(بنانشانی لما شروع_lineno, بنانشانی لما current_lineno,
    بنانشانی لما سرا_lineno)
{
	ساكن time_t ویلا_شروع, ویلا_prev;
	time_t ویلا_now, elapsed;
	بنانشانی لما عدد_منزل_process, processed, بچیا, percent, eta;
	مزدوج ویلا_فی_سطر;
	حرف *eta_str;

	ویلا_now = monotime();
	إذا (ویلا_شروع == 0) {
		ویلا_شروع = ویلا_prev = ویلا_now;
		أرجع;
	}
	/* print progress after 1m then once per 5m */
	إذا (ویلا_now - ویلا_prev < 5 * 60)
		أرجع;
	ویلا_prev = ویلا_now;
	elapsed = ویلا_now - ویلا_شروع;
	processed = current_lineno - شروع_lineno;
	بچیا = سرا_lineno - current_lineno;
	عدد_منزل_process = سرا_lineno - شروع_lineno;
	ویلا_فی_سطر = (مزدوج)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&ویلا_now);
	إذا (سرا_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&ویلا_now),
		    processed, fmt_ویلا(elapsed));
		أرجع;
	}
	percent = 100 * processed / عدد_منزل_process;
	eta = ویلا_فی_سطر * بچیا;
	eta_str = xstrdup(fmt_ویلا(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&ویلا_now), processed, عدد_منزل_process, percent,
	    fmt_ویلا(elapsed), eta_str);
	حرر(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
صحيح
مفرد_test(FILE *وچ, FILE *باہرلا, uint32_t trials, uint32_t generator_wanted,
    حرف *checkpoint_file, بنانشانی لما شروع_lineno, بنانشانی لما عدد_سطریں)
{
	BIGNUM *q, *p, *a;
	حرف *cp, *lp;
	uint32_t گنتی_وچ = 0, گنتی_باہرلا = 0, گنتی_possible = 0;
	uint32_t generator_معلوم, وچ_tests, وچ_tries, وچ_type, وچ_ناپ;
	بنانشانی لما آخری_processed = 0, سرا_lineno;
	time_t ویلا_شروع, ویلا_stop;
	صحيح res, is_مفرد;

	إذا (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		أرجع (-1);
	}

	إذا (عدد_سطریں == 0)
		سرا_lineno = گنتی_سطریں(وچ);
	وإلا
		سرا_lineno = شروع_lineno + عدد_سطریں;

	time(&ویلا_شروع);

	إذا ((p = BN_new()) == عدم)
		fatal("BN_new failed");
	إذا ((q = BN_new()) == عدم)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&ویلا_شروع), trials, generator_wanted);

	إذا (checkpoint_file != عدم)
		آخری_processed = read_checkpoint(checkpoint_file);
	آخری_processed = شروع_lineno = ودھ_توں_ودھ(آخری_processed, شروع_lineno);
	إذا (سرا_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", آخری_processed);
	وإلا
		debug("process from line %lu to line %lu", آخری_processed,
		    سرا_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	طالما (fgets(lp, QLINESIZE + 1, وچ) != عدم && گنتی_وچ < سرا_lineno) {
		گنتی_وچ++;
		إذا (گنتی_وچ <= آخری_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", گنتی_وچ);
			استمر;
		}
		إذا (checkpoint_file != عدم)
			write_checkpoint(checkpoint_file, گنتی_وچ);
		print_ترقی(شروع_lineno, گنتی_وچ, سرا_lineno);
		إذا (لڑی_لمبائی(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", گنتی_وچ);
			استمر;
		}

		/* XXX - fragile parser */
		/*ویلا*/
		cp = &lp[14];	/* (skip) */

		/* type */
		وچ_type = strtoul(cp, &cp, 10);

		/* tests */
		وچ_tests = strtoul(cp, &cp, 10);

		إذا (وچ_tests & MODULI_TESTS_مرکب) {
			debug2("%10u: known composite", گنتی_وچ);
			استمر;
		}

		/* tries */
		وچ_tries = strtoul(cp, &cp, 10);

		/* size (most significant bit) */
		وچ_ناپ = strtoul(cp, &cp, 10);

		/* generator (hex) */
		generator_معلوم = strtoul(cp, &cp, 16);

		/* Skip white space */
		cp += strspn(cp, " ");

		/* modulus (hex) */
		بدل (وچ_type) {
		حالة MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", گنتی_وچ, وچ_type);
			a = q;
			إذا (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			إذا (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			إذا (BN_جوڑو_لفظ(p, 1) == 0)
				fatal("BN_add_word failed");
			وچ_ناپ += 1;
			generator_معلوم = 0;
			اكسر;
		حالة MODULI_TYPE_UNSTRUCTURED:
		حالة MODULI_TYPE_محفوظ:
		حالة MODULI_TYPE_SCHNORR:
		حالة MODULI_TYPE_STRONG:
		حالة MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", گنتی_وچ, وچ_type);
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
		إذا ((uint32_t)BN_عدد_بٹ(p) != (وچ_ناپ + 1)) {
			debug2("%10u: bit size %u mismatch", گنتی_وچ, وچ_ناپ);
			استمر;
		}
		إذا (وچ_ناپ < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", گنتی_وچ, وچ_ناپ);
			استمر;
		}

		إذا (وچ_tests & MODULI_TESTS_MILLER_RABIN)
			وچ_tries += trials;
		وإلا
			وچ_tries = trials;

		/*
		 * guess unknown generator
		 */
		إذا (generator_معلوم == 0) {
			إذا (BN_mod_لفظ(p, 24) == 11)
				generator_معلوم = 2;
			وإلا {
				uint32_t r = BN_mod_لفظ(p, 10);

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
			    گنتی_وچ, generator_معلوم, generator_wanted);
			استمر;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		إذا (generator_معلوم == 0) {
			debug2("%10u: no known generator", گنتی_وچ);
			استمر;
		}

		گنتی_possible++;

		/*
		 * The (1/4)^N performance bound on Miller-Rabin is
		 * extremely pessimistic, so don't spend a lot of time
		 * really verifying that q is prime until after we know
		 * that p is also prime. A single pass will weed out the
		 * vast majority of composite q's.
		 */
		is_مفرد = BN_is_مفرد_ex(q, 1, عدم, عدم);
		إذا (is_مفرد < 0)
			fatal("BN_is_prime_ex failed");
		إذا (is_مفرد == 0) {
			debug("%10u: q failed first possible prime test",
			    گنتی_وچ);
			استمر;
		}

		/*
		 * q is possibly prime, so go ahead and really make sure
		 * that p is prime. If it is, then we can go back and do
		 * the same for q. If p is composite, chances are that
		 * will show up on the first Rabin-Miller iteration so it
		 * doesn't hurt to specify a high iteration count.
		 */
		is_مفرد = BN_is_مفرد_ex(p, trials, عدم, عدم);
		إذا (is_مفرد < 0)
			fatal("BN_is_prime_ex failed");
		إذا (is_مفرد == 0) {
			debug("%10u: p is not prime", گنتی_وچ);
			استمر;
		}
		debug("%10u: p is almost certainly prime", گنتی_وچ);

		/* recheck q more rigorously */
		is_مفرد = BN_is_مفرد_ex(q, trials - 1, عدم, عدم);
		إذا (is_مفرد < 0)
			fatal("BN_is_prime_ex failed");
		إذا (is_مفرد == 0) {
			debug("%10u: q is not prime", گنتی_وچ);
			استمر;
		}
		debug("%10u: q is almost certainly prime", گنتی_وچ);

		إذا (qfileout(باہرلا, MODULI_TYPE_محفوظ,
		    وچ_tests | MODULI_TESTS_MILLER_RABIN,
		    وچ_tries, وچ_ناپ, generator_معلوم, p)) {
			res = -1;
			اكسر;
		}

		گنتی_باہرلا++;
	}

	time(&ویلا_stop);
	حرر(lp);
	BN_free(p);
	BN_free(q);

	إذا (checkpoint_file != عدم)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&ویلا_stop), گنتی_باہرلا, گنتی_possible,
	    (لما) (ویلا_stop - ویلا_شروع));

	أرجع (res);
}

#جے_انت /* WITH_OPENSSL */
