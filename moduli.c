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

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL

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
#وصف_ڪريو QLINESIZE		(100+8192)

/*
 * Size: decimal.
 * Specifies the number of the most significant bit (0 to M).
 * WARNING: internally, usually 1 to N.
 */
#وصف_ڪريو QSIZE_MINIMUM		(511)

/*
 * Prime sieving defines
 */

/* Constant: assuming 8 bit bytes and 32 bit words */
#وصف_ڪريو سرڪايو_ٻٽو_انگ	(3)
#وصف_ڪريو سرڪايو_BYTE	(2)
#وصف_ڪريو سرڪايو_لفظ	(سرڪايو_ٻٽو_انگ+سرڪايو_BYTE)
#وصف_ڪريو سرڪايو_MEGABYTE	(20)
#وصف_ڪريو سرڪايو_MEGAWORD	(سرڪايو_MEGABYTE-سرڪايو_BYTE)

/*
 * Do not increase this number beyond the unsigned integer bit size.
 * Due to a multiple of 4, it must be LESS than 128 (yielding 2**30 bits).
 */
#وصف_ڪريو LARGE_وڌ_کان_وڌ	(127UL)	/* megabytes */

/*
 * Constant: when used with 32-bit integers, the largest sieve prime
 * has to be less than 2**32.
 */
#وصف_ڪريو SMALL_وڌ_کان_وڌ	(0xffffffffUL)

/* Constant: can sieve all primes less than 2**32, as 65537**2 > 2**32-1. */
#وصف_ڪريو TINY_عدد	(1UL<<16)

/* Ensure enough bit space for testing 2*q. */
#وصف_ڪريو TEST_وڌ_کان_وڌ	(1UL<<16)
#وصف_ڪريو TEST_MINIMUM	(QSIZE_MINIMUM + 1)
/* real TEST_MINIMUM	(1UL << (SHIFT_WORD - TEST_POWER)) */
#وصف_ڪريو TEST_POWER	(3)	/* 2**n, n < SHIFT_WORD */

/* bit operations on 32-bit words */
#وصف_ڪريو ٻٽو_انگ_CLEAR(a,n)	((a)[(n)>>سرڪايو_لفظ] &= ~(1L << ((n) & 31)))
#وصف_ڪريو ٻٽو_انگ_سيٽ(a,n)	((a)[(n)>>سرڪايو_لفظ] |= (1L << ((n) & 31)))
#وصف_ڪريو ٻٽو_انگ_TEST(a,n)	((a)[(n)>>سرڪايو_لفظ] & (1L << ((n) & 31)))

/*
 * Prime testing defines
 */

/* Minimum number of primality tests to perform */
#وصف_ڪريو TRIAL_MINIMUM	(4)

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
صحيح مفرد_test(FILE *, FILE *, uint32_t, uint32_t, حرف *, بنانشان ڊگهو,
    بنانشان ڊگهو);

/*
 * print moduli out in consistent form,
 */
ساكن صحيح
qfileout(FILE * ofile, uint32_t otype, uint32_t otests, uint32_t otries,
    uint32_t osize, uint32_t ogenerator, BIGNUM * omodulus)
{
	بنية tm *gtm;
	time_t وقت_now;
	صحيح res;

	time(&وقت_now);
	gtm = gmtime(&وقت_now);
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
			ٻٽو_انگ_سيٽ(LargeSieve, u);
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
			إذا (SMALL_وڌ_کان_وڌ - u < s)
				أرجع;
			u += s;
		}

		/* Mark all multiples of 4*s */
		لكل (u /= 4; u < largebits; u += s)
			ٻٽو_انگ_سيٽ(LargeSieve, u);
	}
}

/*
 * list candidates for Sophie-Germain primes (where q = (p-1)/2)
 * to standard output.
 * The list is checked against small known primes (less than 2**30).
 */
صحيح
gen_candidates(FILE *ٻاهريون, uint32_t power, BIGNUM *شروعات)
{
	BIGNUM *q;
	uint32_t j, r, s, t;
	uint32_t smallwords = TINY_عدد >> 6;
	uint32_t tinywords = TINY_عدد >> 6;
	time_t وقت_شروعات, وقت_stop;
	uint32_t i;
	صحيح ret = 0;

	/*
	 * Set power to the length in bits of the prime to be generated.
	 * This is changed to 1 less than the desired safe prime moduli p.
	 */
	إذا (power > TEST_وڌ_کان_وڌ) {
		error("Too many bits: %u > %lu", power, TEST_وڌ_کان_وڌ);
		أرجع (-1);
	} وإلا إذا (power < TEST_MINIMUM) {
		error("Too few bits: %u < %u", power, TEST_MINIMUM);
		أرجع (-1);
	}
	power--; /* decrement before squaring */

	/* Always use the maximum amount of memory supported by the algorithm. */
	largememory = LARGE_وڌ_کان_وڌ;
	largewords = (largememory << سرڪايو_MEGAWORD);

	TinySieve = xcalloc(tinywords, حجم(uint32_t));
	tinybits = tinywords << سرڪايو_لفظ;

	SmallSieve = xcalloc(smallwords, حجم(uint32_t));
	smallbits = smallwords << سرڪايو_لفظ;

	LargeSieve = xcalloc(largewords, حجم(uint32_t));
	largebits = largewords << سرڪايو_لفظ;
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
	إذا (شروعات == عدم) {
		إذا (BN_rand(largebase, power, 1, 1) == 0)
			fatal("BN_rand failed");
	} وإلا {
		إذا (BN_copy(largebase, شروعات) == عدم)
			fatal("BN_copy: failed");
	}

	/* ensure odd */
	إذا (BN_سيٽ_ٻٽو_انگ(largebase, 0) == 0)
		fatal("BN_set_bit: failed");

	time(&وقت_شروعات);

	logit("%.24s Sieve next %u plus %u-bit", ctime(&وقت_شروعات),
	    largenumbers, power);
	debug2("start point: 0x%s", BN_bn2hex(largebase));

	/*
	 * TinySieve
	 */
	لكل (i = 0; i < tinybits; i++) {
		إذا (ٻٽو_انگ_TEST(TinySieve, i))
			استمر; /* 2*i+3 is composite */

		/* The next tiny prime */
		t = 2 * i + 3;

		/* Mark all multiples of t */
		لكل (j = i + t; j < tinybits; j += t)
			ٻٽو_انگ_سيٽ(TinySieve, j);

		sieve_large(t);
	}

	/*
	 * Start the small block search at the next possible prime. To avoid
	 * fencepost errors, the last pass is skipped.
	 */
	لكل (smallbase = TINY_عدد + 3;
	    smallbase < (SMALL_وڌ_کان_وڌ - TINY_عدد);
	    smallbase += TINY_عدد) {
		لكل (i = 0; i < tinybits; i++) {
			إذا (ٻٽو_انگ_TEST(TinySieve, i))
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
				ٻٽو_انگ_سيٽ(SmallSieve, s);
		}

		/*
		 * SmallSieve
		 */
		لكل (i = 0; i < smallbits; i++) {
			إذا (ٻٽو_انگ_TEST(SmallSieve, i))
				استمر; /* 2*i+smallbase is composite */

			/* The next small prime */
			sieve_large((2 * i) + smallbase);
		}

		memset(SmallSieve, 0, smallwords << سرڪايو_BYTE);
	}

	time(&وقت_stop);

	logit("%.24s Sieved with %u small primes in %lld seconds",
	    ctime(&وقت_stop), largetries, (ڊگهو ڊگهو)(وقت_stop - وقت_شروعات));

	لكل (j = r = 0; j < largebits; j++) {
		إذا (ٻٽو_انگ_TEST(LargeSieve, j))
			استمر; /* Definitely composite, skip */

		debug2("test q = largebase+%u", 2 * j);
		إذا (BN_سيٽ_لفظ(q, 2 * j) == 0)
			fatal("BN_set_word failed");
		إذا (BN_جوڙيو(q, q, largebase) == 0)
			fatal("BN_add failed");
		إذا (qfileout(ٻاهريون, MODULI_TYPE_SOPHIE_GERMAIN,
		    MODULI_TESTS_SIEVE, largetries,
		    (power - 1) /* MSB */, (0), q) == -1) {
			ret = -1;
			اكسر;
		}

		r++; /* count q */
	}

	time(&وقت_stop);

	حرر(LargeSieve);
	حرر(SmallSieve);
	حرر(TinySieve);

	logit("%.24s Found %u candidates", ctime(&وقت_stop), r);

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
	writeok = (fprintf(fp, "%lu\n", (بنانشان ڊگهو)lineno) > 0);
	closeok = (fclose(fp) == 0);
	إذا (writeok && closeok && rename(tmp, cpfile) == 0) {
		debug3("wrote checkpoint line %lu to '%s'",
		    (بنانشان ڊگهو)lineno, cpfile);
	} وإلا {
		logit("failed to write to checkpoint file '%s': %s", cpfile,
		    strerror(errno));
		(فراغ)unlink(tmp);
	}
}

ساكن بنانشان ڊگهو
read_checkpoint(حرف *cpfile)
{
	FILE *fp;
	بنانشان ڊگهو lineno = 0;

	إذا ((fp = fopen(cpfile, "r")) == عدم)
		أرجع 0;
	إذا (fscanf(fp, "%lu\n", &lineno) < 1)
		logit("Failed to load checkpoint from '%s'", cpfile);
	وإلا
		logit("Loaded checkpoint from '%s' line %lu", cpfile, lineno);
	fclose(fp);
	أرجع lineno;
}

ساكن بنانشان ڊگهو
ڳڻپ_سٽون(FILE *f)
{
	بنانشان ڊگهو ڳڻپ = 0;
	حرف lp[QLINESIZE + 1];

	إذا (fseek(f, 0, SEEK_SET) != 0) {
		debug("input file is not seekable");
		أرجع ULONG_MAX;
	}
	طالما (fgets(lp, QLINESIZE + 1, f) != عدم)
		ڳڻپ++;
	rewind(f);
	debug("input file has %lu lines", ڳڻپ);
	أرجع ڳڻپ;
}

ساكن حرف *
fmt_وقت(time_t seconds)
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
print_ترقي(بنانشان ڊگهو شروعات_lineno, بنانشان ڊگهو current_lineno,
    بنانشان ڊگهو پڇاڙي_lineno)
{
	ساكن time_t وقت_شروعات, وقت_prev;
	time_t وقت_now, elapsed;
	بنانشان ڊگهو انگ_منزل_process, processed, بچيل, percent, eta;
	مزدوج وقت_في_سٽ;
	حرف *eta_str;

	وقت_now = monotime();
	إذا (وقت_شروعات == 0) {
		وقت_شروعات = وقت_prev = وقت_now;
		أرجع;
	}
	/* print progress after 1m then once per 5m */
	إذا (وقت_now - وقت_prev < 5 * 60)
		أرجع;
	وقت_prev = وقت_now;
	elapsed = وقت_now - وقت_شروعات;
	processed = current_lineno - شروعات_lineno;
	بچيل = پڇاڙي_lineno - current_lineno;
	انگ_منزل_process = پڇاڙي_lineno - شروعات_lineno;
	وقت_في_سٽ = (مزدوج)elapsed / processed;
	/* if we don't know how many we're processing just report count+time */
	time(&وقت_now);
	إذا (پڇاڙي_lineno == ULONG_MAX) {
		logit("%.24s processed %lu in %s", ctime(&وقت_now),
		    processed, fmt_وقت(elapsed));
		أرجع;
	}
	percent = 100 * processed / انگ_منزل_process;
	eta = وقت_في_سٽ * بچيل;
	eta_str = xstrdup(fmt_وقت(eta));
	logit("%.24s processed %lu of %lu (%lu%%) in %s, ETA %s",
	    ctime(&وقت_now), processed, انگ_منزل_process, percent,
	    fmt_وقت(elapsed), eta_str);
	حرر(eta_str);
}

/*
 * perform a Miller-Rabin primality test
 * on the list of candidates
 * (checking both q and p)
 * The result is a list of so-call "safe" primes
 */
صحيح
مفرد_test(FILE *اندريون, FILE *ٻاهريون, uint32_t trials, uint32_t generator_wanted,
    حرف *checkpoint_file, بنانشان ڊگهو شروعات_lineno, بنانشان ڊگهو انگ_سٽون)
{
	BIGNUM *q, *p, *a;
	حرف *cp, *lp;
	uint32_t ڳڻپ_اندريون = 0, ڳڻپ_ٻاهريون = 0, ڳڻپ_possible = 0;
	uint32_t generator_معلوم, اندريون_tests, اندريون_tries, اندريون_type, اندريون_سائيز;
	بنانشان ڊگهو آخري_processed = 0, پڇاڙي_lineno;
	time_t وقت_شروعات, وقت_stop;
	صحيح res, is_مفرد;

	إذا (trials < TRIAL_MINIMUM) {
		error("Minimum primality trials is %d", TRIAL_MINIMUM);
		أرجع (-1);
	}

	إذا (انگ_سٽون == 0)
		پڇاڙي_lineno = ڳڻپ_سٽون(اندريون);
	وإلا
		پڇاڙي_lineno = شروعات_lineno + انگ_سٽون;

	time(&وقت_شروعات);

	إذا ((p = BN_new()) == عدم)
		fatal("BN_new failed");
	إذا ((q = BN_new()) == عدم)
		fatal("BN_new failed");

	debug2("%.24s Final %u Miller-Rabin trials (%x generator)",
	    ctime(&وقت_شروعات), trials, generator_wanted);

	إذا (checkpoint_file != عدم)
		آخري_processed = read_checkpoint(checkpoint_file);
	آخري_processed = شروعات_lineno = وڌ_کان_وڌ(آخري_processed, شروعات_lineno);
	إذا (پڇاڙي_lineno == ULONG_MAX)
		debug("process from line %lu from pipe", آخري_processed);
	وإلا
		debug("process from line %lu to line %lu", آخري_processed,
		    پڇاڙي_lineno);

	res = 0;
	lp = xmalloc(QLINESIZE + 1);
	طالما (fgets(lp, QLINESIZE + 1, اندريون) != عدم && ڳڻپ_اندريون < پڇاڙي_lineno) {
		ڳڻپ_اندريون++;
		إذا (ڳڻپ_اندريون <= آخري_processed) {
			debug3("skipping line %u, before checkpoint or "
			    "specified start line", ڳڻپ_اندريون);
			استمر;
		}
		إذا (checkpoint_file != عدم)
			write_checkpoint(checkpoint_file, ڳڻپ_اندريون);
		print_ترقي(شروعات_lineno, ڳڻپ_اندريون, پڇاڙي_lineno);
		إذا (لڙي_ڊيگهه(lp) < 14 || *lp == '!' || *lp == '#') {
			debug2("%10u: comment or short line", ڳڻپ_اندريون);
			استمر;
		}

		/* XXX - fragile parser */
		/*وقت*/
		cp = &lp[14];	/* (skip) */

		/* type */
		اندريون_type = strtoul(cp, &cp, 10);

		/* tests */
		اندريون_tests = strtoul(cp, &cp, 10);

		إذا (اندريون_tests & MODULI_TESTS_مرکب) {
			debug2("%10u: known composite", ڳڻپ_اندريون);
			استمر;
		}

		/* tries */
		اندريون_tries = strtoul(cp, &cp, 10);

		/* size (most significant bit) */
		اندريون_سائيز = strtoul(cp, &cp, 10);

		/* generator (hex) */
		generator_معلوم = strtoul(cp, &cp, 16);

		/* Skip white space */
		cp += strspn(cp, " ");

		/* modulus (hex) */
		بدل (اندريون_type) {
		حالة MODULI_TYPE_SOPHIE_GERMAIN:
			debug2("%10u: (%u) Sophie-Germain", ڳڻپ_اندريون, اندريون_type);
			a = q;
			إذا (BN_hex2bn(&a, cp) == 0)
				fatal("BN_hex2bn failed");
			/* p = 2*q + 1 */
			إذا (BN_lshift(p, q, 1) == 0)
				fatal("BN_lshift failed");
			إذا (BN_جوڙيو_لفظ(p, 1) == 0)
				fatal("BN_add_word failed");
			اندريون_سائيز += 1;
			generator_معلوم = 0;
			اكسر;
		حالة MODULI_TYPE_UNSTRUCTURED:
		حالة MODULI_TYPE_محفوظ:
		حالة MODULI_TYPE_SCHNORR:
		حالة MODULI_TYPE_STRONG:
		حالة MODULI_TYPE_UNKNOWN:
			debug2("%10u: (%u)", ڳڻپ_اندريون, اندريون_type);
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
		إذا ((uint32_t)BN_انگ_بٽ(p) != (اندريون_سائيز + 1)) {
			debug2("%10u: bit size %u mismatch", ڳڻپ_اندريون, اندريون_سائيز);
			استمر;
		}
		إذا (اندريون_سائيز < QSIZE_MINIMUM) {
			debug2("%10u: bit size %u too short", ڳڻپ_اندريون, اندريون_سائيز);
			استمر;
		}

		إذا (اندريون_tests & MODULI_TESTS_MILLER_RABIN)
			اندريون_tries += trials;
		وإلا
			اندريون_tries = trials;

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
			    ڳڻپ_اندريون, generator_معلوم, generator_wanted);
			استمر;
		}

		/*
		 * Primes with no known generator are useless for DH, so
		 * skip those.
		 */
		إذا (generator_معلوم == 0) {
			debug2("%10u: no known generator", ڳڻپ_اندريون);
			استمر;
		}

		ڳڻپ_possible++;

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
			    ڳڻپ_اندريون);
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
			debug("%10u: p is not prime", ڳڻپ_اندريون);
			استمر;
		}
		debug("%10u: p is almost certainly prime", ڳڻپ_اندريون);

		/* recheck q more rigorously */
		is_مفرد = BN_is_مفرد_ex(q, trials - 1, عدم, عدم);
		إذا (is_مفرد < 0)
			fatal("BN_is_prime_ex failed");
		إذا (is_مفرد == 0) {
			debug("%10u: q is not prime", ڳڻپ_اندريون);
			استمر;
		}
		debug("%10u: q is almost certainly prime", ڳڻپ_اندريون);

		إذا (qfileout(ٻاهريون, MODULI_TYPE_محفوظ,
		    اندريون_tests | MODULI_TESTS_MILLER_RABIN,
		    اندريون_tries, اندريون_سائيز, generator_معلوم, p)) {
			res = -1;
			اكسر;
		}

		ڳڻپ_ٻاهريون++;
	}

	time(&وقت_stop);
	حرر(lp);
	BN_free(p);
	BN_free(q);

	إذا (checkpoint_file != عدم)
		unlink(checkpoint_file);

	logit("%.24s Found %u safe primes of %u candidates in %ld seconds",
	    ctime(&وقت_stop), ڳڻپ_ٻاهريون, ڳڻپ_possible,
	    (ڊگهو) (وقت_stop - وقت_شروعات));

	أرجع (res);
}

#جيڪڏهن_پورو /* WITH_OPENSSL */
