/*	$OpenBSD: test_helper.c,v 1.18 2026/06/22 12:08:33 dtucker Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Utility functions/framework for regress tests */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/uio.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>

#ಅನ್ತರ್ಭಾವ <assert.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <math.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "entropy.h"
#ಅನ್ತರ್ಭಾವ "test_helper.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

#ವ್ಯಾಖ್ಯಾನಿಸು BENCH_FAST_DEADLINE	1
#ವ್ಯಾಖ್ಯಾನಿಸು BENCH_ಸಾಮಾನ್ಯ_DEADLINE	10
#ವ್ಯಾಖ್ಯಾನಿಸು BENCH_SLOW_DEADLINE	60
#ವ್ಯಾಖ್ಯಾನಿಸು BENCH_SAMPLES_ALLOC	8192
#ವ್ಯಾಖ್ಯಾನಿಸು BENCH_ಸ್ತಂಭ_ಅಗಲ	40

#ವ್ಯಾಖ್ಯಾನಿಸು MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#ವ್ಯಾಖ್ಯಾನಿಸು TEST_CHECK_INT(r, pred) ಮಾಡು {		\
		ಆಯ್ಕೆ (pred) {			\
		ಸ್ಥಿತಿ TEST_EQ:			\
			ಆದರೆ (r == 0)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_NE:			\
			ಆದರೆ (r != 0)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_LT:			\
			ಆದರೆ (r < 0)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_LE:			\
			ಆದರೆ (r <= 0)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_GT:			\
			ಆದರೆ (r > 0)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_GE:			\
			ಆದರೆ (r >= 0)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಪೂರ್ವನಿಯೋಜಿತ:			\
			abort();		\
		}				\
	} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು TEST_CHECK(x1, x2, pred) ಮಾಡು {		\
		ಆಯ್ಕೆ (pred) {			\
		ಸ್ಥಿತಿ TEST_EQ:			\
			ಆದರೆ (x1 == x2)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_NE:			\
			ಆದರೆ (x1 != x2)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_LT:			\
			ಆದರೆ (x1 < x2)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_LE:			\
			ಆದರೆ (x1 <= x2)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_GT:			\
			ಆದರೆ (x1 > x2)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಸ್ಥಿತಿ TEST_GE:			\
			ಆದರೆ (x1 >= x2)		\
				ಹಿಂತಿರುಗಿ;		\
			ನಿಲ್ಲಿಸು;			\
		ಪೂರ್ವನಿಯೋಜಿತ:			\
			abort();		\
		}				\
	} ಆಗ (0)

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ verbose_ಬಹುಲಕ = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ quiet_ಬಹುಲಕ = 0;
ಸ್ಥಿರ ಅಕ್ಷರ *ಸಕ್ರಿಯ_test_name = ಖಾಲಿ;
ಸ್ಥಿರ u_int test_ಸಂಖ್ಯೆ = 0;
ಸ್ಥಿರ test_onerror_func_t *test_onerror = ಖಾಲಿ;
ಸ್ಥಿರ ಶೂನ್ಯ *onerror_ctx = ಖಾಲಿ;
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ದತ್ತಾಂಶ_dir = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ subtest_info[512];
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ fast = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ slow = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ benchmark_detail_statistics = 0;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ benchmark = 0;
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *bench_name = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *benchmark_ನಮೂನೆ = ಖಾಲಿ;
ಸ್ಥಿರ ರಚನೆ timespec bench_ಆರಂಭ_ಸಮಯ, bench_ಮುಕ್ತಾಯ_ಸಮಯ;
ಸ್ಥಿರ ರಚನೆ timespec *bench_samples;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ bench_skip, bench_nruns, bench_nalloc;
ದ್ವಿಗುಣ bench_accum_secs;

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಪೂರ್ಣಾಂಕ ch;

	ಬೀಜ_rng();
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_ತುಂಬು_CRYPTO_ಅಕ್ಷರಸರಣಿಗಳು, ಖಾಲಿ);
#ಆದರೆ_ಅಂತ್ಯ

	/* Handle systems without __progname */
	ಆದರೆ (__progname == ಖಾಲಿ) {
		__progname = strrchr(argv[0], '/');
		ಆದರೆ (__progname == ಖಾಲಿ || __progname[1] == '\0')
			__progname = argv[0];	
		ಇಲ್ಲದಿದ್ದರೆ
			__progname++;
		ಆದರೆ ((__progname = strdup(__progname)) == ಖಾಲಿ) {
			fprintf(stderr, "strdup failed\n");
			ನಿರ್ಗಮಿಸು(1);
		}
	}

	ಆಗ ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'b':
			benchmark = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'B':
			benchmark = benchmark_detail_statistics = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'O':
			benchmark_ನಮೂನೆ = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'F':
			slow = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			fast = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'd':
			ದತ್ತಾಂಶ_dir = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'q':
			verbose_ಬಹುಲಕ = 0;
			quiet_ಬಹುಲಕ = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'v':
			verbose_ಬಹುಲಕ = 1;
			quiet_ಬಹುಲಕ = 0;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			ನಿರ್ಗಮಿಸು(1);
		}
	}
	setvbuf(stdout, ಖಾಲಿ, _IONBF, 0);
	ಆದರೆ (!quiet_ಬಹುಲಕ)
		ಬರೆ("%s: ", __progname);
	ಆದರೆ (verbose_ಬಹುಲಕ)
		ಬರೆ("\n");

	ಆದರೆ (benchmark)
		benchmarks();
	ಇಲ್ಲದಿದ್ದರೆ
		tests();

	ಆದರೆ (!quiet_ಬಹುಲಕ && !benchmark)
		ಬರೆ(" %u tests ok\n", test_ಸಂಖ್ಯೆ);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
test_is_verbose(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ verbose_ಬಹುಲಕ;
}

ಪೂರ್ಣಾಂಕ
test_is_quiet(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ quiet_ಬಹುಲಕ;
}

ಪೂರ್ಣಾಂಕ
test_is_fast(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ fast;
}

ಪೂರ್ಣಾಂಕ
test_is_slow(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ slow;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
test_ದತ್ತಾಂಶ_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರ ಅಕ್ಷರ ret[PATH_MAX];

	ಆದರೆ (ದತ್ತಾಂಶ_dir != ಖಾಲಿ)
		snprintf(ret, ಗಾತ್ರ(ret), "%s/%s", ದತ್ತಾಂಶ_dir, name);
	ಇಲ್ಲದಿದ್ದರೆ
		strlcpy(ret, name, ಗಾತ್ರ(ret));
	ಆದರೆ (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		ನಿರ್ಗಮಿಸು(1);
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
test_info(ಅಕ್ಷರ *s, ಗಾತ್ರ_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_ಸಂಖ್ಯೆ,
	    ಸಕ್ರಿಯ_test_name == ಖಾಲಿ ? "<none>" : ಸಕ್ರಿಯ_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

ಸ್ಥಿರ ಶೂನ್ಯ
siginfo(ಪೂರ್ಣಾಂಕ ಬಳಸದ __attribute__((__unused__)))
{
	ಅಕ್ಷರ buf[256];

	test_info(buf, ಗಾತ್ರ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(buf));
}

ಶೂನ್ಯ
test_ಆರಂಭ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *n)
{
	ಪ್ರತಿಜ್ಞಾ(ಸಕ್ರಿಯ_test_name == ಖಾಲಿ);
	ಪ್ರತಿಜ್ಞಾ((ಸಕ್ರಿಯ_test_name = strdup(n)) != ಖಾಲಿ);
	*subtest_info = '\0';
	ಆದರೆ (verbose_ಬಹುಲಕ)
		ಬರೆ("test %u - \"%s\": ", test_ಸಂಖ್ಯೆ, ಸಕ್ರಿಯ_test_name);
	test_ಸಂಖ್ಯೆ++;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
	ಸಂಕೇತ(SIGINFO, siginfo);
#ಆದರೆ_ಅಂತ್ಯ
	ಸಂಕೇತ(SIGUSR1, siginfo);
}

ಶೂನ್ಯ
ಗಣ_onerror_func(test_onerror_func_t *f, ಶೂನ್ಯ *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

ಶೂನ್ಯ
test_ಮುಗಿದ(ಶೂನ್ಯ)
{
	*subtest_info = '\0';
	ಪ್ರತಿಜ್ಞಾ(ಸಕ್ರಿಯ_test_name != ಖಾಲಿ);
	ಬಿಡುಗಡೆ(ಸಕ್ರಿಯ_test_name);
	ಸಕ್ರಿಯ_test_name = ಖಾಲಿ;
	ಆದರೆ (verbose_ಬಹುಲಕ)
		ಬರೆ("OK\n");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!quiet_ಬಹುಲಕ && !benchmark) {
		ಬರೆ(".");
		fflush(stdout);
	}
}

ಶೂನ್ಯ
test_subtest_info(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, ಗಾತ್ರ(subtest_info), fmt, ap);
	va_end(ap);
}

ಪೂರ್ಣಾಂಕ
test_is_benchmark(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ benchmark;
}

ಶೂನ್ಯ
ssl_err_check(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ದೀರ್ಘ openssl_error = ERR_get_error();

	ಆದರೆ (openssl_error == 0)
		ಹಿಂತಿರುಗಿ;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, ಸಾಲು, ERR_error_string(openssl_error, ಖಾಲಿ));
#ಇಲ್ಲದಿದ್ದರೆ /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, ಸಾಲು);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	abort();
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
pred_name(ಎಣಿಕೆ test_predicate p)
{
	ಆಯ್ಕೆ (p) {
	ಸ್ಥಿತಿ TEST_EQ:
		ಹಿಂತಿರುಗಿ "EQ";
	ಸ್ಥಿತಿ TEST_NE:
		ಹಿಂತಿರುಗಿ "NE";
	ಸ್ಥಿತಿ TEST_LT:
		ಹಿಂತಿರುಗಿ "LT";
	ಸ್ಥಿತಿ TEST_LE:
		ಹಿಂತಿರುಗಿ "LE";
	ಸ್ಥಿತಿ TEST_GT:
		ಹಿಂತಿರುಗಿ "GT";
	ಸ್ಥಿತಿ TEST_GE:
		ಹಿಂತಿರುಗಿ "GE";
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ "UNKNOWN";
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_die(ಶೂನ್ಯ)
{
	ಆದರೆ (test_onerror != ಖಾಲಿ)
		test_onerror(onerror_ctx);
	abort();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_ಶೀರ್ಷಿಕೆ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಎಣಿಕೆ test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, ಸಾಲು, test_ಸಂಖ್ಯೆ, ಸಕ್ರಿಯ_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != ಖಾಲಿ ? ", " : "", a2 != ಖಾಲಿ ? a2 : "");
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಶೂನ್ಯ
assert_bignum(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಸ್ಥಿರಾಂಕ BIGNUM *aa1, ಸ್ಥಿರಾಂಕ BIGNUM *aa2, ಎಣಿಕೆ test_predicate pred)
{
	ಪೂರ್ಣಾಂಕ r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#ಆದರೆ_ಅಂತ್ಯ

ಶೂನ್ಯ
assert_string(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *aa1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *aa2, ಎಣಿಕೆ test_predicate pred)
{
	ಪೂರ್ಣಾಂಕ r;

	/* Verify pointers are not NULL */
	assert_ptr(file, ಸಾಲು, a1, "NULL", aa1, ಖಾಲಿ, TEST_NE);
	assert_ptr(file, ಸಾಲು, a2, "NULL", aa2, ಖಾಲಿ, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(aa2));
	test_die();
}

ಶೂನ್ಯ
assert_mem(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa1, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa2, ಗಾತ್ರ_t l, ಎಣಿಕೆ test_predicate pred)
{
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *aa1_tohex = ಖಾಲಿ;
	ಅಕ್ಷರ *aa2_tohex = ಖಾಲಿ;

	ಆದರೆ (l == 0)
		ಹಿಂತಿರುಗಿ;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, ಸಾಲು, a1, "NULL", aa1, ಖಾಲಿ, TEST_NE);
	assert_ptr(file, ಸಾಲು, a2, "NULL", aa2, ಖಾಲಿ, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	ಬಿಡುಗಡೆ(aa1_tohex);
	ಬಿಡುಗಡೆ(aa2_tohex);
	test_die();
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
memvalcmp(ಸ್ಥಿರಾಂಕ uint8_t *s, u_char v, ಗಾತ್ರ_t l, ಗಾತ್ರ_t *where)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < l; i++) {
		ಆದರೆ (s[i] != v) {
			*where = i;
			ಹಿಂತಿರುಗಿ 1;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
assert_mem_filled(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa1, u_char v, ಗಾತ್ರ_t l, ಎಣಿಕೆ test_predicate pred)
{
	ಗಾತ್ರ_t where = -1;
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ tmp[64];
	ಅಕ್ಷರ *aa1_tohex = ಖಾಲಿ;

	ಆದರೆ (l == 0)
		ಹಿಂತಿರುಗಿ;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, ಸಾಲು, a1, "NULL", aa1, ಖಾಲಿ, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, ಖಾಲಿ, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	ಬಿಡುಗಡೆ(aa1_tohex);
	snprintf(tmp, ಗಾತ್ರ(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

ಶೂನ್ಯ
assert_int(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಪೂರ್ಣಾಂಕ aa1, ಪೂರ್ಣಾಂಕ aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_ಗಾತ್ರ_t(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಗಾತ್ರ_t aa1, ಗಾತ್ರ_t aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u_int(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    u_int aa1, u_int aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_long(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ದೀರ್ಘ aa1, ದೀರ್ಘ aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_long_long(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ದೀರ್ಘ ದೀರ್ಘ aa1, ದೀರ್ಘ ದೀರ್ಘ aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_char(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಅಕ್ಷರ aa1, ಅಕ್ಷರ aa2, ಎಣಿಕೆ test_predicate pred)
{
	ಅಕ್ಷರ buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_ಸುರಕ್ಷಿತ|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_ಸುರಕ್ಷಿತ|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u8(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    uint8_t aa1, uint8_t aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u16(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    uint16_t aa1, uint16_t aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u32(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    uint32_t aa1, uint32_t aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u64(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    uint64_t aa1, uint64_t aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)aa1, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)aa2, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)aa2);
	test_die();
}

ಶೂನ್ಯ
assert_double(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ದ್ವಿಗುಣ aa1, ದ್ವಿಗುಣ aa2, ಎಣಿಕೆ test_predicate pred)
{
	ಸ್ಥಿರಾಂಕ ದ್ವಿಗುಣ epsilon = 0.000000001;

	ಆಯ್ಕೆ (pred) {
	ಸ್ಥಿತಿ TEST_EQ:
		ಆದರೆ (fabs(aa1 - aa2) < epsilon)
			ಹಿಂತಿರುಗಿ;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ TEST_NE:
		ಆದರೆ (fabs(aa1 - aa2) >= epsilon)
			ಹಿಂತಿರುಗಿ;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ TEST_LT:
		ಆದರೆ (aa1 < aa2)
			ಹಿಂತಿರುಗಿ;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ TEST_LE:
		ಆದರೆ (aa1 <= aa2)
			ಹಿಂತಿರುಗಿ;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ TEST_GT:
		ಆದರೆ (aa1 > aa2)
			ಹಿಂತಿರುಗಿ;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ TEST_GE:
		ಆದರೆ (aa1 >= aa2)
			ಹಿಂತಿರುಗಿ;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		abort();
	}

	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_ptr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa1, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa2, ಎಣಿಕೆ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ಶೀರ್ಷಿಕೆ(file, ಸಾಲು, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

ಸ್ಥಿರ ದ್ವಿಗುಣ
tstod(ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *ts)
{
	ಹಿಂತಿರುಗಿ (ದ್ವಿಗುಣ)ts->tv_sec + ((ದ್ವಿಗುಣ)ts->tv_nsec / 1000000000.0);
}

ಶೂನ್ಯ
hex2bin(uint8_t *bin, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hex, ಗಾತ್ರ_t len)
{
	ಗಾತ್ರ_t i;
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	ಗಾಗಿ (i = 0; i < len; i++) {
		ASSERT_INT_EQ(ಅಕ್ಷರಸರಣಿ_ಓದು(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

ಶೂನ್ಯ
bench_ಆರಂಭ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಅಕ್ಷರ *cp;

	ಆದರೆ (bench_name != ಖಾಲಿ) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, ಸಾಲು, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_ನಮೂನೆ != ಖಾಲಿ &&
	    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(cp, benchmark_ನಮೂನೆ, 1) != 1;
	ಬಿಡುಗಡೆ(cp);

	bench_name = name;
	bench_nruns = 0;
	ಆದರೆ (bench_skip)
		ಹಿಂತಿರುಗಿ;
	ಬಿಡುಗಡೆ(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(ಗಾತ್ರ(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

ಪೂರ್ಣಾಂಕ
bench_ಮುಗಿದ(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_ಸಾಮಾನ್ಯ_DEADLINE));
}

ಶೂನ್ಯ
bench_case_ಆರಂಭ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು)
{
	clock_gettime(CLOCK_REALTIME, &bench_ಆರಂಭ_ಸಮಯ);
}

ಶೂನ್ಯ
bench_case_ಮುಕ್ತಾಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು)
{
	ರಚನೆ timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_ಮುಕ್ತಾಯ_ಸಮಯ);
	timespecsub(&bench_ಮುಕ್ತಾಯ_ಸಮಯ, &bench_ಆರಂಭ_ಸಮಯ, &ts);
	ಆದರೆ (bench_nruns >= bench_nalloc) {
		ಆದರೆ (bench_nalloc >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, ಗಾತ್ರ(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
tscmp(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *bb)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *a = (ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *)aa;
	ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *b = (ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *)bb;

	ಆದರೆ (timespeccmp(a, b, ==))
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ timespeccmp(a, b, <) ? -1 : 1;
}

ಶೂನ್ಯ
bench_ಮುಕ್ತಾಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *unit)
{
	ದ್ವಿಗುಣ std_dev = 0, ಸರಾಸರಿ_spr, ಸರಾಸರಿ_rps, med_spr, med_rps;
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (bench_skip)
		ಹೋಗು ಮುಗಿದ;

	ಆದರೆ (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, ಸಾಲು,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, ಗಾತ್ರ(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	ಆದರೆ (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/*ಸರಾಸರಿ*/
	ಸರಾಸರಿ_spr = bench_accum_secs / (ದ್ವಿಗುಣ)bench_nruns;
	ಸರಾಸರಿ_rps = (ಸರಾಸರಿ_spr == 0.0) ? INFINITY : 1.0/ಸರಾಸರಿ_spr;
	/* std. dev */
	std_dev = 0;
	ಗಾಗಿ (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - ಸರಾಸರಿ_spr;
		std_dev *= std_dev;
	}
	std_dev /= (ದ್ವಿಗುಣ)bench_nruns;
	std_dev = ವರ್ಗಮೂಲ(std_dev);
	ಆದರೆ (benchmark_detail_statistics) {
		ಬರೆ("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    ಸರಾಸರಿ_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    ಸರಾಸರಿ_rps, med_rps, unit);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಬರೆ("%-*s %0.2f %s/s\n", BENCH_ಸ್ತಂಭ_ಅಗಲ,
		    bench_name, med_rps, unit);
	}
 ಮುಗಿದ:
	bench_name = ಖಾಲಿ;
	bench_nruns = 0;
	ಬಿಡುಗಡೆ(bench_samples);
	bench_samples = ಖಾಲಿ;
	bench_skip = 0;
}
