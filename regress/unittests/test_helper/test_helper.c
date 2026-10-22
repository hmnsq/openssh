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

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#endif

#ಯದಿ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#ಅನ್ತರ್ಭಾವ "entropy.h"
#ಅನ್ತರ್ಭಾವ "test_helper.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

#define BENCH_FAST_DEADLINE	1
#define BENCH_NORMAL_DEADLINE	10
#define BENCH_SLOW_DEADLINE	60
#define BENCH_SAMPLES_ALLOC	8192
#define BENCH_COLUMN_WIDTH	40

#define MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#define TEST_CHECK_INT(r, pred) ಕುರು {		\
		ವಿಕಲ್ಪ (pred) {			\
		ಪಕ್ಷ TEST_EQ:			\
			ಯದಿ (r == 0)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_NE:			\
			ಯದಿ (r != 0)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_LT:			\
			ಯದಿ (r < 0)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_LE:			\
			ಯದಿ (r <= 0)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_GT:			\
			ಯದಿ (r > 0)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_GE:			\
			ಯದಿ (r >= 0)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಸ್ವಭಾವ:			\
			abort();		\
		}				\
	} ಯಾವತ್ (0)

#define TEST_CHECK(x1, x2, pred) ಕುರು {		\
		ವಿಕಲ್ಪ (pred) {			\
		ಪಕ್ಷ TEST_EQ:			\
			ಯದಿ (x1 == x2)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_NE:			\
			ಯದಿ (x1 != x2)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_LT:			\
			ಯದಿ (x1 < x2)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_LE:			\
			ಯದಿ (x1 <= x2)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_GT:			\
			ಯದಿ (x1 > x2)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಪಕ್ಷ TEST_GE:			\
			ಯದಿ (x1 >= x2)		\
				ಪ್ರತ್ಯಾಗಮ;		\
			ಭಙ್ಗ;			\
		ಸ್ವಭಾವ:			\
			abort();		\
		}				\
	} ಯಾವತ್ (0)

ಬಾಹ್ಯ ವರ್ಣ *__progname;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ verbose_mode = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ quiet_mode = 0;
ಸ್ಥಿರ ವರ್ಣ *active_test_name = ರಿಕ್ತ;
ಸ್ಥಿರ u_int test_ಸಂಖ್ಯೆ = 0;
ಸ್ಥಿರ test_onerror_func_t *test_onerror = ರಿಕ್ತ;
ಸ್ಥಿರ ಶೂನ್ಯ *onerror_ctx = ರಿಕ್ತ;
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *data_dir = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ subtest_info[512];
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ fast = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ slow = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ benchmark_detail_statistics = 0;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ benchmark = 0;
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *bench_name = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *benchmark_pattern = ರಿಕ್ತ;
ಸ್ಥಿರ ಸಂರಚನಾ timespec bench_start_time, bench_finish_time;
ಸ್ಥಿರ ಸಂರಚನಾ timespec *bench_samples;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ bench_skip, bench_nruns, bench_nalloc;
ದ್ವಿಗುಣ bench_accum_secs;

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಪೂರ್ಣಾಙ್ಕ ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ರಿಕ್ತ);
#endif

	/* Handle systems without __progname */
	ಯದಿ (__progname == ರಿಕ್ತ) {
		__progname = strrchr(argv[0], '/');
		ಯದಿ (__progname == ರಿಕ್ತ || __progname[1] == '\0')
			__progname = argv[0];	
		ಅನ್ಯಥಾ
			__progname++;
		ಯದಿ ((__progname = strdup(__progname)) == ರಿಕ್ತ) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	ಯಾವತ್ ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'b':
			benchmark = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'B':
			benchmark = benchmark_detail_statistics = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'O':
			benchmark_pattern = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'F':
			slow = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			fast = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'd':
			data_dir = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, ರಿಕ್ತ, _IONBF, 0);
	ಯದಿ (!quiet_mode)
		printf("%s: ", __progname);
	ಯದಿ (verbose_mode)
		printf("\n");

	ಯದಿ (benchmark)
		benchmarks();
	ಅನ್ಯಥಾ
		tests();

	ಯದಿ (!quiet_mode && !benchmark)
		printf(" %u tests ok\n", test_ಸಂಖ್ಯೆ);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
test_is_verbose(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ verbose_mode;
}

ಪೂರ್ಣಾಙ್ಕ
test_is_quiet(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ quiet_mode;
}

ಪೂರ್ಣಾಙ್ಕ
test_is_fast(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ fast;
}

ಪೂರ್ಣಾಙ್ಕ
test_is_slow(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ slow;
}

ಧ್ರುವ ವರ್ಣ *
test_data_file(ಧ್ರುವ ವರ್ಣ *name)
{
	ಸ್ಥಿರ ವರ್ಣ ret[PATH_MAX];

	ಯದಿ (data_dir != ರಿಕ್ತ)
		snprintf(ret, ಪರಿಮಾಣ(ret), "%s/%s", data_dir, name);
	ಅನ್ಯಥಾ
		strlcpy(ret, name, ಪರಿಮಾಣ(ret));
	ಯದಿ (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
test_info(ವರ್ಣ *s, size_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_ಸಂಖ್ಯೆ,
	    active_test_name == ರಿಕ್ತ ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

ಸ್ಥಿರ ಶೂನ್ಯ
siginfo(ಪೂರ್ಣಾಙ್ಕ unused __attribute__((__unused__)))
{
	ವರ್ಣ buf[256];

	test_info(buf, ಪರಿಮಾಣ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

ಶೂನ್ಯ
test_start(ಧ್ರುವ ವರ್ಣ *n)
{
	ಪ್ರತಿಜ್ಞಾ(active_test_name == ರಿಕ್ತ);
	ಪ್ರತಿಜ್ಞಾ((active_test_name = strdup(n)) != ರಿಕ್ತ);
	*subtest_info = '\0';
	ಯದಿ (verbose_mode)
		printf("test %u - \"%s\": ", test_ಸಂಖ್ಯೆ, active_test_name);
	test_ಸಂಖ್ಯೆ++;
#ifdef SIGINFO
	ಸಙ್ಕೇತ(SIGINFO, siginfo);
#endif
	ಸಙ್ಕೇತ(SIGUSR1, siginfo);
}

ಶೂನ್ಯ
set_onerror_func(test_onerror_func_t *f, ಶೂನ್ಯ *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

ಶೂನ್ಯ
test_done(ಶೂನ್ಯ)
{
	*subtest_info = '\0';
	ಪ್ರತಿಜ್ಞಾ(active_test_name != ರಿಕ್ತ);
	ಮುಕ್ತ(active_test_name);
	active_test_name = ರಿಕ್ತ;
	ಯದಿ (verbose_mode)
		printf("OK\n");
	ಅನ್ಯಥಾ ಯದಿ (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

ಶೂನ್ಯ
test_subtest_info(ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, ಪರಿಮಾಣ(subtest_info), fmt, ap);
	va_end(ap);
}

ಪೂರ್ಣಾಙ್ಕ
test_is_benchmark(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ benchmark;
}

ಶೂನ್ಯ
ssl_err_check(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	ಯದಿ (openssl_error == 0)
		ಪ್ರತ್ಯಾಗಮ;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, ಸಾಲು, ERR_error_string(openssl_error, ರಿಕ್ತ));
#ಅನ್ಯಥಾ /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, ಸಾಲು);
#endif /* WITH_OPENSSL */
	abort();
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
pred_name(ಗಣನಾ test_predicate p)
{
	ವಿಕಲ್ಪ (p) {
	ಪಕ್ಷ TEST_EQ:
		ಪ್ರತ್ಯಾಗಮ "EQ";
	ಪಕ್ಷ TEST_NE:
		ಪ್ರತ್ಯಾಗಮ "NE";
	ಪಕ್ಷ TEST_LT:
		ಪ್ರತ್ಯಾಗಮ "LT";
	ಪಕ್ಷ TEST_LE:
		ಪ್ರತ್ಯಾಗಮ "LE";
	ಪಕ್ಷ TEST_GT:
		ಪ್ರತ್ಯಾಗಮ "GT";
	ಪಕ್ಷ TEST_GE:
		ಪ್ರತ್ಯಾಗಮ "GE";
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ "UNKNOWN";
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_die(ಶೂನ್ಯ)
{
	ಯದಿ (test_onerror != ರಿಕ್ತ)
		test_onerror(onerror_ctx);
	abort();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_header(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    ಧ್ರುವ ವರ್ಣ *name, ಗಣನಾ test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, ಸಾಲು, test_ಸಂಖ್ಯೆ, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != ರಿಕ್ತ ? ", " : "", a2 != ರಿಕ್ತ ? a2 : "");
}

#ifdef WITH_OPENSSL
ಶೂನ್ಯ
assert_bignum(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    ಧ್ರುವ BIGNUM *aa1, ಧ್ರುವ BIGNUM *aa2, ಗಣನಾ test_predicate pred)
{
	ಪೂರ್ಣಾಙ್ಕ r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, ಸಾಲು, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

ಶೂನ್ಯ
assert_string(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    ಧ್ರುವ ವರ್ಣ *aa1, ಧ್ರುವ ವರ್ಣ *aa2, ಗಣನಾ test_predicate pred)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	/* Verify pointers are not NULL */
	assert_ptr(file, ಸಾಲು, a1, "NULL", aa1, ರಿಕ್ತ, TEST_NE);
	assert_ptr(file, ಸಾಲು, a2, "NULL", aa2, ರಿಕ್ತ, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, ಸಾಲು, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

ಶೂನ್ಯ
assert_mem(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    ಧ್ರುವ ಶೂನ್ಯ *aa1, ಧ್ರುವ ಶೂನ್ಯ *aa2, size_t l, ಗಣನಾ test_predicate pred)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *aa1_tohex = ರಿಕ್ತ;
	ವರ್ಣ *aa2_tohex = ರಿಕ್ತ;

	ಯದಿ (l == 0)
		ಪ್ರತ್ಯಾಗಮ;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, ಸಾಲು, a1, "NULL", aa1, ರಿಕ್ತ, TEST_NE);
	assert_ptr(file, ಸಾಲು, a2, "NULL", aa2, ರಿಕ್ತ, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, ಸಾಲು, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	ಮುಕ್ತ(aa1_tohex);
	ಮುಕ್ತ(aa2_tohex);
	test_die();
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
memvalcmp(ಧ್ರುವ uint8_t *s, u_char v, size_t l, size_t *where)
{
	size_t i;

	ಪ್ರತಿ (i = 0; i < l; i++) {
		ಯದಿ (s[i] != v) {
			*where = i;
			ಪ್ರತ್ಯಾಗಮ 1;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
assert_mem_filled(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1,
    ಧ್ರುವ ಶೂನ್ಯ *aa1, u_char v, size_t l, ಗಣನಾ test_predicate pred)
{
	size_t where = -1;
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ tmp[64];
	ವರ್ಣ *aa1_tohex = ರಿಕ್ತ;

	ಯದಿ (l == 0)
		ಪ್ರತ್ಯಾಗಮ;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, ಸಾಲು, a1, "NULL", aa1, ರಿಕ್ತ, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, ಸಾಲು, a1, ರಿಕ್ತ, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	ಮುಕ್ತ(aa1_tohex);
	snprintf(tmp, ಪರಿಮಾಣ(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

ಶೂನ್ಯ
assert_int(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    ಪೂರ್ಣಾಙ್ಕ aa1, ಪೂರ್ಣಾಙ್ಕ aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_size_t(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    size_t aa1, size_t aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u_int(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    u_int aa1, u_int aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_long(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    long aa1, long aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_long_long(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    long long aa1, long long aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_char(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    ವರ್ಣ aa1, ವರ್ಣ aa2, ಗಣನಾ test_predicate pred)
{
	ವರ್ಣ buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u8(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    uint8_t aa1, uint8_t aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u16(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    uint16_t aa1, uint16_t aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u32(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    uint32_t aa1, uint32_t aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_u64(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    uint64_t aa1, uint64_t aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (unsigned long long)aa1, (unsigned long long)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (unsigned long long)aa2, (unsigned long long)aa2);
	test_die();
}

ಶೂನ್ಯ
assert_double(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    ದ್ವಿಗುಣ aa1, ದ್ವಿಗುಣ aa2, ಗಣನಾ test_predicate pred)
{
	ಧ್ರುವ ದ್ವಿಗುಣ epsilon = 0.000000001;

	ವಿಕಲ್ಪ (pred) {
	ಪಕ್ಷ TEST_EQ:
		ಯದಿ (fabs(aa1 - aa2) < epsilon)
			ಪ್ರತ್ಯಾಗಮ;
		ಭಙ್ಗ;
	ಪಕ್ಷ TEST_NE:
		ಯದಿ (fabs(aa1 - aa2) >= epsilon)
			ಪ್ರತ್ಯಾಗಮ;
		ಭಙ್ಗ;
	ಪಕ್ಷ TEST_LT:
		ಯದಿ (aa1 < aa2)
			ಪ್ರತ್ಯಾಗಮ;
		ಭಙ್ಗ;
	ಪಕ್ಷ TEST_LE:
		ಯದಿ (aa1 <= aa2)
			ಪ್ರತ್ಯಾಗಮ;
		ಭಙ್ಗ;
	ಪಕ್ಷ TEST_GT:
		ಯದಿ (aa1 > aa2)
			ಪ್ರತ್ಯಾಗಮ;
		ಭಙ್ಗ;
	ಪಕ್ಷ TEST_GE:
		ಯದಿ (aa1 >= aa2)
			ಪ್ರತ್ಯಾಗಮ;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		abort();
	}

	test_header(file, ಸಾಲು, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

ಶೂನ್ಯ
assert_ptr(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *a1, ಧ್ರುವ ವರ್ಣ *a2,
    ಧ್ರುವ ಶೂನ್ಯ *aa1, ಧ್ರುವ ಶೂನ್ಯ *aa2, ಗಣನಾ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ಸಾಲು, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

ಸ್ಥಿರ ದ್ವಿಗುಣ
tstod(ಧ್ರುವ ಸಂರಚನಾ timespec *ts)
{
	ಪ್ರತ್ಯಾಗಮ (ದ್ವಿಗುಣ)ts->tv_sec + ((ದ್ವಿಗುಣ)ts->tv_nsec / 1000000000.0);
}

ಶೂನ್ಯ
hex2bin(uint8_t *bin, ಧ್ರುವ ವರ್ಣ *hex, size_t len)
{
	size_t i;
	unsigned ಪೂರ್ಣಾಙ್ಕ v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	ಪ್ರತಿ (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

ಶೂನ್ಯ
bench_start(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *name)
{
	ವರ್ಣ *cp;

	ಯದಿ (bench_name != ರಿಕ್ತ) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, ಸಾಲು, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != ರಿಕ್ತ &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	ಮುಕ್ತ(cp);

	bench_name = name;
	bench_nruns = 0;
	ಯದಿ (bench_skip)
		ಪ್ರತ್ಯಾಗಮ;
	ಮುಕ್ತ(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(ಪರಿಮಾಣ(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

ಪೂರ್ಣಾಙ್ಕ
bench_done(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

ಶೂನ್ಯ
bench_case_start(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

ಶೂನ್ಯ
bench_case_finish(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು)
{
	ಸಂರಚನಾ timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	ಯದಿ (bench_nruns >= bench_nalloc) {
		ಯದಿ (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, ಪರಿಮಾಣ(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
tscmp(ಧ್ರುವ ಶೂನ್ಯ *aa, ಧ್ರುವ ಶೂನ್ಯ *bb)
{
	ಧ್ರುವ ಸಂರಚನಾ timespec *a = (ಧ್ರುವ ಸಂರಚನಾ timespec *)aa;
	ಧ್ರುವ ಸಂರಚನಾ timespec *b = (ಧ್ರುವ ಸಂರಚನಾ timespec *)bb;

	ಯದಿ (timespeccmp(a, b, ==))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ timespeccmp(a, b, <) ? -1 : 1;
}

ಶೂನ್ಯ
bench_finish(ಧ್ರುವ ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *unit)
{
	ದ್ವಿಗುಣ std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (bench_skip)
		ಗಚ್ಛ done;

	ಯದಿ (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, ಸಾಲು,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, ಪರಿಮಾಣ(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	ಯದಿ (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (ದ್ವಿಗುಣ)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? INFINITY : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	ಪ್ರತಿ (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (ದ್ವಿಗುಣ)bench_nruns;
	std_dev = sqrt(std_dev);
	ಯದಿ (benchmark_detail_statistics) {
		printf("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} ಅನ್ಯಥಾ {
		printf("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = ರಿಕ್ತ;
	bench_nruns = 0;
	ಮುಕ್ತ(bench_samples);
	bench_samples = ರಿಕ್ತ;
	bench_skip = 0;
}
