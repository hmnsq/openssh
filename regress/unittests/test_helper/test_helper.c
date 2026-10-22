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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <assert.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <math.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "entropy.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "test_helper.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BENCH_FAST_DEADLINE	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BENCH_ਸਾਧਾਰਨ_DEADLINE	10
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BENCH_SLOW_DEADLINE	60
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BENCH_SAMPLES_ALLOC	8192
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BENCH_ਕਾਲਮ_ਚੌੜਾਈ	40

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TEST_CHECK_INT(r, pred) ਕਰੋ {		\
		ਚੋਣ (pred) {			\
		ਹਾਲਤ TEST_EQ:			\
			ਜੇ (r == 0)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_NE:			\
			ਜੇ (r != 0)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_LT:			\
			ਜੇ (r < 0)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_LE:			\
			ਜੇ (r <= 0)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_GT:			\
			ਜੇ (r > 0)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_GE:			\
			ਜੇ (r >= 0)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਮੂਲ:			\
			abort();		\
		}				\
	} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TEST_CHECK(x1, x2, pred) ਕਰੋ {		\
		ਚੋਣ (pred) {			\
		ਹਾਲਤ TEST_EQ:			\
			ਜੇ (x1 == x2)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_NE:			\
			ਜੇ (x1 != x2)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_LT:			\
			ਜੇ (x1 < x2)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_LE:			\
			ਜੇ (x1 <= x2)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_GT:			\
			ਜੇ (x1 > x2)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਹਾਲਤ TEST_GE:			\
			ਜੇ (x1 >= x2)		\
				ਵਾਪਸ;		\
			ਰੋਕੋ;			\
		ਮੂਲ:			\
			abort();		\
		}				\
	} ਜਦੋਂ (0)

ਬਾਹਰੀ ਅੱਖਰ *__progname;

ਸਥਿਰ ਪੂਰਨ verbose_ਬਹੁਲਕ = 0;
ਸਥਿਰ ਪੂਰਨ quiet_ਬਹੁਲਕ = 0;
ਸਥਿਰ ਅੱਖਰ *ਸਰਗਰਮ_test_name = ਨਿਰਾ;
ਸਥਿਰ u_int test_ਸੰਖਿਆ = 0;
ਸਥਿਰ test_onerror_func_t *test_onerror = ਨਿਰਾ;
ਸਥਿਰ ਖਾਲੀ *onerror_ctx = ਨਿਰਾ;
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *ਅੰਕੜੇ_dir = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ subtest_info[512];
ਸਥਿਰ ਪੂਰਨ fast = 0;
ਸਥਿਰ ਪੂਰਨ slow = 0;
ਸਥਿਰ ਪੂਰਨ benchmark_detail_statistics = 0;

ਸਥਿਰ ਪੂਰਨ benchmark = 0;
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *bench_name = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *benchmark_ਨਮੂਨਾ = ਨਿਰਾ;
ਸਥਿਰ ਬਣਤਰ timespec bench_ਸ਼ੁਰੂ_ਸਮਾਂ, bench_ਅੰਤ_ਸਮਾਂ;
ਸਥਿਰ ਬਣਤਰ timespec *bench_samples;
ਸਥਿਰ ਪੂਰਨ bench_skip, bench_nruns, bench_nalloc;
ਦੁੱਗਣਾ bench_accum_secs;

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਪੂਰਨ ch;

	ਬੀਜ_rng();
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_ਲੱਦੋ_CRYPTO_ਲੜੀਆਂ, ਨਿਰਾ);
#ਜੇ_ਅੰਤ

	/* Handle systems without __progname */
	ਜੇ (__progname == ਨਿਰਾ) {
		__progname = strrchr(argv[0], '/');
		ਜੇ (__progname == ਨਿਰਾ || __progname[1] == '\0')
			__progname = argv[0];	
		ਨਹੀਂਤਾਂ
			__progname++;
		ਜੇ ((__progname = strdup(__progname)) == ਨਿਰਾ) {
			fprintf(stderr, "strdup failed\n");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
	}

	ਜਦੋਂ ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'b':
			benchmark = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'B':
			benchmark = benchmark_detail_statistics = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'O':
			benchmark_ਨਮੂਨਾ = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'F':
			slow = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			fast = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'd':
			ਅੰਕੜੇ_dir = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'q':
			verbose_ਬਹੁਲਕ = 0;
			quiet_ਬਹੁਲਕ = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'v':
			verbose_ਬਹੁਲਕ = 1;
			quiet_ਬਹੁਲਕ = 0;
			ਰੋਕੋ;
		ਮੂਲ:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
	}
	setvbuf(stdout, ਨਿਰਾ, _IONBF, 0);
	ਜੇ (!quiet_ਬਹੁਲਕ)
		ਲਿਖੋ("%s: ", __progname);
	ਜੇ (verbose_ਬਹੁਲਕ)
		ਲਿਖੋ("\n");

	ਜੇ (benchmark)
		benchmarks();
	ਨਹੀਂਤਾਂ
		tests();

	ਜੇ (!quiet_ਬਹੁਲਕ && !benchmark)
		ਲਿਖੋ(" %u tests ok\n", test_ਸੰਖਿਆ);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
test_is_verbose(ਖਾਲੀ)
{
	ਵਾਪਸ verbose_ਬਹੁਲਕ;
}

ਪੂਰਨ
test_is_quiet(ਖਾਲੀ)
{
	ਵਾਪਸ quiet_ਬਹੁਲਕ;
}

ਪੂਰਨ
test_is_fast(ਖਾਲੀ)
{
	ਵਾਪਸ fast;
}

ਪੂਰਨ
test_is_slow(ਖਾਲੀ)
{
	ਵਾਪਸ slow;
}

ਅਚਲ ਅੱਖਰ *
test_ਅੰਕੜੇ_file(ਅਚਲ ਅੱਖਰ *name)
{
	ਸਥਿਰ ਅੱਖਰ ret[PATH_MAX];

	ਜੇ (ਅੰਕੜੇ_dir != ਨਿਰਾ)
		snprintf(ret, ਆਕਾਰ(ret), "%s/%s", ਅੰਕੜੇ_dir, name);
	ਨਹੀਂਤਾਂ
		strlcpy(ret, name, ਆਕਾਰ(ret));
	ਜੇ (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	ਵਾਪਸ ret;
}

ਖਾਲੀ
test_info(ਅੱਖਰ *s, ਮਾਪ_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_ਸੰਖਿਆ,
	    ਸਰਗਰਮ_test_name == ਨਿਰਾ ? "<none>" : ਸਰਗਰਮ_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

ਸਥਿਰ ਖਾਲੀ
siginfo(ਪੂਰਨ ਅਣਵਰਤਿਆ __attribute__((__unused__)))
{
	ਅੱਖਰ buf[256];

	test_info(buf, ਆਕਾਰ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, ਲੜੀ_ਲੰਬਾਈ(buf));
}

ਖਾਲੀ
test_ਸ਼ੁਰੂ(ਅਚਲ ਅੱਖਰ *n)
{
	ਪ੍ਰਤਿਜ੍ਞਾ(ਸਰਗਰਮ_test_name == ਨਿਰਾ);
	ਪ੍ਰਤਿਜ੍ਞਾ((ਸਰਗਰਮ_test_name = strdup(n)) != ਨਿਰਾ);
	*subtest_info = '\0';
	ਜੇ (verbose_ਬਹੁਲਕ)
		ਲਿਖੋ("test %u - \"%s\": ", test_ਸੰਖਿਆ, ਸਰਗਰਮ_test_name);
	test_ਸੰਖਿਆ++;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
	ਸੰਕੇਤ(SIGINFO, siginfo);
#ਜੇ_ਅੰਤ
	ਸੰਕੇਤ(SIGUSR1, siginfo);
}

ਖਾਲੀ
ਸੈੱਟ_onerror_func(test_onerror_func_t *f, ਖਾਲੀ *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

ਖਾਲੀ
test_ਪੂਰਾ(ਖਾਲੀ)
{
	*subtest_info = '\0';
	ਪ੍ਰਤਿਜ੍ਞਾ(ਸਰਗਰਮ_test_name != ਨਿਰਾ);
	ਮੁਕਤ(ਸਰਗਰਮ_test_name);
	ਸਰਗਰਮ_test_name = ਨਿਰਾ;
	ਜੇ (verbose_ਬਹੁਲਕ)
		ਲਿਖੋ("OK\n");
	ਨਹੀਂਤਾਂ ਜੇ (!quiet_ਬਹੁਲਕ && !benchmark) {
		ਲਿਖੋ(".");
		fflush(stdout);
	}
}

ਖਾਲੀ
test_subtest_info(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, ਆਕਾਰ(subtest_info), fmt, ap);
	va_end(ap);
}

ਪੂਰਨ
test_is_benchmark(ਖਾਲੀ)
{
	ਵਾਪਸ benchmark;
}

ਖਾਲੀ
ssl_err_check(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਲੰਮਾ openssl_error = ERR_get_error();

	ਜੇ (openssl_error == 0)
		ਵਾਪਸ;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, ਸਤਰ, ERR_error_string(openssl_error, ਨਿਰਾ));
#ਨਹੀਂਤਾਂ /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, ਸਤਰ);
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	abort();
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
pred_name(ਗਿਣਤੀ test_predicate p)
{
	ਚੋਣ (p) {
	ਹਾਲਤ TEST_EQ:
		ਵਾਪਸ "EQ";
	ਹਾਲਤ TEST_NE:
		ਵਾਪਸ "NE";
	ਹਾਲਤ TEST_LT:
		ਵਾਪਸ "LT";
	ਹਾਲਤ TEST_LE:
		ਵਾਪਸ "LE";
	ਹਾਲਤ TEST_GT:
		ਵਾਪਸ "GT";
	ਹਾਲਤ TEST_GE:
		ਵਾਪਸ "GE";
	ਮੂਲ:
		ਵਾਪਸ "UNKNOWN";
	}
}

ਸਥਿਰ ਖਾਲੀ
test_die(ਖਾਲੀ)
{
	ਜੇ (test_onerror != ਨਿਰਾ)
		test_onerror(onerror_ctx);
	abort();
}

ਸਥਿਰ ਖਾਲੀ
test_ਸਿਰਲੇਖ(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅਚਲ ਅੱਖਰ *name, ਗਿਣਤੀ test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, ਸਤਰ, test_ਸੰਖਿਆ, ਸਰਗਰਮ_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != ਨਿਰਾ ? ", " : "", a2 != ਨਿਰਾ ? a2 : "");
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਖਾਲੀ
assert_bignum(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅਚਲ BIGNUM *aa1, ਅਚਲ BIGNUM *aa2, ਗਿਣਤੀ test_predicate pred)
{
	ਪੂਰਨ r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#ਜੇ_ਅੰਤ

ਖਾਲੀ
assert_string(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅਚਲ ਅੱਖਰ *aa1, ਅਚਲ ਅੱਖਰ *aa2, ਗਿਣਤੀ test_predicate pred)
{
	ਪੂਰਨ r;

	/* Verify pointers are not NULL */
	assert_ptr(file, ਸਤਰ, a1, "NULL", aa1, ਨਿਰਾ, TEST_NE);
	assert_ptr(file, ਸਤਰ, a2, "NULL", aa2, ਨਿਰਾ, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, ਲੜੀ_ਲੰਬਾਈ(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, ਲੜੀ_ਲੰਬਾਈ(aa2));
	test_die();
}

ਖਾਲੀ
assert_mem(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅਚਲ ਖਾਲੀ *aa1, ਅਚਲ ਖਾਲੀ *aa2, ਮਾਪ_t l, ਗਿਣਤੀ test_predicate pred)
{
	ਪੂਰਨ r;
	ਅੱਖਰ *aa1_tohex = ਨਿਰਾ;
	ਅੱਖਰ *aa2_tohex = ਨਿਰਾ;

	ਜੇ (l == 0)
		ਵਾਪਸ;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, ਸਤਰ, a1, "NULL", aa1, ਨਿਰਾ, TEST_NE);
	assert_ptr(file, ਸਤਰ, a2, "NULL", aa2, ਨਿਰਾ, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	ਮੁਕਤ(aa1_tohex);
	ਮੁਕਤ(aa2_tohex);
	test_die();
}

ਸਥਿਰ ਪੂਰਨ
memvalcmp(ਅਚਲ uint8_t *s, u_char v, ਮਾਪ_t l, ਮਾਪ_t *where)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < l; i++) {
		ਜੇ (s[i] != v) {
			*where = i;
			ਵਾਪਸ 1;
		}
	}
	ਵਾਪਸ 0;
}

ਖਾਲੀ
assert_mem_filled(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1,
    ਅਚਲ ਖਾਲੀ *aa1, u_char v, ਮਾਪ_t l, ਗਿਣਤੀ test_predicate pred)
{
	ਮਾਪ_t where = -1;
	ਪੂਰਨ r;
	ਅੱਖਰ tmp[64];
	ਅੱਖਰ *aa1_tohex = ਨਿਰਾ;

	ਜੇ (l == 0)
		ਵਾਪਸ;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, ਸਤਰ, a1, "NULL", aa1, ਨਿਰਾ, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, ਨਿਰਾ, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	ਮੁਕਤ(aa1_tohex);
	snprintf(tmp, ਆਕਾਰ(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

ਖਾਲੀ
assert_int(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਪੂਰਨ aa1, ਪੂਰਨ aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

ਖਾਲੀ
assert_ਮਾਪ_t(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਮਾਪ_t aa1, ਮਾਪ_t aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

ਖਾਲੀ
assert_u_int(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    u_int aa1, u_int aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

ਖਾਲੀ
assert_long(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਲੰਮਾ aa1, ਲੰਮਾ aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

ਖਾਲੀ
assert_long_long(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਲੰਮਾ ਲੰਮਾ aa1, ਲੰਮਾ ਲੰਮਾ aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

ਖਾਲੀ
assert_char(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅੱਖਰ aa1, ਅੱਖਰ aa2, ਗਿਣਤੀ test_predicate pred)
{
	ਅੱਖਰ buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_ਸੁਰੱਖਿਅਤ|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_ਸੁਰੱਖਿਅਤ|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

ਖਾਲੀ
assert_u8(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    uint8_t aa1, uint8_t aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

ਖਾਲੀ
assert_u16(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    uint16_t aa1, uint16_t aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

ਖਾਲੀ
assert_u32(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    uint32_t aa1, uint32_t aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

ਖਾਲੀ
assert_u64(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    uint64_t aa1, uint64_t aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)aa1, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)aa2, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)aa2);
	test_die();
}

ਖਾਲੀ
assert_double(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਦੁੱਗਣਾ aa1, ਦੁੱਗਣਾ aa2, ਗਿਣਤੀ test_predicate pred)
{
	ਅਚਲ ਦੁੱਗਣਾ epsilon = 0.000000001;

	ਚੋਣ (pred) {
	ਹਾਲਤ TEST_EQ:
		ਜੇ (fabs(aa1 - aa2) < epsilon)
			ਵਾਪਸ;
		ਰੋਕੋ;
	ਹਾਲਤ TEST_NE:
		ਜੇ (fabs(aa1 - aa2) >= epsilon)
			ਵਾਪਸ;
		ਰੋਕੋ;
	ਹਾਲਤ TEST_LT:
		ਜੇ (aa1 < aa2)
			ਵਾਪਸ;
		ਰੋਕੋ;
	ਹਾਲਤ TEST_LE:
		ਜੇ (aa1 <= aa2)
			ਵਾਪਸ;
		ਰੋਕੋ;
	ਹਾਲਤ TEST_GT:
		ਜੇ (aa1 > aa2)
			ਵਾਪਸ;
		ਰੋਕੋ;
	ਹਾਲਤ TEST_GE:
		ਜੇ (aa1 >= aa2)
			ਵਾਪਸ;
		ਰੋਕੋ;
	ਮੂਲ:
		abort();
	}

	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

ਖਾਲੀ
assert_ptr(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅਚਲ ਖਾਲੀ *aa1, ਅਚਲ ਖਾਲੀ *aa2, ਗਿਣਤੀ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_ਸਿਰਲੇਖ(file, ਸਤਰ, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

ਸਥਿਰ ਦੁੱਗਣਾ
tstod(ਅਚਲ ਬਣਤਰ timespec *ts)
{
	ਵਾਪਸ (ਦੁੱਗਣਾ)ts->tv_sec + ((ਦੁੱਗਣਾ)ts->tv_nsec / 1000000000.0);
}

ਖਾਲੀ
hex2bin(uint8_t *bin, ਅਚਲ ਅੱਖਰ *hex, ਮਾਪ_t len)
{
	ਮਾਪ_t i;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	ਲਈ (i = 0; i < len; i++) {
		ASSERT_INT_EQ(ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

ਖਾਲੀ
bench_ਸ਼ੁਰੂ(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *name)
{
	ਅੱਖਰ *cp;

	ਜੇ (bench_name != ਨਿਰਾ) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, ਸਤਰ, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_ਨਮੂਨਾ != ਨਿਰਾ &&
	    ਮੇਲ_ਨਮੂਨਾ_list(cp, benchmark_ਨਮੂਨਾ, 1) != 1;
	ਮੁਕਤ(cp);

	bench_name = name;
	bench_nruns = 0;
	ਜੇ (bench_skip)
		ਵਾਪਸ;
	ਮੁਕਤ(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(ਆਕਾਰ(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

ਪੂਰਨ
bench_ਪੂਰਾ(ਖਾਲੀ)
{
	ਵਾਪਸ bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_ਸਾਧਾਰਨ_DEADLINE));
}

ਖਾਲੀ
bench_case_ਸ਼ੁਰੂ(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ)
{
	clock_gettime(CLOCK_REALTIME, &bench_ਸ਼ੁਰੂ_ਸਮਾਂ);
}

ਖਾਲੀ
bench_case_ਅੰਤ(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ)
{
	ਬਣਤਰ timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_ਅੰਤ_ਸਮਾਂ);
	timespecsub(&bench_ਅੰਤ_ਸਮਾਂ, &bench_ਸ਼ੁਰੂ_ਸਮਾਂ, &ts);
	ਜੇ (bench_nruns >= bench_nalloc) {
		ਜੇ (bench_nalloc >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, ਆਕਾਰ(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

ਸਥਿਰ ਪੂਰਨ
tscmp(ਅਚਲ ਖਾਲੀ *aa, ਅਚਲ ਖਾਲੀ *bb)
{
	ਅਚਲ ਬਣਤਰ timespec *a = (ਅਚਲ ਬਣਤਰ timespec *)aa;
	ਅਚਲ ਬਣਤਰ timespec *b = (ਅਚਲ ਬਣਤਰ timespec *)bb;

	ਜੇ (timespeccmp(a, b, ==))
		ਵਾਪਸ 0;
	ਵਾਪਸ timespeccmp(a, b, <) ? -1 : 1;
}

ਖਾਲੀ
bench_ਅੰਤ(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *unit)
{
	ਦੁੱਗਣਾ std_dev = 0, ਔਸਤ_spr, ਔਸਤ_rps, med_spr, med_rps;
	ਪੂਰਨ i;

	ਜੇ (bench_skip)
		ਜਾਓ ਪੂਰਾ;

	ਜੇ (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, ਸਤਰ,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, ਆਕਾਰ(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	ਜੇ (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/*ਔਸਤ*/
	ਔਸਤ_spr = bench_accum_secs / (ਦੁੱਗਣਾ)bench_nruns;
	ਔਸਤ_rps = (ਔਸਤ_spr == 0.0) ? INFINITY : 1.0/ਔਸਤ_spr;
	/* std. dev */
	std_dev = 0;
	ਲਈ (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - ਔਸਤ_spr;
		std_dev *= std_dev;
	}
	std_dev /= (ਦੁੱਗਣਾ)bench_nruns;
	std_dev = ਵਰਗਮੂਲ(std_dev);
	ਜੇ (benchmark_detail_statistics) {
		ਲਿਖੋ("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    ਔਸਤ_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    ਔਸਤ_rps, med_rps, unit);
	} ਨਹੀਂਤਾਂ {
		ਲਿਖੋ("%-*s %0.2f %s/s\n", BENCH_ਕਾਲਮ_ਚੌੜਾਈ,
		    bench_name, med_rps, unit);
	}
 ਪੂਰਾ:
	bench_name = ਨਿਰਾ;
	bench_nruns = 0;
	ਮੁਕਤ(bench_samples);
	bench_samples = ਨਿਰਾ;
	bench_skip = 0;
}
