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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/uio.h>
#অন্তর্ভাব <sys/time.h>

#অন্তর্ভাব <assert.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <math.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/err.h>
#endif

#যদি defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#অন্তর্ভাব "entropy.h"
#অন্তর্ভাব "test_helper.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "xmalloc.h"

#define BENCH_FAST_DEADLINE	1
#define BENCH_NORMAL_DEADLINE	10
#define BENCH_SLOW_DEADLINE	60
#define BENCH_SAMPLES_ALLOC	8192
#define BENCH_COLUMN_WIDTH	40

#define MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#define TEST_CHECK_INT(r, pred) কুরু {		\
		বিকল্প (pred) {			\
		পক্ষ TEST_EQ:			\
			যদি (r == 0)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_NE:			\
			যদি (r != 0)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_LT:			\
			যদি (r < 0)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_LE:			\
			যদি (r <= 0)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_GT:			\
			যদি (r > 0)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_GE:			\
			যদি (r >= 0)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		স্বভাব:			\
			abort();		\
		}				\
	} যাবত্ (0)

#define TEST_CHECK(x1, x2, pred) কুরু {		\
		বিকল্প (pred) {			\
		পক্ষ TEST_EQ:			\
			যদি (x1 == x2)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_NE:			\
			যদি (x1 != x2)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_LT:			\
			যদি (x1 < x2)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_LE:			\
			যদি (x1 <= x2)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_GT:			\
			যদি (x1 > x2)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		পক্ষ TEST_GE:			\
			যদি (x1 >= x2)		\
				প্রত্যাগম;		\
			ভঙ্গ;			\
		স্বভাব:			\
			abort();		\
		}				\
	} যাবত্ (0)

বাহ্য বর্ণ *__progname;

স্থির পূর্ণাঙ্ক verbose_mode = 0;
স্থির পূর্ণাঙ্ক quiet_mode = 0;
স্থির বর্ণ *active_test_name = রিক্ত;
স্থির u_int test_সংখ্যা = 0;
স্থির test_onerror_func_t *test_onerror = রিক্ত;
স্থির শূন্য *onerror_ctx = রিক্ত;
স্থির ধ্রুব বর্ণ *data_dir = রিক্ত;
স্থির বর্ণ subtest_info[512];
স্থির পূর্ণাঙ্ক fast = 0;
স্থির পূর্ণাঙ্ক slow = 0;
স্থির পূর্ণাঙ্ক benchmark_detail_statistics = 0;

স্থির পূর্ণাঙ্ক benchmark = 0;
স্থির ধ্রুব বর্ণ *bench_name = রিক্ত;
স্থির বর্ণ *benchmark_pattern = রিক্ত;
স্থির সংরচনা timespec bench_start_time, bench_finish_time;
স্থির সংরচনা timespec *bench_samples;
স্থির পূর্ণাঙ্ক bench_skip, bench_nruns, bench_nalloc;
দ্বিগুণ bench_accum_secs;

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	পূর্ণাঙ্ক ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, রিক্ত);
#endif

	/* Handle systems without __progname */
	যদি (__progname == রিক্ত) {
		__progname = strrchr(argv[0], '/');
		যদি (__progname == রিক্ত || __progname[1] == '\0')
			__progname = argv[0];	
		অন্যথা
			__progname++;
		যদি ((__progname = strdup(__progname)) == রিক্ত) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	যাবত্ ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		বিকল্প (ch) {
		পক্ষ 'b':
			benchmark = 1;
			ভঙ্গ;
		পক্ষ 'B':
			benchmark = benchmark_detail_statistics = 1;
			ভঙ্গ;
		পক্ষ 'O':
			benchmark_pattern = xstrdup(optarg);
			ভঙ্গ;
		পক্ষ 'F':
			slow = 1;
			ভঙ্গ;
		পক্ষ 'f':
			fast = 1;
			ভঙ্গ;
		পক্ষ 'd':
			data_dir = optarg;
			ভঙ্গ;
		পক্ষ 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			ভঙ্গ;
		পক্ষ 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			ভঙ্গ;
		স্বভাব:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, রিক্ত, _IONBF, 0);
	যদি (!quiet_mode)
		printf("%s: ", __progname);
	যদি (verbose_mode)
		printf("\n");

	যদি (benchmark)
		benchmarks();
	অন্যথা
		tests();

	যদি (!quiet_mode && !benchmark)
		printf(" %u tests ok\n", test_সংখ্যা);
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
test_is_verbose(শূন্য)
{
	প্রত্যাগম verbose_mode;
}

পূর্ণাঙ্ক
test_is_quiet(শূন্য)
{
	প্রত্যাগম quiet_mode;
}

পূর্ণাঙ্ক
test_is_fast(শূন্য)
{
	প্রত্যাগম fast;
}

পূর্ণাঙ্ক
test_is_slow(শূন্য)
{
	প্রত্যাগম slow;
}

ধ্রুব বর্ণ *
test_data_file(ধ্রুব বর্ণ *name)
{
	স্থির বর্ণ ret[PATH_MAX];

	যদি (data_dir != রিক্ত)
		snprintf(ret, পরিমাণ(ret), "%s/%s", data_dir, name);
	অন্যথা
		strlcpy(ret, name, পরিমাণ(ret));
	যদি (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	প্রত্যাগম ret;
}

শূন্য
test_info(বর্ণ *s, size_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_সংখ্যা,
	    active_test_name == রিক্ত ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

স্থির শূন্য
siginfo(পূর্ণাঙ্ক unused __attribute__((__unused__)))
{
	বর্ণ buf[256];

	test_info(buf, পরিমাণ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

শূন্য
test_start(ধ্রুব বর্ণ *n)
{
	প্রতিজ্ঞা(active_test_name == রিক্ত);
	প্রতিজ্ঞা((active_test_name = strdup(n)) != রিক্ত);
	*subtest_info = '\0';
	যদি (verbose_mode)
		printf("test %u - \"%s\": ", test_সংখ্যা, active_test_name);
	test_সংখ্যা++;
#ifdef SIGINFO
	সঙ্কেত(SIGINFO, siginfo);
#endif
	সঙ্কেত(SIGUSR1, siginfo);
}

শূন্য
set_onerror_func(test_onerror_func_t *f, শূন্য *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

শূন্য
test_done(শূন্য)
{
	*subtest_info = '\0';
	প্রতিজ্ঞা(active_test_name != রিক্ত);
	মুক্ত(active_test_name);
	active_test_name = রিক্ত;
	যদি (verbose_mode)
		printf("OK\n");
	অন্যথা যদি (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

শূন্য
test_subtest_info(ধ্রুব বর্ণ *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, পরিমাণ(subtest_info), fmt, ap);
	va_end(ap);
}

পূর্ণাঙ্ক
test_is_benchmark(শূন্য)
{
	প্রত্যাগম benchmark;
}

শূন্য
ssl_err_check(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	যদি (openssl_error == 0)
		প্রত্যাগম;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, সারি, ERR_error_string(openssl_error, রিক্ত));
#অন্যথা /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, সারি);
#endif /* WITH_OPENSSL */
	abort();
}

স্থির ধ্রুব বর্ণ *
pred_name(গণনা test_predicate p)
{
	বিকল্প (p) {
	পক্ষ TEST_EQ:
		প্রত্যাগম "EQ";
	পক্ষ TEST_NE:
		প্রত্যাগম "NE";
	পক্ষ TEST_LT:
		প্রত্যাগম "LT";
	পক্ষ TEST_LE:
		প্রত্যাগম "LE";
	পক্ষ TEST_GT:
		প্রত্যাগম "GT";
	পক্ষ TEST_GE:
		প্রত্যাগম "GE";
	স্বভাব:
		প্রত্যাগম "UNKNOWN";
	}
}

স্থির শূন্য
test_die(শূন্য)
{
	যদি (test_onerror != রিক্ত)
		test_onerror(onerror_ctx);
	abort();
}

স্থির শূন্য
test_header(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    ধ্রুব বর্ণ *name, গণনা test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, সারি, test_সংখ্যা, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != রিক্ত ? ", " : "", a2 != রিক্ত ? a2 : "");
}

#ifdef WITH_OPENSSL
শূন্য
assert_bignum(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    ধ্রুব BIGNUM *aa1, ধ্রুব BIGNUM *aa2, গণনা test_predicate pred)
{
	পূর্ণাঙ্ক r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, সারি, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

শূন্য
assert_string(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    ধ্রুব বর্ণ *aa1, ধ্রুব বর্ণ *aa2, গণনা test_predicate pred)
{
	পূর্ণাঙ্ক r;

	/* Verify pointers are not NULL */
	assert_ptr(file, সারি, a1, "NULL", aa1, রিক্ত, TEST_NE);
	assert_ptr(file, সারি, a2, "NULL", aa2, রিক্ত, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, সারি, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

শূন্য
assert_mem(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    ধ্রুব শূন্য *aa1, ধ্রুব শূন্য *aa2, size_t l, গণনা test_predicate pred)
{
	পূর্ণাঙ্ক r;
	বর্ণ *aa1_tohex = রিক্ত;
	বর্ণ *aa2_tohex = রিক্ত;

	যদি (l == 0)
		প্রত্যাগম;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, সারি, a1, "NULL", aa1, রিক্ত, TEST_NE);
	assert_ptr(file, সারি, a2, "NULL", aa2, রিক্ত, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, সারি, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	মুক্ত(aa1_tohex);
	মুক্ত(aa2_tohex);
	test_die();
}

স্থির পূর্ণাঙ্ক
memvalcmp(ধ্রুব uint8_t *s, u_char v, size_t l, size_t *where)
{
	size_t i;

	প্রতি (i = 0; i < l; i++) {
		যদি (s[i] != v) {
			*where = i;
			প্রত্যাগম 1;
		}
	}
	প্রত্যাগম 0;
}

শূন্য
assert_mem_filled(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1,
    ধ্রুব শূন্য *aa1, u_char v, size_t l, গণনা test_predicate pred)
{
	size_t where = -1;
	পূর্ণাঙ্ক r;
	বর্ণ tmp[64];
	বর্ণ *aa1_tohex = রিক্ত;

	যদি (l == 0)
		প্রত্যাগম;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, সারি, a1, "NULL", aa1, রিক্ত, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, সারি, a1, রিক্ত, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	মুক্ত(aa1_tohex);
	snprintf(tmp, পরিমাণ(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

শূন্য
assert_int(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    পূর্ণাঙ্ক aa1, পূর্ণাঙ্ক aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

শূন্য
assert_size_t(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    size_t aa1, size_t aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

শূন্য
assert_u_int(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    u_int aa1, u_int aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_long(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    long aa1, long aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_long_long(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    long long aa1, long long aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_char(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    বর্ণ aa1, বর্ণ aa2, গণনা test_predicate pred)
{
	বর্ণ buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

শূন্য
assert_u8(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    uint8_t aa1, uint8_t aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_u16(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    uint16_t aa1, uint16_t aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_u32(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    uint32_t aa1, uint32_t aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_u64(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    uint64_t aa1, uint64_t aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (unsigned long long)aa1, (unsigned long long)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (unsigned long long)aa2, (unsigned long long)aa2);
	test_die();
}

শূন্য
assert_double(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    দ্বিগুণ aa1, দ্বিগুণ aa2, গণনা test_predicate pred)
{
	ধ্রুব দ্বিগুণ epsilon = 0.000000001;

	বিকল্প (pred) {
	পক্ষ TEST_EQ:
		যদি (fabs(aa1 - aa2) < epsilon)
			প্রত্যাগম;
		ভঙ্গ;
	পক্ষ TEST_NE:
		যদি (fabs(aa1 - aa2) >= epsilon)
			প্রত্যাগম;
		ভঙ্গ;
	পক্ষ TEST_LT:
		যদি (aa1 < aa2)
			প্রত্যাগম;
		ভঙ্গ;
	পক্ষ TEST_LE:
		যদি (aa1 <= aa2)
			প্রত্যাগম;
		ভঙ্গ;
	পক্ষ TEST_GT:
		যদি (aa1 > aa2)
			প্রত্যাগম;
		ভঙ্গ;
	পক্ষ TEST_GE:
		যদি (aa1 >= aa2)
			প্রত্যাগম;
		ভঙ্গ;
	স্বভাব:
		abort();
	}

	test_header(file, সারি, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

শূন্য
assert_ptr(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *a1, ধ্রুব বর্ণ *a2,
    ধ্রুব শূন্য *aa1, ধ্রুব শূন্য *aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

স্থির দ্বিগুণ
tstod(ধ্রুব সংরচনা timespec *ts)
{
	প্রত্যাগম (দ্বিগুণ)ts->tv_sec + ((দ্বিগুণ)ts->tv_nsec / 1000000000.0);
}

শূন্য
hex2bin(uint8_t *bin, ধ্রুব বর্ণ *hex, size_t len)
{
	size_t i;
	unsigned পূর্ণাঙ্ক v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	প্রতি (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

শূন্য
bench_start(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *name)
{
	বর্ণ *cp;

	যদি (bench_name != রিক্ত) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, সারি, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != রিক্ত &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	মুক্ত(cp);

	bench_name = name;
	bench_nruns = 0;
	যদি (bench_skip)
		প্রত্যাগম;
	মুক্ত(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(পরিমাণ(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

পূর্ণাঙ্ক
bench_done(শূন্য)
{
	প্রত্যাগম bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

শূন্য
bench_case_start(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

শূন্য
bench_case_finish(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি)
{
	সংরচনা timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	যদি (bench_nruns >= bench_nalloc) {
		যদি (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, পরিমাণ(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

স্থির পূর্ণাঙ্ক
tscmp(ধ্রুব শূন্য *aa, ধ্রুব শূন্য *bb)
{
	ধ্রুব সংরচনা timespec *a = (ধ্রুব সংরচনা timespec *)aa;
	ধ্রুব সংরচনা timespec *b = (ধ্রুব সংরচনা timespec *)bb;

	যদি (timespeccmp(a, b, ==))
		প্রত্যাগম 0;
	প্রত্যাগম timespeccmp(a, b, <) ? -1 : 1;
}

শূন্য
bench_finish(ধ্রুব বর্ণ *file, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *unit)
{
	দ্বিগুণ std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	পূর্ণাঙ্ক i;

	যদি (bench_skip)
		গচ্ছ done;

	যদি (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, সারি,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, পরিমাণ(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	যদি (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (দ্বিগুণ)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? INFINITY : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	প্রতি (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (দ্বিগুণ)bench_nruns;
	std_dev = sqrt(std_dev);
	যদি (benchmark_detail_statistics) {
		printf("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} অন্যথা {
		printf("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = রিক্ত;
	bench_nruns = 0;
	মুক্ত(bench_samples);
	bench_samples = রিক্ত;
	bench_skip = 0;
}
