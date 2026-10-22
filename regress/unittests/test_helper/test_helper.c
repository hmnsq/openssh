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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/uio.h>
#شامل <sys/time.h>

#شامل <assert.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <math.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/err.h>
#endif

#اگر defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#شامل "entropy.h"
#شامل "test_helper.h"
#شامل "atomicio.h"
#شامل "match.h"
#شامل "misc.h"
#شامل "xmalloc.h"

#define BENCH_FAST_DEADLINE	1
#define BENCH_NORMAL_DEADLINE	10
#define BENCH_SLOW_DEADLINE	60
#define BENCH_SAMPLES_ALLOC	8192
#define BENCH_COLUMN_WIDTH	40

#define MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#define TEST_CHECK_INT(r, pred) انجامبده {		\
		انتخاب (pred) {			\
		حالت TEST_EQ:			\
			اگر (r == 0)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_NE:			\
			اگر (r != 0)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_LT:			\
			اگر (r < 0)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_LE:			\
			اگر (r <= 0)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_GT:			\
			اگر (r > 0)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_GE:			\
			اگر (r >= 0)		\
				بازگشت;		\
			بشکن;			\
		پیشفرض:			\
			abort();		\
		}				\
	} وقتی (0)

#define TEST_CHECK(x1, x2, pred) انجامبده {		\
		انتخاب (pred) {			\
		حالت TEST_EQ:			\
			اگر (x1 == x2)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_NE:			\
			اگر (x1 != x2)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_LT:			\
			اگر (x1 < x2)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_LE:			\
			اگر (x1 <= x2)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_GT:			\
			اگر (x1 > x2)		\
				بازگشت;		\
			بشکن;			\
		حالت TEST_GE:			\
			اگر (x1 >= x2)		\
				بازگشت;		\
			بشکن;			\
		پیشفرض:			\
			abort();		\
		}				\
	} وقتی (0)

بیرونی نویسه *__progname;

ایستا صحیح verbose_mode = 0;
ایستا صحیح quiet_mode = 0;
ایستا نویسه *active_test_name = پوچ;
ایستا u_int test_عدد = 0;
ایستا test_onerror_func_t *test_onerror = پوچ;
ایستا تهی *onerror_ctx = پوچ;
ایستا ثابت نویسه *data_dir = پوچ;
ایستا نویسه subtest_info[512];
ایستا صحیح fast = 0;
ایستا صحیح slow = 0;
ایستا صحیح benchmark_detail_statistics = 0;

ایستا صحیح benchmark = 0;
ایستا ثابت نویسه *bench_name = پوچ;
ایستا نویسه *benchmark_pattern = پوچ;
ایستا ساختار timespec bench_start_time, bench_finish_time;
ایستا ساختار timespec *bench_samples;
ایستا صحیح bench_skip, bench_nruns, bench_nalloc;
دوگانه bench_accum_secs;

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	صحیح ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, پوچ);
#endif

	/* Handle systems without __progname */
	اگر (__progname == پوچ) {
		__progname = strrchr(argv[0], '/');
		اگر (__progname == پوچ || __progname[1] == '\0')
			__progname = argv[0];	
		وگرنه
			__progname++;
		اگر ((__progname = strdup(__progname)) == پوچ) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	وقتی ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		انتخاب (ch) {
		حالت 'b':
			benchmark = 1;
			بشکن;
		حالت 'B':
			benchmark = benchmark_detail_statistics = 1;
			بشکن;
		حالت 'O':
			benchmark_pattern = xstrdup(optarg);
			بشکن;
		حالت 'F':
			slow = 1;
			بشکن;
		حالت 'f':
			fast = 1;
			بشکن;
		حالت 'd':
			data_dir = optarg;
			بشکن;
		حالت 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			بشکن;
		حالت 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			بشکن;
		پیشفرض:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, پوچ, _IONBF, 0);
	اگر (!quiet_mode)
		printf("%s: ", __progname);
	اگر (verbose_mode)
		printf("\n");

	اگر (benchmark)
		benchmarks();
	وگرنه
		tests();

	اگر (!quiet_mode && !benchmark)
		printf(" %u tests ok\n", test_عدد);
	بازگشت 0;
}

صحیح
test_is_verbose(تهی)
{
	بازگشت verbose_mode;
}

صحیح
test_is_quiet(تهی)
{
	بازگشت quiet_mode;
}

صحیح
test_is_fast(تهی)
{
	بازگشت fast;
}

صحیح
test_is_slow(تهی)
{
	بازگشت slow;
}

ثابت نویسه *
test_data_file(ثابت نویسه *name)
{
	ایستا نویسه ret[PATH_MAX];

	اگر (data_dir != پوچ)
		snprintf(ret, اندازه(ret), "%s/%s", data_dir, name);
	وگرنه
		strlcpy(ret, name, اندازه(ret));
	اگر (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	بازگشت ret;
}

تهی
test_info(نویسه *s, size_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_عدد,
	    active_test_name == پوچ ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

ایستا تهی
siginfo(صحیح unused __attribute__((__unused__)))
{
	نویسه buf[256];

	test_info(buf, اندازه(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

تهی
test_start(ثابت نویسه *n)
{
	أكد(active_test_name == پوچ);
	أكد((active_test_name = strdup(n)) != پوچ);
	*subtest_info = '\0';
	اگر (verbose_mode)
		printf("test %u - \"%s\": ", test_عدد, active_test_name);
	test_عدد++;
#ifdef SIGINFO
	سیگنال(SIGINFO, siginfo);
#endif
	سیگنال(SIGUSR1, siginfo);
}

تهی
set_onerror_func(test_onerror_func_t *f, تهی *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

تهی
test_done(تهی)
{
	*subtest_info = '\0';
	أكد(active_test_name != پوچ);
	آزاد(active_test_name);
	active_test_name = پوچ;
	اگر (verbose_mode)
		printf("OK\n");
	وگرنه اگر (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

تهی
test_subtest_info(ثابت نویسه *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, اندازه(subtest_info), fmt, ap);
	va_end(ap);
}

صحیح
test_is_benchmark(تهی)
{
	بازگشت benchmark;
}

تهی
ssl_err_check(ثابت نویسه *file, صحیح سطر)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	اگر (openssl_error == 0)
		بازگشت;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, سطر, ERR_error_string(openssl_error, پوچ));
#وگرنه /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, سطر);
#endif /* WITH_OPENSSL */
	abort();
}

ایستا ثابت نویسه *
pred_name(شمارش test_predicate p)
{
	انتخاب (p) {
	حالت TEST_EQ:
		بازگشت "EQ";
	حالت TEST_NE:
		بازگشت "NE";
	حالت TEST_LT:
		بازگشت "LT";
	حالت TEST_LE:
		بازگشت "LE";
	حالت TEST_GT:
		بازگشت "GT";
	حالت TEST_GE:
		بازگشت "GE";
	پیشفرض:
		بازگشت "UNKNOWN";
	}
}

ایستا تهی
test_die(تهی)
{
	اگر (test_onerror != پوچ)
		test_onerror(onerror_ctx);
	abort();
}

ایستا تهی
test_header(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    ثابت نویسه *name, شمارش test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, سطر, test_عدد, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != پوچ ? ", " : "", a2 != پوچ ? a2 : "");
}

#ifdef WITH_OPENSSL
تهی
assert_bignum(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    ثابت BIGNUM *aa1, ثابت BIGNUM *aa2, شمارش test_predicate pred)
{
	صحیح r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, سطر, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

تهی
assert_string(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    ثابت نویسه *aa1, ثابت نویسه *aa2, شمارش test_predicate pred)
{
	صحیح r;

	/* Verify pointers are not NULL */
	assert_ptr(file, سطر, a1, "NULL", aa1, پوچ, TEST_NE);
	assert_ptr(file, سطر, a2, "NULL", aa2, پوچ, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, سطر, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

تهی
assert_mem(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    ثابت تهی *aa1, ثابت تهی *aa2, size_t l, شمارش test_predicate pred)
{
	صحیح r;
	نویسه *aa1_tohex = پوچ;
	نویسه *aa2_tohex = پوچ;

	اگر (l == 0)
		بازگشت;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, سطر, a1, "NULL", aa1, پوچ, TEST_NE);
	assert_ptr(file, سطر, a2, "NULL", aa2, پوچ, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, سطر, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	آزاد(aa1_tohex);
	آزاد(aa2_tohex);
	test_die();
}

ایستا صحیح
memvalcmp(ثابت uint8_t *s, u_char v, size_t l, size_t *where)
{
	size_t i;

	برای (i = 0; i < l; i++) {
		اگر (s[i] != v) {
			*where = i;
			بازگشت 1;
		}
	}
	بازگشت 0;
}

تهی
assert_mem_filled(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1,
    ثابت تهی *aa1, u_char v, size_t l, شمارش test_predicate pred)
{
	size_t where = -1;
	صحیح r;
	نویسه tmp[64];
	نویسه *aa1_tohex = پوچ;

	اگر (l == 0)
		بازگشت;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, سطر, a1, "NULL", aa1, پوچ, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, سطر, a1, پوچ, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	آزاد(aa1_tohex);
	snprintf(tmp, اندازه(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

تهی
assert_int(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    صحیح aa1, صحیح aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

تهی
assert_size_t(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    size_t aa1, size_t aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

تهی
assert_u_int(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    u_int aa1, u_int aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

تهی
assert_long(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    long aa1, long aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

تهی
assert_long_long(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    long long aa1, long long aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

تهی
assert_char(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    نویسه aa1, نویسه aa2, شمارش test_predicate pred)
{
	نویسه buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

تهی
assert_u8(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    uint8_t aa1, uint8_t aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

تهی
assert_u16(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    uint16_t aa1, uint16_t aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

تهی
assert_u32(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    uint32_t aa1, uint32_t aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

تهی
assert_u64(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    uint64_t aa1, uint64_t aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (unsigned long long)aa1, (unsigned long long)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (unsigned long long)aa2, (unsigned long long)aa2);
	test_die();
}

تهی
assert_double(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    دوگانه aa1, دوگانه aa2, شمارش test_predicate pred)
{
	ثابت دوگانه epsilon = 0.000000001;

	انتخاب (pred) {
	حالت TEST_EQ:
		اگر (fabs(aa1 - aa2) < epsilon)
			بازگشت;
		بشکن;
	حالت TEST_NE:
		اگر (fabs(aa1 - aa2) >= epsilon)
			بازگشت;
		بشکن;
	حالت TEST_LT:
		اگر (aa1 < aa2)
			بازگشت;
		بشکن;
	حالت TEST_LE:
		اگر (aa1 <= aa2)
			بازگشت;
		بشکن;
	حالت TEST_GT:
		اگر (aa1 > aa2)
			بازگشت;
		بشکن;
	حالت TEST_GE:
		اگر (aa1 >= aa2)
			بازگشت;
		بشکن;
	پیشفرض:
		abort();
	}

	test_header(file, سطر, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

تهی
assert_ptr(ثابت نویسه *file, صحیح سطر, ثابت نویسه *a1, ثابت نویسه *a2,
    ثابت تهی *aa1, ثابت تهی *aa2, شمارش test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, سطر, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

ایستا دوگانه
tstod(ثابت ساختار timespec *ts)
{
	بازگشت (دوگانه)ts->tv_sec + ((دوگانه)ts->tv_nsec / 1000000000.0);
}

تهی
hex2bin(uint8_t *bin, ثابت نویسه *hex, size_t len)
{
	size_t i;
	unsigned صحیح v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	برای (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

تهی
bench_start(ثابت نویسه *file, صحیح سطر, ثابت نویسه *name)
{
	نویسه *cp;

	اگر (bench_name != پوچ) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, سطر, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != پوچ &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	آزاد(cp);

	bench_name = name;
	bench_nruns = 0;
	اگر (bench_skip)
		بازگشت;
	آزاد(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(اندازه(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

صحیح
bench_done(تهی)
{
	بازگشت bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

تهی
bench_case_start(ثابت نویسه *file, صحیح سطر)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

تهی
bench_case_finish(ثابت نویسه *file, صحیح سطر)
{
	ساختار timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	اگر (bench_nruns >= bench_nalloc) {
		اگر (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, اندازه(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

ایستا صحیح
tscmp(ثابت تهی *aa, ثابت تهی *bb)
{
	ثابت ساختار timespec *a = (ثابت ساختار timespec *)aa;
	ثابت ساختار timespec *b = (ثابت ساختار timespec *)bb;

	اگر (timespeccmp(a, b, ==))
		بازگشت 0;
	بازگشت timespeccmp(a, b, <) ? -1 : 1;
}

تهی
bench_finish(ثابت نویسه *file, صحیح سطر, ثابت نویسه *unit)
{
	دوگانه std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	صحیح i;

	اگر (bench_skip)
		برو done;

	اگر (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, سطر,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, اندازه(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	اگر (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (دوگانه)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? INFINITY : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	برای (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (دوگانه)bench_nruns;
	std_dev = sqrt(std_dev);
	اگر (benchmark_detail_statistics) {
		printf("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} وگرنه {
		printf("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = پوچ;
	bench_nruns = 0;
	آزاد(bench_samples);
	bench_samples = پوچ;
	bench_skip = 0;
}
