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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/uio.h>
#ضمن <sys/time.h>

#ضمن <assert.h>
#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <math.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/err.h>
#جے_انت

#إذا defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#جے_انت

#ضمن "entropy.h"
#ضمن "test_helper.h"
#ضمن "atomicio.h"
#ضمن "match.h"
#ضمن "misc.h"
#ضمن "xmalloc.h"

#تعریف_کرو BENCH_FAST_DEADLINE	1
#تعریف_کرو BENCH_عام_DEADLINE	10
#تعریف_کرو BENCH_SLOW_DEADLINE	60
#تعریف_کرو BENCH_SAMPLES_ALLOC	8192
#تعریف_کرو BENCH_کالم_چوڑائی	40

#تعریف_کرو MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#تعریف_کرو TEST_CHECK_INT(r, pred) افعل {		\
		بدل (pred) {			\
		حالة TEST_EQ:			\
			إذا (r == 0)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_NE:			\
			إذا (r != 0)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_LT:			\
			إذا (r < 0)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_LE:			\
			إذا (r <= 0)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_GT:			\
			إذا (r > 0)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_GE:			\
			إذا (r >= 0)		\
				أرجع;		\
			اكسر;			\
		افتراضي:			\
			abort();		\
		}				\
	} طالما (0)

#تعریف_کرو TEST_CHECK(x1, x2, pred) افعل {		\
		بدل (pred) {			\
		حالة TEST_EQ:			\
			إذا (x1 == x2)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_NE:			\
			إذا (x1 != x2)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_LT:			\
			إذا (x1 < x2)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_LE:			\
			إذا (x1 <= x2)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_GT:			\
			إذا (x1 > x2)		\
				أرجع;		\
			اكسر;			\
		حالة TEST_GE:			\
			إذا (x1 >= x2)		\
				أرجع;		\
			اكسر;			\
		افتراضي:			\
			abort();		\
		}				\
	} طالما (0)

خارجي حرف *__progname;

ساكن صحيح verbose_منوال = 0;
ساكن صحيح quiet_منوال = 0;
ساكن حرف *سرگرم_test_name = عدم;
ساكن u_int test_نمبر = 0;
ساكن test_onerror_func_t *test_onerror = عدم;
ساكن فراغ *onerror_ctx = عدم;
ساكن ثابت حرف *انکڑے_dir = عدم;
ساكن حرف subtest_info[512];
ساكن صحيح fast = 0;
ساكن صحيح slow = 0;
ساكن صحيح benchmark_detail_statistics = 0;

ساكن صحيح benchmark = 0;
ساكن ثابت حرف *bench_name = عدم;
ساكن حرف *benchmark_نمونہ = عدم;
ساكن بنية timespec bench_شروع_ویلا, bench_انت_ویلا;
ساكن بنية timespec *bench_samples;
ساكن صحيح bench_skip, bench_nruns, bench_nalloc;
مزدوج bench_accum_secs;

صحيح
مکھ(صحيح argc, حرف **argv)
{
	صحيح ch;

	بیج_rng();
#جے_تعریف_شدہ WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_لدو_CRYPTO_لڑیاں, عدم);
#جے_انت

	/* Handle systems without __progname */
	إذا (__progname == عدم) {
		__progname = strrchr(argv[0], '/');
		إذا (__progname == عدم || __progname[1] == '\0')
			__progname = argv[0];	
		وإلا
			__progname++;
		إذا ((__progname = strdup(__progname)) == عدم) {
			fprintf(stderr, "strdup failed\n");
			باہر_نکلو(1);
		}
	}

	طالما ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		بدل (ch) {
		حالة 'b':
			benchmark = 1;
			اكسر;
		حالة 'B':
			benchmark = benchmark_detail_statistics = 1;
			اكسر;
		حالة 'O':
			benchmark_نمونہ = xstrdup(optarg);
			اكسر;
		حالة 'F':
			slow = 1;
			اكسر;
		حالة 'f':
			fast = 1;
			اكسر;
		حالة 'd':
			انکڑے_dir = optarg;
			اكسر;
		حالة 'q':
			verbose_منوال = 0;
			quiet_منوال = 1;
			اكسر;
		حالة 'v':
			verbose_منوال = 1;
			quiet_منوال = 0;
			اكسر;
		افتراضي:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			باہر_نکلو(1);
		}
	}
	setvbuf(stdout, عدم, _IONBF, 0);
	إذا (!quiet_منوال)
		لکھو("%s: ", __progname);
	إذا (verbose_منوال)
		لکھو("\n");

	إذا (benchmark)
		benchmarks();
	وإلا
		tests();

	إذا (!quiet_منوال && !benchmark)
		لکھو(" %u tests ok\n", test_نمبر);
	أرجع 0;
}

صحيح
test_is_verbose(فراغ)
{
	أرجع verbose_منوال;
}

صحيح
test_is_quiet(فراغ)
{
	أرجع quiet_منوال;
}

صحيح
test_is_fast(فراغ)
{
	أرجع fast;
}

صحيح
test_is_slow(فراغ)
{
	أرجع slow;
}

ثابت حرف *
test_انکڑے_file(ثابت حرف *name)
{
	ساكن حرف ret[PATH_MAX];

	إذا (انکڑے_dir != عدم)
		snprintf(ret, حجم(ret), "%s/%s", انکڑے_dir, name);
	وإلا
		strlcpy(ret, name, حجم(ret));
	إذا (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		باہر_نکلو(1);
	}
	أرجع ret;
}

فراغ
test_info(حرف *s, ناپ_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_نمبر,
	    سرگرم_test_name == عدم ? "<none>" : سرگرم_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

ساكن فراغ
siginfo(صحيح بن_ورتیا __attribute__((__unused__)))
{
	حرف buf[256];

	test_info(buf, حجم(buf));
	atomicio(vwrite, STDERR_FILENO, buf, لڑی_لمبائی(buf));
}

فراغ
test_شروع(ثابت حرف *n)
{
	أكد(سرگرم_test_name == عدم);
	أكد((سرگرم_test_name = strdup(n)) != عدم);
	*subtest_info = '\0';
	إذا (verbose_منوال)
		لکھو("test %u - \"%s\": ", test_نمبر, سرگرم_test_name);
	test_نمبر++;
#جے_تعریف_شدہ SIGINFO
	إشارة(SIGINFO, siginfo);
#جے_انت
	إشارة(SIGUSR1, siginfo);
}

فراغ
سیٹ_onerror_func(test_onerror_func_t *f, فراغ *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

فراغ
test_پورا(فراغ)
{
	*subtest_info = '\0';
	أكد(سرگرم_test_name != عدم);
	حرر(سرگرم_test_name);
	سرگرم_test_name = عدم;
	إذا (verbose_منوال)
		لکھو("OK\n");
	وإلا إذا (!quiet_منوال && !benchmark) {
		لکھو(".");
		fflush(stdout);
	}
}

فراغ
test_subtest_info(ثابت حرف *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, حجم(subtest_info), fmt, ap);
	va_end(ap);
}

صحيح
test_is_benchmark(فراغ)
{
	أرجع benchmark;
}

فراغ
ssl_err_check(ثابت حرف *file, صحيح سطر)
{
#جے_تعریف_شدہ WITH_OPENSSL
	لما openssl_error = ERR_get_error();

	إذا (openssl_error == 0)
		أرجع;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, سطر, ERR_error_string(openssl_error, عدم));
#وإلا /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, سطر);
#جے_انت /* WITH_OPENSSL */
	abort();
}

ساكن ثابت حرف *
pred_name(تعداد test_predicate p)
{
	بدل (p) {
	حالة TEST_EQ:
		أرجع "EQ";
	حالة TEST_NE:
		أرجع "NE";
	حالة TEST_LT:
		أرجع "LT";
	حالة TEST_LE:
		أرجع "LE";
	حالة TEST_GT:
		أرجع "GT";
	حالة TEST_GE:
		أرجع "GE";
	افتراضي:
		أرجع "UNKNOWN";
	}
}

ساكن فراغ
test_die(فراغ)
{
	إذا (test_onerror != عدم)
		test_onerror(onerror_ctx);
	abort();
}

ساكن فراغ
test_سرخی(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت حرف *name, تعداد test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, سطر, test_نمبر, سرگرم_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != عدم ? ", " : "", a2 != عدم ? a2 : "");
}

#جے_تعریف_شدہ WITH_OPENSSL
فراغ
assert_bignum(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت BIGNUM *aa1, ثابت BIGNUM *aa2, تعداد test_predicate pred)
{
	صحيح r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_سرخی(file, سطر, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#جے_انت

فراغ
assert_string(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت حرف *aa1, ثابت حرف *aa2, تعداد test_predicate pred)
{
	صحيح r;

	/* Verify pointers are not NULL */
	assert_ptr(file, سطر, a1, "NULL", aa1, عدم, TEST_NE);
	assert_ptr(file, سطر, a2, "NULL", aa2, عدم, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_سرخی(file, سطر, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, لڑی_لمبائی(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, لڑی_لمبائی(aa2));
	test_die();
}

فراغ
assert_mem(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت فراغ *aa1, ثابت فراغ *aa2, ناپ_t l, تعداد test_predicate pred)
{
	صحيح r;
	حرف *aa1_tohex = عدم;
	حرف *aa2_tohex = عدم;

	إذا (l == 0)
		أرجع;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, سطر, a1, "NULL", aa1, عدم, TEST_NE);
	assert_ptr(file, سطر, a2, "NULL", aa2, عدم, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_سرخی(file, سطر, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	حرر(aa1_tohex);
	حرر(aa2_tohex);
	test_die();
}

ساكن صحيح
memvalcmp(ثابت uint8_t *s, u_char v, ناپ_t l, ناپ_t *where)
{
	ناپ_t i;

	لكل (i = 0; i < l; i++) {
		إذا (s[i] != v) {
			*where = i;
			أرجع 1;
		}
	}
	أرجع 0;
}

فراغ
assert_mem_filled(ثابت حرف *file, صحيح سطر, ثابت حرف *a1,
    ثابت فراغ *aa1, u_char v, ناپ_t l, تعداد test_predicate pred)
{
	ناپ_t where = -1;
	صحيح r;
	حرف tmp[64];
	حرف *aa1_tohex = عدم;

	إذا (l == 0)
		أرجع;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, سطر, a1, "NULL", aa1, عدم, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_سرخی(file, سطر, a1, عدم, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	حرر(aa1_tohex);
	snprintf(tmp, حجم(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

فراغ
assert_int(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    صحيح aa1, صحيح aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

فراغ
assert_ناپ_t(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ناپ_t aa1, ناپ_t aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

فراغ
assert_u_int(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    u_int aa1, u_int aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

فراغ
assert_long(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    لما aa1, لما aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

فراغ
assert_long_long(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    لما لما aa1, لما لما aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

فراغ
assert_char(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    حرف aa1, حرف aa2, تعداد test_predicate pred)
{
	حرف buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_محفوظ|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_محفوظ|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

فراغ
assert_u8(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    uint8_t aa1, uint8_t aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

فراغ
assert_u16(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    uint16_t aa1, uint16_t aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

فراغ
assert_u32(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    uint32_t aa1, uint32_t aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

فراغ
assert_u64(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    uint64_t aa1, uint64_t aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (بنانشانی لما لما)aa1, (بنانشانی لما لما)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (بنانشانی لما لما)aa2, (بنانشانی لما لما)aa2);
	test_die();
}

فراغ
assert_double(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    مزدوج aa1, مزدوج aa2, تعداد test_predicate pred)
{
	ثابت مزدوج epsilon = 0.000000001;

	بدل (pred) {
	حالة TEST_EQ:
		إذا (fabs(aa1 - aa2) < epsilon)
			أرجع;
		اكسر;
	حالة TEST_NE:
		إذا (fabs(aa1 - aa2) >= epsilon)
			أرجع;
		اكسر;
	حالة TEST_LT:
		إذا (aa1 < aa2)
			أرجع;
		اكسر;
	حالة TEST_LE:
		إذا (aa1 <= aa2)
			أرجع;
		اكسر;
	حالة TEST_GT:
		إذا (aa1 > aa2)
			أرجع;
		اكسر;
	حالة TEST_GE:
		إذا (aa1 >= aa2)
			أرجع;
		اكسر;
	افتراضي:
		abort();
	}

	test_سرخی(file, سطر, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

فراغ
assert_ptr(ثابت حرف *file, صحيح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت فراغ *aa1, ثابت فراغ *aa2, تعداد test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

ساكن مزدوج
tstod(ثابت بنية timespec *ts)
{
	أرجع (مزدوج)ts->tv_sec + ((مزدوج)ts->tv_nsec / 1000000000.0);
}

فراغ
hex2bin(uint8_t *bin, ثابت حرف *hex, ناپ_t len)
{
	ناپ_t i;
	بنانشانی صحيح v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	لكل (i = 0; i < len; i++) {
		ASSERT_INT_EQ(لڑی_توں_پڑھو(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

فراغ
bench_شروع(ثابت حرف *file, صحيح سطر, ثابت حرف *name)
{
	حرف *cp;

	إذا (bench_name != عدم) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, سطر, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_نمونہ != عدم &&
	    میل_نمونہ_list(cp, benchmark_نمونہ, 1) != 1;
	حرر(cp);

	bench_name = name;
	bench_nruns = 0;
	إذا (bench_skip)
		أرجع;
	حرر(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(حجم(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

صحيح
bench_پورا(فراغ)
{
	أرجع bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_عام_DEADLINE));
}

فراغ
bench_case_شروع(ثابت حرف *file, صحيح سطر)
{
	clock_gettime(CLOCK_REALTIME, &bench_شروع_ویلا);
}

فراغ
bench_case_انت(ثابت حرف *file, صحيح سطر)
{
	بنية timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_انت_ویلا);
	timespecsub(&bench_انت_ویلا, &bench_شروع_ویلا, &ts);
	إذا (bench_nruns >= bench_nalloc) {
		إذا (bench_nalloc >= ودھ_توں_ودھ_عدد / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, حجم(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

ساكن صحيح
tscmp(ثابت فراغ *aa, ثابت فراغ *bb)
{
	ثابت بنية timespec *a = (ثابت بنية timespec *)aa;
	ثابت بنية timespec *b = (ثابت بنية timespec *)bb;

	إذا (timespeccmp(a, b, ==))
		أرجع 0;
	أرجع timespeccmp(a, b, <) ? -1 : 1;
}

فراغ
bench_انت(ثابت حرف *file, صحيح سطر, ثابت حرف *unit)
{
	مزدوج std_dev = 0, اوسط_spr, اوسط_rps, med_spr, med_rps;
	صحيح i;

	إذا (bench_skip)
		اذهب پورا;

	إذا (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, سطر,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, حجم(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	إذا (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/*اوسط*/
	اوسط_spr = bench_accum_secs / (مزدوج)bench_nruns;
	اوسط_rps = (اوسط_spr == 0.0) ? INFINITY : 1.0/اوسط_spr;
	/* std. dev */
	std_dev = 0;
	لكل (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - اوسط_spr;
		std_dev *= std_dev;
	}
	std_dev /= (مزدوج)bench_nruns;
	std_dev = جذر(std_dev);
	إذا (benchmark_detail_statistics) {
		لکھو("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    اوسط_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    اوسط_rps, med_rps, unit);
	} وإلا {
		لکھو("%-*s %0.2f %s/s\n", BENCH_کالم_چوڑائی,
		    bench_name, med_rps, unit);
	}
 پورا:
	bench_name = عدم;
	bench_nruns = 0;
	حرر(bench_samples);
	bench_samples = عدم;
	bench_skip = 0;
}
