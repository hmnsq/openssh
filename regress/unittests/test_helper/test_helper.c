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

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/err.h>
#اگر_ختم

#اگر defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#اگر_ختم

#شامل "entropy.h"
#شامل "test_helper.h"
#شامل "atomicio.h"
#شامل "match.h"
#شامل "misc.h"
#شامل "xmalloc.h"

#تعریف_کرو BENCH_FAST_DEADLINE	1
#تعریف_کرو BENCH_معمول_DEADLINE	10
#تعریف_کرو BENCH_SLOW_DEADLINE	60
#تعریف_کرو BENCH_SAMPLES_ALLOC	8192
#تعریف_کرو BENCH_عمود_چوڑائی	40

#تعریف_کرو MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#تعریف_کرو TEST_CHECK_INT(r, pred) کرو {		\
		انتخاب (pred) {			\
		حالت TEST_EQ:			\
			اگر (r == 0)		\
				واپس;		\
			توڑو;			\
		حالت TEST_NE:			\
			اگر (r != 0)		\
				واپس;		\
			توڑو;			\
		حالت TEST_LT:			\
			اگر (r < 0)		\
				واپس;		\
			توڑو;			\
		حالت TEST_LE:			\
			اگر (r <= 0)		\
				واپس;		\
			توڑو;			\
		حالت TEST_GT:			\
			اگر (r > 0)		\
				واپس;		\
			توڑو;			\
		حالت TEST_GE:			\
			اگر (r >= 0)		\
				واپس;		\
			توڑو;			\
		طےشدہ:			\
			abort();		\
		}				\
	} جب (0)

#تعریف_کرو TEST_CHECK(x1, x2, pred) کرو {		\
		انتخاب (pred) {			\
		حالت TEST_EQ:			\
			اگر (x1 == x2)		\
				واپس;		\
			توڑو;			\
		حالت TEST_NE:			\
			اگر (x1 != x2)		\
				واپس;		\
			توڑو;			\
		حالت TEST_LT:			\
			اگر (x1 < x2)		\
				واپس;		\
			توڑو;			\
		حالت TEST_LE:			\
			اگر (x1 <= x2)		\
				واپس;		\
			توڑو;			\
		حالت TEST_GT:			\
			اگر (x1 > x2)		\
				واپس;		\
			توڑو;			\
		حالت TEST_GE:			\
			اگر (x1 >= x2)		\
				واپس;		\
			توڑو;			\
		طےشدہ:			\
			abort();		\
		}				\
	} جب (0)

خارجی حرف *__progname;

ساکن صحیح verbose_منوال = 0;
ساکن صحیح quiet_منوال = 0;
ساکن حرف *فعال_test_name = تہی;
ساکن u_int test_نمبر = 0;
ساکن test_onerror_func_t *test_onerror = تہی;
ساکن خالی *onerror_ctx = تہی;
ساکن ثابت حرف *ڈیٹا_dir = تہی;
ساکن حرف subtest_info[512];
ساکن صحیح fast = 0;
ساکن صحیح slow = 0;
ساکن صحیح benchmark_detail_statistics = 0;

ساکن صحیح benchmark = 0;
ساکن ثابت حرف *bench_name = تہی;
ساکن حرف *benchmark_نمونہ = تہی;
ساکن ساخت timespec bench_آغاز_وقت, bench_اختتام_وقت;
ساکن ساخت timespec *bench_samples;
ساکن صحیح bench_skip, bench_nruns, bench_nalloc;
دوہرا bench_accum_secs;

صحیح
مین(صحیح argc, حرف **argv)
{
	صحیح ch;

	بیج_rng();
#اگر_تعریف_شدہ WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_بھرو_CRYPTO_لڑیاں, تہی);
#اگر_ختم

	/* Handle systems without __progname */
	اگر (__progname == تہی) {
		__progname = strrchr(argv[0], '/');
		اگر (__progname == تہی || __progname[1] == '\0')
			__progname = argv[0];	
		ورنہ
			__progname++;
		اگر ((__progname = strdup(__progname)) == تہی) {
			fprintf(stderr, "strdup failed\n");
			باہر_نکلو(1);
		}
	}

	جب ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		انتخاب (ch) {
		حالت 'b':
			benchmark = 1;
			توڑو;
		حالت 'B':
			benchmark = benchmark_detail_statistics = 1;
			توڑو;
		حالت 'O':
			benchmark_نمونہ = xstrdup(optarg);
			توڑو;
		حالت 'F':
			slow = 1;
			توڑو;
		حالت 'f':
			fast = 1;
			توڑو;
		حالت 'd':
			ڈیٹا_dir = optarg;
			توڑو;
		حالت 'q':
			verbose_منوال = 0;
			quiet_منوال = 1;
			توڑو;
		حالت 'v':
			verbose_منوال = 1;
			quiet_منوال = 0;
			توڑو;
		طےشدہ:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			باہر_نکلو(1);
		}
	}
	setvbuf(stdout, تہی, _IONBF, 0);
	اگر (!quiet_منوال)
		لکھو("%s: ", __progname);
	اگر (verbose_منوال)
		لکھو("\n");

	اگر (benchmark)
		benchmarks();
	ورنہ
		tests();

	اگر (!quiet_منوال && !benchmark)
		لکھو(" %u tests ok\n", test_نمبر);
	واپس 0;
}

صحیح
test_is_verbose(خالی)
{
	واپس verbose_منوال;
}

صحیح
test_is_quiet(خالی)
{
	واپس quiet_منوال;
}

صحیح
test_is_fast(خالی)
{
	واپس fast;
}

صحیح
test_is_slow(خالی)
{
	واپس slow;
}

ثابت حرف *
test_ڈیٹا_file(ثابت حرف *name)
{
	ساکن حرف ret[PATH_MAX];

	اگر (ڈیٹا_dir != تہی)
		snprintf(ret, حجم(ret), "%s/%s", ڈیٹا_dir, name);
	ورنہ
		strlcpy(ret, name, حجم(ret));
	اگر (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		باہر_نکلو(1);
	}
	واپس ret;
}

خالی
test_info(حرف *s, سائز_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_نمبر,
	    فعال_test_name == تہی ? "<none>" : فعال_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

ساکن خالی
siginfo(صحیح غیر_مستعمل __attribute__((__unused__)))
{
	حرف buf[256];

	test_info(buf, حجم(buf));
	atomicio(vwrite, STDERR_FILENO, buf, لڑی_لمبائی(buf));
}

خالی
test_آغاز(ثابت حرف *n)
{
	أكد(فعال_test_name == تہی);
	أكد((فعال_test_name = strdup(n)) != تہی);
	*subtest_info = '\0';
	اگر (verbose_منوال)
		لکھو("test %u - \"%s\": ", test_نمبر, فعال_test_name);
	test_نمبر++;
#اگر_تعریف_شدہ SIGINFO
	اشارہ(SIGINFO, siginfo);
#اگر_ختم
	اشارہ(SIGUSR1, siginfo);
}

خالی
سیٹ_onerror_func(test_onerror_func_t *f, خالی *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

خالی
test_مکمل(خالی)
{
	*subtest_info = '\0';
	أكد(فعال_test_name != تہی);
	آزاد(فعال_test_name);
	فعال_test_name = تہی;
	اگر (verbose_منوال)
		لکھو("OK\n");
	ورنہ اگر (!quiet_منوال && !benchmark) {
		لکھو(".");
		fflush(stdout);
	}
}

خالی
test_subtest_info(ثابت حرف *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, حجم(subtest_info), fmt, ap);
	va_end(ap);
}

صحیح
test_is_benchmark(خالی)
{
	واپس benchmark;
}

خالی
ssl_err_check(ثابت حرف *file, صحیح سطر)
{
#اگر_تعریف_شدہ WITH_OPENSSL
	طویل openssl_error = ERR_get_error();

	اگر (openssl_error == 0)
		واپس;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, سطر, ERR_error_string(openssl_error, تہی));
#ورنہ /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, سطر);
#اگر_ختم /* WITH_OPENSSL */
	abort();
}

ساکن ثابت حرف *
pred_name(شمار test_predicate p)
{
	انتخاب (p) {
	حالت TEST_EQ:
		واپس "EQ";
	حالت TEST_NE:
		واپس "NE";
	حالت TEST_LT:
		واپس "LT";
	حالت TEST_LE:
		واپس "LE";
	حالت TEST_GT:
		واپس "GT";
	حالت TEST_GE:
		واپس "GE";
	طےشدہ:
		واپس "UNKNOWN";
	}
}

ساکن خالی
test_die(خالی)
{
	اگر (test_onerror != تہی)
		test_onerror(onerror_ctx);
	abort();
}

ساکن خالی
test_سرخی(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت حرف *name, شمار test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, سطر, test_نمبر, فعال_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != تہی ? ", " : "", a2 != تہی ? a2 : "");
}

#اگر_تعریف_شدہ WITH_OPENSSL
خالی
assert_bignum(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت BIGNUM *aa1, ثابت BIGNUM *aa2, شمار test_predicate pred)
{
	صحیح r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_سرخی(file, سطر, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#اگر_ختم

خالی
assert_string(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت حرف *aa1, ثابت حرف *aa2, شمار test_predicate pred)
{
	صحیح r;

	/* Verify pointers are not NULL */
	assert_ptr(file, سطر, a1, "NULL", aa1, تہی, TEST_NE);
	assert_ptr(file, سطر, a2, "NULL", aa2, تہی, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_سرخی(file, سطر, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, لڑی_لمبائی(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, لڑی_لمبائی(aa2));
	test_die();
}

خالی
assert_mem(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت خالی *aa1, ثابت خالی *aa2, سائز_t l, شمار test_predicate pred)
{
	صحیح r;
	حرف *aa1_tohex = تہی;
	حرف *aa2_tohex = تہی;

	اگر (l == 0)
		واپس;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, سطر, a1, "NULL", aa1, تہی, TEST_NE);
	assert_ptr(file, سطر, a2, "NULL", aa2, تہی, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_سرخی(file, سطر, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	آزاد(aa1_tohex);
	آزاد(aa2_tohex);
	test_die();
}

ساکن صحیح
memvalcmp(ثابت uint8_t *s, u_char v, سائز_t l, سائز_t *where)
{
	سائز_t i;

	برائے (i = 0; i < l; i++) {
		اگر (s[i] != v) {
			*where = i;
			واپس 1;
		}
	}
	واپس 0;
}

خالی
assert_mem_filled(ثابت حرف *file, صحیح سطر, ثابت حرف *a1,
    ثابت خالی *aa1, u_char v, سائز_t l, شمار test_predicate pred)
{
	سائز_t where = -1;
	صحیح r;
	حرف tmp[64];
	حرف *aa1_tohex = تہی;

	اگر (l == 0)
		واپس;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, سطر, a1, "NULL", aa1, تہی, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_سرخی(file, سطر, a1, تہی, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	آزاد(aa1_tohex);
	snprintf(tmp, حجم(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

خالی
assert_int(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    صحیح aa1, صحیح aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

خالی
assert_سائز_t(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    سائز_t aa1, سائز_t aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

خالی
assert_u_int(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    u_int aa1, u_int aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

خالی
assert_long(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    طویل aa1, طویل aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

خالی
assert_long_long(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    طویل طویل aa1, طویل طویل aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

خالی
assert_char(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    حرف aa1, حرف aa2, شمار test_predicate pred)
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

خالی
assert_u8(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    uint8_t aa1, uint8_t aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

خالی
assert_u16(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    uint16_t aa1, uint16_t aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

خالی
assert_u32(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    uint32_t aa1, uint32_t aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

خالی
assert_u64(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    uint64_t aa1, uint64_t aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (غیرعلامتی طویل طویل)aa1, (غیرعلامتی طویل طویل)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (غیرعلامتی طویل طویل)aa2, (غیرعلامتی طویل طویل)aa2);
	test_die();
}

خالی
assert_double(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    دوہرا aa1, دوہرا aa2, شمار test_predicate pred)
{
	ثابت دوہرا epsilon = 0.000000001;

	انتخاب (pred) {
	حالت TEST_EQ:
		اگر (fabs(aa1 - aa2) < epsilon)
			واپس;
		توڑو;
	حالت TEST_NE:
		اگر (fabs(aa1 - aa2) >= epsilon)
			واپس;
		توڑو;
	حالت TEST_LT:
		اگر (aa1 < aa2)
			واپس;
		توڑو;
	حالت TEST_LE:
		اگر (aa1 <= aa2)
			واپس;
		توڑو;
	حالت TEST_GT:
		اگر (aa1 > aa2)
			واپس;
		توڑو;
	حالت TEST_GE:
		اگر (aa1 >= aa2)
			واپس;
		توڑو;
	طےشدہ:
		abort();
	}

	test_سرخی(file, سطر, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

خالی
assert_ptr(ثابت حرف *file, صحیح سطر, ثابت حرف *a1, ثابت حرف *a2,
    ثابت خالی *aa1, ثابت خالی *aa2, شمار test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_سرخی(file, سطر, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

ساکن دوہرا
tstod(ثابت ساخت timespec *ts)
{
	واپس (دوہرا)ts->tv_sec + ((دوہرا)ts->tv_nsec / 1000000000.0);
}

خالی
hex2bin(uint8_t *bin, ثابت حرف *hex, سائز_t len)
{
	سائز_t i;
	غیرعلامتی صحیح v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	برائے (i = 0; i < len; i++) {
		ASSERT_INT_EQ(لڑی_سے_پڑھو(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

خالی
bench_آغاز(ثابت حرف *file, صحیح سطر, ثابت حرف *name)
{
	حرف *cp;

	اگر (bench_name != تہی) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, سطر, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_نمونہ != تہی &&
	    مطابقت_نمونہ_list(cp, benchmark_نمونہ, 1) != 1;
	آزاد(cp);

	bench_name = name;
	bench_nruns = 0;
	اگر (bench_skip)
		واپس;
	آزاد(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(حجم(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

صحیح
bench_مکمل(خالی)
{
	واپس bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_معمول_DEADLINE));
}

خالی
bench_case_آغاز(ثابت حرف *file, صحیح سطر)
{
	clock_gettime(CLOCK_REALTIME, &bench_آغاز_وقت);
}

خالی
bench_case_اختتام(ثابت حرف *file, صحیح سطر)
{
	ساخت timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_اختتام_وقت);
	timespecsub(&bench_اختتام_وقت, &bench_آغاز_وقت, &ts);
	اگر (bench_nruns >= bench_nalloc) {
		اگر (bench_nalloc >= زیادہ_سے_زیادہ_عدد / 2) {
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

ساکن صحیح
tscmp(ثابت خالی *aa, ثابت خالی *bb)
{
	ثابت ساخت timespec *a = (ثابت ساخت timespec *)aa;
	ثابت ساخت timespec *b = (ثابت ساخت timespec *)bb;

	اگر (timespeccmp(a, b, ==))
		واپس 0;
	واپس timespeccmp(a, b, <) ? -1 : 1;
}

خالی
bench_اختتام(ثابت حرف *file, صحیح سطر, ثابت حرف *unit)
{
	دوہرا std_dev = 0, اوسط_spr, اوسط_rps, med_spr, med_rps;
	صحیح i;

	اگر (bench_skip)
		جاؤ مکمل;

	اگر (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, سطر,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, حجم(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	اگر (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/*اوسط*/
	اوسط_spr = bench_accum_secs / (دوہرا)bench_nruns;
	اوسط_rps = (اوسط_spr == 0.0) ? INFINITY : 1.0/اوسط_spr;
	/* std. dev */
	std_dev = 0;
	برائے (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - اوسط_spr;
		std_dev *= std_dev;
	}
	std_dev /= (دوہرا)bench_nruns;
	std_dev = جذر(std_dev);
	اگر (benchmark_detail_statistics) {
		لکھو("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    اوسط_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    اوسط_rps, med_rps, unit);
	} ورنہ {
		لکھو("%-*s %0.2f %s/s\n", BENCH_عمود_چوڑائی,
		    bench_name, med_rps, unit);
	}
 مکمل:
	bench_name = تہی;
	bench_nruns = 0;
	آزاد(bench_samples);
	bench_samples = تہی;
	bench_skip = 0;
}
