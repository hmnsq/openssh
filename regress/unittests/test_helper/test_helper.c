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

#define TEST_CHECK_INT(r, pred) করো {		\
		নির্বাচন (pred) {			\
		ক্ষেত্র TEST_EQ:			\
			যদি (r == 0)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_NE:			\
			যদি (r != 0)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_LT:			\
			যদি (r < 0)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_LE:			\
			যদি (r <= 0)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_GT:			\
			যদি (r > 0)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_GE:			\
			যদি (r >= 0)		\
				ফেরত;		\
			বিরতি;			\
		পূর্বনির্ধারিত:			\
			abort();		\
		}				\
	} যখন (0)

#define TEST_CHECK(x1, x2, pred) করো {		\
		নির্বাচন (pred) {			\
		ক্ষেত্র TEST_EQ:			\
			যদি (x1 == x2)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_NE:			\
			যদি (x1 != x2)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_LT:			\
			যদি (x1 < x2)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_LE:			\
			যদি (x1 <= x2)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_GT:			\
			যদি (x1 > x2)		\
				ফেরত;		\
			বিরতি;			\
		ক্ষেত্র TEST_GE:			\
			যদি (x1 >= x2)		\
				ফেরত;		\
			বিরতি;			\
		পূর্বনির্ধারিত:			\
			abort();		\
		}				\
	} যখন (0)

বাহ্যিক অক্ষর *__progname;

স্থির পূর্ণসংখ্যা verbose_mode = 0;
স্থির পূর্ণসংখ্যা quiet_mode = 0;
স্থির অক্ষর *active_test_name = ফাঁকা;
স্থির u_int test_সংখ্যা = 0;
স্থির test_onerror_func_t *test_onerror = ফাঁকা;
স্থির শূন্য *onerror_ctx = ফাঁকা;
স্থির ধ্রুবক অক্ষর *তথ্য_dir = ফাঁকা;
স্থির অক্ষর subtest_info[512];
স্থির পূর্ণসংখ্যা fast = 0;
স্থির পূর্ণসংখ্যা slow = 0;
স্থির পূর্ণসংখ্যা benchmark_detail_statistics = 0;

স্থির পূর্ণসংখ্যা benchmark = 0;
স্থির ধ্রুবক অক্ষর *bench_name = ফাঁকা;
স্থির অক্ষর *benchmark_pattern = ফাঁকা;
স্থির কাঠামো timespec bench_start_time, bench_finish_time;
স্থির কাঠামো timespec *bench_samples;
স্থির পূর্ণসংখ্যা bench_skip, bench_nruns, bench_nalloc;
দ্বিগুণ bench_accum_secs;

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	পূর্ণসংখ্যা ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ফাঁকা);
#endif

	/* Handle systems without __progname */
	যদি (__progname == ফাঁকা) {
		__progname = strrchr(argv[0], '/');
		যদি (__progname == ফাঁকা || __progname[1] == '\0')
			__progname = argv[0];	
		অন্যথা
			__progname++;
		যদি ((__progname = strdup(__progname)) == ফাঁকা) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	যখন ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'b':
			benchmark = 1;
			বিরতি;
		ক্ষেত্র 'B':
			benchmark = benchmark_detail_statistics = 1;
			বিরতি;
		ক্ষেত্র 'O':
			benchmark_pattern = xstrdup(optarg);
			বিরতি;
		ক্ষেত্র 'F':
			slow = 1;
			বিরতি;
		ক্ষেত্র 'f':
			fast = 1;
			বিরতি;
		ক্ষেত্র 'd':
			তথ্য_dir = optarg;
			বিরতি;
		ক্ষেত্র 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			বিরতি;
		ক্ষেত্র 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			বিরতি;
		পূর্বনির্ধারিত:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, ফাঁকা, _IONBF, 0);
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
	ফেরত 0;
}

পূর্ণসংখ্যা
test_is_verbose(শূন্য)
{
	ফেরত verbose_mode;
}

পূর্ণসংখ্যা
test_is_quiet(শূন্য)
{
	ফেরত quiet_mode;
}

পূর্ণসংখ্যা
test_is_fast(শূন্য)
{
	ফেরত fast;
}

পূর্ণসংখ্যা
test_is_slow(শূন্য)
{
	ফেরত slow;
}

ধ্রুবক অক্ষর *
test_তথ্য_file(ধ্রুবক অক্ষর *name)
{
	স্থির অক্ষর ret[PATH_MAX];

	যদি (তথ্য_dir != ফাঁকা)
		snprintf(ret, আকার(ret), "%s/%s", তথ্য_dir, name);
	অন্যথা
		strlcpy(ret, name, আকার(ret));
	যদি (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	ফেরত ret;
}

শূন্য
test_info(অক্ষর *s, আকার_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_সংখ্যা,
	    active_test_name == ফাঁকা ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

স্থির শূন্য
siginfo(পূর্ণসংখ্যা unused __attribute__((__unused__)))
{
	অক্ষর buf[256];

	test_info(buf, আকার(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

শূন্য
test_start(ধ্রুবক অক্ষর *n)
{
	প্রতিজ্ঞা(active_test_name == ফাঁকা);
	প্রতিজ্ঞা((active_test_name = strdup(n)) != ফাঁকা);
	*subtest_info = '\0';
	যদি (verbose_mode)
		printf("test %u - \"%s\": ", test_সংখ্যা, active_test_name);
	test_সংখ্যা++;
#ifdef SIGINFO
	সংকেত(SIGINFO, siginfo);
#endif
	সংকেত(SIGUSR1, siginfo);
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
	প্রতিজ্ঞা(active_test_name != ফাঁকা);
	মুক্ত(active_test_name);
	active_test_name = ফাঁকা;
	যদি (verbose_mode)
		printf("OK\n");
	অন্যথা যদি (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

শূন্য
test_subtest_info(ধ্রুবক অক্ষর *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, আকার(subtest_info), fmt, ap);
	va_end(ap);
}

পূর্ণসংখ্যা
test_is_benchmark(শূন্য)
{
	ফেরত benchmark;
}

শূন্য
ssl_err_check(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	যদি (openssl_error == 0)
		ফেরত;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, সারি, ERR_error_string(openssl_error, ফাঁকা));
#অন্যথা /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, সারি);
#endif /* WITH_OPENSSL */
	abort();
}

স্থির ধ্রুবক অক্ষর *
pred_name(গণনা test_predicate p)
{
	নির্বাচন (p) {
	ক্ষেত্র TEST_EQ:
		ফেরত "EQ";
	ক্ষেত্র TEST_NE:
		ফেরত "NE";
	ক্ষেত্র TEST_LT:
		ফেরত "LT";
	ক্ষেত্র TEST_LE:
		ফেরত "LE";
	ক্ষেত্র TEST_GT:
		ফেরত "GT";
	ক্ষেত্র TEST_GE:
		ফেরত "GE";
	পূর্বনির্ধারিত:
		ফেরত "UNKNOWN";
	}
}

স্থির শূন্য
test_die(শূন্য)
{
	যদি (test_onerror != ফাঁকা)
		test_onerror(onerror_ctx);
	abort();
}

স্থির শূন্য
test_header(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    ধ্রুবক অক্ষর *name, গণনা test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, সারি, test_সংখ্যা, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != ফাঁকা ? ", " : "", a2 != ফাঁকা ? a2 : "");
}

#ifdef WITH_OPENSSL
শূন্য
assert_bignum(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    ধ্রুবক BIGNUM *aa1, ধ্রুবক BIGNUM *aa2, গণনা test_predicate pred)
{
	পূর্ণসংখ্যা r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, সারি, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

শূন্য
assert_string(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    ধ্রুবক অক্ষর *aa1, ধ্রুবক অক্ষর *aa2, গণনা test_predicate pred)
{
	পূর্ণসংখ্যা r;

	/* Verify pointers are not NULL */
	assert_ptr(file, সারি, a1, "NULL", aa1, ফাঁকা, TEST_NE);
	assert_ptr(file, সারি, a2, "NULL", aa2, ফাঁকা, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, সারি, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

শূন্য
assert_mem(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    ধ্রুবক শূন্য *aa1, ধ্রুবক শূন্য *aa2, আকার_t l, গণনা test_predicate pred)
{
	পূর্ণসংখ্যা r;
	অক্ষর *aa1_tohex = ফাঁকা;
	অক্ষর *aa2_tohex = ফাঁকা;

	যদি (l == 0)
		ফেরত;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, সারি, a1, "NULL", aa1, ফাঁকা, TEST_NE);
	assert_ptr(file, সারি, a2, "NULL", aa2, ফাঁকা, TEST_NE);

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

স্থির পূর্ণসংখ্যা
memvalcmp(ধ্রুবক uint8_t *s, u_char v, আকার_t l, আকার_t *where)
{
	আকার_t i;

	জন্য (i = 0; i < l; i++) {
		যদি (s[i] != v) {
			*where = i;
			ফেরত 1;
		}
	}
	ফেরত 0;
}

শূন্য
assert_mem_filled(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1,
    ধ্রুবক শূন্য *aa1, u_char v, আকার_t l, গণনা test_predicate pred)
{
	আকার_t where = -1;
	পূর্ণসংখ্যা r;
	অক্ষর tmp[64];
	অক্ষর *aa1_tohex = ফাঁকা;

	যদি (l == 0)
		ফেরত;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, সারি, a1, "NULL", aa1, ফাঁকা, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, সারি, a1, ফাঁকা, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	মুক্ত(aa1_tohex);
	snprintf(tmp, আকার(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

শূন্য
assert_int(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    পূর্ণসংখ্যা aa1, পূর্ণসংখ্যা aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

শূন্য
assert_আকার_t(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    আকার_t aa1, আকার_t aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

শূন্য
assert_u_int(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    u_int aa1, u_int aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_long(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    long aa1, long aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_long_long(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    long long aa1, long long aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_char(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    অক্ষর aa1, অক্ষর aa2, গণনা test_predicate pred)
{
	অক্ষর buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

শূন্য
assert_u8(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    uint8_t aa1, uint8_t aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_u16(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    uint16_t aa1, uint16_t aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_u32(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    uint32_t aa1, uint32_t aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

শূন্য
assert_u64(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
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
assert_double(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    দ্বিগুণ aa1, দ্বিগুণ aa2, গণনা test_predicate pred)
{
	ধ্রুবক দ্বিগুণ epsilon = 0.000000001;

	নির্বাচন (pred) {
	ক্ষেত্র TEST_EQ:
		যদি (fabs(aa1 - aa2) < epsilon)
			ফেরত;
		বিরতি;
	ক্ষেত্র TEST_NE:
		যদি (fabs(aa1 - aa2) >= epsilon)
			ফেরত;
		বিরতি;
	ক্ষেত্র TEST_LT:
		যদি (aa1 < aa2)
			ফেরত;
		বিরতি;
	ক্ষেত্র TEST_LE:
		যদি (aa1 <= aa2)
			ফেরত;
		বিরতি;
	ক্ষেত্র TEST_GT:
		যদি (aa1 > aa2)
			ফেরত;
		বিরতি;
	ক্ষেত্র TEST_GE:
		যদি (aa1 >= aa2)
			ফেরত;
		বিরতি;
	পূর্বনির্ধারিত:
		abort();
	}

	test_header(file, সারি, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

শূন্য
assert_ptr(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    ধ্রুবক শূন্য *aa1, ধ্রুবক শূন্য *aa2, গণনা test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, সারি, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

স্থির দ্বিগুণ
tstod(ধ্রুবক কাঠামো timespec *ts)
{
	ফেরত (দ্বিগুণ)ts->tv_sec + ((দ্বিগুণ)ts->tv_nsec / 1000000000.0);
}

শূন্য
hex2bin(uint8_t *bin, ধ্রুবক অক্ষর *hex, আকার_t len)
{
	আকার_t i;
	unsigned পূর্ণসংখ্যা v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	জন্য (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

শূন্য
bench_start(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *name)
{
	অক্ষর *cp;

	যদি (bench_name != ফাঁকা) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, সারি, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != ফাঁকা &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	মুক্ত(cp);

	bench_name = name;
	bench_nruns = 0;
	যদি (bench_skip)
		ফেরত;
	মুক্ত(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(আকার(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

পূর্ণসংখ্যা
bench_done(শূন্য)
{
	ফেরত bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

শূন্য
bench_case_start(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

শূন্য
bench_case_finish(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি)
{
	কাঠামো timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	যদি (bench_nruns >= bench_nalloc) {
		যদি (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, আকার(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

স্থির পূর্ণসংখ্যা
tscmp(ধ্রুবক শূন্য *aa, ধ্রুবক শূন্য *bb)
{
	ধ্রুবক কাঠামো timespec *a = (ধ্রুবক কাঠামো timespec *)aa;
	ধ্রুবক কাঠামো timespec *b = (ধ্রুবক কাঠামো timespec *)bb;

	যদি (timespeccmp(a, b, ==))
		ফেরত 0;
	ফেরত timespeccmp(a, b, <) ? -1 : 1;
}

শূন্য
bench_finish(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *unit)
{
	দ্বিগুণ std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	পূর্ণসংখ্যা i;

	যদি (bench_skip)
		যাও done;

	যদি (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, সারি,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, আকার(*bench_samples), tscmp);
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
	জন্য (i = 0; i < bench_nruns; i++) {
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
	bench_name = ফাঁকা;
	bench_nruns = 0;
	মুক্ত(bench_samples);
	bench_samples = ফাঁকা;
	bench_skip = 0;
}
