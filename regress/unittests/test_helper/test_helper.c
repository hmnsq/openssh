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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/uio.h>
#अन्तर्भाव <sys/time.h>

#अन्तर्भाव <assert.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <math.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/err.h>
#endif

#सचे defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#अन्तर्भाव "entropy.h"
#अन्तर्भाव "test_helper.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "xmalloc.h"

#define BENCH_FAST_DEADLINE	1
#define BENCH_NORMAL_DEADLINE	10
#define BENCH_SLOW_DEADLINE	60
#define BENCH_SAMPLES_ALLOC	8192
#define BENCH_COLUMN_WIDTH	40

#define MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#define TEST_CHECK_INT(r, pred) करोहि {		\
		विकल्प (pred) {			\
		पक्ष TEST_EQ:			\
			सचे (r == 0)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_NE:			\
			सचे (r != 0)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_LT:			\
			सचे (r < 0)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_LE:			\
			सचे (r <= 0)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_GT:			\
			सचे (r > 0)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_GE:			\
			सचे (r >= 0)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		स्वभाव:			\
			abort();		\
		}				\
	} याव (0)

#define TEST_CHECK(x1, x2, pred) करोहि {		\
		विकल्प (pred) {			\
		पक्ष TEST_EQ:			\
			सचे (x1 == x2)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_NE:			\
			सचे (x1 != x2)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_LT:			\
			सचे (x1 < x2)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_LE:			\
			सचे (x1 <= x2)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_GT:			\
			सचे (x1 > x2)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		पक्ष TEST_GE:			\
			सचे (x1 >= x2)		\
				पटिनिवत्त;		\
			भङ्ग;			\
		स्वभाव:			\
			abort();		\
		}				\
	} याव (0)

बाह्य वर्ण *__progname;

स्थिर पूर्णाङ्क verbose_mode = 0;
स्थिर पूर्णाङ्क quiet_mode = 0;
स्थिर वर्ण *active_test_name = रिक्त;
स्थिर u_int test_सङ्ख्या = 0;
स्थिर test_onerror_func_t *test_onerror = रिक्त;
स्थिर शून्य *onerror_ctx = रिक्त;
स्थिर ध्रुव वर्ण *data_dir = रिक्त;
स्थिर वर्ण subtest_info[512];
स्थिर पूर्णाङ्क fast = 0;
स्थिर पूर्णाङ्क slow = 0;
स्थिर पूर्णाङ्क benchmark_detail_statistics = 0;

स्थिर पूर्णाङ्क benchmark = 0;
स्थिर ध्रुव वर्ण *bench_name = रिक्त;
स्थिर वर्ण *benchmark_pattern = रिक्त;
स्थिर संरचना timespec bench_start_time, bench_finish_time;
स्थिर संरचना timespec *bench_samples;
स्थिर पूर्णाङ्क bench_skip, bench_nruns, bench_nalloc;
द्विगुण bench_accum_secs;

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, रिक्त);
#endif

	/* Handle systems without __progname */
	सचे (__progname == रिक्त) {
		__progname = strrchr(argv[0], '/');
		सचे (__progname == रिक्त || __progname[1] == '\0')
			__progname = argv[0];	
		अञ्ञथा
			__progname++;
		सचे ((__progname = strdup(__progname)) == रिक्त) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	याव ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		विकल्प (ch) {
		पक्ष 'b':
			benchmark = 1;
			भङ्ग;
		पक्ष 'B':
			benchmark = benchmark_detail_statistics = 1;
			भङ्ग;
		पक्ष 'O':
			benchmark_pattern = xstrdup(optarg);
			भङ्ग;
		पक्ष 'F':
			slow = 1;
			भङ्ग;
		पक्ष 'f':
			fast = 1;
			भङ्ग;
		पक्ष 'd':
			data_dir = optarg;
			भङ्ग;
		पक्ष 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			भङ्ग;
		पक्ष 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			भङ्ग;
		स्वभाव:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, रिक्त, _IONBF, 0);
	सचे (!quiet_mode)
		printf("%s: ", __progname);
	सचे (verbose_mode)
		printf("\n");

	सचे (benchmark)
		benchmarks();
	अञ्ञथा
		tests();

	सचे (!quiet_mode && !benchmark)
		printf(" %u tests ok\n", test_सङ्ख्या);
	पटिनिवत्त 0;
}

पूर्णाङ्क
test_is_verbose(शून्य)
{
	पटिनिवत्त verbose_mode;
}

पूर्णाङ्क
test_is_quiet(शून्य)
{
	पटिनिवत्त quiet_mode;
}

पूर्णाङ्क
test_is_fast(शून्य)
{
	पटिनिवत्त fast;
}

पूर्णाङ्क
test_is_slow(शून्य)
{
	पटिनिवत्त slow;
}

ध्रुव वर्ण *
test_data_file(ध्रुव वर्ण *name)
{
	स्थिर वर्ण ret[PATH_MAX];

	सचे (data_dir != रिक्त)
		snprintf(ret, परिमाण(ret), "%s/%s", data_dir, name);
	अञ्ञथा
		strlcpy(ret, name, परिमाण(ret));
	सचे (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	पटिनिवत्त ret;
}

शून्य
test_info(वर्ण *s, size_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_सङ्ख्या,
	    active_test_name == रिक्त ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

स्थिर शून्य
siginfo(पूर्णाङ्क unused __attribute__((__unused__)))
{
	वर्ण buf[256];

	test_info(buf, परिमाण(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

शून्य
test_start(ध्रुव वर्ण *n)
{
	प्रतिज्ञा(active_test_name == रिक्त);
	प्रतिज्ञा((active_test_name = strdup(n)) != रिक्त);
	*subtest_info = '\0';
	सचे (verbose_mode)
		printf("test %u - \"%s\": ", test_सङ्ख्या, active_test_name);
	test_सङ्ख्या++;
#ifdef SIGINFO
	सङ्केत(SIGINFO, siginfo);
#endif
	सङ्केत(SIGUSR1, siginfo);
}

शून्य
set_onerror_func(test_onerror_func_t *f, शून्य *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

शून्य
test_done(शून्य)
{
	*subtest_info = '\0';
	प्रतिज्ञा(active_test_name != रिक्त);
	मुक्त(active_test_name);
	active_test_name = रिक्त;
	सचे (verbose_mode)
		printf("OK\n");
	अञ्ञथा सचे (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

शून्य
test_subtest_info(ध्रुव वर्ण *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, परिमाण(subtest_info), fmt, ap);
	va_end(ap);
}

पूर्णाङ्क
test_is_benchmark(शून्य)
{
	पटिनिवत्त benchmark;
}

शून्य
ssl_err_check(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	सचे (openssl_error == 0)
		पटिनिवत्त;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, पङ्क्तिः, ERR_error_string(openssl_error, रिक्त));
#अञ्ञथा /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, पङ्क्तिः);
#endif /* WITH_OPENSSL */
	abort();
}

स्थिर ध्रुव वर्ण *
pred_name(गणना test_predicate p)
{
	विकल्प (p) {
	पक्ष TEST_EQ:
		पटिनिवत्त "EQ";
	पक्ष TEST_NE:
		पटिनिवत्त "NE";
	पक्ष TEST_LT:
		पटिनिवत्त "LT";
	पक्ष TEST_LE:
		पटिनिवत्त "LE";
	पक्ष TEST_GT:
		पटिनिवत्त "GT";
	पक्ष TEST_GE:
		पटिनिवत्त "GE";
	स्वभाव:
		पटिनिवत्त "UNKNOWN";
	}
}

स्थिर शून्य
test_die(शून्य)
{
	सचे (test_onerror != रिक्त)
		test_onerror(onerror_ctx);
	abort();
}

स्थिर शून्य
test_header(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    ध्रुव वर्ण *name, गणना test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, पङ्क्तिः, test_सङ्ख्या, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != रिक्त ? ", " : "", a2 != रिक्त ? a2 : "");
}

#ifdef WITH_OPENSSL
शून्य
assert_bignum(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    ध्रुव BIGNUM *aa1, ध्रुव BIGNUM *aa2, गणना test_predicate pred)
{
	पूर्णाङ्क r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, पङ्क्तिः, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

शून्य
assert_string(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    ध्रुव वर्ण *aa1, ध्रुव वर्ण *aa2, गणना test_predicate pred)
{
	पूर्णाङ्क r;

	/* Verify pointers are not NULL */
	assert_ptr(file, पङ्क्तिः, a1, "NULL", aa1, रिक्त, TEST_NE);
	assert_ptr(file, पङ्क्तिः, a2, "NULL", aa2, रिक्त, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, पङ्क्तिः, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

शून्य
assert_mem(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    ध्रुव शून्य *aa1, ध्रुव शून्य *aa2, size_t l, गणना test_predicate pred)
{
	पूर्णाङ्क r;
	वर्ण *aa1_tohex = रिक्त;
	वर्ण *aa2_tohex = रिक्त;

	सचे (l == 0)
		पटिनिवत्त;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, पङ्क्तिः, a1, "NULL", aa1, रिक्त, TEST_NE);
	assert_ptr(file, पङ्क्तिः, a2, "NULL", aa2, रिक्त, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, पङ्क्तिः, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	मुक्त(aa1_tohex);
	मुक्त(aa2_tohex);
	test_die();
}

स्थिर पूर्णाङ्क
memvalcmp(ध्रुव uint8_t *s, u_char v, size_t l, size_t *where)
{
	size_t i;

	अत्थाय (i = 0; i < l; i++) {
		सचे (s[i] != v) {
			*where = i;
			पटिनिवत्त 1;
		}
	}
	पटिनिवत्त 0;
}

शून्य
assert_mem_filled(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1,
    ध्रुव शून्य *aa1, u_char v, size_t l, गणना test_predicate pred)
{
	size_t where = -1;
	पूर्णाङ्क r;
	वर्ण tmp[64];
	वर्ण *aa1_tohex = रिक्त;

	सचे (l == 0)
		पटिनिवत्त;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, पङ्क्तिः, a1, "NULL", aa1, रिक्त, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, पङ्क्तिः, a1, रिक्त, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	मुक्त(aa1_tohex);
	snprintf(tmp, परिमाण(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

शून्य
assert_int(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    पूर्णाङ्क aa1, पूर्णाङ्क aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

शून्य
assert_size_t(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    size_t aa1, size_t aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

शून्य
assert_u_int(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    u_int aa1, u_int aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_long(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    long aa1, long aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_long_long(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    long long aa1, long long aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_char(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    वर्ण aa1, वर्ण aa2, गणना test_predicate pred)
{
	वर्ण buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

शून्य
assert_u8(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    uint8_t aa1, uint8_t aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_u16(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    uint16_t aa1, uint16_t aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_u32(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    uint32_t aa1, uint32_t aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_u64(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    uint64_t aa1, uint64_t aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (unsigned long long)aa1, (unsigned long long)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (unsigned long long)aa2, (unsigned long long)aa2);
	test_die();
}

शून्य
assert_double(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    द्विगुण aa1, द्विगुण aa2, गणना test_predicate pred)
{
	ध्रुव द्विगुण epsilon = 0.000000001;

	विकल्प (pred) {
	पक्ष TEST_EQ:
		सचे (fabs(aa1 - aa2) < epsilon)
			पटिनिवत्त;
		भङ्ग;
	पक्ष TEST_NE:
		सचे (fabs(aa1 - aa2) >= epsilon)
			पटिनिवत्त;
		भङ्ग;
	पक्ष TEST_LT:
		सचे (aa1 < aa2)
			पटिनिवत्त;
		भङ्ग;
	पक्ष TEST_LE:
		सचे (aa1 <= aa2)
			पटिनिवत्त;
		भङ्ग;
	पक्ष TEST_GT:
		सचे (aa1 > aa2)
			पटिनिवत्त;
		भङ्ग;
	पक्ष TEST_GE:
		सचे (aa1 >= aa2)
			पटिनिवत्त;
		भङ्ग;
	स्वभाव:
		abort();
	}

	test_header(file, पङ्क्तिः, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

शून्य
assert_ptr(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    ध्रुव शून्य *aa1, ध्रुव शून्य *aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पङ्क्तिः, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

स्थिर द्विगुण
tstod(ध्रुव संरचना timespec *ts)
{
	पटिनिवत्त (द्विगुण)ts->tv_sec + ((द्विगुण)ts->tv_nsec / 1000000000.0);
}

शून्य
hex2bin(uint8_t *bin, ध्रुव वर्ण *hex, size_t len)
{
	size_t i;
	unsigned पूर्णाङ्क v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	अत्थाय (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

शून्य
bench_start(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *name)
{
	वर्ण *cp;

	सचे (bench_name != रिक्त) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, पङ्क्तिः, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != रिक्त &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	मुक्त(cp);

	bench_name = name;
	bench_nruns = 0;
	सचे (bench_skip)
		पटिनिवत्त;
	मुक्त(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(परिमाण(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

पूर्णाङ्क
bench_done(शून्य)
{
	पटिनिवत्त bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

शून्य
bench_case_start(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

शून्य
bench_case_finish(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः)
{
	संरचना timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	सचे (bench_nruns >= bench_nalloc) {
		सचे (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, परिमाण(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

स्थिर पूर्णाङ्क
tscmp(ध्रुव शून्य *aa, ध्रुव शून्य *bb)
{
	ध्रुव संरचना timespec *a = (ध्रुव संरचना timespec *)aa;
	ध्रुव संरचना timespec *b = (ध्रुव संरचना timespec *)bb;

	सचे (timespeccmp(a, b, ==))
		पटिनिवत्त 0;
	पटिनिवत्त timespeccmp(a, b, <) ? -1 : 1;
}

शून्य
bench_finish(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *unit)
{
	द्विगुण std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	पूर्णाङ्क i;

	सचे (bench_skip)
		गच्छ done;

	सचे (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, पङ्क्तिः,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, परिमाण(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	सचे (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (द्विगुण)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? INFINITY : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	अत्थाय (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (द्विगुण)bench_nruns;
	std_dev = sqrt(std_dev);
	सचे (benchmark_detail_statistics) {
		printf("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} अञ्ञथा {
		printf("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = रिक्त;
	bench_nruns = 0;
	मुक्त(bench_samples);
	bench_samples = रिक्त;
	bench_skip = 0;
}
