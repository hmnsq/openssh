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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/uio.h>
#అన్తర్భావ <sys/time.h>

#అన్తర్భావ <assert.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <math.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/err.h>
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#అయితే_ముగింపు

#అన్తర్భావ "entropy.h"
#అన్తర్భావ "test_helper.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "xmalloc.h"

#నిర్వచించు BENCH_FAST_DEADLINE	1
#నిర్వచించు BENCH_సాధారణ_DEADLINE	10
#నిర్వచించు BENCH_SLOW_DEADLINE	60
#నిర్వచించు BENCH_SAMPLES_ALLOC	8192
#నిర్వచించు BENCH_స్తంభం_వెడల్పు	40

#నిర్వచించు MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#నిర్వచించు TEST_CHECK_INT(r, pred) చేయి {		\
		ఎంపిక (pred) {			\
		స్థితి TEST_EQ:			\
			ఒకవేళ (r == 0)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_NE:			\
			ఒకవేళ (r != 0)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_LT:			\
			ఒకవేళ (r < 0)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_LE:			\
			ఒకవేళ (r <= 0)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_GT:			\
			ఒకవేళ (r > 0)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_GE:			\
			ఒకవేళ (r >= 0)		\
				తిరిగి;		\
			ఆపు;			\
		అప్రమేయ:			\
			abort();		\
		}				\
	} అయితే (0)

#నిర్వచించు TEST_CHECK(x1, x2, pred) చేయి {		\
		ఎంపిక (pred) {			\
		స్థితి TEST_EQ:			\
			ఒకవేళ (x1 == x2)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_NE:			\
			ఒకవేళ (x1 != x2)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_LT:			\
			ఒకవేళ (x1 < x2)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_LE:			\
			ఒకవేళ (x1 <= x2)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_GT:			\
			ఒకవేళ (x1 > x2)		\
				తిరిగి;		\
			ఆపు;			\
		స్థితి TEST_GE:			\
			ఒకవేళ (x1 >= x2)		\
				తిరిగి;		\
			ఆపు;			\
		అప్రమేయ:			\
			abort();		\
		}				\
	} అయితే (0)

బాహ్య అక్షరం *__progname;

స్థిర పూర్ణాంకం verbose_బహుళకం = 0;
స్థిర పూర్ణాంకం quiet_బహుళకం = 0;
స్థిర అక్షరం *చురుకైన_test_name = ఖాళీ;
స్థిర u_int test_సంఖ్య = 0;
స్థిర test_onerror_func_t *test_onerror = ఖాళీ;
స్థిర శూన్య *onerror_ctx = ఖాళీ;
స్థిర స్థిరరాశి అక్షరం *దత్తాంశం_dir = ఖాళీ;
స్థిర అక్షరం subtest_info[512];
స్థిర పూర్ణాంకం fast = 0;
స్థిర పూర్ణాంకం slow = 0;
స్థిర పూర్ణాంకం benchmark_detail_statistics = 0;

స్థిర పూర్ణాంకం benchmark = 0;
స్థిర స్థిరరాశి అక్షరం *bench_name = ఖాళీ;
స్థిర అక్షరం *benchmark_నమూనా = ఖాళీ;
స్థిర నిర్మాణం timespec bench_ప్రారంభం_సమయం, bench_ముగింపు_సమయం;
స్థిర నిర్మాణం timespec *bench_samples;
స్థిర పూర్ణాంకం bench_skip, bench_nruns, bench_nalloc;
ద్విగుణ bench_accum_secs;

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	పూర్ణాంకం ch;

	విత్తనం_rng();
#నిర్వచితమైతే WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_ఎక్కించు_CRYPTO_అక్షరశ్రేణులు, ఖాళీ);
#అయితే_ముగింపు

	/* Handle systems without __progname */
	ఒకవేళ (__progname == ఖాళీ) {
		__progname = strrchr(argv[0], '/');
		ఒకవేళ (__progname == ఖాళీ || __progname[1] == '\0')
			__progname = argv[0];	
		లేకపోతే
			__progname++;
		ఒకవేళ ((__progname = strdup(__progname)) == ఖాళీ) {
			fprintf(stderr, "strdup failed\n");
			నిష్క్రమించు(1);
		}
	}

	అయితే ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'b':
			benchmark = 1;
			ఆపు;
		స్థితి 'B':
			benchmark = benchmark_detail_statistics = 1;
			ఆపు;
		స్థితి 'O':
			benchmark_నమూనా = xstrdup(optarg);
			ఆపు;
		స్థితి 'F':
			slow = 1;
			ఆపు;
		స్థితి 'f':
			fast = 1;
			ఆపు;
		స్థితి 'd':
			దత్తాంశం_dir = optarg;
			ఆపు;
		స్థితి 'q':
			verbose_బహుళకం = 0;
			quiet_బహుళకం = 1;
			ఆపు;
		స్థితి 'v':
			verbose_బహుళకం = 1;
			quiet_బహుళకం = 0;
			ఆపు;
		అప్రమేయ:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			నిష్క్రమించు(1);
		}
	}
	setvbuf(stdout, ఖాళీ, _IONBF, 0);
	ఒకవేళ (!quiet_బహుళకం)
		రాయి("%s: ", __progname);
	ఒకవేళ (verbose_బహుళకం)
		రాయి("\n");

	ఒకవేళ (benchmark)
		benchmarks();
	లేకపోతే
		tests();

	ఒకవేళ (!quiet_బహుళకం && !benchmark)
		రాయి(" %u tests ok\n", test_సంఖ్య);
	తిరిగి 0;
}

పూర్ణాంకం
test_is_verbose(శూన్య)
{
	తిరిగి verbose_బహుళకం;
}

పూర్ణాంకం
test_is_quiet(శూన్య)
{
	తిరిగి quiet_బహుళకం;
}

పూర్ణాంకం
test_is_fast(శూన్య)
{
	తిరిగి fast;
}

పూర్ణాంకం
test_is_slow(శూన్య)
{
	తిరిగి slow;
}

స్థిరరాశి అక్షరం *
test_దత్తాంశం_file(స్థిరరాశి అక్షరం *name)
{
	స్థిర అక్షరం ret[PATH_MAX];

	ఒకవేళ (దత్తాంశం_dir != ఖాళీ)
		snprintf(ret, పరిమాణం(ret), "%s/%s", దత్తాంశం_dir, name);
	లేకపోతే
		strlcpy(ret, name, పరిమాణం(ret));
	ఒకవేళ (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		నిష్క్రమించు(1);
	}
	తిరిగి ret;
}

శూన్య
test_info(అక్షరం *s, కొలత_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_సంఖ్య,
	    చురుకైన_test_name == ఖాళీ ? "<none>" : చురుకైన_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

స్థిర శూన్య
siginfo(పూర్ణాంకం వాడని __attribute__((__unused__)))
{
	అక్షరం buf[256];

	test_info(buf, పరిమాణం(buf));
	atomicio(vwrite, STDERR_FILENO, buf, అక్షరశ్రేణి_పొడవు(buf));
}

శూన్య
test_ప్రారంభం(స్థిరరాశి అక్షరం *n)
{
	ప్రతిజ్ఞా(చురుకైన_test_name == ఖాళీ);
	ప్రతిజ్ఞా((చురుకైన_test_name = strdup(n)) != ఖాళీ);
	*subtest_info = '\0';
	ఒకవేళ (verbose_బహుళకం)
		రాయి("test %u - \"%s\": ", test_సంఖ్య, చురుకైన_test_name);
	test_సంఖ్య++;
#నిర్వచితమైతే SIGINFO
	సంకేతం(SIGINFO, siginfo);
#అయితే_ముగింపు
	సంకేతం(SIGUSR1, siginfo);
}

శూన్య
సమితి_onerror_func(test_onerror_func_t *f, శూన్య *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

శూన్య
test_పూర్తి(శూన్య)
{
	*subtest_info = '\0';
	ప్రతిజ్ఞా(చురుకైన_test_name != ఖాళీ);
	విడుదల(చురుకైన_test_name);
	చురుకైన_test_name = ఖాళీ;
	ఒకవేళ (verbose_బహుళకం)
		రాయి("OK\n");
	లేకపోతే ఒకవేళ (!quiet_బహుళకం && !benchmark) {
		రాయి(".");
		fflush(stdout);
	}
}

శూన్య
test_subtest_info(స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, పరిమాణం(subtest_info), fmt, ap);
	va_end(ap);
}

పూర్ణాంకం
test_is_benchmark(శూన్య)
{
	తిరిగి benchmark;
}

శూన్య
ssl_err_check(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి)
{
#నిర్వచితమైతే WITH_OPENSSL
	దీర్ఘ openssl_error = ERR_get_error();

	ఒకవేళ (openssl_error == 0)
		తిరిగి;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, పంక్తి, ERR_error_string(openssl_error, ఖాళీ));
#లేకపోతే /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, పంక్తి);
#అయితే_ముగింపు /* WITH_OPENSSL */
	abort();
}

స్థిర స్థిరరాశి అక్షరం *
pred_name(గణన test_predicate p)
{
	ఎంపిక (p) {
	స్థితి TEST_EQ:
		తిరిగి "EQ";
	స్థితి TEST_NE:
		తిరిగి "NE";
	స్థితి TEST_LT:
		తిరిగి "LT";
	స్థితి TEST_LE:
		తిరిగి "LE";
	స్థితి TEST_GT:
		తిరిగి "GT";
	స్థితి TEST_GE:
		తిరిగి "GE";
	అప్రమేయ:
		తిరిగి "UNKNOWN";
	}
}

స్థిర శూన్య
test_die(శూన్య)
{
	ఒకవేళ (test_onerror != ఖాళీ)
		test_onerror(onerror_ctx);
	abort();
}

స్థిర శూన్య
test_శీర్షిక(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    స్థిరరాశి అక్షరం *name, గణన test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, పంక్తి, test_సంఖ్య, చురుకైన_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != ఖాళీ ? ", " : "", a2 != ఖాళీ ? a2 : "");
}

#నిర్వచితమైతే WITH_OPENSSL
శూన్య
assert_bignum(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    స్థిరరాశి BIGNUM *aa1, స్థిరరాశి BIGNUM *aa2, గణన test_predicate pred)
{
	పూర్ణాంకం r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#అయితే_ముగింపు

శూన్య
assert_string(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    స్థిరరాశి అక్షరం *aa1, స్థిరరాశి అక్షరం *aa2, గణన test_predicate pred)
{
	పూర్ణాంకం r;

	/* Verify pointers are not NULL */
	assert_ptr(file, పంక్తి, a1, "NULL", aa1, ఖాళీ, TEST_NE);
	assert_ptr(file, పంక్తి, a2, "NULL", aa2, ఖాళీ, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, అక్షరశ్రేణి_పొడవు(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, అక్షరశ్రేణి_పొడవు(aa2));
	test_die();
}

శూన్య
assert_mem(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    స్థిరరాశి శూన్య *aa1, స్థిరరాశి శూన్య *aa2, కొలత_t l, గణన test_predicate pred)
{
	పూర్ణాంకం r;
	అక్షరం *aa1_tohex = ఖాళీ;
	అక్షరం *aa2_tohex = ఖాళీ;

	ఒకవేళ (l == 0)
		తిరిగి;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, పంక్తి, a1, "NULL", aa1, ఖాళీ, TEST_NE);
	assert_ptr(file, పంక్తి, a2, "NULL", aa2, ఖాళీ, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	విడుదల(aa1_tohex);
	విడుదల(aa2_tohex);
	test_die();
}

స్థిర పూర్ణాంకం
memvalcmp(స్థిరరాశి uint8_t *s, u_char v, కొలత_t l, కొలత_t *where)
{
	కొలత_t i;

	కొరకు (i = 0; i < l; i++) {
		ఒకవేళ (s[i] != v) {
			*where = i;
			తిరిగి 1;
		}
	}
	తిరిగి 0;
}

శూన్య
assert_mem_filled(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1,
    స్థిరరాశి శూన్య *aa1, u_char v, కొలత_t l, గణన test_predicate pred)
{
	కొలత_t where = -1;
	పూర్ణాంకం r;
	అక్షరం tmp[64];
	అక్షరం *aa1_tohex = ఖాళీ;

	ఒకవేళ (l == 0)
		తిరిగి;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, పంక్తి, a1, "NULL", aa1, ఖాళీ, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_శీర్షిక(file, పంక్తి, a1, ఖాళీ, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	విడుదల(aa1_tohex);
	snprintf(tmp, పరిమాణం(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

శూన్య
assert_int(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    పూర్ణాంకం aa1, పూర్ణాంకం aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

శూన్య
assert_కొలత_t(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    కొలత_t aa1, కొలత_t aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

శూన్య
assert_u_int(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    u_int aa1, u_int aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

శూన్య
assert_long(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    దీర్ఘ aa1, దీర్ఘ aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

శూన్య
assert_long_long(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    దీర్ఘ దీర్ఘ aa1, దీర్ఘ దీర్ఘ aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

శూన్య
assert_char(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    అక్షరం aa1, అక్షరం aa2, గణన test_predicate pred)
{
	అక్షరం buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_సురక్షిత|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_సురక్షిత|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

శూన్య
assert_u8(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    uint8_t aa1, uint8_t aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

శూన్య
assert_u16(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    uint16_t aa1, uint16_t aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

శూన్య
assert_u32(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    uint32_t aa1, uint32_t aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

శూన్య
assert_u64(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    uint64_t aa1, uint64_t aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (గుర్తులేని దీర్ఘ దీర్ఘ)aa1, (గుర్తులేని దీర్ఘ దీర్ఘ)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (గుర్తులేని దీర్ఘ దీర్ఘ)aa2, (గుర్తులేని దీర్ఘ దీర్ఘ)aa2);
	test_die();
}

శూన్య
assert_double(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    ద్విగుణ aa1, ద్విగుణ aa2, గణన test_predicate pred)
{
	స్థిరరాశి ద్విగుణ epsilon = 0.000000001;

	ఎంపిక (pred) {
	స్థితి TEST_EQ:
		ఒకవేళ (fabs(aa1 - aa2) < epsilon)
			తిరిగి;
		ఆపు;
	స్థితి TEST_NE:
		ఒకవేళ (fabs(aa1 - aa2) >= epsilon)
			తిరిగి;
		ఆపు;
	స్థితి TEST_LT:
		ఒకవేళ (aa1 < aa2)
			తిరిగి;
		ఆపు;
	స్థితి TEST_LE:
		ఒకవేళ (aa1 <= aa2)
			తిరిగి;
		ఆపు;
	స్థితి TEST_GT:
		ఒకవేళ (aa1 > aa2)
			తిరిగి;
		ఆపు;
	స్థితి TEST_GE:
		ఒకవేళ (aa1 >= aa2)
			తిరిగి;
		ఆపు;
	అప్రమేయ:
		abort();
	}

	test_శీర్షిక(file, పంక్తి, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

శూన్య
assert_ptr(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    స్థిరరాశి శూన్య *aa1, స్థిరరాశి శూన్య *aa2, గణన test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_శీర్షిక(file, పంక్తి, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

స్థిర ద్విగుణ
tstod(స్థిరరాశి నిర్మాణం timespec *ts)
{
	తిరిగి (ద్విగుణ)ts->tv_sec + ((ద్విగుణ)ts->tv_nsec / 1000000000.0);
}

శూన్య
hex2bin(uint8_t *bin, స్థిరరాశి అక్షరం *hex, కొలత_t len)
{
	కొలత_t i;
	గుర్తులేని పూర్ణాంకం v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	కొరకు (i = 0; i < len; i++) {
		ASSERT_INT_EQ(అక్షరశ్రేణి_చదువు(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

శూన్య
bench_ప్రారంభం(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *name)
{
	అక్షరం *cp;

	ఒకవేళ (bench_name != ఖాళీ) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, పంక్తి, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_నమూనా != ఖాళీ &&
	    సరిపోలిక_నమూనా_list(cp, benchmark_నమూనా, 1) != 1;
	విడుదల(cp);

	bench_name = name;
	bench_nruns = 0;
	ఒకవేళ (bench_skip)
		తిరిగి;
	విడుదల(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(పరిమాణం(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

పూర్ణాంకం
bench_పూర్తి(శూన్య)
{
	తిరిగి bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_సాధారణ_DEADLINE));
}

శూన్య
bench_case_ప్రారంభం(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి)
{
	clock_gettime(CLOCK_REALTIME, &bench_ప్రారంభం_సమయం);
}

శూన్య
bench_case_ముగింపు(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి)
{
	నిర్మాణం timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_ముగింపు_సమయం);
	timespecsub(&bench_ముగింపు_సమయం, &bench_ప్రారంభం_సమయం, &ts);
	ఒకవేళ (bench_nruns >= bench_nalloc) {
		ఒకవేళ (bench_nalloc >= గరిష్ఠ_పూర్ణాంకం / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, పరిమాణం(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

స్థిర పూర్ణాంకం
tscmp(స్థిరరాశి శూన్య *aa, స్థిరరాశి శూన్య *bb)
{
	స్థిరరాశి నిర్మాణం timespec *a = (స్థిరరాశి నిర్మాణం timespec *)aa;
	స్థిరరాశి నిర్మాణం timespec *b = (స్థిరరాశి నిర్మాణం timespec *)bb;

	ఒకవేళ (timespeccmp(a, b, ==))
		తిరిగి 0;
	తిరిగి timespeccmp(a, b, <) ? -1 : 1;
}

శూన్య
bench_ముగింపు(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *unit)
{
	ద్విగుణ std_dev = 0, సగటు_spr, సగటు_rps, med_spr, med_rps;
	పూర్ణాంకం i;

	ఒకవేళ (bench_skip)
		వెళ్ళు పూర్తి;

	ఒకవేళ (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, పంక్తి,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, పరిమాణం(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	ఒకవేళ (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/*సగటు*/
	సగటు_spr = bench_accum_secs / (ద్విగుణ)bench_nruns;
	సగటు_rps = (సగటు_spr == 0.0) ? INFINITY : 1.0/సగటు_spr;
	/* std. dev */
	std_dev = 0;
	కొరకు (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - సగటు_spr;
		std_dev *= std_dev;
	}
	std_dev /= (ద్విగుణ)bench_nruns;
	std_dev = వర్గమూలం(std_dev);
	ఒకవేళ (benchmark_detail_statistics) {
		రాయి("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    సగటు_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    సగటు_rps, med_rps, unit);
	} లేకపోతే {
		రాయి("%-*s %0.2f %s/s\n", BENCH_స్తంభం_వెడల్పు,
		    bench_name, med_rps, unit);
	}
 పూర్తి:
	bench_name = ఖాళీ;
	bench_nruns = 0;
	విడుదల(bench_samples);
	bench_samples = ఖాళీ;
	bench_skip = 0;
}
