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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/uio.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>

#ଅନ୍ତର୍ଭାଵ <assert.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <math.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/err.h>
#endif

#ଯଦି defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#ଅନ୍ତର୍ଭାଵ "entropy.h"
#ଅନ୍ତର୍ଭାଵ "test_helper.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

#define BENCH_FAST_DEADLINE	1
#define BENCH_NORMAL_DEADLINE	10
#define BENCH_SLOW_DEADLINE	60
#define BENCH_SAMPLES_ALLOC	8192
#define BENCH_COLUMN_WIDTH	40

#define MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#define TEST_CHECK_INT(r, pred) କର {		\
		ବାଛ (pred) {			\
		ସ୍ଥିତି TEST_EQ:			\
			ଯଦି (r == 0)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_NE:			\
			ଯଦି (r != 0)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_LT:			\
			ଯଦି (r < 0)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_LE:			\
			ଯଦି (r <= 0)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_GT:			\
			ଯଦି (r > 0)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_GE:			\
			ଯଦି (r >= 0)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:			\
			abort();		\
		}				\
	} ଯେତେବେଳେ (0)

#define TEST_CHECK(x1, x2, pred) କର {		\
		ବାଛ (pred) {			\
		ସ୍ଥିତି TEST_EQ:			\
			ଯଦି (x1 == x2)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_NE:			\
			ଯଦି (x1 != x2)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_LT:			\
			ଯଦି (x1 < x2)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_LE:			\
			ଯଦି (x1 <= x2)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_GT:			\
			ଯଦି (x1 > x2)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ସ୍ଥିତି TEST_GE:			\
			ଯଦି (x1 >= x2)		\
				ଫେରନ୍ତୁ;		\
			ଭାଙ୍ଗ;			\
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:			\
			abort();		\
		}				\
	} ଯେତେବେଳେ (0)

ବାହ୍ୟ ଅକ୍ଷର *__progname;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା verbose_mode = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet_mode = 0;
ସ୍ଥିର ଅକ୍ଷର *active_test_name = ଖାଲି;
ସ୍ଥିର u_int test_ସଂଖ୍ୟା = 0;
ସ୍ଥିର test_onerror_func_t *test_onerror = ଖାଲି;
ସ୍ଥିର ଶୂନ୍ୟ *onerror_ctx = ଖାଲି;
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *data_dir = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର subtest_info[512];
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା fast = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା slow = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା benchmark_detail_statistics = 0;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା benchmark = 0;
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *bench_name = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *benchmark_pattern = ଖାଲି;
ସ୍ଥିର ସଂରଚନା timespec bench_start_time, bench_finish_time;
ସ୍ଥିର ସଂରଚନା timespec *bench_samples;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା bench_skip, bench_nruns, bench_nalloc;
ଦ୍ୱିଗୁଣ bench_accum_secs;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ଖାଲି);
#endif

	/* Handle systems without __progname */
	ଯଦି (__progname == ଖାଲି) {
		__progname = strrchr(argv[0], '/');
		ଯଦି (__progname == ଖାଲି || __progname[1] == '\0')
			__progname = argv[0];	
		ଅନ୍ୟଥା
			__progname++;
		ଯଦି ((__progname = strdup(__progname)) == ଖାଲି) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	ଯେତେବେଳେ ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'b':
			benchmark = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'B':
			benchmark = benchmark_detail_statistics = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'O':
			benchmark_pattern = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'F':
			slow = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':
			fast = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'd':
			data_dir = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, ଖାଲି, _IONBF, 0);
	ଯଦି (!quiet_mode)
		printf("%s: ", __progname);
	ଯଦି (verbose_mode)
		printf("\n");

	ଯଦି (benchmark)
		benchmarks();
	ଅନ୍ୟଥା
		tests();

	ଯଦି (!quiet_mode && !benchmark)
		printf(" %u tests ok\n", test_ସଂଖ୍ୟା);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
test_is_verbose(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ verbose_mode;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
test_is_quiet(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ quiet_mode;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
test_is_fast(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ fast;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
test_is_slow(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ slow;
}

ଅଚଳ ଅକ୍ଷର *
test_data_file(ଅଚଳ ଅକ୍ଷର *name)
{
	ସ୍ଥିର ଅକ୍ଷର ret[PATH_MAX];

	ଯଦି (data_dir != ଖାଲି)
		snprintf(ret, ଆକାର(ret), "%s/%s", data_dir, name);
	ଅନ୍ୟଥା
		strlcpy(ret, name, ଆକାର(ret));
	ଯଦି (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
test_info(ଅକ୍ଷର *s, size_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_ସଂଖ୍ୟା,
	    active_test_name == ଖାଲି ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

ସ୍ଥିର ଶୂନ୍ୟ
siginfo(ପୂର୍ଣ୍ଣସଂଖ୍ୟା unused __attribute__((__unused__)))
{
	ଅକ୍ଷର buf[256];

	test_info(buf, ଆକାର(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

ଶୂନ୍ୟ
test_start(ଅଚଳ ଅକ୍ଷର *n)
{
	ପ୍ରତିଜ୍ଞା(active_test_name == ଖାଲି);
	ପ୍ରତିଜ୍ଞା((active_test_name = strdup(n)) != ଖାଲି);
	*subtest_info = '\0';
	ଯଦି (verbose_mode)
		printf("test %u - \"%s\": ", test_ସଂଖ୍ୟା, active_test_name);
	test_ସଂଖ୍ୟା++;
#ifdef SIGINFO
	ସଙ୍କେତ(SIGINFO, siginfo);
#endif
	ସଙ୍କେତ(SIGUSR1, siginfo);
}

ଶୂନ୍ୟ
set_onerror_func(test_onerror_func_t *f, ଶୂନ୍ୟ *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

ଶୂନ୍ୟ
test_done(ଶୂନ୍ୟ)
{
	*subtest_info = '\0';
	ପ୍ରତିଜ୍ଞା(active_test_name != ଖାଲି);
	ମୁକ୍ତ(active_test_name);
	active_test_name = ଖାଲି;
	ଯଦି (verbose_mode)
		printf("OK\n");
	ଅନ୍ୟଥା ଯଦି (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

ଶୂନ୍ୟ
test_subtest_info(ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, ଆକାର(subtest_info), fmt, ap);
	va_end(ap);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
test_is_benchmark(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ benchmark;
}

ଶୂନ୍ୟ
ssl_err_check(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	ଯଦି (openssl_error == 0)
		ଫେରନ୍ତୁ;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, ଧାଡ଼ି, ERR_error_string(openssl_error, ଖାଲି));
#ଅନ୍ୟଥା /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, ଧାଡ଼ି);
#endif /* WITH_OPENSSL */
	abort();
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
pred_name(ଗଣନା test_predicate p)
{
	ବାଛ (p) {
	ସ୍ଥିତି TEST_EQ:
		ଫେରନ୍ତୁ "EQ";
	ସ୍ଥିତି TEST_NE:
		ଫେରନ୍ତୁ "NE";
	ସ୍ଥିତି TEST_LT:
		ଫେରନ୍ତୁ "LT";
	ସ୍ଥିତି TEST_LE:
		ଫେରନ୍ତୁ "LE";
	ସ୍ଥିତି TEST_GT:
		ଫେରନ୍ତୁ "GT";
	ସ୍ଥିତି TEST_GE:
		ଫେରନ୍ତୁ "GE";
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ "UNKNOWN";
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
test_die(ଶୂନ୍ୟ)
{
	ଯଦି (test_onerror != ଖାଲି)
		test_onerror(onerror_ctx);
	abort();
}

ସ୍ଥିର ଶୂନ୍ୟ
test_header(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    ଅଚଳ ଅକ୍ଷର *name, ଗଣନା test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, ଧାଡ଼ି, test_ସଂଖ୍ୟା, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != ଖାଲି ? ", " : "", a2 != ଖାଲି ? a2 : "");
}

#ifdef WITH_OPENSSL
ଶୂନ୍ୟ
assert_bignum(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    ଅଚଳ BIGNUM *aa1, ଅଚଳ BIGNUM *aa2, ଗଣନା test_predicate pred)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

ଶୂନ୍ୟ
assert_string(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    ଅଚଳ ଅକ୍ଷର *aa1, ଅଚଳ ଅକ୍ଷର *aa2, ଗଣନା test_predicate pred)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* Verify pointers are not NULL */
	assert_ptr(file, ଧାଡ଼ି, a1, "NULL", aa1, ଖାଲି, TEST_NE);
	assert_ptr(file, ଧାଡ଼ି, a2, "NULL", aa2, ଖାଲି, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

ଶୂନ୍ୟ
assert_mem(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    ଅଚଳ ଶୂନ୍ୟ *aa1, ଅଚଳ ଶୂନ୍ୟ *aa2, size_t l, ଗଣନା test_predicate pred)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *aa1_tohex = ଖାଲି;
	ଅକ୍ଷର *aa2_tohex = ଖାଲି;

	ଯଦି (l == 0)
		ଫେରନ୍ତୁ;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, ଧାଡ଼ି, a1, "NULL", aa1, ଖାଲି, TEST_NE);
	assert_ptr(file, ଧାଡ଼ି, a2, "NULL", aa2, ଖାଲି, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	ମୁକ୍ତ(aa1_tohex);
	ମୁକ୍ତ(aa2_tohex);
	test_die();
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
memvalcmp(ଅଚଳ uint8_t *s, u_char v, size_t l, size_t *where)
{
	size_t i;

	ପାଇଁ (i = 0; i < l; i++) {
		ଯଦି (s[i] != v) {
			*where = i;
			ଫେରନ୍ତୁ 1;
		}
	}
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
assert_mem_filled(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1,
    ଅଚଳ ଶୂନ୍ୟ *aa1, u_char v, size_t l, ଗଣନା test_predicate pred)
{
	size_t where = -1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର tmp[64];
	ଅକ୍ଷର *aa1_tohex = ଖାଲି;

	ଯଦି (l == 0)
		ଫେରନ୍ତୁ;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, ଧାଡ଼ି, a1, "NULL", aa1, ଖାଲି, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, ଧାଡ଼ି, a1, ଖାଲି, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	ମୁକ୍ତ(aa1_tohex);
	snprintf(tmp, ଆକାର(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

ଶୂନ୍ୟ
assert_int(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା aa1, ପୂର୍ଣ୍ଣସଂଖ୍ୟା aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_size_t(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    size_t aa1, size_t aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_u_int(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    u_int aa1, u_int aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_long(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    long aa1, long aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_long_long(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    long long aa1, long long aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_char(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    ଅକ୍ଷର aa1, ଅକ୍ଷର aa2, ଗଣନା test_predicate pred)
{
	ଅକ୍ଷର buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_u8(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    uint8_t aa1, uint8_t aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_u16(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    uint16_t aa1, uint16_t aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_u32(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    uint32_t aa1, uint32_t aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_u64(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    uint64_t aa1, uint64_t aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (unsigned long long)aa1, (unsigned long long)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (unsigned long long)aa2, (unsigned long long)aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_double(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    ଦ୍ୱିଗୁଣ aa1, ଦ୍ୱିଗୁଣ aa2, ଗଣନା test_predicate pred)
{
	ଅଚଳ ଦ୍ୱିଗୁଣ epsilon = 0.000000001;

	ବାଛ (pred) {
	ସ୍ଥିତି TEST_EQ:
		ଯଦି (fabs(aa1 - aa2) < epsilon)
			ଫେରନ୍ତୁ;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି TEST_NE:
		ଯଦି (fabs(aa1 - aa2) >= epsilon)
			ଫେରନ୍ତୁ;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି TEST_LT:
		ଯଦି (aa1 < aa2)
			ଫେରନ୍ତୁ;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି TEST_LE:
		ଯଦି (aa1 <= aa2)
			ଫେରନ୍ତୁ;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି TEST_GT:
		ଯଦି (aa1 > aa2)
			ଫେରନ୍ତୁ;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି TEST_GE:
		ଯଦି (aa1 >= aa2)
			ଫେରନ୍ତୁ;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		abort();
	}

	test_header(file, ଧାଡ଼ି, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

ଶୂନ୍ୟ
assert_ptr(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *a1, ଅଚଳ ଅକ୍ଷର *a2,
    ଅଚଳ ଶୂନ୍ୟ *aa1, ଅଚଳ ଶୂନ୍ୟ *aa2, ଗଣନା test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ଧାଡ଼ି, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

ସ୍ଥିର ଦ୍ୱିଗୁଣ
tstod(ଅଚଳ ସଂରଚନା timespec *ts)
{
	ଫେରନ୍ତୁ (ଦ୍ୱିଗୁଣ)ts->tv_sec + ((ଦ୍ୱିଗୁଣ)ts->tv_nsec / 1000000000.0);
}

ଶୂନ୍ୟ
hex2bin(uint8_t *bin, ଅଚଳ ଅକ୍ଷର *hex, size_t len)
{
	size_t i;
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	ପାଇଁ (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

ଶୂନ୍ୟ
bench_start(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *name)
{
	ଅକ୍ଷର *cp;

	ଯଦି (bench_name != ଖାଲି) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, ଧାଡ଼ି, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != ଖାଲି &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	ମୁକ୍ତ(cp);

	bench_name = name;
	bench_nruns = 0;
	ଯଦି (bench_skip)
		ଫେରନ୍ତୁ;
	ମୁକ୍ତ(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(ଆକାର(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
bench_done(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

ଶୂନ୍ୟ
bench_case_start(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

ଶୂନ୍ୟ
bench_case_finish(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି)
{
	ସଂରଚନା timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	ଯଦି (bench_nruns >= bench_nalloc) {
		ଯଦି (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, ଆକାର(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
tscmp(ଅଚଳ ଶୂନ୍ୟ *aa, ଅଚଳ ଶୂନ୍ୟ *bb)
{
	ଅଚଳ ସଂରଚନା timespec *a = (ଅଚଳ ସଂରଚନା timespec *)aa;
	ଅଚଳ ସଂରଚନା timespec *b = (ଅଚଳ ସଂରଚନା timespec *)bb;

	ଯଦି (timespeccmp(a, b, ==))
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ timespeccmp(a, b, <) ? -1 : 1;
}

ଶୂନ୍ୟ
bench_finish(ଅଚଳ ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *unit)
{
	ଦ୍ୱିଗୁଣ std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (bench_skip)
		ଯାଅ done;

	ଯଦି (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, ଧାଡ଼ି,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, ଆକାର(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	ଯଦି (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (ଦ୍ୱିଗୁଣ)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? INFINITY : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	ପାଇଁ (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (ଦ୍ୱିଗୁଣ)bench_nruns;
	std_dev = sqrt(std_dev);
	ଯଦି (benchmark_detail_statistics) {
		printf("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} ଅନ୍ୟଥା {
		printf("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = ଖାଲି;
	bench_nruns = 0;
	ମୁକ୍ତ(bench_samples);
	bench_samples = ଖାଲି;
	bench_skip = 0;
}
