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

#include "includes.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/err.h>
#endif

#ꦪꦼꦤ꧀ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#include "entropy.h"
#include "test_helper.h"
#include "atomicio.h"
#include "match.h"
#include "misc.h"
#include "xmalloc.h"

#define BENCH_FAST_DEADLINE	1
#define BENCH_NORMAL_DEADLINE	10
#define BENCH_SLOW_DEADLINE	60
#define BENCH_SAMPLES_ALLOC	8192
#define BENCH_COLUMN_WIDTH	40

#define MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#define TEST_CHECK_INT(r, pred) do {		\
		switch (pred) {			\
		pak_sa TEST_EQ:			\
			ꦪꦼꦤ꧀ (r == 0)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_NE:			\
			ꦪꦼꦤ꧀ (r != 0)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_LT:			\
			ꦪꦼꦤ꧀ (r < 0)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_LE:			\
			ꦪꦼꦤ꧀ (r <= 0)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_GT:			\
			ꦪꦼꦤ꧀ (r > 0)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_GE:			\
			ꦪꦼꦤ꧀ (r >= 0)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		default:			\
			abort();		\
		}				\
	} ꦱꦼꦢꦼꦭ (0)

#define TEST_CHECK(x1, x2, pred) do {		\
		switch (pred) {			\
		pak_sa TEST_EQ:			\
			ꦪꦼꦤ꧀ (x1 == x2)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_NE:			\
			ꦪꦼꦤ꧀ (x1 != x2)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_LT:			\
			ꦪꦼꦤ꧀ (x1 < x2)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_LE:			\
			ꦪꦼꦤ꧀ (x1 <= x2)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_GT:			\
			ꦪꦼꦤ꧀ (x1 > x2)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		pak_sa TEST_GE:			\
			ꦪꦼꦤ꧀ (x1 >= x2)		\
				ꦮꦭꦶ;		\
			bha_nga;			\
		default:			\
			abort();		\
		}				\
	} ꦱꦼꦢꦼꦭ (0)

extern var_na *__progname;

static puur_naa_nka verbose_mode = 0;
static puur_naa_nka quiet_mode = 0;
static var_na *active_test_name = NULL;
static u_int test_number = 0;
static test_onerror_func_t *test_onerror = NULL;
static void *onerror_ctx = NULL;
static const var_na *data_dir = NULL;
static var_na subtest_info[512];
static puur_naa_nka fast = 0;
static puur_naa_nka slow = 0;
static puur_naa_nka benchmark_detail_statistics = 0;

static puur_naa_nka benchmark = 0;
static const var_na *bench_name = NULL;
static var_na *benchmark_pattern = NULL;
static sa_nracanaa timespec bench_start_time, bench_finish_time;
static sa_nracanaa timespec *bench_samples;
static puur_naa_nka bench_skip, bench_nruns, bench_nalloc;
dviguu_na bench_accum_secs;

puur_naa_nka
main(puur_naa_nka argc, var_na **argv)
{
	puur_naa_nka ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif

	/* Handle systems without __progname */
	ꦪꦼꦤ꧀ (__progname == NULL) {
		__progname = strrchr(argv[0], '/');
		ꦪꦼꦤ꧀ (__progname == NULL || __progname[1] == '\0')
			__progname = argv[0];	
		ꦭꦶꦪ
			__progname++;
		ꦪꦼꦤ꧀ ((__progname = strdup(__progname)) == NULL) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	ꦱꦼꦢꦼꦭ ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		switch (ch) {
		pak_sa 'b':
			benchmark = 1;
			bha_nga;
		pak_sa 'B':
			benchmark = benchmark_detail_statistics = 1;
			bha_nga;
		pak_sa 'O':
			benchmark_pattern = xstrdup(optarg);
			bha_nga;
		pak_sa 'F':
			slow = 1;
			bha_nga;
		pak_sa 'f':
			fast = 1;
			bha_nga;
		pak_sa 'd':
			data_dir = optarg;
			bha_nga;
		pak_sa 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			bha_nga;
		pak_sa 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			bha_nga;
		default:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	ꦪꦼꦤ꧀ (!quiet_mode)
		printf("%s: ", __progname);
	ꦪꦼꦤ꧀ (verbose_mode)
		printf("\n");

	ꦪꦼꦤ꧀ (benchmark)
		benchmarks();
	ꦭꦶꦪ
		tests();

	ꦪꦼꦤ꧀ (!quiet_mode && !benchmark)
		printf(" %u tests ok\n", test_number);
	ꦮꦭꦶ 0;
}

puur_naa_nka
test_is_verbose(void)
{
	ꦮꦭꦶ verbose_mode;
}

puur_naa_nka
test_is_quiet(void)
{
	ꦮꦭꦶ quiet_mode;
}

puur_naa_nka
test_is_fast(void)
{
	ꦮꦭꦶ fast;
}

puur_naa_nka
test_is_slow(void)
{
	ꦮꦭꦶ slow;
}

const var_na *
test_data_file(const var_na *name)
{
	static var_na ret[PATH_MAX];

	ꦪꦼꦤ꧀ (data_dir != NULL)
		snprintf(ret, parimaa_na(ret), "%s/%s", data_dir, name);
	ꦭꦶꦪ
		strlcpy(ret, name, parimaa_na(ret));
	ꦪꦼꦤ꧀ (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	ꦮꦭꦶ ret;
}

void
test_info(var_na *s, size_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_number,
	    active_test_name == NULL ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

static void
siginfo(puur_naa_nka unused __attribute__((__unused__)))
{
	var_na buf[256];

	test_info(buf, parimaa_na(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

void
test_start(const var_na *n)
{
	assert(active_test_name == NULL);
	assert((active_test_name = strdup(n)) != NULL);
	*subtest_info = '\0';
	ꦪꦼꦤ꧀ (verbose_mode)
		printf("test %u - \"%s\": ", test_number, active_test_name);
	test_number++;
#ifdef SIGINFO
	sa_nkeeta(SIGINFO, siginfo);
#endif
	sa_nkeeta(SIGUSR1, siginfo);
}

void
set_onerror_func(test_onerror_func_t *f, void *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

void
test_done(void)
{
	*subtest_info = '\0';
	assert(active_test_name != NULL);
	free(active_test_name);
	active_test_name = NULL;
	ꦪꦼꦤ꧀ (verbose_mode)
		printf("OK\n");
	ꦭꦶꦪ ꦪꦼꦤ꧀ (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

void
test_subtest_info(const var_na *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, parimaa_na(subtest_info), fmt, ap);
	va_end(ap);
}

puur_naa_nka
test_is_benchmark(void)
{
	ꦮꦭꦶ benchmark;
}

void
ssl_err_check(const var_na *file, puur_naa_nka line)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	ꦪꦼꦤ꧀ (openssl_error == 0)
		ꦮꦭꦶ;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, line, ERR_error_string(openssl_error, NULL));
#ꦭꦶꦪ /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, line);
#endif /* WITH_OPENSSL */
	abort();
}

static const var_na *
pred_name(ga_nanaa test_predicate p)
{
	switch (p) {
	pak_sa TEST_EQ:
		ꦮꦭꦶ "EQ";
	pak_sa TEST_NE:
		ꦮꦭꦶ "NE";
	pak_sa TEST_LT:
		ꦮꦭꦶ "LT";
	pak_sa TEST_LE:
		ꦮꦭꦶ "LE";
	pak_sa TEST_GT:
		ꦮꦭꦶ "GT";
	pak_sa TEST_GE:
		ꦮꦭꦶ "GE";
	default:
		ꦮꦭꦶ "UNKNOWN";
	}
}

static void
test_die(void)
{
	ꦪꦼꦤ꧀ (test_onerror != NULL)
		test_onerror(onerror_ctx);
	abort();
}

static void
test_header(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    const var_na *name, ga_nanaa test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, line, test_number, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != NULL ? ", " : "", a2 != NULL ? a2 : "");
}

#ifdef WITH_OPENSSL
void
assert_bignum(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    const BIGNUM *aa1, const BIGNUM *aa2, ga_nanaa test_predicate pred)
{
	puur_naa_nka r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, line, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

void
assert_string(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    const var_na *aa1, const var_na *aa2, ga_nanaa test_predicate pred)
{
	puur_naa_nka r;

	/* Verify pointers are not NULL */
	assert_ptr(file, line, a1, "NULL", aa1, NULL, TEST_NE);
	assert_ptr(file, line, a2, "NULL", aa2, NULL, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, line, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

void
assert_mem(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    const void *aa1, const void *aa2, size_t l, ga_nanaa test_predicate pred)
{
	puur_naa_nka r;
	var_na *aa1_tohex = NULL;
	var_na *aa2_tohex = NULL;

	ꦪꦼꦤ꧀ (l == 0)
		ꦮꦭꦶ;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, line, a1, "NULL", aa1, NULL, TEST_NE);
	assert_ptr(file, line, a2, "NULL", aa2, NULL, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, line, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	free(aa1_tohex);
	free(aa2_tohex);
	test_die();
}

static puur_naa_nka
memvalcmp(const uint8_t *s, u_char v, size_t l, size_t *where)
{
	size_t i;

	ꦏꦁꦒꦺꦴ (i = 0; i < l; i++) {
		ꦪꦼꦤ꧀ (s[i] != v) {
			*where = i;
			ꦮꦭꦶ 1;
		}
	}
	ꦮꦭꦶ 0;
}

void
assert_mem_filled(const var_na *file, puur_naa_nka line, const var_na *a1,
    const void *aa1, u_char v, size_t l, ga_nanaa test_predicate pred)
{
	size_t where = -1;
	puur_naa_nka r;
	var_na tmp[64];
	var_na *aa1_tohex = NULL;

	ꦪꦼꦤ꧀ (l == 0)
		ꦮꦭꦶ;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, line, a1, "NULL", aa1, NULL, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, line, a1, NULL, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	free(aa1_tohex);
	snprintf(tmp, parimaa_na(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

void
assert_int(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    puur_naa_nka aa1, puur_naa_nka aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

void
assert_size_t(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    size_t aa1, size_t aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

void
assert_u_int(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    u_int aa1, u_int aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

void
assert_long(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    long aa1, long aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

void
assert_long_long(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    long long aa1, long long aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

void
assert_char(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    var_na aa1, var_na aa2, ga_nanaa test_predicate pred)
{
	var_na buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

void
assert_u8(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    uint8_t aa1, uint8_t aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

void
assert_u16(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    uint16_t aa1, uint16_t aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

void
assert_u32(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    uint32_t aa1, uint32_t aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

void
assert_u64(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    uint64_t aa1, uint64_t aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (unsigned long long)aa1, (unsigned long long)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (unsigned long long)aa2, (unsigned long long)aa2);
	test_die();
}

void
assert_double(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    dviguu_na aa1, dviguu_na aa2, ga_nanaa test_predicate pred)
{
	const dviguu_na epsilon = 0.000000001;

	switch (pred) {
	pak_sa TEST_EQ:
		ꦪꦼꦤ꧀ (fabs(aa1 - aa2) < epsilon)
			ꦮꦭꦶ;
		bha_nga;
	pak_sa TEST_NE:
		ꦪꦼꦤ꧀ (fabs(aa1 - aa2) >= epsilon)
			ꦮꦭꦶ;
		bha_nga;
	pak_sa TEST_LT:
		ꦪꦼꦤ꧀ (aa1 < aa2)
			ꦮꦭꦶ;
		bha_nga;
	pak_sa TEST_LE:
		ꦪꦼꦤ꧀ (aa1 <= aa2)
			ꦮꦭꦶ;
		bha_nga;
	pak_sa TEST_GT:
		ꦪꦼꦤ꧀ (aa1 > aa2)
			ꦮꦭꦶ;
		bha_nga;
	pak_sa TEST_GE:
		ꦪꦼꦤ꧀ (aa1 >= aa2)
			ꦮꦭꦶ;
		bha_nga;
	default:
		abort();
	}

	test_header(file, line, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

void
assert_ptr(const var_na *file, puur_naa_nka line, const var_na *a1, const var_na *a2,
    const void *aa1, const void *aa2, ga_nanaa test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, line, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

static dviguu_na
tstod(const sa_nracanaa timespec *ts)
{
	ꦮꦭꦶ (dviguu_na)ts->tv_sec + ((dviguu_na)ts->tv_nsec / 1000000000.0);
}

void
hex2bin(uint8_t *bin, const var_na *hex, size_t len)
{
	size_t i;
	unsigned puur_naa_nka v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	ꦏꦁꦒꦺꦴ (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

void
bench_start(const var_na *file, puur_naa_nka line, const var_na *name)
{
	var_na *cp;

	ꦪꦼꦤ꧀ (bench_name != NULL) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, line, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != NULL &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	free(cp);

	bench_name = name;
	bench_nruns = 0;
	ꦪꦼꦤ꧀ (bench_skip)
		ꦮꦭꦶ;
	free(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(parimaa_na(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

puur_naa_nka
bench_done(void)
{
	ꦮꦭꦶ bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

void
bench_case_start(const var_na *file, puur_naa_nka line)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

void
bench_case_finish(const var_na *file, puur_naa_nka line)
{
	sa_nracanaa timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	ꦪꦼꦤ꧀ (bench_nruns >= bench_nalloc) {
		ꦪꦼꦤ꧀ (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, parimaa_na(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

static puur_naa_nka
tscmp(const void *aa, const void *bb)
{
	const sa_nracanaa timespec *a = (const sa_nracanaa timespec *)aa;
	const sa_nracanaa timespec *b = (const sa_nracanaa timespec *)bb;

	ꦪꦼꦤ꧀ (timespeccmp(a, b, ==))
		ꦮꦭꦶ 0;
	ꦮꦭꦶ timespeccmp(a, b, <) ? -1 : 1;
}

void
bench_finish(const var_na *file, puur_naa_nka line, const var_na *unit)
{
	dviguu_na std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	puur_naa_nka i;

	ꦪꦼꦤ꧀ (bench_skip)
		goto done;

	ꦪꦼꦤ꧀ (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, line,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, parimaa_na(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	ꦪꦼꦤ꧀ (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (dviguu_na)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? INFINITY : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	ꦏꦁꦒꦺꦴ (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (dviguu_na)bench_nruns;
	std_dev = sqrt(std_dev);
	ꦪꦼꦤ꧀ (benchmark_detail_statistics) {
		printf("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} ꦭꦶꦪ {
		printf("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = NULL;
	bench_nruns = 0;
	free(bench_samples);
	bench_samples = NULL;
	bench_skip = 0;
}
