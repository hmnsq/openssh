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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/uio.h>
#અન્તર્ભાવ <sys/time.h>

#અન્તર્ભાવ <assert.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <math.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/err.h>
#endif

#જો defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#અન્તર્ભાવ "entropy.h"
#અન્તર્ભાવ "test_helper.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "xmalloc.h"

#define BENCH_FAST_DEADLINE	1
#define BENCH_NORMAL_DEADLINE	10
#define BENCH_SLOW_DEADLINE	60
#define BENCH_SAMPLES_ALLOC	8192
#define BENCH_COLUMN_WIDTH	40

#define MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#define TEST_CHECK_INT(r, pred) કરો {		\
		પસંદગી (pred) {			\
		સ્થિતિ TEST_EQ:			\
			જો (r == 0)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_NE:			\
			જો (r != 0)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_LT:			\
			જો (r < 0)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_LE:			\
			જો (r <= 0)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_GT:			\
			જો (r > 0)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_GE:			\
			જો (r >= 0)		\
				પાછા;		\
			તોડો;			\
		મૂળભૂત:			\
			abort();		\
		}				\
	} જ્યારે (0)

#define TEST_CHECK(x1, x2, pred) કરો {		\
		પસંદગી (pred) {			\
		સ્થિતિ TEST_EQ:			\
			જો (x1 == x2)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_NE:			\
			જો (x1 != x2)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_LT:			\
			જો (x1 < x2)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_LE:			\
			જો (x1 <= x2)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_GT:			\
			જો (x1 > x2)		\
				પાછા;		\
			તોડો;			\
		સ્થિતિ TEST_GE:			\
			જો (x1 >= x2)		\
				પાછા;		\
			તોડો;			\
		મૂળભૂત:			\
			abort();		\
		}				\
	} જ્યારે (0)

બાહ્ય અક્ષર *__progname;

સ્થિર પૂર્ણાંક verbose_mode = 0;
સ્થિર પૂર્ણાંક quiet_mode = 0;
સ્થિર અક્ષર *active_test_name = ખાલી;
સ્થિર u_int test_સંખ્યા = 0;
સ્થિર test_onerror_func_t *test_onerror = ખાલી;
સ્થિર શૂન્ય *onerror_ctx = ખાલી;
સ્થિર અચલ અક્ષર *data_dir = ખાલી;
સ્થિર અક્ષર subtest_info[512];
સ્થિર પૂર્ણાંક fast = 0;
સ્થિર પૂર્ણાંક slow = 0;
સ્થિર પૂર્ણાંક benchmark_detail_statistics = 0;

સ્થિર પૂર્ણાંક benchmark = 0;
સ્થિર અચલ અક્ષર *bench_name = ખાલી;
સ્થિર અક્ષર *benchmark_pattern = ખાલી;
સ્થિર સંરચના timespec bench_start_time, bench_finish_time;
સ્થિર સંરચના timespec *bench_samples;
સ્થિર પૂર્ણાંક bench_skip, bench_nruns, bench_nalloc;
દ્વિગુણ bench_accum_secs;

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	પૂર્ણાંક ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ખાલી);
#endif

	/* Handle systems without __progname */
	જો (__progname == ખાલી) {
		__progname = strrchr(argv[0], '/');
		જો (__progname == ખાલી || __progname[1] == '\0')
			__progname = argv[0];	
		નહીંતર
			__progname++;
		જો ((__progname = strdup(__progname)) == ખાલી) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	જ્યારે ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'b':
			benchmark = 1;
			તોડો;
		સ્થિતિ 'B':
			benchmark = benchmark_detail_statistics = 1;
			તોડો;
		સ્થિતિ 'O':
			benchmark_pattern = xstrdup(optarg);
			તોડો;
		સ્થિતિ 'F':
			slow = 1;
			તોડો;
		સ્થિતિ 'f':
			fast = 1;
			તોડો;
		સ્થિતિ 'd':
			data_dir = optarg;
			તોડો;
		સ્થિતિ 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			તોડો;
		સ્થિતિ 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			તોડો;
		મૂળભૂત:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, ખાલી, _IONBF, 0);
	જો (!quiet_mode)
		printf("%s: ", __progname);
	જો (verbose_mode)
		printf("\n");

	જો (benchmark)
		benchmarks();
	નહીંતર
		tests();

	જો (!quiet_mode && !benchmark)
		printf(" %u tests ok\n", test_સંખ્યા);
	પાછા 0;
}

પૂર્ણાંક
test_is_verbose(શૂન્ય)
{
	પાછા verbose_mode;
}

પૂર્ણાંક
test_is_quiet(શૂન્ય)
{
	પાછા quiet_mode;
}

પૂર્ણાંક
test_is_fast(શૂન્ય)
{
	પાછા fast;
}

પૂર્ણાંક
test_is_slow(શૂન્ય)
{
	પાછા slow;
}

અચલ અક્ષર *
test_data_file(અચલ અક્ષર *name)
{
	સ્થિર અક્ષર ret[PATH_MAX];

	જો (data_dir != ખાલી)
		snprintf(ret, કદ(ret), "%s/%s", data_dir, name);
	નહીંતર
		strlcpy(ret, name, કદ(ret));
	જો (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	પાછા ret;
}

શૂન્ય
test_info(અક્ષર *s, size_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_સંખ્યા,
	    active_test_name == ખાલી ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

સ્થિર શૂન્ય
siginfo(પૂર્ણાંક unused __attribute__((__unused__)))
{
	અક્ષર buf[256];

	test_info(buf, કદ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

શૂન્ય
test_start(અચલ અક્ષર *n)
{
	પ્રતિજ્ઞા(active_test_name == ખાલી);
	પ્રતિજ્ઞા((active_test_name = strdup(n)) != ખાલી);
	*subtest_info = '\0';
	જો (verbose_mode)
		printf("test %u - \"%s\": ", test_સંખ્યા, active_test_name);
	test_સંખ્યા++;
#ifdef SIGINFO
	સંકેત(SIGINFO, siginfo);
#endif
	સંકેત(SIGUSR1, siginfo);
}

શૂન્ય
set_onerror_func(test_onerror_func_t *f, શૂન્ય *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

શૂન્ય
test_done(શૂન્ય)
{
	*subtest_info = '\0';
	પ્રતિજ્ઞા(active_test_name != ખાલી);
	મુક્ત(active_test_name);
	active_test_name = ખાલી;
	જો (verbose_mode)
		printf("OK\n");
	નહીંતર જો (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

શૂન્ય
test_subtest_info(અચલ અક્ષર *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, કદ(subtest_info), fmt, ap);
	va_end(ap);
}

પૂર્ણાંક
test_is_benchmark(શૂન્ય)
{
	પાછા benchmark;
}

શૂન્ય
ssl_err_check(અચલ અક્ષર *file, પૂર્ણાંક લીટી)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	જો (openssl_error == 0)
		પાછા;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, લીટી, ERR_error_string(openssl_error, ખાલી));
#નહીંતર /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, લીટી);
#endif /* WITH_OPENSSL */
	abort();
}

સ્થિર અચલ અક્ષર *
pred_name(ગણના test_predicate p)
{
	પસંદગી (p) {
	સ્થિતિ TEST_EQ:
		પાછા "EQ";
	સ્થિતિ TEST_NE:
		પાછા "NE";
	સ્થિતિ TEST_LT:
		પાછા "LT";
	સ્થિતિ TEST_LE:
		પાછા "LE";
	સ્થિતિ TEST_GT:
		પાછા "GT";
	સ્થિતિ TEST_GE:
		પાછા "GE";
	મૂળભૂત:
		પાછા "UNKNOWN";
	}
}

સ્થિર શૂન્ય
test_die(શૂન્ય)
{
	જો (test_onerror != ખાલી)
		test_onerror(onerror_ctx);
	abort();
}

સ્થિર શૂન્ય
test_header(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અચલ અક્ષર *name, ગણના test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, લીટી, test_સંખ્યા, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != ખાલી ? ", " : "", a2 != ખાલી ? a2 : "");
}

#ifdef WITH_OPENSSL
શૂન્ય
assert_bignum(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અચલ BIGNUM *aa1, અચલ BIGNUM *aa2, ગણના test_predicate pred)
{
	પૂર્ણાંક r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, લીટી, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

શૂન્ય
assert_string(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અચલ અક્ષર *aa1, અચલ અક્ષર *aa2, ગણના test_predicate pred)
{
	પૂર્ણાંક r;

	/* Verify pointers are not NULL */
	assert_ptr(file, લીટી, a1, "NULL", aa1, ખાલી, TEST_NE);
	assert_ptr(file, લીટી, a2, "NULL", aa2, ખાલી, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, લીટી, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

શૂન્ય
assert_mem(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અચલ શૂન્ય *aa1, અચલ શૂન્ય *aa2, size_t l, ગણના test_predicate pred)
{
	પૂર્ણાંક r;
	અક્ષર *aa1_tohex = ખાલી;
	અક્ષર *aa2_tohex = ખાલી;

	જો (l == 0)
		પાછા;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, લીટી, a1, "NULL", aa1, ખાલી, TEST_NE);
	assert_ptr(file, લીટી, a2, "NULL", aa2, ખાલી, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, લીટી, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	મુક્ત(aa1_tohex);
	મુક્ત(aa2_tohex);
	test_die();
}

સ્થિર પૂર્ણાંક
memvalcmp(અચલ uint8_t *s, u_char v, size_t l, size_t *where)
{
	size_t i;

	માટે (i = 0; i < l; i++) {
		જો (s[i] != v) {
			*where = i;
			પાછા 1;
		}
	}
	પાછા 0;
}

શૂન્ય
assert_mem_filled(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1,
    અચલ શૂન્ય *aa1, u_char v, size_t l, ગણના test_predicate pred)
{
	size_t where = -1;
	પૂર્ણાંક r;
	અક્ષર tmp[64];
	અક્ષર *aa1_tohex = ખાલી;

	જો (l == 0)
		પાછા;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, લીટી, a1, "NULL", aa1, ખાલી, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, લીટી, a1, ખાલી, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	મુક્ત(aa1_tohex);
	snprintf(tmp, કદ(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

શૂન્ય
assert_int(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    પૂર્ણાંક aa1, પૂર્ણાંક aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

શૂન્ય
assert_size_t(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    size_t aa1, size_t aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

શૂન્ય
assert_u_int(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    u_int aa1, u_int aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

શૂન્ય
assert_long(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    long aa1, long aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

શૂન્ય
assert_long_long(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    long long aa1, long long aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

શૂન્ય
assert_char(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અક્ષર aa1, અક્ષર aa2, ગણના test_predicate pred)
{
	અક્ષર buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

શૂન્ય
assert_u8(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    uint8_t aa1, uint8_t aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

શૂન્ય
assert_u16(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    uint16_t aa1, uint16_t aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

શૂન્ય
assert_u32(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    uint32_t aa1, uint32_t aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

શૂન્ય
assert_u64(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    uint64_t aa1, uint64_t aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (unsigned long long)aa1, (unsigned long long)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (unsigned long long)aa2, (unsigned long long)aa2);
	test_die();
}

શૂન્ય
assert_double(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    દ્વિગુણ aa1, દ્વિગુણ aa2, ગણના test_predicate pred)
{
	અચલ દ્વિગુણ epsilon = 0.000000001;

	પસંદગી (pred) {
	સ્થિતિ TEST_EQ:
		જો (fabs(aa1 - aa2) < epsilon)
			પાછા;
		તોડો;
	સ્થિતિ TEST_NE:
		જો (fabs(aa1 - aa2) >= epsilon)
			પાછા;
		તોડો;
	સ્થિતિ TEST_LT:
		જો (aa1 < aa2)
			પાછા;
		તોડો;
	સ્થિતિ TEST_LE:
		જો (aa1 <= aa2)
			પાછા;
		તોડો;
	સ્થિતિ TEST_GT:
		જો (aa1 > aa2)
			પાછા;
		તોડો;
	સ્થિતિ TEST_GE:
		જો (aa1 >= aa2)
			પાછા;
		તોડો;
	મૂળભૂત:
		abort();
	}

	test_header(file, લીટી, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

શૂન્ય
assert_ptr(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અચલ શૂન્ય *aa1, અચલ શૂન્ય *aa2, ગણના test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, લીટી, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

સ્થિર દ્વિગુણ
tstod(અચલ સંરચના timespec *ts)
{
	પાછા (દ્વિગુણ)ts->tv_sec + ((દ્વિગુણ)ts->tv_nsec / 1000000000.0);
}

શૂન્ય
hex2bin(uint8_t *bin, અચલ અક્ષર *hex, size_t len)
{
	size_t i;
	unsigned પૂર્ણાંક v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	માટે (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

શૂન્ય
bench_start(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *name)
{
	અક્ષર *cp;

	જો (bench_name != ખાલી) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, લીટી, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != ખાલી &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	મુક્ત(cp);

	bench_name = name;
	bench_nruns = 0;
	જો (bench_skip)
		પાછા;
	મુક્ત(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(કદ(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

પૂર્ણાંક
bench_done(શૂન્ય)
{
	પાછા bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

શૂન્ય
bench_case_start(અચલ અક્ષર *file, પૂર્ણાંક લીટી)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

શૂન્ય
bench_case_finish(અચલ અક્ષર *file, પૂર્ણાંક લીટી)
{
	સંરચના timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	જો (bench_nruns >= bench_nalloc) {
		જો (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, કદ(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

સ્થિર પૂર્ણાંક
tscmp(અચલ શૂન્ય *aa, અચલ શૂન્ય *bb)
{
	અચલ સંરચના timespec *a = (અચલ સંરચના timespec *)aa;
	અચલ સંરચના timespec *b = (અચલ સંરચના timespec *)bb;

	જો (timespeccmp(a, b, ==))
		પાછા 0;
	પાછા timespeccmp(a, b, <) ? -1 : 1;
}

શૂન્ય
bench_finish(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *unit)
{
	દ્વિગુણ std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	પૂર્ણાંક i;

	જો (bench_skip)
		જાઓ done;

	જો (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, લીટી,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, કદ(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	જો (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (દ્વિગુણ)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? INFINITY : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	માટે (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (દ્વિગુણ)bench_nruns;
	std_dev = sqrt(std_dev);
	જો (benchmark_detail_statistics) {
		printf("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} નહીંતર {
		printf("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = ખાલી;
	bench_nruns = 0;
	મુક્ત(bench_samples);
	bench_samples = ખાલી;
	bench_skip = 0;
}
