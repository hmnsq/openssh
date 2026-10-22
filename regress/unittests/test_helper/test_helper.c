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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/uio.h>
#அந்தர்பாவ <sys/time.h>

#அந்தர்பாவ <assert.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <math.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/err.h>
#endif

#எனில் defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#அந்தர்பாவ "entropy.h"
#அந்தர்பாவ "test_helper.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "xmalloc.h"

#define BENCH_FAST_DEADLINE	1
#define BENCH_NORMAL_DEADLINE	10
#define BENCH_SLOW_DEADLINE	60
#define BENCH_SAMPLES_ALLOC	8192
#define BENCH_COLUMN_WIDTH	40

#define MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#define TEST_CHECK_INT(r, pred) செய் {		\
		தேர்வு (pred) {			\
		நிலை TEST_EQ:			\
			எனில் (r == 0)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_NE:			\
			எனில் (r != 0)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_LT:			\
			எனில் (r < 0)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_LE:			\
			எனில் (r <= 0)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_GT:			\
			எனில் (r > 0)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_GE:			\
			எனில் (r >= 0)		\
				திரும்பு;		\
			நிறுத்து;			\
		இயல்பு:			\
			abort();		\
		}				\
	} போது (0)

#define TEST_CHECK(x1, x2, pred) செய் {		\
		தேர்வு (pred) {			\
		நிலை TEST_EQ:			\
			எனில் (x1 == x2)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_NE:			\
			எனில் (x1 != x2)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_LT:			\
			எனில் (x1 < x2)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_LE:			\
			எனில் (x1 <= x2)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_GT:			\
			எனில் (x1 > x2)		\
				திரும்பு;		\
			நிறுத்து;			\
		நிலை TEST_GE:			\
			எனில் (x1 >= x2)		\
				திரும்பு;		\
			நிறுத்து;			\
		இயல்பு:			\
			abort();		\
		}				\
	} போது (0)

வெளி எழுத்து *__progname;

நிலையான முழு verbose_mode = 0;
நிலையான முழு quiet_mode = 0;
நிலையான எழுத்து *active_test_name = வெற்று;
நிலையான u_int test_எண் = 0;
நிலையான test_onerror_func_t *test_onerror = வெற்று;
நிலையான வெறுமை *onerror_ctx = வெற்று;
நிலையான மாறிலி எழுத்து *data_dir = வெற்று;
நிலையான எழுத்து subtest_info[512];
நிலையான முழு fast = 0;
நிலையான முழு slow = 0;
நிலையான முழு benchmark_detail_statistics = 0;

நிலையான முழு benchmark = 0;
நிலையான மாறிலி எழுத்து *bench_name = வெற்று;
நிலையான எழுத்து *benchmark_pattern = வெற்று;
நிலையான கட்டமைப்பு timespec bench_start_time, bench_finish_time;
நிலையான கட்டமைப்பு timespec *bench_samples;
நிலையான முழு bench_skip, bench_nruns, bench_nalloc;
இரட்டை bench_accum_secs;

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	முழு ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, வெற்று);
#endif

	/* Handle systems without __progname */
	எனில் (__progname == வெற்று) {
		__progname = strrchr(argv[0], '/');
		எனில் (__progname == வெற்று || __progname[1] == '\0')
			__progname = argv[0];	
		இல்லையெனில்
			__progname++;
		எனில் ((__progname = strdup(__progname)) == வெற்று) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	போது ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		தேர்வு (ch) {
		நிலை 'b':
			benchmark = 1;
			நிறுத்து;
		நிலை 'B':
			benchmark = benchmark_detail_statistics = 1;
			நிறுத்து;
		நிலை 'O':
			benchmark_pattern = xstrdup(optarg);
			நிறுத்து;
		நிலை 'F':
			slow = 1;
			நிறுத்து;
		நிலை 'f':
			fast = 1;
			நிறுத்து;
		நிலை 'd':
			data_dir = optarg;
			நிறுத்து;
		நிலை 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			நிறுத்து;
		நிலை 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			நிறுத்து;
		இயல்பு:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, வெற்று, _IONBF, 0);
	எனில் (!quiet_mode)
		printf("%s: ", __progname);
	எனில் (verbose_mode)
		printf("\n");

	எனில் (benchmark)
		benchmarks();
	இல்லையெனில்
		tests();

	எனில் (!quiet_mode && !benchmark)
		printf(" %u tests ok\n", test_எண்);
	திரும்பு 0;
}

முழு
test_is_verbose(வெறுமை)
{
	திரும்பு verbose_mode;
}

முழு
test_is_quiet(வெறுமை)
{
	திரும்பு quiet_mode;
}

முழு
test_is_fast(வெறுமை)
{
	திரும்பு fast;
}

முழு
test_is_slow(வெறுமை)
{
	திரும்பு slow;
}

மாறிலி எழுத்து *
test_data_file(மாறிலி எழுத்து *name)
{
	நிலையான எழுத்து ret[PATH_MAX];

	எனில் (data_dir != வெற்று)
		snprintf(ret, அளவு(ret), "%s/%s", data_dir, name);
	இல்லையெனில்
		strlcpy(ret, name, அளவு(ret));
	எனில் (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	திரும்பு ret;
}

வெறுமை
test_info(எழுத்து *s, size_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_எண்,
	    active_test_name == வெற்று ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

நிலையான வெறுமை
siginfo(முழு unused __attribute__((__unused__)))
{
	எழுத்து buf[256];

	test_info(buf, அளவு(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

வெறுமை
test_start(மாறிலி எழுத்து *n)
{
	ப்ரதிஜ்ஞா(active_test_name == வெற்று);
	ப்ரதிஜ்ஞா((active_test_name = strdup(n)) != வெற்று);
	*subtest_info = '\0';
	எனில் (verbose_mode)
		printf("test %u - \"%s\": ", test_எண், active_test_name);
	test_எண்++;
#ifdef SIGINFO
	சமிக்ஞை(SIGINFO, siginfo);
#endif
	சமிக்ஞை(SIGUSR1, siginfo);
}

வெறுமை
set_onerror_func(test_onerror_func_t *f, வெறுமை *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

வெறுமை
test_done(வெறுமை)
{
	*subtest_info = '\0';
	ப்ரதிஜ்ஞா(active_test_name != வெற்று);
	விடுவி(active_test_name);
	active_test_name = வெற்று;
	எனில் (verbose_mode)
		printf("OK\n");
	இல்லையெனில் எனில் (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

வெறுமை
test_subtest_info(மாறிலி எழுத்து *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, அளவு(subtest_info), fmt, ap);
	va_end(ap);
}

முழு
test_is_benchmark(வெறுமை)
{
	திரும்பு benchmark;
}

வெறுமை
ssl_err_check(மாறிலி எழுத்து *file, முழு வரி)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	எனில் (openssl_error == 0)
		திரும்பு;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, வரி, ERR_error_string(openssl_error, வெற்று));
#இல்லையெனில் /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, வரி);
#endif /* WITH_OPENSSL */
	abort();
}

நிலையான மாறிலி எழுத்து *
pred_name(எண்ணிக்கை test_predicate p)
{
	தேர்வு (p) {
	நிலை TEST_EQ:
		திரும்பு "EQ";
	நிலை TEST_NE:
		திரும்பு "NE";
	நிலை TEST_LT:
		திரும்பு "LT";
	நிலை TEST_LE:
		திரும்பு "LE";
	நிலை TEST_GT:
		திரும்பு "GT";
	நிலை TEST_GE:
		திரும்பு "GE";
	இயல்பு:
		திரும்பு "UNKNOWN";
	}
}

நிலையான வெறுமை
test_die(வெறுமை)
{
	எனில் (test_onerror != வெற்று)
		test_onerror(onerror_ctx);
	abort();
}

நிலையான வெறுமை
test_header(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    மாறிலி எழுத்து *name, எண்ணிக்கை test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, வரி, test_எண், active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != வெற்று ? ", " : "", a2 != வெற்று ? a2 : "");
}

#ifdef WITH_OPENSSL
வெறுமை
assert_bignum(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    மாறிலி BIGNUM *aa1, மாறிலி BIGNUM *aa2, எண்ணிக்கை test_predicate pred)
{
	முழு r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, வரி, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

வெறுமை
assert_string(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    மாறிலி எழுத்து *aa1, மாறிலி எழுத்து *aa2, எண்ணிக்கை test_predicate pred)
{
	முழு r;

	/* Verify pointers are not NULL */
	assert_ptr(file, வரி, a1, "NULL", aa1, வெற்று, TEST_NE);
	assert_ptr(file, வரி, a2, "NULL", aa2, வெற்று, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, வரி, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

வெறுமை
assert_mem(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    மாறிலி வெறுமை *aa1, மாறிலி வெறுமை *aa2, size_t l, எண்ணிக்கை test_predicate pred)
{
	முழு r;
	எழுத்து *aa1_tohex = வெற்று;
	எழுத்து *aa2_tohex = வெற்று;

	எனில் (l == 0)
		திரும்பு;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, வரி, a1, "NULL", aa1, வெற்று, TEST_NE);
	assert_ptr(file, வரி, a2, "NULL", aa2, வெற்று, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, வரி, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	விடுவி(aa1_tohex);
	விடுவி(aa2_tohex);
	test_die();
}

நிலையான முழு
memvalcmp(மாறிலி uint8_t *s, u_char v, size_t l, size_t *where)
{
	size_t i;

	க்கு (i = 0; i < l; i++) {
		எனில் (s[i] != v) {
			*where = i;
			திரும்பு 1;
		}
	}
	திரும்பு 0;
}

வெறுமை
assert_mem_filled(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1,
    மாறிலி வெறுமை *aa1, u_char v, size_t l, எண்ணிக்கை test_predicate pred)
{
	size_t where = -1;
	முழு r;
	எழுத்து tmp[64];
	எழுத்து *aa1_tohex = வெற்று;

	எனில் (l == 0)
		திரும்பு;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, வரி, a1, "NULL", aa1, வெற்று, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, வரி, a1, வெற்று, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	விடுவி(aa1_tohex);
	snprintf(tmp, அளவு(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

வெறுமை
assert_int(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    முழு aa1, முழு aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

வெறுமை
assert_size_t(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    size_t aa1, size_t aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

வெறுமை
assert_u_int(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    u_int aa1, u_int aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

வெறுமை
assert_long(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    long aa1, long aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

வெறுமை
assert_long_long(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    long long aa1, long long aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

வெறுமை
assert_char(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    எழுத்து aa1, எழுத்து aa2, எண்ணிக்கை test_predicate pred)
{
	எழுத்து buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

வெறுமை
assert_u8(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    uint8_t aa1, uint8_t aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

வெறுமை
assert_u16(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    uint16_t aa1, uint16_t aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

வெறுமை
assert_u32(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    uint32_t aa1, uint32_t aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

வெறுமை
assert_u64(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    uint64_t aa1, uint64_t aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (unsigned long long)aa1, (unsigned long long)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (unsigned long long)aa2, (unsigned long long)aa2);
	test_die();
}

வெறுமை
assert_double(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    இரட்டை aa1, இரட்டை aa2, எண்ணிக்கை test_predicate pred)
{
	மாறிலி இரட்டை epsilon = 0.000000001;

	தேர்வு (pred) {
	நிலை TEST_EQ:
		எனில் (fabs(aa1 - aa2) < epsilon)
			திரும்பு;
		நிறுத்து;
	நிலை TEST_NE:
		எனில் (fabs(aa1 - aa2) >= epsilon)
			திரும்பு;
		நிறுத்து;
	நிலை TEST_LT:
		எனில் (aa1 < aa2)
			திரும்பு;
		நிறுத்து;
	நிலை TEST_LE:
		எனில் (aa1 <= aa2)
			திரும்பு;
		நிறுத்து;
	நிலை TEST_GT:
		எனில் (aa1 > aa2)
			திரும்பு;
		நிறுத்து;
	நிலை TEST_GE:
		எனில் (aa1 >= aa2)
			திரும்பு;
		நிறுத்து;
	இயல்பு:
		abort();
	}

	test_header(file, வரி, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

வெறுமை
assert_ptr(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    மாறிலி வெறுமை *aa1, மாறிலி வெறுமை *aa2, எண்ணிக்கை test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, வரி, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

நிலையான இரட்டை
tstod(மாறிலி கட்டமைப்பு timespec *ts)
{
	திரும்பு (இரட்டை)ts->tv_sec + ((இரட்டை)ts->tv_nsec / 1000000000.0);
}

வெறுமை
hex2bin(uint8_t *bin, மாறிலி எழுத்து *hex, size_t len)
{
	size_t i;
	unsigned முழு v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	க்கு (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

வெறுமை
bench_start(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *name)
{
	எழுத்து *cp;

	எனில் (bench_name != வெற்று) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, வரி, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != வெற்று &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	விடுவி(cp);

	bench_name = name;
	bench_nruns = 0;
	எனில் (bench_skip)
		திரும்பு;
	விடுவி(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(அளவு(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

முழு
bench_done(வெறுமை)
{
	திரும்பு bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

வெறுமை
bench_case_start(மாறிலி எழுத்து *file, முழு வரி)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

வெறுமை
bench_case_finish(மாறிலி எழுத்து *file, முழு வரி)
{
	கட்டமைப்பு timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	எனில் (bench_nruns >= bench_nalloc) {
		எனில் (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, அளவு(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

நிலையான முழு
tscmp(மாறிலி வெறுமை *aa, மாறிலி வெறுமை *bb)
{
	மாறிலி கட்டமைப்பு timespec *a = (மாறிலி கட்டமைப்பு timespec *)aa;
	மாறிலி கட்டமைப்பு timespec *b = (மாறிலி கட்டமைப்பு timespec *)bb;

	எனில் (timespeccmp(a, b, ==))
		திரும்பு 0;
	திரும்பு timespeccmp(a, b, <) ? -1 : 1;
}

வெறுமை
bench_finish(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *unit)
{
	இரட்டை std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	முழு i;

	எனில் (bench_skip)
		செல் done;

	எனில் (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, வரி,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, அளவு(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	எனில் (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (இரட்டை)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? INFINITY : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	க்கு (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (இரட்டை)bench_nruns;
	std_dev = sqrt(std_dev);
	எனில் (benchmark_detail_statistics) {
		printf("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} இல்லையெனில் {
		printf("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = வெற்று;
	bench_nruns = 0;
	விடுவி(bench_samples);
	bench_samples = வெற்று;
	bench_skip = 0;
}
