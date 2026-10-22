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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/uio.h>
#അന്തര്ഭാവ <sys/time.h>

#അന്തര്ഭാവ <assert.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <math.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/err.h>
#endif

#എങ്കിൽ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#അന്തര്ഭാവ "entropy.h"
#അന്തര്ഭാവ "test_helper.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "xmalloc.h"

#define BENCH_FAST_DEADLINE	1
#define BENCH_NORMAL_DEADLINE	10
#define BENCH_SLOW_DEADLINE	60
#define BENCH_SAMPLES_ALLOC	8192
#define BENCH_COLUMN_WIDTH	40

#define MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#define TEST_CHECK_INT(r, pred) ചെയ്യുക {		\
		തിരഞ്ഞെടുപ്പ് (pred) {			\
		അവസ്ഥ TEST_EQ:			\
			എങ്കിൽ (r == 0)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_NE:			\
			എങ്കിൽ (r != 0)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_LT:			\
			എങ്കിൽ (r < 0)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_LE:			\
			എങ്കിൽ (r <= 0)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_GT:			\
			എങ്കിൽ (r > 0)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_GE:			\
			എങ്കിൽ (r >= 0)		\
				തിരികെ;		\
			നിർത്തുക;			\
		സ്ഥിരസ്ഥിതി:			\
			abort();		\
		}				\
	} ആകുമ്പോൾ (0)

#define TEST_CHECK(x1, x2, pred) ചെയ്യുക {		\
		തിരഞ്ഞെടുപ്പ് (pred) {			\
		അവസ്ഥ TEST_EQ:			\
			എങ്കിൽ (x1 == x2)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_NE:			\
			എങ്കിൽ (x1 != x2)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_LT:			\
			എങ്കിൽ (x1 < x2)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_LE:			\
			എങ്കിൽ (x1 <= x2)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_GT:			\
			എങ്കിൽ (x1 > x2)		\
				തിരികെ;		\
			നിർത്തുക;			\
		അവസ്ഥ TEST_GE:			\
			എങ്കിൽ (x1 >= x2)		\
				തിരികെ;		\
			നിർത്തുക;			\
		സ്ഥിരസ്ഥിതി:			\
			abort();		\
		}				\
	} ആകുമ്പോൾ (0)

ബാഹ്യ അക്ഷരം *__progname;

സ്ഥിതം പൂർണ്ണസംഖ്യ verbose_mode = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ quiet_mode = 0;
സ്ഥിതം അക്ഷരം *active_test_name = ശൂന്യ;
സ്ഥിതം u_int test_സംഖ്യ = 0;
സ്ഥിതം test_onerror_func_t *test_onerror = ശൂന്യ;
സ്ഥിതം ശൂന്യം *onerror_ctx = ശൂന്യ;
സ്ഥിതം സ്ഥിരം അക്ഷരം *data_dir = ശൂന്യ;
സ്ഥിതം അക്ഷരം subtest_info[512];
സ്ഥിതം പൂർണ്ണസംഖ്യ fast = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ slow = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ benchmark_detail_statistics = 0;

സ്ഥിതം പൂർണ്ണസംഖ്യ benchmark = 0;
സ്ഥിതം സ്ഥിരം അക്ഷരം *bench_name = ശൂന്യ;
സ്ഥിതം അക്ഷരം *benchmark_pattern = ശൂന്യ;
സ്ഥിതം ഘടന timespec bench_start_time, bench_finish_time;
സ്ഥിതം ഘടന timespec *bench_samples;
സ്ഥിതം പൂർണ്ണസംഖ്യ bench_skip, bench_nruns, bench_nalloc;
ഇരട്ട bench_accum_secs;

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	പൂർണ്ണസംഖ്യ ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ശൂന്യ);
#endif

	/* Handle systems without __progname */
	എങ്കിൽ (__progname == ശൂന്യ) {
		__progname = strrchr(argv[0], '/');
		എങ്കിൽ (__progname == ശൂന്യ || __progname[1] == '\0')
			__progname = argv[0];	
		അല്ലെങ്കിൽ
			__progname++;
		എങ്കിൽ ((__progname = strdup(__progname)) == ശൂന്യ) {
			fprintf(stderr, "strdup failed\n");
			exit(1);
		}
	}

	ആകുമ്പോൾ ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'b':
			benchmark = 1;
			നിർത്തുക;
		അവസ്ഥ 'B':
			benchmark = benchmark_detail_statistics = 1;
			നിർത്തുക;
		അവസ്ഥ 'O':
			benchmark_pattern = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 'F':
			slow = 1;
			നിർത്തുക;
		അവസ്ഥ 'f':
			fast = 1;
			നിർത്തുക;
		അവസ്ഥ 'd':
			data_dir = optarg;
			നിർത്തുക;
		അവസ്ഥ 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			നിർത്തുക;
		അവസ്ഥ 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fprintf(stderr, "Unrecognised command line option\n");
			fprintf(stderr, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			exit(1);
		}
	}
	setvbuf(stdout, ശൂന്യ, _IONBF, 0);
	എങ്കിൽ (!quiet_mode)
		printf("%s: ", __progname);
	എങ്കിൽ (verbose_mode)
		printf("\n");

	എങ്കിൽ (benchmark)
		benchmarks();
	അല്ലെങ്കിൽ
		tests();

	എങ്കിൽ (!quiet_mode && !benchmark)
		printf(" %u tests ok\n", test_സംഖ്യ);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
test_is_verbose(ശൂന്യം)
{
	തിരികെ verbose_mode;
}

പൂർണ്ണസംഖ്യ
test_is_quiet(ശൂന്യം)
{
	തിരികെ quiet_mode;
}

പൂർണ്ണസംഖ്യ
test_is_fast(ശൂന്യം)
{
	തിരികെ fast;
}

പൂർണ്ണസംഖ്യ
test_is_slow(ശൂന്യം)
{
	തിരികെ slow;
}

സ്ഥിരം അക്ഷരം *
test_data_file(സ്ഥിരം അക്ഷരം *name)
{
	സ്ഥിതം അക്ഷരം ret[PATH_MAX];

	എങ്കിൽ (data_dir != ശൂന്യ)
		snprintf(ret, വലുപ്പം(ret), "%s/%s", data_dir, name);
	അല്ലെങ്കിൽ
		strlcpy(ret, name, വലുപ്പം(ret));
	എങ്കിൽ (access(ret, F_OK) != 0) {
		fprintf(stderr, "Cannot access data file %s: %s\n",
		    ret, strerror(errno));
		exit(1);
	}
	തിരികെ ret;
}

ശൂന്യം
test_info(അക്ഷരം *s, size_t len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_സംഖ്യ,
	    active_test_name == ശൂന്യ ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

സ്ഥിതം ശൂന്യം
siginfo(പൂർണ്ണസംഖ്യ unused __attribute__((__unused__)))
{
	അക്ഷരം buf[256];

	test_info(buf, വലുപ്പം(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
}

ശൂന്യം
test_start(സ്ഥിരം അക്ഷരം *n)
{
	പ്രതിജ്ഞാ(active_test_name == ശൂന്യ);
	പ്രതിജ്ഞാ((active_test_name = strdup(n)) != ശൂന്യ);
	*subtest_info = '\0';
	എങ്കിൽ (verbose_mode)
		printf("test %u - \"%s\": ", test_സംഖ്യ, active_test_name);
	test_സംഖ്യ++;
#ifdef SIGINFO
	സൂചന(SIGINFO, siginfo);
#endif
	സൂചന(SIGUSR1, siginfo);
}

ശൂന്യം
set_onerror_func(test_onerror_func_t *f, ശൂന്യം *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

ശൂന്യം
test_done(ശൂന്യം)
{
	*subtest_info = '\0';
	പ്രതിജ്ഞാ(active_test_name != ശൂന്യ);
	സ്വതന്ത്രം(active_test_name);
	active_test_name = ശൂന്യ;
	എങ്കിൽ (verbose_mode)
		printf("OK\n");
	അല്ലെങ്കിൽ എങ്കിൽ (!quiet_mode && !benchmark) {
		printf(".");
		fflush(stdout);
	}
}

ശൂന്യം
test_subtest_info(സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(subtest_info, വലുപ്പം(subtest_info), fmt, ap);
	va_end(ap);
}

പൂർണ്ണസംഖ്യ
test_is_benchmark(ശൂന്യം)
{
	തിരികെ benchmark;
}

ശൂന്യം
ssl_err_check(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി)
{
#ifdef WITH_OPENSSL
	long openssl_error = ERR_get_error();

	എങ്കിൽ (openssl_error == 0)
		തിരികെ;

	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, വരി, ERR_error_string(openssl_error, ശൂന്യ));
#അല്ലെങ്കിൽ /* WITH_OPENSSL */
	fprintf(stderr, "\n%s:%d: uncaught OpenSSL error ",
	    file, വരി);
#endif /* WITH_OPENSSL */
	abort();
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
pred_name(എണ്ണൽ test_predicate p)
{
	തിരഞ്ഞെടുപ്പ് (p) {
	അവസ്ഥ TEST_EQ:
		തിരികെ "EQ";
	അവസ്ഥ TEST_NE:
		തിരികെ "NE";
	അവസ്ഥ TEST_LT:
		തിരികെ "LT";
	അവസ്ഥ TEST_LE:
		തിരികെ "LE";
	അവസ്ഥ TEST_GT:
		തിരികെ "GT";
	അവസ്ഥ TEST_GE:
		തിരികെ "GE";
	സ്ഥിരസ്ഥിതി:
		തിരികെ "UNKNOWN";
	}
}

സ്ഥിതം ശൂന്യം
test_die(ശൂന്യം)
{
	എങ്കിൽ (test_onerror != ശൂന്യ)
		test_onerror(onerror_ctx);
	abort();
}

സ്ഥിതം ശൂന്യം
test_header(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    സ്ഥിരം അക്ഷരം *name, എണ്ണൽ test_predicate pred)
{
	fprintf(stderr, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, വരി, test_സംഖ്യ, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	fprintf(stderr, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != ശൂന്യ ? ", " : "", a2 != ശൂന്യ ? a2 : "");
}

#ifdef WITH_OPENSSL
ശൂന്യം
assert_bignum(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    സ്ഥിരം BIGNUM *aa1, സ്ഥിരം BIGNUM *aa2, എണ്ണൽ test_predicate pred)
{
	പൂർണ്ണസംഖ്യ r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, വരി, a1, a2, "BIGNUM", pred);
	fprintf(stderr, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	fprintf(stderr, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

ശൂന്യം
assert_string(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    സ്ഥിരം അക്ഷരം *aa1, സ്ഥിരം അക്ഷരം *aa2, എണ്ണൽ test_predicate pred)
{
	പൂർണ്ണസംഖ്യ r;

	/* Verify pointers are not NULL */
	assert_ptr(file, വരി, a1, "NULL", aa1, ശൂന്യ, TEST_NE);
	assert_ptr(file, വരി, a2, "NULL", aa2, ശൂന്യ, TEST_NE);

	r = strcmp(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, വരി, a1, a2, "STRING", pred);
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1, strlen(aa1));
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2, strlen(aa2));
	test_die();
}

ശൂന്യം
assert_mem(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    സ്ഥിരം ശൂന്യം *aa1, സ്ഥിരം ശൂന്യം *aa2, size_t l, എണ്ണൽ test_predicate pred)
{
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *aa1_tohex = ശൂന്യ;
	അക്ഷരം *aa2_tohex = ശൂന്യ;

	എങ്കിൽ (l == 0)
		തിരികെ;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, വരി, a1, "NULL", aa1, ശൂന്യ, TEST_NE);
	assert_ptr(file, വരി, a2, "NULL", aa2, ശൂന്യ, TEST_NE);

	r = memcmp(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, വരി, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	fprintf(stderr, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	fprintf(stderr, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	സ്വതന്ത്രം(aa1_tohex);
	സ്വതന്ത്രം(aa2_tohex);
	test_die();
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
memvalcmp(സ്ഥിരം uint8_t *s, u_char v, size_t l, size_t *where)
{
	size_t i;

	വേണ്ടി (i = 0; i < l; i++) {
		എങ്കിൽ (s[i] != v) {
			*where = i;
			തിരികെ 1;
		}
	}
	തിരികെ 0;
}

ശൂന്യം
assert_mem_filled(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1,
    സ്ഥിരം ശൂന്യം *aa1, u_char v, size_t l, എണ്ണൽ test_predicate pred)
{
	size_t where = -1;
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം tmp[64];
	അക്ഷരം *aa1_tohex = ശൂന്യ;

	എങ്കിൽ (l == 0)
		തിരികെ;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, വരി, a1, "NULL", aa1, ശൂന്യ, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, വരി, a1, ശൂന്യ, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	fprintf(stderr, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	സ്വതന്ത്രം(aa1_tohex);
	snprintf(tmp, വലുപ്പം(tmp), "(%s)[%zu]", a1, where);
	fprintf(stderr, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

ശൂന്യം
assert_int(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    പൂർണ്ണസംഖ്യ aa1, പൂർണ്ണസംഖ്യ aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "INT", pred);
	fprintf(stderr, "%12s = %d\n", a1, aa1);
	fprintf(stderr, "%12s = %d\n", a2, aa2);
	test_die();
}

ശൂന്യം
assert_size_t(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    size_t aa1, size_t aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "SIZE_T", pred);
	fprintf(stderr, "%12s = %zu\n", a1, aa1);
	fprintf(stderr, "%12s = %zu\n", a2, aa2);
	test_die();
}

ശൂന്യം
assert_u_int(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    u_int aa1, u_int aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "U_INT", pred);
	fprintf(stderr, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

ശൂന്യം
assert_long(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    long aa1, long aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "LONG", pred);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

ശൂന്യം
assert_long_long(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    long long aa1, long long aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "LONG LONG", pred);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

ശൂന്യം
assert_char(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    അക്ഷരം aa1, അക്ഷരം aa2, എണ്ണൽ test_predicate pred)
{
	അക്ഷരം buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "CHAR", pred);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	fprintf(stderr, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

ശൂന്യം
assert_u8(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    uint8_t aa1, uint8_t aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "U8", pred);
	fprintf(stderr, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

ശൂന്യം
assert_u16(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    uint16_t aa1, uint16_t aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "U16", pred);
	fprintf(stderr, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

ശൂന്യം
assert_u32(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    uint32_t aa1, uint32_t aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "U32", pred);
	fprintf(stderr, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	fprintf(stderr, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

ശൂന്യം
assert_u64(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    uint64_t aa1, uint64_t aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "U64", pred);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a1,
	    (unsigned long long)aa1, (unsigned long long)aa1);
	fprintf(stderr, "%12s = 0x%016llx %llu\n", a2,
	    (unsigned long long)aa2, (unsigned long long)aa2);
	test_die();
}

ശൂന്യം
assert_double(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    ഇരട്ട aa1, ഇരട്ട aa2, എണ്ണൽ test_predicate pred)
{
	സ്ഥിരം ഇരട്ട epsilon = 0.000000001;

	തിരഞ്ഞെടുപ്പ് (pred) {
	അവസ്ഥ TEST_EQ:
		എങ്കിൽ (fabs(aa1 - aa2) < epsilon)
			തിരികെ;
		നിർത്തുക;
	അവസ്ഥ TEST_NE:
		എങ്കിൽ (fabs(aa1 - aa2) >= epsilon)
			തിരികെ;
		നിർത്തുക;
	അവസ്ഥ TEST_LT:
		എങ്കിൽ (aa1 < aa2)
			തിരികെ;
		നിർത്തുക;
	അവസ്ഥ TEST_LE:
		എങ്കിൽ (aa1 <= aa2)
			തിരികെ;
		നിർത്തുക;
	അവസ്ഥ TEST_GT:
		എങ്കിൽ (aa1 > aa2)
			തിരികെ;
		നിർത്തുക;
	അവസ്ഥ TEST_GE:
		എങ്കിൽ (aa1 >= aa2)
			തിരികെ;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		abort();
	}

	test_header(file, വരി, a1, a2, "DOUBLE", pred);
	fprintf(stderr, "%12s = %f\n", a1, aa1);
	fprintf(stderr, "%12s = %f\n", a2, aa2);
	test_die();
}

ശൂന്യം
assert_ptr(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    സ്ഥിരം ശൂന്യം *aa1, സ്ഥിരം ശൂന്യം *aa2, എണ്ണൽ test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, വരി, a1, a2, "PTR", pred);
	fprintf(stderr, "%12s = %p\n", a1, aa1);
	fprintf(stderr, "%12s = %p\n", a2, aa2);
	test_die();
}

സ്ഥിതം ഇരട്ട
tstod(സ്ഥിരം ഘടന timespec *ts)
{
	തിരികെ (ഇരട്ട)ts->tv_sec + ((ഇരട്ട)ts->tv_nsec / 1000000000.0);
}

ശൂന്യം
hex2bin(uint8_t *bin, സ്ഥിരം അക്ഷരം *hex, size_t len)
{
	size_t i;
	unsigned പൂർണ്ണസംഖ്യ v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	വേണ്ടി (i = 0; i < len; i++) {
		ASSERT_INT_EQ(sscanf(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

ശൂന്യം
bench_start(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *name)
{
	അക്ഷരം *cp;

	എങ്കിൽ (bench_name != ശൂന്യ) {
		fprintf(stderr, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, വരി, bench_name);
		abort();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != ശൂന്യ &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	സ്വതന്ത്രം(cp);

	bench_name = name;
	bench_nruns = 0;
	എങ്കിൽ (bench_skip)
		തിരികെ;
	സ്വതന്ത്രം(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(വലുപ്പം(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

പൂർണ്ണസംഖ്യ
bench_done(ശൂന്യം)
{
	തിരികെ bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

ശൂന്യം
bench_case_start(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

ശൂന്യം
bench_case_finish(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി)
{
	ഘടന timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	എങ്കിൽ (bench_nruns >= bench_nalloc) {
		എങ്കിൽ (bench_nalloc >= INT_MAX / 2) {
			fprintf(stderr, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			abort();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, വലുപ്പം(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
tscmp(സ്ഥിരം ശൂന്യം *aa, സ്ഥിരം ശൂന്യം *bb)
{
	സ്ഥിരം ഘടന timespec *a = (സ്ഥിരം ഘടന timespec *)aa;
	സ്ഥിരം ഘടന timespec *b = (സ്ഥിരം ഘടന timespec *)bb;

	എങ്കിൽ (timespeccmp(a, b, ==))
		തിരികെ 0;
	തിരികെ timespeccmp(a, b, <) ? -1 : 1;
}

ശൂന്യം
bench_finish(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *unit)
{
	ഇരട്ട std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (bench_skip)
		പോകുക done;

	എങ്കിൽ (bench_nruns < 1) {
		fprintf(stderr, "\n%s:%d benchmark %s never ran", file, വരി,
		    bench_name);
		abort();
	}
	/* median */
	qsort(bench_samples, bench_nruns, വലുപ്പം(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	എങ്കിൽ (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? INFINITY : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (ഇരട്ട)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? INFINITY : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	വേണ്ടി (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (ഇരട്ട)bench_nruns;
	std_dev = sqrt(std_dev);
	എങ്കിൽ (benchmark_detail_statistics) {
		printf("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} അല്ലെങ്കിൽ {
		printf("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = ശൂന്യ;
	bench_nruns = 0;
	സ്വതന്ത്രം(bench_samples);
	bench_samples = ശൂന്യ;
	bench_skip = 0;
}
