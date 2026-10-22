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

#जर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
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

#define TEST_CHECK_INT(r, pred) करा {		\
		निवड (pred) {			\
		स्थिती TEST_EQ:			\
			जर (r == 0)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_NE:			\
			जर (r != 0)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_LT:			\
			जर (r < 0)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_LE:			\
			जर (r <= 0)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_GT:			\
			जर (r > 0)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_GE:			\
			जर (r >= 0)		\
				परत;		\
			थांबा;			\
		पूर्वनिर्धारित:			\
			पात();		\
		}				\
	} पर्यंत (0)

#define TEST_CHECK(x1, x2, pred) करा {		\
		निवड (pred) {			\
		स्थिती TEST_EQ:			\
			जर (x1 == x2)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_NE:			\
			जर (x1 != x2)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_LT:			\
			जर (x1 < x2)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_LE:			\
			जर (x1 <= x2)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_GT:			\
			जर (x1 > x2)		\
				परत;		\
			थांबा;			\
		स्थिती TEST_GE:			\
			जर (x1 >= x2)		\
				परत;		\
			थांबा;			\
		पूर्वनिर्धारित:			\
			पात();		\
		}				\
	} पर्यंत (0)

बाह्य अक्षर *__progname;

स्थिर पूर्णांक verbose_mode = 0;
स्थिर पूर्णांक quiet_mode = 0;
स्थिर अक्षर *active_test_name = रिक्त;
स्थिर u_int test_संख्या = 0;
स्थिर test_onerror_func_t *test_onerror = रिक्त;
स्थिर शून्य *onerror_ctx = रिक्त;
स्थिर स्थिरांक अक्षर *data_dir = रिक्त;
स्थिर अक्षर subtest_info[512];
स्थिर पूर्णांक fast = 0;
स्थिर पूर्णांक slow = 0;
स्थिर पूर्णांक benchmark_detail_statistics = 0;

स्थिर पूर्णांक benchmark = 0;
स्थिर स्थिरांक अक्षर *bench_name = रिक्त;
स्थिर अक्षर *benchmark_pattern = रिक्त;
स्थिर संरचना timespec bench_start_time, bench_finish_time;
स्थिर संरचना timespec *bench_samples;
स्थिर पूर्णांक bench_skip, bench_nruns, bench_nalloc;
द्विगुण bench_accum_secs;

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक ch;

	seed_rng();
#ifdef WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, रिक्त);
#endif

	/* Handle systems without __progname */
	जर (__progname == रिक्त) {
		__progname = म_खोजप(argv[0], '/');
		जर (__progname == रिक्त || __progname[1] == '\0')
			__progname = argv[0];	
		अन्यथा
			__progname++;
		जर ((__progname = strdup(__progname)) == रिक्त) {
			ख_लिखो(मानक_त्रुटि, "strdup failed\n");
			निकास(1);
		}
	}

	पर्यंत ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		निवड (ch) {
		स्थिती 'b':
			benchmark = 1;
			थांबा;
		स्थिती 'B':
			benchmark = benchmark_detail_statistics = 1;
			थांबा;
		स्थिती 'O':
			benchmark_pattern = xstrdup(optarg);
			थांबा;
		स्थिती 'F':
			slow = 1;
			थांबा;
		स्थिती 'f':
			fast = 1;
			थांबा;
		स्थिती 'd':
			data_dir = optarg;
			थांबा;
		स्थिती 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			थांबा;
		स्थिती 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			थांबा;
		पूर्वनिर्धारित:
			ख_लिखो(मानक_त्रुटि, "Unrecognised command line option\n");
			ख_लिखो(मानक_त्रुटि, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			निकास(1);
		}
	}
	रखो_भबफ(मानक_निकास, रिक्त, _IONBF, 0);
	जर (!quiet_mode)
		म_लिखो("%s: ", __progname);
	जर (verbose_mode)
		म_लिखो("\n");

	जर (benchmark)
		benchmarks();
	अन्यथा
		tests();

	जर (!quiet_mode && !benchmark)
		म_लिखो(" %u tests ok\n", test_संख्या);
	परत 0;
}

पूर्णांक
test_is_verbose(शून्य)
{
	परत verbose_mode;
}

पूर्णांक
test_is_quiet(शून्य)
{
	परत quiet_mode;
}

पूर्णांक
test_is_fast(शून्य)
{
	परत fast;
}

पूर्णांक
test_is_slow(शून्य)
{
	परत slow;
}

स्थिरांक अक्षर *
test_data_file(स्थिरांक अक्षर *name)
{
	स्थिर अक्षर ret[PATH_MAX];

	जर (data_dir != रिक्त)
		snprintf(ret, आकार(ret), "%s/%s", data_dir, name);
	अन्यथा
		strlcpy(ret, name, आकार(ret));
	जर (access(ret, F_OK) != 0) {
		ख_लिखो(मानक_त्रुटि, "Cannot access data file %s: %s\n",
		    ret, म_त्रुटि(त्रुटि_सं));
		निकास(1);
	}
	परत ret;
}

शून्य
test_info(अक्षर *s, माप_प्रकार len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_संख्या,
	    active_test_name == रिक्त ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

स्थिर शून्य
siginfo(पूर्णांक unused __attribute__((__unused__)))
{
	अक्षर buf[256];

	test_info(buf, आकार(buf));
	atomicio(vwrite, STDERR_FILENO, buf, म_माप(buf));
}

शून्य
test_start(स्थिरांक अक्षर *n)
{
	प्रतिज्ञा(active_test_name == रिक्त);
	प्रतिज्ञा((active_test_name = strdup(n)) != रिक्त);
	*subtest_info = '\0';
	जर (verbose_mode)
		म_लिखो("test %u - \"%s\": ", test_संख्या, active_test_name);
	test_संख्या++;
#ifdef SIGINFO
	संकेत(SIGINFO, siginfo);
#endif
	संकेत(SIGUSR1, siginfo);
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
	जर (verbose_mode)
		म_लिखो("OK\n");
	अन्यथा जर (!quiet_mode && !benchmark) {
		म_लिखो(".");
		ख_साफ(मानक_निकास);
	}
}

शून्य
test_subtest_info(स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	vsnprintf(subtest_info, आकार(subtest_info), fmt, ap);
	बहु_पूर्ण(ap);
}

पूर्णांक
test_is_benchmark(शून्य)
{
	परत benchmark;
}

शून्य
ssl_err_check(स्थिरांक अक्षर *file, पूर्णांक ओळ)
{
#ifdef WITH_OPENSSL
	दीर्घ openssl_error = ERR_get_error();

	जर (openssl_error == 0)
		परत;

	ख_लिखो(मानक_त्रुटि, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, ओळ, ERR_error_string(openssl_error, रिक्त));
#अन्यथा /* WITH_OPENSSL */
	ख_लिखो(मानक_त्रुटि, "\n%s:%d: uncaught OpenSSL error ",
	    file, ओळ);
#endif /* WITH_OPENSSL */
	पात();
}

स्थिर स्थिरांक अक्षर *
pred_name(गणना test_predicate p)
{
	निवड (p) {
	स्थिती TEST_EQ:
		परत "EQ";
	स्थिती TEST_NE:
		परत "NE";
	स्थिती TEST_LT:
		परत "LT";
	स्थिती TEST_LE:
		परत "LE";
	स्थिती TEST_GT:
		परत "GT";
	स्थिती TEST_GE:
		परत "GE";
	पूर्वनिर्धारित:
		परत "UNKNOWN";
	}
}

स्थिर शून्य
test_die(शून्य)
{
	जर (test_onerror != रिक्त)
		test_onerror(onerror_ctx);
	पात();
}

स्थिर शून्य
test_header(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    स्थिरांक अक्षर *name, गणना test_predicate pred)
{
	ख_लिखो(मानक_त्रुटि, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, ओळ, test_संख्या, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	ख_लिखो(मानक_त्रुटि, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != रिक्त ? ", " : "", a2 != रिक्त ? a2 : "");
}

#ifdef WITH_OPENSSL
शून्य
assert_bignum(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    स्थिरांक BIGNUM *aa1, स्थिरांक BIGNUM *aa2, गणना test_predicate pred)
{
	पूर्णांक r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, ओळ, a1, a2, "BIGNUM", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#endif

शून्य
assert_string(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    स्थिरांक अक्षर *aa1, स्थिरांक अक्षर *aa2, गणना test_predicate pred)
{
	पूर्णांक r;

	/* Verify pointers are not NULL */
	assert_ptr(file, ओळ, a1, "NULL", aa1, रिक्त, TEST_NE);
	assert_ptr(file, ओळ, a2, "NULL", aa2, रिक्त, TEST_NE);

	r = म_भेद(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, ओळ, a1, a2, "STRING", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %s (len %zu)\n", a1, aa1, म_माप(aa1));
	ख_लिखो(मानक_त्रुटि, "%12s = %s (len %zu)\n", a2, aa2, म_माप(aa2));
	test_die();
}

शून्य
assert_mem(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    स्थिरांक शून्य *aa1, स्थिरांक शून्य *aa2, माप_प्रकार l, गणना test_predicate pred)
{
	पूर्णांक r;
	अक्षर *aa1_tohex = रिक्त;
	अक्षर *aa2_tohex = रिक्त;

	जर (l == 0)
		परत;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, ओळ, a1, "NULL", aa1, रिक्त, TEST_NE);
	assert_ptr(file, ओळ, a2, "NULL", aa2, रिक्त, TEST_NE);

	r = स_भेद(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, ओळ, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	ख_लिखो(मानक_त्रुटि, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	ख_लिखो(मानक_त्रुटि, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	मुक्त(aa1_tohex);
	मुक्त(aa2_tohex);
	test_die();
}

स्थिर पूर्णांक
memvalcmp(स्थिरांक uint8_t *s, u_char v, माप_प्रकार l, माप_प्रकार *where)
{
	माप_प्रकार i;

	साठी (i = 0; i < l; i++) {
		जर (s[i] != v) {
			*where = i;
			परत 1;
		}
	}
	परत 0;
}

शून्य
assert_mem_filled(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1,
    स्थिरांक शून्य *aa1, u_char v, माप_प्रकार l, गणना test_predicate pred)
{
	माप_प्रकार where = -1;
	पूर्णांक r;
	अक्षर tmp[64];
	अक्षर *aa1_tohex = रिक्त;

	जर (l == 0)
		परत;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, ओळ, a1, "NULL", aa1, रिक्त, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, ओळ, a1, रिक्त, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	ख_लिखो(मानक_त्रुटि, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	मुक्त(aa1_tohex);
	snprintf(tmp, आकार(tmp), "(%s)[%zu]", a1, where);
	ख_लिखो(मानक_त्रुटि, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

शून्य
assert_int(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    पूर्णांक aa1, पूर्णांक aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "INT", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %d\n", a1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %d\n", a2, aa2);
	test_die();
}

शून्य
assert_size_t(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    माप_प्रकार aa1, माप_प्रकार aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "SIZE_T", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %zu\n", a1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %zu\n", a2, aa2);
	test_die();
}

शून्य
assert_u_int(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    u_int aa1, u_int aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "U_INT", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_long(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    दीर्घ aa1, दीर्घ aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "LONG", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_long_long(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    दीर्घ दीर्घ aa1, दीर्घ दीर्घ aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "LONG LONG", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_char(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    अक्षर aa1, अक्षर aa2, गणना test_predicate pred)
{
	अक्षर buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "CHAR", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

शून्य
assert_u8(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    uint8_t aa1, uint8_t aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "U8", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_u16(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    uint16_t aa1, uint16_t aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "U16", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_u32(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    uint32_t aa1, uint32_t aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "U32", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

शून्य
assert_u64(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    uint64_t aa1, uint64_t aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "U64", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%016llx %llu\n", a1,
	    (अचिन्हित दीर्घ दीर्घ)aa1, (अचिन्हित दीर्घ दीर्घ)aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%016llx %llu\n", a2,
	    (अचिन्हित दीर्घ दीर्घ)aa2, (अचिन्हित दीर्घ दीर्घ)aa2);
	test_die();
}

शून्य
assert_double(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    द्विगुण aa1, द्विगुण aa2, गणना test_predicate pred)
{
	स्थिरांक द्विगुण epsilon = 0.000000001;

	निवड (pred) {
	स्थिती TEST_EQ:
		जर (भ_असल(aa1 - aa2) < epsilon)
			परत;
		थांबा;
	स्थिती TEST_NE:
		जर (भ_असल(aa1 - aa2) >= epsilon)
			परत;
		थांबा;
	स्थिती TEST_LT:
		जर (aa1 < aa2)
			परत;
		थांबा;
	स्थिती TEST_LE:
		जर (aa1 <= aa2)
			परत;
		थांबा;
	स्थिती TEST_GT:
		जर (aa1 > aa2)
			परत;
		थांबा;
	स्थिती TEST_GE:
		जर (aa1 >= aa2)
			परत;
		थांबा;
	पूर्वनिर्धारित:
		पात();
	}

	test_header(file, ओळ, a1, a2, "DOUBLE", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %f\n", a1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %f\n", a2, aa2);
	test_die();
}

शून्य
assert_ptr(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *a1, स्थिरांक अक्षर *a2,
    स्थिरांक शून्य *aa1, स्थिरांक शून्य *aa2, गणना test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, ओळ, a1, a2, "PTR", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %p\n", a1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %p\n", a2, aa2);
	test_die();
}

स्थिर द्विगुण
tstod(स्थिरांक संरचना timespec *ts)
{
	परत (द्विगुण)ts->tv_sec + ((द्विगुण)ts->tv_nsec / 1000000000.0);
}

शून्य
hex2bin(uint8_t *bin, स्थिरांक अक्षर *hex, माप_प्रकार len)
{
	माप_प्रकार i;
	अचिन्हित पूर्णांक v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	साठी (i = 0; i < len; i++) {
		ASSERT_INT_EQ(माला_पूछो(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

शून्य
bench_start(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *name)
{
	अक्षर *cp;

	जर (bench_name != रिक्त) {
		ख_लिखो(मानक_त्रुटि, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, ओळ, bench_name);
		पात();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != रिक्त &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	मुक्त(cp);

	bench_name = name;
	bench_nruns = 0;
	जर (bench_skip)
		परत;
	मुक्त(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(आकार(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

पूर्णांक
bench_done(शून्य)
{
	परत bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

शून्य
bench_case_start(स्थिरांक अक्षर *file, पूर्णांक ओळ)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

शून्य
bench_case_finish(स्थिरांक अक्षर *file, पूर्णांक ओळ)
{
	संरचना timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	जर (bench_nruns >= bench_nalloc) {
		जर (bench_nalloc >= पूर्णांक_उच्च / 2) {
			ख_लिखो(मानक_त्रुटि, "\n%s:%d benchmark %s too many samples",
			    __FILE__, __LINE__, bench_name);
			पात();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, आकार(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

स्थिर पूर्णांक
tscmp(स्थिरांक शून्य *aa, स्थिरांक शून्य *bb)
{
	स्थिरांक संरचना timespec *a = (स्थिरांक संरचना timespec *)aa;
	स्थिरांक संरचना timespec *b = (स्थिरांक संरचना timespec *)bb;

	जर (timespeccmp(a, b, ==))
		परत 0;
	परत timespeccmp(a, b, <) ? -1 : 1;
}

शून्य
bench_finish(स्थिरांक अक्षर *file, पूर्णांक ओळ, स्थिरांक अक्षर *unit)
{
	द्विगुण std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	पूर्णांक i;

	जर (bench_skip)
		जा done;

	जर (bench_nruns < 1) {
		ख_लिखो(मानक_त्रुटि, "\n%s:%d benchmark %s never ran", file, ओळ,
		    bench_name);
		पात();
	}
	/* median */
	क्विक(bench_samples, bench_nruns, आकार(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	जर (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? अनन्त : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (द्विगुण)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? अनन्त : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	साठी (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (द्विगुण)bench_nruns;
	std_dev = वर्ग_मूल(std_dev);
	जर (benchmark_detail_statistics) {
		म_लिखो("%s: %d runs in %0.3fs, %0.03f/%0.03f ms/%s "
		    "(mean/median), std.dev %0.03f ms, "
		    "%0.2f/%0.2f %s/s (mean/median)\n",
		    bench_name, bench_nruns, bench_accum_secs,
		    mean_spr * 1000, med_spr * 1000, unit, std_dev * 1000,
		    mean_rps, med_rps, unit);
	} अन्यथा {
		म_लिखो("%-*s %0.2f %s/s\n", BENCH_COLUMN_WIDTH,
		    bench_name, med_rps, unit);
	}
 done:
	bench_name = रिक्त;
	bench_nruns = 0;
	मुक्त(bench_samples);
	bench_samples = रिक्त;
	bench_skip = 0;
}
