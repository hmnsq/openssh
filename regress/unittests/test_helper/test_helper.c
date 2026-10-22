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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/uio.h>
#समावेश <sys/time.h>

#समावेश <assert.h>
#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <math.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdint.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/err.h>
#पूर्ण_अगर

#अगर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#पूर्ण_अगर

#समावेश "entropy.h"
#समावेश "test_helper.h"
#समावेश "atomicio.h"
#समावेश "match.h"
#समावेश "misc.h"
#समावेश "xmalloc.h"

#घोषणा BENCH_FAST_DEADLINE	1
#घोषणा BENCH_NORMAL_DEADLINE	10
#घोषणा BENCH_SLOW_DEADLINE	60
#घोषणा BENCH_SAMPLES_ALLOC	8192
#घोषणा BENCH_COLUMN_WIDTH	40

#घोषणा MINIMUM(a, b)    (((a) < (b)) ? (a) : (b))

#घोषणा TEST_CHECK_INT(r, pred) करो {		\
		चयन (pred) {			\
		हाल TEST_EQ:			\
			अगर (r == 0)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_NE:			\
			अगर (r != 0)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_LT:			\
			अगर (r < 0)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_LE:			\
			अगर (r <= 0)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_GT:			\
			अगर (r > 0)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_GE:			\
			अगर (r >= 0)		\
				वापस;		\
			अवरोध;			\
		शेष:			\
			पात();		\
		}				\
	} जबतक (0)

#घोषणा TEST_CHECK(x1, x2, pred) करो {		\
		चयन (pred) {			\
		हाल TEST_EQ:			\
			अगर (x1 == x2)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_NE:			\
			अगर (x1 != x2)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_LT:			\
			अगर (x1 < x2)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_LE:			\
			अगर (x1 <= x2)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_GT:			\
			अगर (x1 > x2)		\
				वापस;		\
			अवरोध;			\
		हाल TEST_GE:			\
			अगर (x1 >= x2)		\
				वापस;		\
			अवरोध;			\
		शेष:			\
			पात();		\
		}				\
	} जबतक (0)

बाह्य अक्षर *__progname;

अटल पूर्णांक verbose_mode = 0;
अटल पूर्णांक quiet_mode = 0;
अटल अक्षर *active_test_name = शून्य;
अटल u_int test_संख्या = 0;
अटल test_onerror_func_t *test_onerror = शून्य;
अटल व्योम *onerror_ctx = शून्य;
अटल स्थिर अक्षर *तथ्य_dir = शून्य;
अटल अक्षर subtest_info[512];
अटल पूर्णांक fast = 0;
अटल पूर्णांक slow = 0;
अटल पूर्णांक benchmark_detail_statistics = 0;

अटल पूर्णांक benchmark = 0;
अटल स्थिर अक्षर *bench_name = शून्य;
अटल अक्षर *benchmark_pattern = शून्य;
अटल काष्ठा timespec bench_start_time, bench_finish_time;
अटल काष्ठा timespec *bench_samples;
अटल पूर्णांक bench_skip, bench_nruns, bench_nalloc;
द्विगुन bench_accum_secs;

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक ch;

	seed_rng();
#अगर_घोषित WITH_OPENSSL
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, शून्य);
#पूर्ण_अगर

	/* Handle systems without __progname */
	अगर (__progname == शून्य) {
		__progname = म_खोजप(argv[0], '/');
		अगर (__progname == शून्य || __progname[1] == '\0')
			__progname = argv[0];	
		अन्यथा
			__progname++;
		अगर ((__progname = strdup(__progname)) == शून्य) {
			ख_लिखो(मानक_त्रुटि, "strdup failed\n");
			निकास(1);
		}
	}

	जबतक ((ch = getopt(argc, argv, "O:bBFfvqd:")) != -1) {
		चयन (ch) {
		हाल 'b':
			benchmark = 1;
			अवरोध;
		हाल 'B':
			benchmark = benchmark_detail_statistics = 1;
			अवरोध;
		हाल 'O':
			benchmark_pattern = xstrdup(optarg);
			अवरोध;
		हाल 'F':
			slow = 1;
			अवरोध;
		हाल 'f':
			fast = 1;
			अवरोध;
		हाल 'd':
			तथ्य_dir = optarg;
			अवरोध;
		हाल 'q':
			verbose_mode = 0;
			quiet_mode = 1;
			अवरोध;
		हाल 'v':
			verbose_mode = 1;
			quiet_mode = 0;
			अवरोध;
		शेष:
			ख_लिखो(मानक_त्रुटि, "Unrecognised command line option\n");
			ख_लिखो(मानक_त्रुटि, "Usage: %s [-vqfFbB] [-d data_dir] "
			    "[-O pattern]\n", __progname);
			निकास(1);
		}
	}
	रखो_भबफ(मानक_निकास, शून्य, _IONBF, 0);
	अगर (!quiet_mode)
		म_लिखो("%s: ", __progname);
	अगर (verbose_mode)
		म_लिखो("\n");

	अगर (benchmark)
		benchmarks();
	अन्यथा
		tests();

	अगर (!quiet_mode && !benchmark)
		म_लिखो(" %u tests ok\n", test_संख्या);
	वापस 0;
}

पूर्णांक
test_is_verbose(व्योम)
{
	वापस verbose_mode;
}

पूर्णांक
test_is_quiet(व्योम)
{
	वापस quiet_mode;
}

पूर्णांक
test_is_fast(व्योम)
{
	वापस fast;
}

पूर्णांक
test_is_slow(व्योम)
{
	वापस slow;
}

स्थिर अक्षर *
test_तथ्य_file(स्थिर अक्षर *name)
{
	अटल अक्षर ret[PATH_MAX];

	अगर (तथ्य_dir != शून्य)
		snprintf(ret, माप(ret), "%s/%s", तथ्य_dir, name);
	अन्यथा
		strlcpy(ret, name, माप(ret));
	अगर (access(ret, F_OK) != 0) {
		ख_लिखो(मानक_त्रुटि, "Cannot access data file %s: %s\n",
		    ret, म_त्रुटि(त्रुटि_सं));
		निकास(1);
	}
	वापस ret;
}

व्योम
test_info(अक्षर *s, माप_प्रकार len)
{
	snprintf(s, len, "In test %u: \"%s\"%s%s\n", test_संख्या,
	    active_test_name == शून्य ? "<none>" : active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
}

अटल व्योम
siginfo(पूर्णांक unused __attribute__((__unused__)))
{
	अक्षर buf[256];

	test_info(buf, माप(buf));
	atomicio(vwrite, STDERR_FILENO, buf, म_माप(buf));
}

व्योम
test_start(स्थिर अक्षर *n)
{
	निश्चित(active_test_name == शून्य);
	निश्चित((active_test_name = strdup(n)) != शून्य);
	*subtest_info = '\0';
	अगर (verbose_mode)
		म_लिखो("test %u - \"%s\": ", test_संख्या, active_test_name);
	test_संख्या++;
#अगर_घोषित SIGINFO
	संकेत(SIGINFO, siginfo);
#पूर्ण_अगर
	संकेत(SIGUSR1, siginfo);
}

व्योम
set_onerror_func(test_onerror_func_t *f, व्योम *ctx)
{
	test_onerror = f;
	onerror_ctx = ctx;
}

व्योम
test_done(व्योम)
{
	*subtest_info = '\0';
	निश्चित(active_test_name != शून्य);
	मुक्त(active_test_name);
	active_test_name = शून्य;
	अगर (verbose_mode)
		म_लिखो("OK\n");
	अन्यथा अगर (!quiet_mode && !benchmark) {
		म_लिखो(".");
		ख_साफ(मानक_निकास);
	}
}

व्योम
test_subtest_info(स्थिर अक्षर *fmt, ...)
{
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	vsnprintf(subtest_info, माप(subtest_info), fmt, ap);
	बहु_पूर्ण(ap);
}

पूर्णांक
test_is_benchmark(व्योम)
{
	वापस benchmark;
}

व्योम
ssl_err_check(स्थिर अक्षर *file, पूर्णांक पंक्ति)
{
#अगर_घोषित WITH_OPENSSL
	दीर्घ openssl_error = ERR_get_error();

	अगर (openssl_error == 0)
		वापस;

	ख_लिखो(मानक_त्रुटि, "\n%s:%d: uncaught OpenSSL error: %s",
	    file, पंक्ति, ERR_error_string(openssl_error, शून्य));
#अन्यथा /* WITH_OPENSSL */
	ख_लिखो(मानक_त्रुटि, "\n%s:%d: uncaught OpenSSL error ",
	    file, पंक्ति);
#पूर्ण_अगर /* WITH_OPENSSL */
	पात();
}

अटल स्थिर अक्षर *
pred_name(क्रमागत test_predicate p)
{
	चयन (p) {
	हाल TEST_EQ:
		वापस "EQ";
	हाल TEST_NE:
		वापस "NE";
	हाल TEST_LT:
		वापस "LT";
	हाल TEST_LE:
		वापस "LE";
	हाल TEST_GT:
		वापस "GT";
	हाल TEST_GE:
		वापस "GE";
	शेष:
		वापस "UNKNOWN";
	}
}

अटल व्योम
test_die(व्योम)
{
	अगर (test_onerror != शून्य)
		test_onerror(onerror_ctx);
	पात();
}

अटल व्योम
test_header(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    स्थिर अक्षर *name, क्रमागत test_predicate pred)
{
	ख_लिखो(मानक_त्रुटि, "\n%s:%d test #%u \"%s\"%s%s\n", 
	    file, पंक्ति, test_संख्या, active_test_name,
	    *subtest_info != '\0' ? " - " : "", subtest_info);
	ख_लिखो(मानक_त्रुटि, "ASSERT_%s_%s(%s%s%s) failed:\n",
	    name, pred_name(pred), a1,
	    a2 != शून्य ? ", " : "", a2 != शून्य ? a2 : "");
}

#अगर_घोषित WITH_OPENSSL
व्योम
assert_bignum(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    स्थिर BIGNUM *aa1, स्थिर BIGNUM *aa2, क्रमागत test_predicate pred)
{
	पूर्णांक r = BN_cmp(aa1, aa2);

	TEST_CHECK_INT(r, pred);
	test_header(file, पंक्ति, a1, a2, "BIGNUM", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%s\n", a1, BN_bn2hex(aa1));
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%s\n", a2, BN_bn2hex(aa2));
	test_die();
}
#पूर्ण_अगर

व्योम
assert_string(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    स्थिर अक्षर *aa1, स्थिर अक्षर *aa2, क्रमागत test_predicate pred)
{
	पूर्णांक r;

	/* Verify pointers are not NULL */
	assert_ptr(file, पंक्ति, a1, "NULL", aa1, शून्य, TEST_NE);
	assert_ptr(file, पंक्ति, a2, "NULL", aa2, शून्य, TEST_NE);

	r = म_भेद(aa1, aa2);
	TEST_CHECK_INT(r, pred);
	test_header(file, पंक्ति, a1, a2, "STRING", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %s (len %zu)\n", a1, aa1, म_माप(aa1));
	ख_लिखो(मानक_त्रुटि, "%12s = %s (len %zu)\n", a2, aa2, म_माप(aa2));
	test_die();
}

व्योम
assert_mem(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    स्थिर व्योम *aa1, स्थिर व्योम *aa2, माप_प्रकार l, क्रमागत test_predicate pred)
{
	पूर्णांक r;
	अक्षर *aa1_tohex = शून्य;
	अक्षर *aa2_tohex = शून्य;

	अगर (l == 0)
		वापस;
	/* If length is >0, then verify pointers are not NULL */
	assert_ptr(file, पंक्ति, a1, "NULL", aa1, शून्य, TEST_NE);
	assert_ptr(file, पंक्ति, a2, "NULL", aa2, शून्य, TEST_NE);

	r = स_भेद(aa1, aa2, l);
	TEST_CHECK_INT(r, pred);
	test_header(file, पंक्ति, a1, a2, "STRING", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 256));
	aa2_tohex = tohex(aa2, MINIMUM(l, 256));
	ख_लिखो(मानक_त्रुटि, "%12s = %s (len %zu)\n", a1, aa1_tohex, l);
	ख_लिखो(मानक_त्रुटि, "%12s = %s (len %zu)\n", a2, aa2_tohex, l);
	मुक्त(aa1_tohex);
	मुक्त(aa2_tohex);
	test_die();
}

अटल पूर्णांक
memvalcmp(स्थिर uint8_t *s, u_char v, माप_प्रकार l, माप_प्रकार *where)
{
	माप_प्रकार i;

	क्रम (i = 0; i < l; i++) {
		अगर (s[i] != v) {
			*where = i;
			वापस 1;
		}
	}
	वापस 0;
}

व्योम
assert_mem_filled(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1,
    स्थिर व्योम *aa1, u_char v, माप_प्रकार l, क्रमागत test_predicate pred)
{
	माप_प्रकार where = -1;
	पूर्णांक r;
	अक्षर tmp[64];
	अक्षर *aa1_tohex = शून्य;

	अगर (l == 0)
		वापस;
	/* If length is >0, then verify the pointer is not NULL */
	assert_ptr(file, पंक्ति, a1, "NULL", aa1, शून्य, TEST_NE);

	r = memvalcmp(aa1, v, l, &where);
	TEST_CHECK_INT(r, pred);
	test_header(file, पंक्ति, a1, शून्य, "MEM_ZERO", pred);
	aa1_tohex = tohex(aa1, MINIMUM(l, 20));
	ख_लिखो(मानक_त्रुटि, "%20s = %s%s (len %zu)\n", a1,
	    aa1_tohex, l > 20 ? "..." : "", l);
	मुक्त(aa1_tohex);
	snprintf(tmp, माप(tmp), "(%s)[%zu]", a1, where);
	ख_लिखो(मानक_त्रुटि, "%20s = 0x%02x (expected 0x%02x)\n", tmp,
	    ((u_char *)aa1)[where], v);
	test_die();
}

व्योम
assert_int(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    पूर्णांक aa1, पूर्णांक aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "INT", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %d\n", a1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %d\n", a2, aa2);
	test_die();
}

व्योम
assert_आकार_t(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    माप_प्रकार aa1, माप_प्रकार aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "SIZE_T", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %zu\n", a1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %zu\n", a2, aa2);
	test_die();
}

व्योम
assert_u_int(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    u_int aa1, u_int aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "U_INT", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %u / 0x%x\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %u / 0x%x\n", a2, aa2, aa2);
	test_die();
}

व्योम
assert_long(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    दीर्घ aa1, दीर्घ aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "LONG", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %ld / 0x%lx\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %ld / 0x%lx\n", a2, aa2, aa2);
	test_die();
}

व्योम
assert_long_long(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    दीर्घ दीर्घ aa1, दीर्घ दीर्घ aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "LONG LONG", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %lld / 0x%llx\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %lld / 0x%llx\n", a2, aa2, aa2);
	test_die();
}

व्योम
assert_char(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    अक्षर aa1, अक्षर aa2, क्रमागत test_predicate pred)
{
	अक्षर buf[8];

	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "CHAR", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa1, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = '%s' / 0x02%x\n", a1,
	    vis(buf, aa2, VIS_SAFE|VIS_NL|VIS_TAB|VIS_OCTAL, 0), aa2);
	test_die();
}

व्योम
assert_u8(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    uint8_t aa1, uint8_t aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "U8", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%02x %u\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%02x %u\n", a2, aa2, aa2);
	test_die();
}

व्योम
assert_u16(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    uint16_t aa1, uint16_t aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "U16", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%04x %u\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%04x %u\n", a2, aa2, aa2);
	test_die();
}

व्योम
assert_u32(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    uint32_t aa1, uint32_t aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "U32", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%08x %u\n", a1, aa1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%08x %u\n", a2, aa2, aa2);
	test_die();
}

व्योम
assert_u64(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    uint64_t aa1, uint64_t aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "U64", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%016llx %llu\n", a1,
	    (अचिन्हित दीर्घ दीर्घ)aa1, (अचिन्हित दीर्घ दीर्घ)aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = 0x%016llx %llu\n", a2,
	    (अचिन्हित दीर्घ दीर्घ)aa2, (अचिन्हित दीर्घ दीर्घ)aa2);
	test_die();
}

व्योम
assert_double(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    द्विगुन aa1, द्विगुन aa2, क्रमागत test_predicate pred)
{
	स्थिर द्विगुन epsilon = 0.000000001;

	चयन (pred) {
	हाल TEST_EQ:
		अगर (भ_असल(aa1 - aa2) < epsilon)
			वापस;
		अवरोध;
	हाल TEST_NE:
		अगर (भ_असल(aa1 - aa2) >= epsilon)
			वापस;
		अवरोध;
	हाल TEST_LT:
		अगर (aa1 < aa2)
			वापस;
		अवरोध;
	हाल TEST_LE:
		अगर (aa1 <= aa2)
			वापस;
		अवरोध;
	हाल TEST_GT:
		अगर (aa1 > aa2)
			वापस;
		अवरोध;
	हाल TEST_GE:
		अगर (aa1 >= aa2)
			वापस;
		अवरोध;
	शेष:
		पात();
	}

	test_header(file, पंक्ति, a1, a2, "DOUBLE", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %f\n", a1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %f\n", a2, aa2);
	test_die();
}

व्योम
assert_ptr(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    स्थिर व्योम *aa1, स्थिर व्योम *aa2, क्रमागत test_predicate pred)
{
	TEST_CHECK(aa1, aa2, pred);
	test_header(file, पंक्ति, a1, a2, "PTR", pred);
	ख_लिखो(मानक_त्रुटि, "%12s = %p\n", a1, aa1);
	ख_लिखो(मानक_त्रुटि, "%12s = %p\n", a2, aa2);
	test_die();
}

अटल द्विगुन
tstod(स्थिर काष्ठा timespec *ts)
{
	वापस (द्विगुन)ts->tv_sec + ((द्विगुन)ts->tv_nsec / 1000000000.0);
}

व्योम
hex2bin(uint8_t *bin, स्थिर अक्षर *hex, माप_प्रकार len)
{
	माप_प्रकार i;
	अचिन्हित पूर्णांक v;

	/* Don't use %hhx since it's C99 and older platforms don't have it. */
	क्रम (i = 0; i < len; i++) {
		ASSERT_INT_EQ(माला_पूछो(hex + i * 2, "%02x", &v), 1);
		ASSERT_U_INT_LE(v, 256);
		bin[i] = (uint8_t)v;
	}
}

व्योम
bench_start(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *name)
{
	अक्षर *cp;

	अगर (bench_name != शून्य) {
		ख_लिखो(मानक_त्रुटि, "\n%s:%d internal error: BENCH_START() called "
		    "while previous benchmark \"%s\" incomplete",
		    file, पंक्ति, bench_name);
		पात();
	}
	cp = xstrdup(name);
	lowercase(cp);
	bench_skip = benchmark_pattern != शून्य &&
	    match_pattern_list(cp, benchmark_pattern, 1) != 1;
	मुक्त(cp);

	bench_name = name;
	bench_nruns = 0;
	अगर (bench_skip)
		वापस;
	मुक्त(bench_samples);
	bench_nalloc = BENCH_SAMPLES_ALLOC;
	bench_samples = xcalloc(माप(*bench_samples), bench_nalloc);
	bench_accum_secs = 0;
}

पूर्णांक
bench_done(व्योम)
{
	वापस bench_skip || bench_accum_secs >= (fast ? BENCH_FAST_DEADLINE :
	    (slow ? BENCH_SLOW_DEADLINE : BENCH_NORMAL_DEADLINE));
}

व्योम
bench_case_start(स्थिर अक्षर *file, पूर्णांक पंक्ति)
{
	clock_gettime(CLOCK_REALTIME, &bench_start_time);
}

व्योम
bench_case_finish(स्थिर अक्षर *file, पूर्णांक पंक्ति)
{
	काष्ठा timespec ts;

	clock_gettime(CLOCK_REALTIME, &bench_finish_time);
	timespecsub(&bench_finish_time, &bench_start_time, &ts);
	अगर (bench_nruns >= bench_nalloc) {
		अगर (bench_nalloc >= पूर्णांक_उच्च / 2) {
			ख_लिखो(मानक_त्रुटि, "\n%s:%d benchmark %s too many samples",
			    __खाता__, __LINE__, bench_name);
			पात();
		}
		bench_samples = xrecallocarray(bench_samples, bench_nalloc,
		    bench_nalloc * 2, माप(*bench_samples));
		bench_nalloc *= 2;
	}
	bench_samples[bench_nruns++] = ts;
	bench_accum_secs += tstod(&ts);
}

अटल पूर्णांक
tscmp(स्थिर व्योम *aa, स्थिर व्योम *bb)
{
	स्थिर काष्ठा timespec *a = (स्थिर काष्ठा timespec *)aa;
	स्थिर काष्ठा timespec *b = (स्थिर काष्ठा timespec *)bb;

	अगर (timespeccmp(a, b, ==))
		वापस 0;
	वापस timespeccmp(a, b, <) ? -1 : 1;
}

व्योम
bench_finish(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *unit)
{
	द्विगुन std_dev = 0, mean_spr, mean_rps, med_spr, med_rps;
	पूर्णांक i;

	अगर (bench_skip)
		जाओ done;

	अगर (bench_nruns < 1) {
		ख_लिखो(मानक_त्रुटि, "\n%s:%d benchmark %s never ran", file, पंक्ति,
		    bench_name);
		पात();
	}
	/* median */
	क्विक(bench_samples, bench_nruns, माप(*bench_samples), tscmp);
	i = bench_nruns / 2;
	med_spr = tstod(&bench_samples[i]);
	अगर (bench_nruns > 1 && bench_nruns & 1)
		med_spr = (med_spr + tstod(&bench_samples[i - 1])) / 2.0;
	med_rps = (med_spr == 0.0) ? अनन्त : 1.0/med_spr;
	/* mean */
	mean_spr = bench_accum_secs / (द्विगुन)bench_nruns;
	mean_rps = (mean_spr == 0.0) ? अनन्त : 1.0/mean_spr;
	/* std. dev */
	std_dev = 0;
	क्रम (i = 0; i < bench_nruns; i++) {
		std_dev = tstod(&bench_samples[i]) - mean_spr;
		std_dev *= std_dev;
	}
	std_dev /= (द्विगुन)bench_nruns;
	std_dev = वर्ग_मूल(std_dev);
	अगर (benchmark_detail_statistics) {
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
	bench_name = शून्य;
	bench_nruns = 0;
	मुक्त(bench_samples);
	bench_samples = शून्य;
	bench_skip = 0;
}
