/* 	$OpenBSD: tests.c,v 1.10 2026/05/31 04:20:58 djm Exp $ */
/*
 * Regress test for matching functions
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "match.h"

/* Original match_pattern() implementation; has bad worst-case behaviour */
ساكن صحيح
تطابق_الگو_original(ثابت حرف *s, ثابت حرف *الگو)
{
	لكل (;;) {
		/* If at end of pattern, accept if also at end of string. */
		إذا (!*الگو)
			أرجع !*s;

		إذا (*الگو == '*') {
			/* Skip this and any consecutive asterisks. */
			طالما (*الگو == '*')
				الگو++;

			/* If at end of pattern, accept immediately. */
			إذا (!*الگو)
				أرجع 1;

			/* If next character in pattern is known, optimize. */
			إذا (*الگو != '?' && *الگو != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				لكل (; *s; s++)
					إذا (*s == *الگو &&
					    تطابق_الگو_original(s + 1,
					    الگو + 1))
						أرجع 1;
				/* Failed. */
				أرجع 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			لكل (; *s; s++)
				إذا (تطابق_الگو_original(s, الگو))
					أرجع 1;
			/* Failed. */
			أرجع 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		إذا (!*s)
			أرجع 0;

		/* Check if the next character of the string is acceptable. */
		إذا (*الگو != '?' && *الگو != *s)
			أرجع 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		الگو++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
ساكن اندازه_t
pow_اندازه(اندازه_t پایه, اندازه_t نمایی_تابع)
{
	اندازه_t r = 1;

	ASSERT_اندازه_T_NE(پایه, 0);
	طالما (نمایی_تابع-- != 0) {
		ASSERT_اندازه_T_LE(r, SIZE_MAX / پایه);
		r *= پایه;
	}
	أرجع r;
}

ساكن فراغ
make_کلمه(اندازه_t v, ثابت حرف *alphabet, اندازه_t alphabet_len,
    حرف *کلمه, اندازه_t wordlen)
{
	اندازه_t i;

	لكل (i = 0; i < wordlen; i++) {
		کلمه[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	کلمه[wordlen] = '\0';
}

#تعریف_کن الگو_LEN	8
#تعریف_کن درون_داد_LEN	7

ساكن فراغ
تطابق_الگو_check_one_درون_داد(ثابت حرف *درون_داد, ثابت حرف *الگو_alphabet)
{
	حرف الگو[الگو_LEN];
	اندازه_t len, i, npatterns;
	صحيح actual, expected;

	لكل (len = 0; len < حجم(الگو); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_اندازه(طول_رشته(الگو_alphabet), len);
		لكل (i = 0; i < npatterns; i++) {
			make_کلمه(i, الگو_alphabet,
			    طول_رشته(الگو_alphabet), الگو, len);
			actual = تطابق_الگو(درون_داد, الگو);
			expected = تطابق_الگو_original(درون_داد, الگو);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    درون_داد, الگو);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
ساكن فراغ
تطابق_الگو_exhaustive_original(فراغ)
{
	ثابت حرف *الگو_alphabet = "abx?*";
	ثابت حرف *درون_داد_alphabet = "abc";
	حرف درون_داد[درون_داد_LEN];
	اندازه_t len, i, ninputs;

	لكل (len = 0; len < حجم(درون_داد); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_اندازه(طول_رشته(درون_داد_alphabet), len);
		لكل (i = 0; i < ninputs; i++) {
			make_کلمه(i, درون_داد_alphabet,
			    طول_رشته(درون_داد_alphabet), درون_داد, len);
			تطابق_الگو_check_one_درون_داد(درون_داد, الگو_alphabet);
		}
	}
}

فراغ
tests(فراغ)
{
	TEST_شروع("match_pattern");
	ASSERT_INT_EQ(تطابق_الگو("", ""), 1);
	ASSERT_INT_EQ(تطابق_الگو("", "aaa"), 0);
	ASSERT_INT_EQ(تطابق_الگو("aaa", ""), 0);
	ASSERT_INT_EQ(تطابق_الگو("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(تطابق_الگو("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "abc"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abc", "abd"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "abcd"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abcd", "abc"), 0);
	TEST_انجامشده();

	TEST_شروع("match_pattern wildcard");
	ASSERT_INT_EQ(تطابق_الگو("", "*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("", "**"), 1);
	ASSERT_INT_EQ(تطابق_الگو("", "***"), 1);
	ASSERT_INT_EQ(تطابق_الگو("", "?"), 0);
	ASSERT_INT_EQ(تطابق_الگو("", "*?"), 0);
	ASSERT_INT_EQ(تطابق_الگو("", "?*"), 0);
	ASSERT_INT_EQ(تطابق_الگو("", "**a*"), 0);
	ASSERT_INT_EQ(تطابق_الگو("a", "?"), 1);
	ASSERT_INT_EQ(تطابق_الگو("aa", "a?"), 1);
	ASSERT_INT_EQ(تطابق_الگو("a", "*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("aa", "a*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("aa", "?*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("aa", "?a"), 1);
	ASSERT_INT_EQ(تطابق_الگو("aa", "*a"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ba", "a?"), 0);
	ASSERT_INT_EQ(تطابق_الگو("ba", "a*"), 0);
	ASSERT_INT_EQ(تطابق_الگو("ab", "?a"), 0);
	ASSERT_INT_EQ(تطابق_الگو("ab", "*a"), 0);
	ASSERT_INT_EQ(تطابق_الگو("aa", "**"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ab", "a***b"), 1);
	ASSERT_INT_EQ(تطابق_الگو("axb", "a***b"), 1);
	ASSERT_INT_EQ(تطابق_الگو("axxb", "a***b"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ax", "a***b"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(تطابق_الگو("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(تطابق_الگو("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ab", "*b"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ab", "*a*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ab", "*a*b"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ab", "*a*c"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "a?c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abc", "??c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abc", "???"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abc", "a?d"), 0);
	ASSERT_INT_EQ(تطابق_الگو("ab", "???"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "ab*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ab", "ab*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("a", "ab*"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "ab?"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ab", "ab?"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abcd", "ab?"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "?bc"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abc", "?b*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abc", "?c"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "a*?c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ac", "a*?c"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abc", "a?*c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ac", "a?*c"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "?*c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ac", "?*c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("c", "?*c"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "*?c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ac", "*?c"), 1);
	ASSERT_INT_EQ(تطابق_الگو("c", "*?c"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "a?*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ab", "a?*"), 1);
	ASSERT_INT_EQ(تطابق_الگو("a", "a?*"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abc", "a*?"), 1);
	ASSERT_INT_EQ(تطابق_الگو("ab", "a*?"), 1);
	ASSERT_INT_EQ(تطابق_الگو("a", "a*?"), 0);
	ASSERT_INT_EQ(تطابق_الگو("abb", "a*b"), 1);
	ASSERT_INT_EQ(تطابق_الگو("abbc", "a*b"), 0);
	TEST_انجامشده();

	TEST_شروع("match_pattern exhaustive original");
	تطابق_الگو_exhaustive_original();
	TEST_انجامشده();

	TEST_شروع("match_pattern_list");
	ASSERT_INT_EQ(تطابق_الگو_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(تطابق_الگو_list("", "*", 0), 1);
	ASSERT_INT_EQ(تطابق_الگو_list("", "!*", 0), -1);
	ASSERT_INT_EQ(تطابق_الگو_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(تطابق_الگو_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(تطابق_الگو_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(تطابق_الگو_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(تطابق_الگو_list("a", "", 0), 0);
	ASSERT_INT_EQ(تطابق_الگو_list("a", "*", 0), 1);
	ASSERT_INT_EQ(تطابق_الگو_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(تطابق_الگو_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(تطابق_الگو_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(تطابق_الگو_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(تطابق_الگو_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(تطابق_الگو_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(تطابق_الگو_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(تطابق_الگو_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(تطابق_الگو_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(تطابق_الگو_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(تطابق_الگو_list("b", "!*,a", 0), -1);
	TEST_انجامشده();

	TEST_شروع("match_pattern_list lowercase");
	ASSERT_INT_EQ(تطابق_الگو_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(تطابق_الگو_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(تطابق_الگو_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(تطابق_الگو_list("ABC", "abc", 1), 0);
	TEST_انجامشده();

	TEST_شروع("addr_match_list");
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_تطابق_list(عدم, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_تطابق_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_تطابق_list(عدم, "*"), 0);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_تطابق_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_انجامشده();

#تعریف_کن CHECK_FILTER(string,filter,expected) \
	افعل { \
		حرف *نتیجه = تطابق_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(نتیجه, expected); \
		حرر(نتیجه); \
	} طالما (0)

	TEST_شروع("match_filter_list");
	CHECK_FILTER("a,b,c", "", "a,b,c");
	CHECK_FILTER("a,b,c", "a", "b,c");
	CHECK_FILTER("a,b,c", "b", "a,c");
	CHECK_FILTER("a,b,c", "c", "a,b");
	CHECK_FILTER("a,b,c", "a,b", "c");
	CHECK_FILTER("a,b,c", "a,c", "b");
	CHECK_FILTER("a,b,c", "b,c", "a");
	CHECK_FILTER("a,b,c", "a,b,c", "");
	CHECK_FILTER("a,b,c", "b,c", "a");
	CHECK_FILTER("", "a,b,c", "");
	TEST_انجامشده();
/*
 * XXX TODO
 * int      match_host_and_ip(const char *, const char *, const char *);
 * int      match_user(const char *, const char *, const char *, const char *);
 * char    *match_list(const char *, const char *, u_int *);
 * int      addr_match_cidr_list(const char *, const char *);
 */
}

فراغ
benchmarks(فراغ)
{
	چاپ_کن("no benchmarks\n");
}
