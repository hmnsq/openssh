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
سمون_نمونه_original(ثابت حرف *s, ثابت حرف *نمونه)
{
	لكل (;;) {
		/* If at end of pattern, accept if also at end of string. */
		إذا (!*نمونه)
			أرجع !*s;

		إذا (*نمونه == '*') {
			/* Skip this and any consecutive asterisks. */
			طالما (*نمونه == '*')
				نمونه++;

			/* If at end of pattern, accept immediately. */
			إذا (!*نمونه)
				أرجع 1;

			/* If next character in pattern is known, optimize. */
			إذا (*نمونه != '?' && *نمونه != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				لكل (; *s; s++)
					إذا (*s == *نمونه &&
					    سمون_نمونه_original(s + 1,
					    نمونه + 1))
						أرجع 1;
				/* Failed. */
				أرجع 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			لكل (; *s; s++)
				إذا (سمون_نمونه_original(s, نمونه))
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
		إذا (*نمونه != '?' && *نمونه != *s)
			أرجع 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		نمونه++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
ساكن اندازه_t
pow_اندازه(اندازه_t بنسټ, اندازه_t توانیز_تابع)
{
	اندازه_t r = 1;

	ASSERT_اندازه_T_NE(بنسټ, 0);
	طالما (توانیز_تابع-- != 0) {
		ASSERT_اندازه_T_LE(r, SIZE_MAX / بنسټ);
		r *= بنسټ;
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

#تعریف_کړه نمونه_LEN	8
#تعریف_کړه ننوت_LEN	7

ساكن فراغ
سمون_نمونه_check_one_ننوت(ثابت حرف *ننوت, ثابت حرف *نمونه_alphabet)
{
	حرف نمونه[نمونه_LEN];
	اندازه_t len, i, npatterns;
	صحيح actual, expected;

	لكل (len = 0; len < حجم(نمونه); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_اندازه(مزي_اوږدوالی(نمونه_alphabet), len);
		لكل (i = 0; i < npatterns; i++) {
			make_کلمه(i, نمونه_alphabet,
			    مزي_اوږدوالی(نمونه_alphabet), نمونه, len);
			actual = سمون_نمونه(ننوت, نمونه);
			expected = سمون_نمونه_original(ننوت, نمونه);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    ننوت, نمونه);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
ساكن فراغ
سمون_نمونه_exhaustive_original(فراغ)
{
	ثابت حرف *نمونه_alphabet = "abx?*";
	ثابت حرف *ننوت_alphabet = "abc";
	حرف ننوت[ننوت_LEN];
	اندازه_t len, i, ninputs;

	لكل (len = 0; len < حجم(ننوت); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_اندازه(مزي_اوږدوالی(ننوت_alphabet), len);
		لكل (i = 0; i < ninputs; i++) {
			make_کلمه(i, ننوت_alphabet,
			    مزي_اوږدوالی(ننوت_alphabet), ننوت, len);
			سمون_نمونه_check_one_ننوت(ننوت, نمونه_alphabet);
		}
	}
}

فراغ
tests(فراغ)
{
	TEST_پیل("match_pattern");
	ASSERT_INT_EQ(سمون_نمونه("", ""), 1);
	ASSERT_INT_EQ(سمون_نمونه("", "aaa"), 0);
	ASSERT_INT_EQ(سمون_نمونه("aaa", ""), 0);
	ASSERT_INT_EQ(سمون_نمونه("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(سمون_نمونه("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "abc"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abc", "abd"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "abcd"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abcd", "abc"), 0);
	TEST_بشپړ();

	TEST_پیل("match_pattern wildcard");
	ASSERT_INT_EQ(سمون_نمونه("", "*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("", "**"), 1);
	ASSERT_INT_EQ(سمون_نمونه("", "***"), 1);
	ASSERT_INT_EQ(سمون_نمونه("", "?"), 0);
	ASSERT_INT_EQ(سمون_نمونه("", "*?"), 0);
	ASSERT_INT_EQ(سمون_نمونه("", "?*"), 0);
	ASSERT_INT_EQ(سمون_نمونه("", "**a*"), 0);
	ASSERT_INT_EQ(سمون_نمونه("a", "?"), 1);
	ASSERT_INT_EQ(سمون_نمونه("aa", "a?"), 1);
	ASSERT_INT_EQ(سمون_نمونه("a", "*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("aa", "a*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("aa", "?*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("aa", "?a"), 1);
	ASSERT_INT_EQ(سمون_نمونه("aa", "*a"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ba", "a?"), 0);
	ASSERT_INT_EQ(سمون_نمونه("ba", "a*"), 0);
	ASSERT_INT_EQ(سمون_نمونه("ab", "?a"), 0);
	ASSERT_INT_EQ(سمون_نمونه("ab", "*a"), 0);
	ASSERT_INT_EQ(سمون_نمونه("aa", "**"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ab", "a***b"), 1);
	ASSERT_INT_EQ(سمون_نمونه("axb", "a***b"), 1);
	ASSERT_INT_EQ(سمون_نمونه("axxb", "a***b"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ax", "a***b"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(سمون_نمونه("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(سمون_نمونه("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ab", "*b"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ab", "*a*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ab", "*a*b"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ab", "*a*c"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "a?c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abc", "??c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abc", "???"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abc", "a?d"), 0);
	ASSERT_INT_EQ(سمون_نمونه("ab", "???"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "ab*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ab", "ab*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("a", "ab*"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "ab?"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ab", "ab?"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abcd", "ab?"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "?bc"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abc", "?b*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abc", "?c"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "a*?c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ac", "a*?c"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abc", "a?*c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ac", "a?*c"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "?*c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ac", "?*c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("c", "?*c"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "*?c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ac", "*?c"), 1);
	ASSERT_INT_EQ(سمون_نمونه("c", "*?c"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "a?*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ab", "a?*"), 1);
	ASSERT_INT_EQ(سمون_نمونه("a", "a?*"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abc", "a*?"), 1);
	ASSERT_INT_EQ(سمون_نمونه("ab", "a*?"), 1);
	ASSERT_INT_EQ(سمون_نمونه("a", "a*?"), 0);
	ASSERT_INT_EQ(سمون_نمونه("abb", "a*b"), 1);
	ASSERT_INT_EQ(سمون_نمونه("abbc", "a*b"), 0);
	TEST_بشپړ();

	TEST_پیل("match_pattern exhaustive original");
	سمون_نمونه_exhaustive_original();
	TEST_بشپړ();

	TEST_پیل("match_pattern_list");
	ASSERT_INT_EQ(سمون_نمونه_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(سمون_نمونه_list("", "*", 0), 1);
	ASSERT_INT_EQ(سمون_نمونه_list("", "!*", 0), -1);
	ASSERT_INT_EQ(سمون_نمونه_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(سمون_نمونه_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(سمون_نمونه_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(سمون_نمونه_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(سمون_نمونه_list("a", "", 0), 0);
	ASSERT_INT_EQ(سمون_نمونه_list("a", "*", 0), 1);
	ASSERT_INT_EQ(سمون_نمونه_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(سمون_نمونه_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(سمون_نمونه_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(سمون_نمونه_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(سمون_نمونه_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(سمون_نمونه_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(سمون_نمونه_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(سمون_نمونه_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(سمون_نمونه_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(سمون_نمونه_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(سمون_نمونه_list("b", "!*,a", 0), -1);
	TEST_بشپړ();

	TEST_پیل("match_pattern_list lowercase");
	ASSERT_INT_EQ(سمون_نمونه_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(سمون_نمونه_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(سمون_نمونه_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(سمون_نمونه_list("ABC", "abc", 1), 0);
	TEST_بشپړ();

	TEST_پیل("addr_match_list");
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_سمون_list(عدم, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_سمون_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_سمون_list(عدم, "*"), 0);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_سمون_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_سمون_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_بشپړ();

#تعریف_کړه CHECK_FILTER(string,filter,expected) \
	افعل { \
		حرف *پایله = سمون_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(پایله, expected); \
		حرر(پایله); \
	} طالما (0)

	TEST_پیل("match_filter_list");
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
	TEST_بشپړ();
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
	چاپ_کړه("no benchmarks\n");
}
