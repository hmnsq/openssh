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
ميلاپ_نمونو_original(ثابت حرف *s, ثابت حرف *نمونو)
{
	لكل (;;) {
		/* If at end of pattern, accept if also at end of string. */
		إذا (!*نمونو)
			أرجع !*s;

		إذا (*نمونو == '*') {
			/* Skip this and any consecutive asterisks. */
			طالما (*نمونو == '*')
				نمونو++;

			/* If at end of pattern, accept immediately. */
			إذا (!*نمونو)
				أرجع 1;

			/* If next character in pattern is known, optimize. */
			إذا (*نمونو != '?' && *نمونو != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				لكل (; *s; s++)
					إذا (*s == *نمونو &&
					    ميلاپ_نمونو_original(s + 1,
					    نمونو + 1))
						أرجع 1;
				/* Failed. */
				أرجع 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			لكل (; *s; s++)
				إذا (ميلاپ_نمونو_original(s, نمونو))
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
		إذا (*نمونو != '?' && *نمونو != *s)
			أرجع 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		نمونو++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
ساكن سائيز_t
pow_سائيز(سائيز_t بنياد, سائيز_t قوت_نما)
{
	سائيز_t r = 1;

	ASSERT_سائيز_T_NE(بنياد, 0);
	طالما (قوت_نما-- != 0) {
		ASSERT_سائيز_T_LE(r, SIZE_MAX / بنياد);
		r *= بنياد;
	}
	أرجع r;
}

ساكن فراغ
make_لفظ(سائيز_t v, ثابت حرف *alphabet, سائيز_t alphabet_len,
    حرف *لفظ_2, سائيز_t wordlen)
{
	سائيز_t i;

	لكل (i = 0; i < wordlen; i++) {
		لفظ_2[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	لفظ_2[wordlen] = '\0';
}

#وصف_ڪريو نمونو_LEN	8
#وصف_ڪريو داخلا_LEN	7

ساكن فراغ
ميلاپ_نمونو_check_one_داخلا(ثابت حرف *داخلا_2, ثابت حرف *نمونو_alphabet)
{
	حرف نمونو[نمونو_LEN];
	سائيز_t len, i, npatterns;
	صحيح actual, expected;

	لكل (len = 0; len < حجم(نمونو); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_سائيز(لڙي_ڊيگهه(نمونو_alphabet), len);
		لكل (i = 0; i < npatterns; i++) {
			make_لفظ(i, نمونو_alphabet,
			    لڙي_ڊيگهه(نمونو_alphabet), نمونو, len);
			actual = ميلاپ_نمونو(داخلا_2, نمونو);
			expected = ميلاپ_نمونو_original(داخلا_2, نمونو);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    داخلا_2, نمونو);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
ساكن فراغ
ميلاپ_نمونو_exhaustive_original(فراغ)
{
	ثابت حرف *نمونو_alphabet = "abx?*";
	ثابت حرف *داخلا_alphabet = "abc";
	حرف داخلا_2[داخلا_LEN];
	سائيز_t len, i, ninputs;

	لكل (len = 0; len < حجم(داخلا_2); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_سائيز(لڙي_ڊيگهه(داخلا_alphabet), len);
		لكل (i = 0; i < ninputs; i++) {
			make_لفظ(i, داخلا_alphabet,
			    لڙي_ڊيگهه(داخلا_alphabet), داخلا_2, len);
			ميلاپ_نمونو_check_one_داخلا(داخلا_2, نمونو_alphabet);
		}
	}
}

فراغ
tests(فراغ)
{
	TEST_شروعات("match_pattern");
	ASSERT_INT_EQ(ميلاپ_نمونو("", ""), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("", "aaa"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("aaa", ""), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "abc"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "abd"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "abcd"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abcd", "abc"), 0);
	TEST_پورو();

	TEST_شروعات("match_pattern wildcard");
	ASSERT_INT_EQ(ميلاپ_نمونو("", "*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("", "**"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("", "***"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("", "?"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("", "*?"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("", "?*"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("", "**a*"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("a", "?"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("aa", "a?"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("a", "*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("aa", "a*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("aa", "?*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("aa", "?a"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("aa", "*a"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ba", "a?"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("ba", "a*"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "?a"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "*a"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("aa", "**"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "a***b"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("axb", "a***b"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("axxb", "a***b"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ax", "a***b"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "*b"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "*a*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "*a*b"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "*a*c"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "a?c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "??c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "???"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "a?d"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "???"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "ab*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "ab*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("a", "ab*"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "ab?"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "ab?"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abcd", "ab?"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "?bc"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "?b*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "?c"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "a*?c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ac", "a*?c"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "a?*c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ac", "a?*c"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "?*c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ac", "?*c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("c", "?*c"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "*?c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ac", "*?c"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("c", "*?c"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "a?*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "a?*"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("a", "a?*"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abc", "a*?"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("ab", "a*?"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("a", "a*?"), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو("abb", "a*b"), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو("abbc", "a*b"), 0);
	TEST_پورو();

	TEST_شروعات("match_pattern exhaustive original");
	ميلاپ_نمونو_exhaustive_original();
	TEST_پورو();

	TEST_شروعات("match_pattern_list");
	ASSERT_INT_EQ(ميلاپ_نمونو_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(ميلاپ_نمونو_list("", "*", 0), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("", "!*", 0), -1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("a", "", 0), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("a", "*", 0), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(ميلاپ_نمونو_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(ميلاپ_نمونو_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("b", "!*,a", 0), -1);
	TEST_پورو();

	TEST_شروعات("match_pattern_list lowercase");
	ASSERT_INT_EQ(ميلاپ_نمونو_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(ميلاپ_نمونو_list("ABC", "abc", 1), 0);
	TEST_پورو();

	TEST_شروعات("addr_match_list");
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_ميلاپ_list(عدم, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_ميلاپ_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_ميلاپ_list(عدم, "*"), 0);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_ميلاپ_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_پورو();

#وصف_ڪريو CHECK_FILTER(string,filter,expected) \
	افعل { \
		حرف *نتيجو = ميلاپ_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(نتيجو, expected); \
		حرر(نتيجو); \
	} طالما (0)

	TEST_شروعات("match_filter_list");
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
	TEST_پورو();
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
	لکو("no benchmarks\n");
}
