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
میل_نمونہ_original(ثابت حرف *s, ثابت حرف *نمونہ)
{
	لكل (;;) {
		/* If at end of pattern, accept if also at end of string. */
		إذا (!*نمونہ)
			أرجع !*s;

		إذا (*نمونہ == '*') {
			/* Skip this and any consecutive asterisks. */
			طالما (*نمونہ == '*')
				نمونہ++;

			/* If at end of pattern, accept immediately. */
			إذا (!*نمونہ)
				أرجع 1;

			/* If next character in pattern is known, optimize. */
			إذا (*نمونہ != '?' && *نمونہ != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				لكل (; *s; s++)
					إذا (*s == *نمونہ &&
					    میل_نمونہ_original(s + 1,
					    نمونہ + 1))
						أرجع 1;
				/* Failed. */
				أرجع 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			لكل (; *s; s++)
				إذا (میل_نمونہ_original(s, نمونہ))
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
		إذا (*نمونہ != '?' && *نمونہ != *s)
			أرجع 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		نمونہ++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
ساكن ناپ_t
pow_ناپ(ناپ_t ادھار, ناپ_t قوت_نما)
{
	ناپ_t r = 1;

	ASSERT_ناپ_T_NE(ادھار, 0);
	طالما (قوت_نما-- != 0) {
		ASSERT_ناپ_T_LE(r, SIZE_MAX / ادھار);
		r *= ادھار;
	}
	أرجع r;
}

ساكن فراغ
make_لفظ(ناپ_t v, ثابت حرف *alphabet, ناپ_t alphabet_len,
    حرف *لفظ, ناپ_t wordlen)
{
	ناپ_t i;

	لكل (i = 0; i < wordlen; i++) {
		لفظ[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	لفظ[wordlen] = '\0';
}

#تعریف_کرو نمونہ_LEN	8
#تعریف_کرو داخلہ_LEN	7

ساكن فراغ
میل_نمونہ_check_one_داخلہ(ثابت حرف *داخلہ, ثابت حرف *نمونہ_alphabet)
{
	حرف نمونہ[نمونہ_LEN];
	ناپ_t len, i, npatterns;
	صحيح actual, expected;

	لكل (len = 0; len < حجم(نمونہ); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_ناپ(لڑی_لمبائی(نمونہ_alphabet), len);
		لكل (i = 0; i < npatterns; i++) {
			make_لفظ(i, نمونہ_alphabet,
			    لڑی_لمبائی(نمونہ_alphabet), نمونہ, len);
			actual = میل_نمونہ(داخلہ, نمونہ);
			expected = میل_نمونہ_original(داخلہ, نمونہ);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    داخلہ, نمونہ);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
ساكن فراغ
میل_نمونہ_exhaustive_original(فراغ)
{
	ثابت حرف *نمونہ_alphabet = "abx?*";
	ثابت حرف *داخلہ_alphabet = "abc";
	حرف داخلہ[داخلہ_LEN];
	ناپ_t len, i, ninputs;

	لكل (len = 0; len < حجم(داخلہ); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_ناپ(لڑی_لمبائی(داخلہ_alphabet), len);
		لكل (i = 0; i < ninputs; i++) {
			make_لفظ(i, داخلہ_alphabet,
			    لڑی_لمبائی(داخلہ_alphabet), داخلہ, len);
			میل_نمونہ_check_one_داخلہ(داخلہ, نمونہ_alphabet);
		}
	}
}

فراغ
tests(فراغ)
{
	TEST_شروع("match_pattern");
	ASSERT_INT_EQ(میل_نمونہ("", ""), 1);
	ASSERT_INT_EQ(میل_نمونہ("", "aaa"), 0);
	ASSERT_INT_EQ(میل_نمونہ("aaa", ""), 0);
	ASSERT_INT_EQ(میل_نمونہ("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(میل_نمونہ("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "abc"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abc", "abd"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "abcd"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abcd", "abc"), 0);
	TEST_پورا();

	TEST_شروع("match_pattern wildcard");
	ASSERT_INT_EQ(میل_نمونہ("", "*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("", "**"), 1);
	ASSERT_INT_EQ(میل_نمونہ("", "***"), 1);
	ASSERT_INT_EQ(میل_نمونہ("", "?"), 0);
	ASSERT_INT_EQ(میل_نمونہ("", "*?"), 0);
	ASSERT_INT_EQ(میل_نمونہ("", "?*"), 0);
	ASSERT_INT_EQ(میل_نمونہ("", "**a*"), 0);
	ASSERT_INT_EQ(میل_نمونہ("a", "?"), 1);
	ASSERT_INT_EQ(میل_نمونہ("aa", "a?"), 1);
	ASSERT_INT_EQ(میل_نمونہ("a", "*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("aa", "a*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("aa", "?*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("aa", "?a"), 1);
	ASSERT_INT_EQ(میل_نمونہ("aa", "*a"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ba", "a?"), 0);
	ASSERT_INT_EQ(میل_نمونہ("ba", "a*"), 0);
	ASSERT_INT_EQ(میل_نمونہ("ab", "?a"), 0);
	ASSERT_INT_EQ(میل_نمونہ("ab", "*a"), 0);
	ASSERT_INT_EQ(میل_نمونہ("aa", "**"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ab", "a***b"), 1);
	ASSERT_INT_EQ(میل_نمونہ("axb", "a***b"), 1);
	ASSERT_INT_EQ(میل_نمونہ("axxb", "a***b"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ax", "a***b"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(میل_نمونہ("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(میل_نمونہ("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ab", "*b"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ab", "*a*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ab", "*a*b"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ab", "*a*c"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "a?c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abc", "??c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abc", "???"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abc", "a?d"), 0);
	ASSERT_INT_EQ(میل_نمونہ("ab", "???"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "ab*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ab", "ab*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("a", "ab*"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "ab?"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ab", "ab?"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abcd", "ab?"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "?bc"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abc", "?b*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abc", "?c"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "a*?c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ac", "a*?c"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abc", "a?*c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ac", "a?*c"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "?*c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ac", "?*c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("c", "?*c"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "*?c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ac", "*?c"), 1);
	ASSERT_INT_EQ(میل_نمونہ("c", "*?c"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "a?*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ab", "a?*"), 1);
	ASSERT_INT_EQ(میل_نمونہ("a", "a?*"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abc", "a*?"), 1);
	ASSERT_INT_EQ(میل_نمونہ("ab", "a*?"), 1);
	ASSERT_INT_EQ(میل_نمونہ("a", "a*?"), 0);
	ASSERT_INT_EQ(میل_نمونہ("abb", "a*b"), 1);
	ASSERT_INT_EQ(میل_نمونہ("abbc", "a*b"), 0);
	TEST_پورا();

	TEST_شروع("match_pattern exhaustive original");
	میل_نمونہ_exhaustive_original();
	TEST_پورا();

	TEST_شروع("match_pattern_list");
	ASSERT_INT_EQ(میل_نمونہ_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(میل_نمونہ_list("", "*", 0), 1);
	ASSERT_INT_EQ(میل_نمونہ_list("", "!*", 0), -1);
	ASSERT_INT_EQ(میل_نمونہ_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(میل_نمونہ_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(میل_نمونہ_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(میل_نمونہ_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(میل_نمونہ_list("a", "", 0), 0);
	ASSERT_INT_EQ(میل_نمونہ_list("a", "*", 0), 1);
	ASSERT_INT_EQ(میل_نمونہ_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(میل_نمونہ_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(میل_نمونہ_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(میل_نمونہ_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(میل_نمونہ_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(میل_نمونہ_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(میل_نمونہ_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(میل_نمونہ_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(میل_نمونہ_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(میل_نمونہ_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(میل_نمونہ_list("b", "!*,a", 0), -1);
	TEST_پورا();

	TEST_شروع("match_pattern_list lowercase");
	ASSERT_INT_EQ(میل_نمونہ_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(میل_نمونہ_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(میل_نمونہ_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(میل_نمونہ_list("ABC", "abc", 1), 0);
	TEST_پورا();

	TEST_شروع("addr_match_list");
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_میل_list(عدم, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_میل_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_میل_list(عدم, "*"), 0);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_میل_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_میل_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_میل_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_پورا();

#تعریف_کرو CHECK_FILTER(string,filter,expected) \
	افعل { \
		حرف *نتیجہ = میل_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(نتیجہ, expected); \
		حرر(نتیجہ); \
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
	TEST_پورا();
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
	لکھو("no benchmarks\n");
}
