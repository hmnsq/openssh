/* 	$OpenBSD: tests.c,v 1.10 2026/05/31 04:20:58 djm Exp $ */
/*
 * Regress test for matching functions
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "match.h"

/* Original match_pattern() implementation; has bad worst-case behaviour */
ساکن صحیح
مطابقت_نمونہ_original(ثابت حرف *s, ثابت حرف *نمونہ)
{
	برائے (;;) {
		/* If at end of pattern, accept if also at end of string. */
		اگر (!*نمونہ)
			واپس !*s;

		اگر (*نمونہ == '*') {
			/* Skip this and any consecutive asterisks. */
			جب (*نمونہ == '*')
				نمونہ++;

			/* If at end of pattern, accept immediately. */
			اگر (!*نمونہ)
				واپس 1;

			/* If next character in pattern is known, optimize. */
			اگر (*نمونہ != '?' && *نمونہ != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				برائے (; *s; s++)
					اگر (*s == *نمونہ &&
					    مطابقت_نمونہ_original(s + 1,
					    نمونہ + 1))
						واپس 1;
				/* Failed. */
				واپس 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			برائے (; *s; s++)
				اگر (مطابقت_نمونہ_original(s, نمونہ))
					واپس 1;
			/* Failed. */
			واپس 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		اگر (!*s)
			واپس 0;

		/* Check if the next character of the string is acceptable. */
		اگر (*نمونہ != '?' && *نمونہ != *s)
			واپس 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		نمونہ++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
ساکن سائز_t
pow_سائز(سائز_t بنیاد, سائز_t قوت_نما)
{
	سائز_t r = 1;

	ASSERT_سائز_T_NE(بنیاد, 0);
	جب (قوت_نما-- != 0) {
		ASSERT_سائز_T_LE(r, SIZE_MAX / بنیاد);
		r *= بنیاد;
	}
	واپس r;
}

ساکن خالی
make_لفظ(سائز_t v, ثابت حرف *alphabet, سائز_t alphabet_len,
    حرف *لفظ, سائز_t wordlen)
{
	سائز_t i;

	برائے (i = 0; i < wordlen; i++) {
		لفظ[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	لفظ[wordlen] = '\0';
}

#تعریف_کرو نمونہ_LEN	8
#تعریف_کرو داخلہ_LEN	7

ساکن خالی
مطابقت_نمونہ_check_one_داخلہ(ثابت حرف *داخلہ, ثابت حرف *نمونہ_alphabet)
{
	حرف نمونہ[نمونہ_LEN];
	سائز_t len, i, npatterns;
	صحیح actual, expected;

	برائے (len = 0; len < حجم(نمونہ); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_سائز(لڑی_لمبائی(نمونہ_alphabet), len);
		برائے (i = 0; i < npatterns; i++) {
			make_لفظ(i, نمونہ_alphabet,
			    لڑی_لمبائی(نمونہ_alphabet), نمونہ, len);
			actual = مطابقت_نمونہ(داخلہ, نمونہ);
			expected = مطابقت_نمونہ_original(داخلہ, نمونہ);
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
ساکن خالی
مطابقت_نمونہ_exhaustive_original(خالی)
{
	ثابت حرف *نمونہ_alphabet = "abx?*";
	ثابت حرف *داخلہ_alphabet = "abc";
	حرف داخلہ[داخلہ_LEN];
	سائز_t len, i, ninputs;

	برائے (len = 0; len < حجم(داخلہ); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_سائز(لڑی_لمبائی(داخلہ_alphabet), len);
		برائے (i = 0; i < ninputs; i++) {
			make_لفظ(i, داخلہ_alphabet,
			    لڑی_لمبائی(داخلہ_alphabet), داخلہ, len);
			مطابقت_نمونہ_check_one_داخلہ(داخلہ, نمونہ_alphabet);
		}
	}
}

خالی
tests(خالی)
{
	TEST_آغاز("match_pattern");
	ASSERT_INT_EQ(مطابقت_نمونہ("", ""), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("", "aaa"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("aaa", ""), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "abc"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "abd"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "abcd"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abcd", "abc"), 0);
	TEST_مکمل();

	TEST_آغاز("match_pattern wildcard");
	ASSERT_INT_EQ(مطابقت_نمونہ("", "*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("", "**"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("", "***"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("", "?"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("", "*?"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("", "?*"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("", "**a*"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("a", "?"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("aa", "a?"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("a", "*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("aa", "a*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("aa", "?*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("aa", "?a"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("aa", "*a"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ba", "a?"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("ba", "a*"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "?a"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "*a"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("aa", "**"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "a***b"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("axb", "a***b"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("axxb", "a***b"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ax", "a***b"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "*b"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "*a*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "*a*b"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "*a*c"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "a?c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "??c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "???"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "a?d"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "???"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "ab*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "ab*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("a", "ab*"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "ab?"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "ab?"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abcd", "ab?"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "?bc"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "?b*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "?c"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "a*?c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ac", "a*?c"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "a?*c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ac", "a?*c"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "?*c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ac", "?*c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("c", "?*c"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "*?c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ac", "*?c"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("c", "*?c"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "a?*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "a?*"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("a", "a?*"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abc", "a*?"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("ab", "a*?"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("a", "a*?"), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ("abb", "a*b"), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ("abbc", "a*b"), 0);
	TEST_مکمل();

	TEST_آغاز("match_pattern exhaustive original");
	مطابقت_نمونہ_exhaustive_original();
	TEST_مکمل();

	TEST_آغاز("match_pattern_list");
	ASSERT_INT_EQ(مطابقت_نمونہ_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(مطابقت_نمونہ_list("", "*", 0), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("", "!*", 0), -1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("a", "", 0), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("a", "*", 0), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(مطابقت_نمونہ_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(مطابقت_نمونہ_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("b", "!*,a", 0), -1);
	TEST_مکمل();

	TEST_آغاز("match_pattern_list lowercase");
	ASSERT_INT_EQ(مطابقت_نمونہ_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(مطابقت_نمونہ_list("ABC", "abc", 1), 0);
	TEST_مکمل();

	TEST_آغاز("addr_match_list");
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_مطابقت_list(تہی, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_مطابقت_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_مطابقت_list(تہی, "*"), 0);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_مطابقت_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_مکمل();

#تعریف_کرو CHECK_FILTER(string,filter,expected) \
	کرو { \
		حرف *نتیجہ = مطابقت_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(نتیجہ, expected); \
		آزاد(نتیجہ); \
	} جب (0)

	TEST_آغاز("match_filter_list");
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
	TEST_مکمل();
/*
 * XXX TODO
 * int      match_host_and_ip(const char *, const char *, const char *);
 * int      match_user(const char *, const char *, const char *, const char *);
 * char    *match_list(const char *, const char *, u_int *);
 * int      addr_match_cidr_list(const char *, const char *);
 */
}

خالی
benchmarks(خالی)
{
	لکھو("no benchmarks\n");
}
