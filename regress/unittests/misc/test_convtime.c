/* 	$OpenBSD: test_convtime.c,v 1.4 2025/12/05 07:43:24 djm Exp $ */
/*
 * Regress test for misc time conversion functions.
 *
 * Placed in the public domain.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਖਾਲੀ test_convtime(ਖਾਲੀ);

ਖਾਲੀ
test_convtime(ਖਾਲੀ)
{
	ਅੱਖਰ buf[1024];
	uint64_t t;

	TEST_ਸ਼ੁਰੂ("misc_convtime");
	ASSERT_INT_EQ(convtime("0"), 0);
	ASSERT_INT_EQ(convtime("1"), 1);
	ASSERT_INT_EQ(convtime("2s"), 2);
	ASSERT_INT_EQ(convtime("3m"), 180);
	ASSERT_INT_EQ(convtime("1m30"), 90);
	ASSERT_INT_EQ(convtime("1m30s"), 90);
	ASSERT_INT_EQ(convtime("1h1s"), 3601);
	ASSERT_INT_EQ(convtime("1h30m"), 90 * 60);
	ASSERT_INT_EQ(convtime("1d"), 24 * 60 * 60);
	ASSERT_INT_EQ(convtime("1w"), 7 * 24 * 60 * 60);
	ASSERT_INT_EQ(convtime("1w2d3h4m5"), 788645);
	ASSERT_INT_EQ(convtime("1w2d3h4m5s"), 788645);
	/* any negative number or error returns -1 */
	ASSERT_INT_EQ(convtime("-1"),  -1);
	ASSERT_INT_EQ(convtime(""),  -1);
	ASSERT_INT_EQ(convtime("trout"),  -1);
	ASSERT_INT_EQ(convtime("-77"),  -1);
	/* boundary conditions */
	snprintf(buf, ਆਕਾਰ buf, "%llu", (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ);
	ASSERT_INT_EQ(convtime(buf), ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ);
	snprintf(buf, ਆਕਾਰ buf, "%llu", (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ + 1);
	ASSERT_INT_EQ(convtime(buf), -1);
	ASSERT_INT_EQ(convtime("3550w5d3h14m7s"), 2147483647);
#ਜੇ ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ == 2147483647
	ASSERT_INT_EQ(convtime("3550w5d3h14m8s"), -1);
#ਜੇ_ਅੰਤ
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("misc_convtime_double");
	ASSERT_DOUBLE_EQ(convtime_double("0"), 0);
	ASSERT_DOUBLE_EQ(convtime_double("1"), 1.0);
	ASSERT_DOUBLE_EQ(convtime_double("2s"), 2.0);
	ASSERT_DOUBLE_EQ(convtime_double("3m"), 180.0);
	ASSERT_DOUBLE_EQ(convtime_double("1m30s"), 90.0);
	ASSERT_DOUBLE_EQ(convtime_double("1.5s"), 1.5);
	ASSERT_DOUBLE_EQ(convtime_double(".5s"), 0.5);
	ASSERT_DOUBLE_EQ(convtime_double("0.5s"), 0.5);
	ASSERT_DOUBLE_EQ(convtime_double("1.123456s"), 1.123456);
	ASSERT_DOUBLE_EQ(convtime_double("1.1234567s"), 1.1234567);
	ASSERT_DOUBLE_EQ(convtime_double("1.123s"), 1.123);
	ASSERT_DOUBLE_EQ(convtime_double("1m0.5s"), 60.5);
	ASSERT_DOUBLE_EQ(convtime_double("1m.5s"), 60.5);
	ASSERT_DOUBLE_EQ(convtime_double("1.5"), 1.5);
	ASSERT_DOUBLE_EQ(convtime_double("1.123456"), 1.123456);
	ASSERT_DOUBLE_EQ(convtime_double("1.1234567"), 1.1234567);
	/* errors */
	ASSERT_DOUBLE_LT(convtime_double(""), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("trout"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("1.s"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("0x1"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("inf"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("nan"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("1e10"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("-1"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("3.w0.5s"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("1.0d0.5s"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("1.5m"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("1.5h"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("1.5d"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("1.5w"), 0.0);
	ASSERT_DOUBLE_LT(convtime_double("1s1.5"), 0.0);
	TEST_ਪੂਰਾ();

	/* XXX timezones/DST make verification of this tricky */
	/* XXX maybe setenv TZ and tzset() to make it unambiguous? */
	TEST_ਸ਼ੁਰੂ("misc_parse_absolute_time");
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101", &t), 0);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("200001011223", &t), 0);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101122345", &t), 0);

	/* forced UTC TZ */
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101Z", &t), 0);
	ASSERT_U64_EQ(t, 946684800);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("200001011223Z", &t), 0);
	ASSERT_U64_EQ(t, 946729380);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101122345Z", &t), 0);
	ASSERT_U64_EQ(t, 946729425);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101UTC", &t), 0);
	ASSERT_U64_EQ(t, 946684800);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("200001011223UTC", &t), 0);
	ASSERT_U64_EQ(t, 946729380);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101122345UTC", &t), 0);
	ASSERT_U64_EQ(t, 946729425);

	/* Bad month */
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20001301", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000001", &t),
	    SSH_ERR_INVALID_FORMAT);
	/* Incomplete */
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("2", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("2000", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("200001", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("2000010", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("200001010", &t),
	    SSH_ERR_INVALID_FORMAT);
	/* Bad day, hour, minute, second */
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000199", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("200001019900", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("200001010099", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101000099", &t),
	    SSH_ERR_INVALID_FORMAT);
	/* Invalid TZ specifier */
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101ZZ", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101PDT", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101U", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_ਸਮਾਂ("20000101UTCUTC", &t),
	    SSH_ERR_INVALID_FORMAT);

	TEST_ਪੂਰਾ();
}
