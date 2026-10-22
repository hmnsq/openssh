/* 	$OpenBSD: tests.c,v 1.5 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for conversions
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "misc.h"

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ buf[1024];

	TEST_ಆರಂಭ("conversion_convtime");
	ASSERT_INT_EQ(convtime("0"), 0);
	ASSERT_INT_EQ(convtime("1"), 1);
	ASSERT_INT_EQ(convtime("1S"), 1);
	/* from the examples in the comment above the function */
	ASSERT_INT_EQ(convtime("90m"), 5400);
	ASSERT_INT_EQ(convtime("1h30m"), 5400);
	ASSERT_INT_EQ(convtime("2d"), 172800);
	ASSERT_INT_EQ(convtime("1w"), 604800);

	/* negative time is not allowed */
	ASSERT_INT_EQ(convtime("-7"), -1);
	ASSERT_INT_EQ(convtime("-9d"), -1);
	
	/*ಅತಿಪ್ರವಾಹ*/
	snprintf(buf, ಗಾತ್ರ buf, "%llu", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ);
	ASSERT_INT_EQ(convtime(buf), ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ);
	snprintf(buf, ಗಾತ್ರ buf, "%llu", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ + 1);
	ASSERT_INT_EQ(convtime(buf), -1);

	/* overflow with multiplier */
	snprintf(buf, ಗಾತ್ರ buf, "%lluM", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ/60 + 1);
	ASSERT_INT_EQ(convtime(buf), -1);
	ASSERT_INT_EQ(convtime("1000000000000000000000w"), -1);
	TEST_ಮುಗಿದ();
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	ಬರೆ("no benchmarks\n");
}
