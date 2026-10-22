/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"

வெறுமை test_parse(வெறுமை);
வெறுமை test_convtime(வெறுமை);
வெறுமை test_expand(வெறுமை);
வெறுமை test_argv(வெறுமை);
வெறுமை test_strdelim(வெறுமை);
வெறுமை test_hpdelim(வெறுமை);
வெறுமை test_ptimeout(வெறுமை);
வெறுமை test_xextendf(வெறுமை);
வெறுமை test_misc(வெறுமை);

வெறுமை
tests(வெறுமை)
{
	test_parse();
	test_convtime();
	test_expand();
	test_argv();
	test_strdelim();
	test_hpdelim();
	test_ptimeout();
	test_xextendf();
	test_misc();
}

வெறுமை
benchmarks(வெறுமை)
{
	printf("no benchmarks\n");
}
