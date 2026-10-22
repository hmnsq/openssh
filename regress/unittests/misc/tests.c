/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"

शून्य test_parse(शून्य);
शून्य test_convtime(शून्य);
शून्य test_expand(शून्य);
शून्य test_argv(शून्य);
शून्य test_strdelim(शून्य);
शून्य test_hpdelim(शून्य);
शून्य test_ptimeout(शून्य);
शून्य test_xextendf(शून्य);
शून्य test_misc(शून्य);

शून्य
tests(शून्य)
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

शून्य
benchmarks(शून्य)
{
	म_लिखो("no benchmarks\n");
}
