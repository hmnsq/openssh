/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdio.h>

#अन्तर्भाव "../test_helper/test_helper.h"

शून्य tests(शून्य);
शून्य test_iterate(शून्य); /* test_iterate.c */

शून्य
tests(शून्य)
{
	test_iterate();
}

शून्य
benchmarks(शून्य)
{
	प्रारूप_लिख("no benchmarks\n");
}
