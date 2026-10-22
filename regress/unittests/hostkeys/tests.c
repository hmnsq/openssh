/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdio.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

ശൂന്യം tests(ശൂന്യം);
ശൂന്യം test_iterate(ശൂന്യം); /* test_iterate.c */

ശൂന്യം
tests(ശൂന്യം)
{
	test_iterate();
}

ശൂന്യം
benchmarks(ശൂന്യം)
{
	printf("no benchmarks\n");
}
