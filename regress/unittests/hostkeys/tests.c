/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <stdio.h>

#شامل "../test_helper/test_helper.h"

خالی tests(خالی);
خالی test_iterate(خالی); /* test_iterate.c */

خالی
tests(خالی)
{
	test_iterate();
}

خالی
benchmarks(خالی)
{
	لکھو("no benchmarks\n");
}
