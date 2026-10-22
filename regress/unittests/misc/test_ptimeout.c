/* 	$OpenBSD: test_ptimeout.c,v 1.1 2023/01/06 02:59:50 djm Exp $ */
/*
 * Regress test for misc poll/ppoll timeout helpers.
 *
 * Placed in the public domain.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <time.h>

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"

शून्य test_ptimeout(शून्य);

शून्य
test_ptimeout(शून्य)
{
	संरचना timespec pt, *ts;

	TEST_START("ptimeout_init");
	ptimeout_init(&pt);
	ASSERT_PTR_EQ(ptimeout_get_tsp(&pt), रिक्त);
	ASSERT_INT_EQ(ptimeout_get_ms(&pt), -1);
	TEST_DONE();

	TEST_START("ptimeout_deadline_sec");
	ptimeout_deadline_sec(&pt, 100);
	ptimeout_deadline_sec(&pt, 200);
	ASSERT_INT_EQ(ptimeout_get_ms(&pt), 100 * 1000);
	ts = ptimeout_get_tsp(&pt);
	ASSERT_PTR_NE(ts, रिक्त);
	ASSERT_LONG_EQ(ts->tv_nsec, 0);
	ASSERT_LONG_EQ(ts->tv_sec, 100);
	TEST_DONE();

	TEST_START("ptimeout_deadline_ms");
	ptimeout_deadline_ms(&pt, 50123);
	ptimeout_deadline_ms(&pt, 50500);
	ASSERT_INT_EQ(ptimeout_get_ms(&pt), 50123);
	ts = ptimeout_get_tsp(&pt);
	ASSERT_PTR_NE(ts, रिक्त);
	ASSERT_LONG_EQ(ts->tv_nsec, 123 * 1000000);
	ASSERT_LONG_EQ(ts->tv_sec, 50);
	TEST_DONE();

	TEST_START("ptimeout zero");
	ptimeout_init(&pt);
	ptimeout_deadline_ms(&pt, 0);
	ASSERT_INT_EQ(ptimeout_get_ms(&pt), 0);
	ts = ptimeout_get_tsp(&pt);
	ASSERT_PTR_NE(ts, रिक्त);
	ASSERT_LONG_EQ(ts->tv_nsec, 0);
	ASSERT_LONG_EQ(ts->tv_sec, 0);
	TEST_DONE();

	TEST_START("ptimeout_deadline_monotime");
	ptimeout_init(&pt);
	ptimeout_deadline_monotime(&pt, monotime() + 100);
	ASSERT_INT_GT(ptimeout_get_ms(&pt), 50000);
	ASSERT_INT_LT(ptimeout_get_ms(&pt), 200000);
	ts = ptimeout_get_tsp(&pt);
	ASSERT_PTR_NE(ts, रिक्त);
	ASSERT_LONG_GT(ts->tv_sec, 50);
	ASSERT_LONG_LT(ts->tv_sec, 200);
	TEST_DONE();

	TEST_START("ptimeout_deadline_monotime past");
	ptimeout_init(&pt);
	ptimeout_deadline_monotime(&pt, monotime() + 100);
	ptimeout_deadline_monotime(&pt, monotime() - 100);
	ASSERT_INT_EQ(ptimeout_get_ms(&pt), 0);
	ts = ptimeout_get_tsp(&pt);
	ASSERT_PTR_NE(ts, रिक्त);
	ASSERT_LONG_EQ(ts->tv_nsec, 0);
	ASSERT_LONG_EQ(ts->tv_sec, 0);
	TEST_DONE();
}
