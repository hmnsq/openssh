/* 	$OpenBSD: test_argv.c,v 1.4 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc argv handling functions.
 *
 * Placed in the public domain.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

ਖਾਲੀ test_argv(ਖਾਲੀ);

ਖਾਲੀ
test_argv(ਖਾਲੀ)
{
	ਅੱਖਰ **av = ਨਿਰਾ;
	ਪੂਰਨ ac = 0;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RESET_ARGV() \
	ਕਰੋ { \
		argv_free(av, ac); \
		av = ਨਿਰਾ; \
		ac = -1; \
	} ਜਦੋਂ (0)

	TEST_ਸ਼ੁਰੂ("empty args");
	ASSERT_INT_EQ(argv_ਵੰਡੋ("", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_PTR_EQ(av[0], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("    ", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_PTR_EQ(av[0], ਨਿਰਾ);
	RESET_ARGV();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("trivial args");
	ASSERT_INT_EQ(argv_ਵੰਡੋ("leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("smiley leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_STRING_EQ(av[1], "leamas");
	ASSERT_PTR_EQ(av[2], ਨਿਰਾ);
	RESET_ARGV();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("quoted");
	ASSERT_INT_EQ(argv_ਵੰਡੋ("\"smiley\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("leamas \" smiley \"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_STRING_EQ(av[1], " smiley ");
	ASSERT_PTR_EQ(av[2], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("\"smiley leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("smiley\" leamas\" liz", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_STRING_EQ(av[1], "liz");
	ASSERT_PTR_EQ(av[2], ਨਿਰਾ);
	RESET_ARGV();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("escaped");
	ASSERT_INT_EQ(argv_ਵੰਡੋ("\\\"smiley\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "\"smiley'");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("'\\'smiley\\\"'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "'smiley\"");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("smiley\\'s leamas\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "smiley's");
	ASSERT_STRING_EQ(av[1], "leamas'");
	ASSERT_PTR_EQ(av[2], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("leamas\\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "leamas\\smiley");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("leamas\\\\ \\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "leamas\\");
	ASSERT_STRING_EQ(av[1], "\\smiley");
	ASSERT_PTR_EQ(av[2], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("smiley\\ leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("quoted escaped");
	ASSERT_INT_EQ(argv_ਵੰਡੋ("'smiley\\ leamas'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("\"smiley\\ leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("comments");
	ASSERT_INT_EQ(argv_ਵੰਡੋ("# gold", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "#");
	ASSERT_STRING_EQ(av[1], "gold");
	ASSERT_PTR_EQ(av[2], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("# gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_PTR_EQ(av[0], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("leamas#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("\"leamas # gold\"", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "leamas # gold");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ਵੰਡੋ("\"leamas\"#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ਨਿਰਾ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ਨਿਰਾ);
	RESET_ARGV();
	TEST_ਪੂਰਾ();

	/* XXX test char *argv_assemble(int argc, char **argv) */
}
