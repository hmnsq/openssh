/*
 * Copyright (c) 2020 Darren Tucker <dtucker@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
সংরচনা xaddr;

সংরচনা per_source_penalty;

শূন্য	srclimit_init(পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক,
    সংরচনা per_source_penalty *, ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	srclimit_check_allow(পূর্ণাঙ্ক, পূর্ণাঙ্ক);
শূন্য	srclimit_done(পূর্ণাঙ্ক);

#define SRCLIMIT_PENALTY_NONE			0
#define SRCLIMIT_PENALTY_CRASH			1
#define SRCLIMIT_PENALTY_AUTHFAIL		2
#define SRCLIMIT_PENALTY_GRACE_EXCEEDED		3
#define SRCLIMIT_PENALTY_NOAUTH			4
#define SRCLIMIT_PENALTY_REFUSECONNECTION	5
#define SRCLIMIT_PENALTY_INVALIDUSER		6

/* meaningful exit values, used by sshd listener for penalties */
#define EXIT_LOGIN_GRACE	3	/* login grace period exceeded */
#define EXIT_CHILD_CRASH	4	/* preauth child crashed */
#define EXIT_AUTH_ATTEMPTED	5	/* at least one auth attempt made */
#define EXIT_CONFIG_REFUSED	6	/* sshd_config RefuseConnection */
#define EXIT_INVALID_USER	7	/* invalid user supplied */

শূন্য	srclimit_penalise(সংরচনা xaddr *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	srclimit_penalty_check_allow(পূর্ণাঙ্ক, ধ্রুৱ ৱর্ণ **);
শূন্য	srclimit_penalty_info(শূন্য);
