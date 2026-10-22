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
بنية xaddr;

بنية فی_سرچینه_penalty;

فراغ	srclimit_init(صحيح, صحيح, صحيح, صحيح,
    بنية فی_سرچینه_penalty *, ثابت حرف *);
صحيح	srclimit_check_allow(صحيح, صحيح);
فراغ	srclimit_بشپړ(صحيح);

#تعریف_کړه SRCLIMIT_PENALTY_NONE			0
#تعریف_کړه SRCLIMIT_PENALTY_CRASH			1
#تعریف_کړه SRCLIMIT_PENALTY_AUTHFAIL		2
#تعریف_کړه SRCLIMIT_PENALTY_GRACE_EXCEEDED		3
#تعریف_کړه SRCLIMIT_PENALTY_NOAUTH			4
#تعریف_کړه SRCLIMIT_PENALTY_REFUSECONNECTION	5
#تعریف_کړه SRCLIMIT_PENALTY_INVALIDUSER		6

/* meaningful exit values, used by sshd listener for penalties */
#تعریف_کړه EXIT_LOGIN_GRACE	3	/* login grace period exceeded */
#تعریف_کړه EXIT_ماشوم_CRASH	4	/* preauth child crashed */
#تعریف_کړه EXIT_AUTH_ATTEMPTED	5	/* at least one auth attempt made */
#تعریف_کړه EXIT_CONFIG_REFUSED	6	/* sshd_config RefuseConnection */
#تعریف_کړه EXIT_INVALID_USER	7	/* invalid user supplied */

فراغ	srclimit_penalise(بنية xaddr *, صحيح);
صحيح	srclimit_penalty_check_allow(صحيح, ثابت حرف **);
فراغ	srclimit_penalty_info(فراغ);
