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

بنية في_ذريعو_penalty;

فراغ	srclimit_init(صحيح, صحيح, صحيح, صحيح,
    بنية في_ذريعو_penalty *, ثابت حرف *);
صحيح	srclimit_check_allow(صحيح, صحيح);
فراغ	srclimit_پورو(صحيح);

#وصف_ڪريو SRCLIMIT_PENALTY_NONE			0
#وصف_ڪريو SRCLIMIT_PENALTY_CRASH			1
#وصف_ڪريو SRCLIMIT_PENALTY_AUTHFAIL		2
#وصف_ڪريو SRCLIMIT_PENALTY_GRACE_EXCEEDED		3
#وصف_ڪريو SRCLIMIT_PENALTY_NOAUTH			4
#وصف_ڪريو SRCLIMIT_PENALTY_REFUSECONNECTION	5
#وصف_ڪريو SRCLIMIT_PENALTY_INVALIDUSER		6

/* meaningful exit values, used by sshd listener for penalties */
#وصف_ڪريو EXIT_LOGIN_GRACE	3	/* login grace period exceeded */
#وصف_ڪريو EXIT_ٻار_CRASH	4	/* preauth child crashed */
#وصف_ڪريو EXIT_AUTH_ATTEMPTED	5	/* at least one auth attempt made */
#وصف_ڪريو EXIT_CONFIG_REFUSED	6	/* sshd_config RefuseConnection */
#وصف_ڪريو EXIT_INVALID_USER	7	/* invalid user supplied */

فراغ	srclimit_penalise(بنية xaddr *, صحيح);
صحيح	srclimit_penalty_check_allow(صحيح, ثابت حرف **);
فراغ	srclimit_penalty_info(فراغ);
