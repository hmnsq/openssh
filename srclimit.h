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
काष्ठा xaddr;

काष्ठा per_source_penalty;

व्योम	srclimit_init(पूर्णांक, पूर्णांक, पूर्णांक, पूर्णांक,
    काष्ठा per_source_penalty *, स्थिर अक्षर *);
पूर्णांक	srclimit_check_allow(पूर्णांक, पूर्णांक);
व्योम	srclimit_done(पूर्णांक);

#घोषणा SRCLIMIT_PENALTY_NONE			0
#घोषणा SRCLIMIT_PENALTY_CRASH			1
#घोषणा SRCLIMIT_PENALTY_AUTHFAIL		2
#घोषणा SRCLIMIT_PENALTY_GRACE_EXCEEDED		3
#घोषणा SRCLIMIT_PENALTY_NOAUTH			4
#घोषणा SRCLIMIT_PENALTY_REFUSECONNECTION	5
#घोषणा SRCLIMIT_PENALTY_INVALIDUSER		6

/* meaningful exit values, used by sshd listener for penalties */
#घोषणा EXIT_LOGIN_GRACE	3	/* login grace period exceeded */
#घोषणा EXIT_CHILD_CRASH	4	/* preauth child crashed */
#घोषणा EXIT_AUTH_ATTEMPTED	5	/* at least one auth attempt made */
#घोषणा EXIT_CONFIG_REFUSED	6	/* sshd_config RefuseConnection */
#घोषणा EXIT_INVALID_USER	7	/* invalid user supplied */

व्योम	srclimit_penalise(काष्ठा xaddr *, पूर्णांक);
पूर्णांक	srclimit_penalty_check_allow(पूर्णांक, स्थिर अक्षर **);
व्योम	srclimit_penalty_info(व्योम);
