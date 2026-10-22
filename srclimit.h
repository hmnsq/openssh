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
संरचना xaddr;

संरचना प्रत्येकम्_source_penalty;

शून्य	srclimit_init(पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क,
    संरचना प्रत्येकम्_source_penalty *, ध्रुव वर्ण *);
पूर्णाङ्क	srclimit_check_allow(पूर्णाङ्क, पूर्णाङ्क);
शून्य	srclimit_समाप्तम्(पूर्णाङ्क);

#परिभाषय SRCLIMIT_PENALTY_NONE			0
#परिभाषय SRCLIMIT_PENALTY_CRASH			1
#परिभाषय SRCLIMIT_PENALTY_AUTHFAIL		2
#परिभाषय SRCLIMIT_PENALTY_GRACE_EXCEEDED		3
#परिभाषय SRCLIMIT_PENALTY_NOAUTH			4
#परिभाषय SRCLIMIT_PENALTY_REFUSECONNECTION	5
#परिभाषय SRCLIMIT_PENALTY_INVALIDUSER		6

/* meaningful exit values, used by sshd listener for penalties */
#परिभाषय EXIT_LOGIN_GRACE	3	/* login grace period exceeded */
#परिभाषय EXIT_CHILD_CRASH	4	/* preauth child crashed */
#परिभाषय EXIT_AUTH_ATTEMPTED	5	/* at least one auth attempt made */
#परिभाषय EXIT_CONFIG_REFUSED	6	/* sshd_config RefuseConnection */
#परिभाषय EXIT_INVALID_USER	7	/* invalid user supplied */

शून्य	srclimit_penalise(संरचना xaddr *, पूर्णाङ्क);
पूर्णाङ्क	srclimit_penalty_check_allow(पूर्णाङ्क, ध्रुव वर्ण **);
शून्य	srclimit_penalty_info(शून्य);
