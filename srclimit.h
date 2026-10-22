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
నిర్మాణం xaddr;

నిర్మాణం చొప్పున_ఆధారం_penalty;

శూన్య	srclimit_init(పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం,
    నిర్మాణం చొప్పున_ఆధారం_penalty *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	srclimit_check_allow(పూర్ణాంకం, పూర్ణాంకం);
శూన్య	srclimit_పూర్తి(పూర్ణాంకం);

#నిర్వచించు SRCLIMIT_PENALTY_NONE			0
#నిర్వచించు SRCLIMIT_PENALTY_CRASH			1
#నిర్వచించు SRCLIMIT_PENALTY_AUTHFAIL		2
#నిర్వచించు SRCLIMIT_PENALTY_GRACE_EXCEEDED		3
#నిర్వచించు SRCLIMIT_PENALTY_NOAUTH			4
#నిర్వచించు SRCLIMIT_PENALTY_REFUSECONNECTION	5
#నిర్వచించు SRCLIMIT_PENALTY_INVALIDUSER		6

/* meaningful exit values, used by sshd listener for penalties */
#నిర్వచించు EXIT_LOGIN_GRACE	3	/* login grace period exceeded */
#నిర్వచించు EXIT_బిడ్డ_CRASH	4	/* preauth child crashed */
#నిర్వచించు EXIT_AUTH_ATTEMPTED	5	/* at least one auth attempt made */
#నిర్వచించు EXIT_CONFIG_REFUSED	6	/* sshd_config RefuseConnection */
#నిర్వచించు EXIT_INVALID_USER	7	/* invalid user supplied */

శూన్య	srclimit_penalise(నిర్మాణం xaddr *, పూర్ణాంకం);
పూర్ణాంకం	srclimit_penalty_check_allow(పూర్ణాంకం, స్థిరరాశి అక్షరం **);
శూన్య	srclimit_penalty_info(శూన్య);
