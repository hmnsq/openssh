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
ਬਣਤਰ xaddr;

ਬਣਤਰ ਪ੍ਰਤੀ_ਸਰੋਤ_penalty;

ਖਾਲੀ	srclimit_init(ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ,
    ਬਣਤਰ ਪ੍ਰਤੀ_ਸਰੋਤ_penalty *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	srclimit_check_allow(ਪੂਰਨ, ਪੂਰਨ);
ਖਾਲੀ	srclimit_ਪੂਰਾ(ਪੂਰਨ);

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SRCLIMIT_PENALTY_NONE			0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SRCLIMIT_PENALTY_CRASH			1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SRCLIMIT_PENALTY_AUTHFAIL		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SRCLIMIT_PENALTY_GRACE_EXCEEDED		3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SRCLIMIT_PENALTY_NOAUTH			4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SRCLIMIT_PENALTY_REFUSECONNECTION	5
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SRCLIMIT_PENALTY_INVALIDUSER		6

/* meaningful exit values, used by sshd listener for penalties */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EXIT_LOGIN_GRACE	3	/* login grace period exceeded */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EXIT_ਬੱਚਾ_CRASH	4	/* preauth child crashed */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EXIT_AUTH_ATTEMPTED	5	/* at least one auth attempt made */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EXIT_CONFIG_REFUSED	6	/* sshd_config RefuseConnection */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EXIT_INVALID_USER	7	/* invalid user supplied */

ਖਾਲੀ	srclimit_penalise(ਬਣਤਰ xaddr *, ਪੂਰਨ);
ਪੂਰਨ	srclimit_penalty_check_allow(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ **);
ਖਾਲੀ	srclimit_penalty_info(ਖਾਲੀ);
