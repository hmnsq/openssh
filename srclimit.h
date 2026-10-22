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
ರಚನೆ xaddr;

ರಚನೆ ಪ್ರತಿ_ಮೂಲ_penalty;

ಶೂನ್ಯ	srclimit_init(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    ರಚನೆ ಪ್ರತಿ_ಮೂಲ_penalty *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	srclimit_check_allow(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	srclimit_ಮುಗಿದ(ಪೂರ್ಣಾಂಕ);

#ವ್ಯಾಖ್ಯಾನಿಸು SRCLIMIT_PENALTY_NONE			0
#ವ್ಯಾಖ್ಯಾನಿಸು SRCLIMIT_PENALTY_CRASH			1
#ವ್ಯಾಖ್ಯಾನಿಸು SRCLIMIT_PENALTY_AUTHFAIL		2
#ವ್ಯಾಖ್ಯಾನಿಸು SRCLIMIT_PENALTY_GRACE_EXCEEDED		3
#ವ್ಯಾಖ್ಯಾನಿಸು SRCLIMIT_PENALTY_NOAUTH			4
#ವ್ಯಾಖ್ಯಾನಿಸು SRCLIMIT_PENALTY_REFUSECONNECTION	5
#ವ್ಯಾಖ್ಯಾನಿಸು SRCLIMIT_PENALTY_INVALIDUSER		6

/* meaningful exit values, used by sshd listener for penalties */
#ವ್ಯಾಖ್ಯಾನಿಸು EXIT_LOGIN_GRACE	3	/* login grace period exceeded */
#ವ್ಯಾಖ್ಯಾನಿಸು EXIT_ಮಗು_CRASH	4	/* preauth child crashed */
#ವ್ಯಾಖ್ಯಾನಿಸು EXIT_AUTH_ATTEMPTED	5	/* at least one auth attempt made */
#ವ್ಯಾಖ್ಯಾನಿಸು EXIT_CONFIG_REFUSED	6	/* sshd_config RefuseConnection */
#ವ್ಯಾಖ್ಯಾನಿಸು EXIT_INVALID_USER	7	/* invalid user supplied */

ಶೂನ್ಯ	srclimit_penalise(ರಚನೆ xaddr *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	srclimit_penalty_check_allow(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **);
ಶೂನ್ಯ	srclimit_penalty_info(ಶೂನ್ಯ);
