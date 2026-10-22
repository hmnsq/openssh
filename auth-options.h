/* $OpenBSD: auth-options.h,v 1.31 2021/07/23 03:57:20 djm Exp $ */

/*
 * Copyright (c) 2018 Damien Miller <djm@mindrot.org>
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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ AUTH_OPTIONS_H
#ವ್ಯಾಖ್ಯಾನಿಸು AUTH_OPTIONS_H

ರಚನೆ passwd;
ರಚನೆ sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
ರಚನೆ sshauthopt {
	/* Feature flags */
	ಪೂರ್ಣಾಂಕ permit_ಪೋರ್ಟ್_forwarding_flag;
	ಪೂರ್ಣಾಂಕ permit_agent_forwarding_flag;
	ಪೂರ್ಣಾಂಕ permit_x11_forwarding_flag;
	ಪೂರ್ಣಾಂಕ permit_pty_flag;
	ಪೂರ್ಣಾಂಕ permit_user_rc;

	/* "restrict" keyword was invoked */
	ಪೂರ್ಣಾಂಕ restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	ಪೂರ್ಣಾಂಕ cert_authority;
	ಅಕ್ಷರ *cert_principals;

	ಪೂರ್ಣಾಂಕ force_tun_device;
	ಅಕ್ಷರ *force_command;

	/* Custom environment */
	ಗಾತ್ರ_t nenv;
	ಅಕ್ಷರ **env;

	/* Permitted port forwardings */
	ಗಾತ್ರ_t npermitopen;
	ಅಕ್ಷರ **permitopen;

	/* Permitted listens (remote forwarding) */
	ಗಾತ್ರ_t npermitlisten;
	ಅಕ್ಷರ **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	ಅಕ್ಷರ *required_from_host_cert;
	ಅಕ್ಷರ *required_from_host_ಕೀಲಿಗಳು;

	/* Key requires user presence asserted */
	ಪೂರ್ಣಾಂಕ no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	ಪೂರ್ಣಾಂಕ require_verify;
};

ರಚನೆ sshauthopt *sshauthopt_new(ಶೂನ್ಯ);
ರಚನೆ sshauthopt *sshauthopt_new_with_ಕೀಲಿಗಳು_defaults(ಶೂನ್ಯ);
ಶೂನ್ಯ sshauthopt_free(ರಚನೆ sshauthopt *opts);
ರಚನೆ sshauthopt *sshauthopt_copy(ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *orig);
ಪೂರ್ಣಾಂಕ sshauthopt_serialise(ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *opts, ರಚನೆ sshbuf *m, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ sshauthopt_deserialise(ರಚನೆ sshbuf *m, ರಚನೆ sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
ರಚನೆ sshauthopt *sshauthopt_parse(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
ರಚನೆ sshauthopt *sshauthopt_from_cert(ರಚನೆ sshkey *k);

/*
 * Merge key options.
 */
ರಚನೆ sshauthopt *sshauthopt_ವಿಲೀನ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *primary,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *additional, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstrp);

#ಆದರೆ_ಅಂತ್ಯ
