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

#ifndef AUTH_OPTIONS_H
#define AUTH_OPTIONS_H

ಸಂರಚನಾ passwd;
ಸಂರಚನಾ sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
ಸಂರಚನಾ sshauthopt {
	/* Feature flags */
	ಪೂರ್ಣಾಙ್ಕ permit_port_forwarding_flag;
	ಪೂರ್ಣಾಙ್ಕ permit_agent_forwarding_flag;
	ಪೂರ್ಣಾಙ್ಕ permit_x11_forwarding_flag;
	ಪೂರ್ಣಾಙ್ಕ permit_pty_flag;
	ಪೂರ್ಣಾಙ್ಕ permit_user_rc;

	/* "restrict" keyword was invoked */
	ಪೂರ್ಣಾಙ್ಕ restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	ಪೂರ್ಣಾಙ್ಕ cert_authority;
	ವರ್ಣ *cert_principals;

	ಪೂರ್ಣಾಙ್ಕ force_tun_device;
	ವರ್ಣ *force_command;

	/* Custom environment */
	size_t nenv;
	ವರ್ಣ **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	ವರ್ಣ **permitopen;

	/* Permitted listens (remote forwarding) */
	size_t npermitlisten;
	ವರ್ಣ **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	ವರ್ಣ *required_from_host_cert;
	ವರ್ಣ *required_from_host_ಕೀಲಿಗಳು;

	/* Key requires user presence asserted */
	ಪೂರ್ಣಾಙ್ಕ no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	ಪೂರ್ಣಾಙ್ಕ require_verify;
};

ಸಂರಚನಾ sshauthopt *sshauthopt_new(ಶೂನ್ಯ);
ಸಂರಚನಾ sshauthopt *sshauthopt_new_with_ಕೀಲಿಗಳು_defaults(ಶೂನ್ಯ);
ಶೂನ್ಯ sshauthopt_free(ಸಂರಚನಾ sshauthopt *opts);
ಸಂರಚನಾ sshauthopt *sshauthopt_copy(ಧ್ರುವ ಸಂರಚನಾ sshauthopt *orig);
ಪೂರ್ಣಾಙ್ಕ sshauthopt_serialise(ಧ್ರುವ ಸಂರಚನಾ sshauthopt *opts, ಸಂರಚನಾ sshbuf *m, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ sshauthopt_deserialise(ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
ಸಂರಚನಾ sshauthopt *sshauthopt_parse(ಧ್ರುವ ವರ್ಣ *s, ಧ್ರುವ ವರ್ಣ **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
ಸಂರಚನಾ sshauthopt *sshauthopt_from_cert(ಸಂರಚನಾ sshkey *k);

/*
 * Merge key options.
 */
ಸಂರಚನಾ sshauthopt *sshauthopt_merge(ಧ್ರುವ ಸಂರಚನಾ sshauthopt *primary,
    ಧ್ರುವ ಸಂರಚನಾ sshauthopt *additional, ಧ್ರುವ ವರ್ಣ **errstrp);

#endif
