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

संरचना passwd;
संरचना sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
संरचना sshauthopt {
	/* Feature flags */
	पूर्णांक permit_port_forwarding_flag;
	पूर्णांक permit_agent_forwarding_flag;
	पूर्णांक permit_x11_forwarding_flag;
	पूर्णांक permit_pty_flag;
	पूर्णांक permit_user_rc;

	/* "restrict" keyword was invoked */
	पूर्णांक restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	पूर्णांक cert_authority;
	अक्षर *cert_principals;

	पूर्णांक force_tun_device;
	अक्षर *force_command;

	/* Custom environment */
	माप_प्रकार nenv;
	अक्षर **env;

	/* Permitted port forwardings */
	माप_प्रकार npermitopen;
	अक्षर **permitopen;

	/* Permitted listens (remote forwarding) */
	माप_प्रकार npermitlisten;
	अक्षर **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	अक्षर *required_from_host_cert;
	अक्षर *required_from_host_किल्ल्या;

	/* Key requires user presence asserted */
	पूर्णांक no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	पूर्णांक require_verify;
};

संरचना sshauthopt *sshauthopt_new(शून्य);
संरचना sshauthopt *sshauthopt_new_with_किल्ल्या_defaults(शून्य);
शून्य sshauthopt_free(संरचना sshauthopt *opts);
संरचना sshauthopt *sshauthopt_copy(स्थिरांक संरचना sshauthopt *orig);
पूर्णांक sshauthopt_serialise(स्थिरांक संरचना sshauthopt *opts, संरचना sshbuf *m, पूर्णांक);
पूर्णांक sshauthopt_deserialise(संरचना sshbuf *m, संरचना sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
संरचना sshauthopt *sshauthopt_parse(स्थिरांक अक्षर *s, स्थिरांक अक्षर **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
संरचना sshauthopt *sshauthopt_from_cert(संरचना sshkey *k);

/*
 * Merge key options.
 */
संरचना sshauthopt *sshauthopt_merge(स्थिरांक संरचना sshauthopt *primary,
    स्थिरांक संरचना sshauthopt *additional, स्थिरांक अक्षर **errstrp);

#endif
