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

بنية passwd;
بنية sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
بنية sshauthopt {
	/* Feature flags */
	صحيح permit_port_forwarding_flag;
	صحيح permit_agent_forwarding_flag;
	صحيح permit_x11_forwarding_flag;
	صحيح permit_pty_flag;
	صحيح permit_user_rc;

	/* "restrict" keyword was invoked */
	صحيح restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	صحيح cert_authority;
	حرف *cert_principals;

	صحيح force_tun_device;
	حرف *force_command;

	/* Custom environment */
	size_t nenv;
	حرف **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	حرف **permitopen;

	/* Permitted listens (remote forwarding) */
	size_t npermitlisten;
	حرف **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	حرف *required_from_host_cert;
	حرف *required_from_host_مبوداي;

	/* Key requires user presence asserted */
	صحيح no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	صحيح require_verify;
};

بنية sshauthopt *sshauthopt_new(فراغ);
بنية sshauthopt *sshauthopt_new_with_مبوداي_defaults(فراغ);
فراغ sshauthopt_free(بنية sshauthopt *opts);
بنية sshauthopt *sshauthopt_copy(ثابت بنية sshauthopt *orig);
صحيح sshauthopt_serialise(ثابت بنية sshauthopt *opts, بنية sshbuf *m, صحيح);
صحيح sshauthopt_deserialise(بنية sshbuf *m, بنية sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
بنية sshauthopt *sshauthopt_parse(ثابت حرف *s, ثابت حرف **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
بنية sshauthopt *sshauthopt_from_cert(بنية sshkey *k);

/*
 * Merge key options.
 */
بنية sshauthopt *sshauthopt_merge(ثابت بنية sshauthopt *primary,
    ثابت بنية sshauthopt *additional, ثابت حرف **errstrp);

#endif
