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

ساختار passwd;
ساختار sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
ساختار sshauthopt {
	/* Feature flags */
	صحیح permit_port_forwarding_flag;
	صحیح permit_agent_forwarding_flag;
	صحیح permit_x11_forwarding_flag;
	صحیح permit_pty_flag;
	صحیح permit_user_rc;

	/* "restrict" keyword was invoked */
	صحیح restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	صحیح cert_authority;
	نویسه *cert_principals;

	صحیح force_tun_device;
	نویسه *force_command;

	/* Custom environment */
	size_t nenv;
	نویسه **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	نویسه **permitopen;

	/* Permitted listens (remote forwarding) */
	size_t npermitlisten;
	نویسه **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	نویسه *required_from_host_cert;
	نویسه *required_from_host_کلیدها;

	/* Key requires user presence asserted */
	صحیح no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	صحیح require_verify;
};

ساختار sshauthopt *sshauthopt_new(تهی);
ساختار sshauthopt *sshauthopt_new_with_کلیدها_defaults(تهی);
تهی sshauthopt_free(ساختار sshauthopt *opts);
ساختار sshauthopt *sshauthopt_copy(ثابت ساختار sshauthopt *orig);
صحیح sshauthopt_serialise(ثابت ساختار sshauthopt *opts, ساختار sshbuf *m, صحیح);
صحیح sshauthopt_deserialise(ساختار sshbuf *m, ساختار sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
ساختار sshauthopt *sshauthopt_parse(ثابت نویسه *s, ثابت نویسه **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
ساختار sshauthopt *sshauthopt_from_cert(ساختار sshkey *k);

/*
 * Merge key options.
 */
ساختار sshauthopt *sshauthopt_merge(ثابت ساختار sshauthopt *primary,
    ثابت ساختار sshauthopt *additional, ثابت نویسه **errstrp);

#endif
