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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AUTH_OPTIONS_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AUTH_OPTIONS_H

ਬਣਤਰ passwd;
ਬਣਤਰ sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
ਬਣਤਰ sshauthopt {
	/* Feature flags */
	ਪੂਰਨ permit_ਪੋਰਟ_forwarding_flag;
	ਪੂਰਨ permit_agent_forwarding_flag;
	ਪੂਰਨ permit_x11_forwarding_flag;
	ਪੂਰਨ permit_pty_flag;
	ਪੂਰਨ permit_user_rc;

	/* "restrict" keyword was invoked */
	ਪੂਰਨ restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	ਪੂਰਨ cert_authority;
	ਅੱਖਰ *cert_principals;

	ਪੂਰਨ force_tun_device;
	ਅੱਖਰ *force_command;

	/* Custom environment */
	ਮਾਪ_t nenv;
	ਅੱਖਰ **env;

	/* Permitted port forwardings */
	ਮਾਪ_t npermitopen;
	ਅੱਖਰ **permitopen;

	/* Permitted listens (remote forwarding) */
	ਮਾਪ_t npermitlisten;
	ਅੱਖਰ **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	ਅੱਖਰ *required_from_host_cert;
	ਅੱਖਰ *required_from_host_ਕੁੰਜੀਆਂ;

	/* Key requires user presence asserted */
	ਪੂਰਨ no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	ਪੂਰਨ require_verify;
};

ਬਣਤਰ sshauthopt *sshauthopt_new(ਖਾਲੀ);
ਬਣਤਰ sshauthopt *sshauthopt_new_with_ਕੁੰਜੀਆਂ_defaults(ਖਾਲੀ);
ਖਾਲੀ sshauthopt_free(ਬਣਤਰ sshauthopt *opts);
ਬਣਤਰ sshauthopt *sshauthopt_copy(ਅਚਲ ਬਣਤਰ sshauthopt *orig);
ਪੂਰਨ sshauthopt_serialise(ਅਚਲ ਬਣਤਰ sshauthopt *opts, ਬਣਤਰ sshbuf *m, ਪੂਰਨ);
ਪੂਰਨ sshauthopt_deserialise(ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
ਬਣਤਰ sshauthopt *sshauthopt_parse(ਅਚਲ ਅੱਖਰ *s, ਅਚਲ ਅੱਖਰ **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
ਬਣਤਰ sshauthopt *sshauthopt_from_cert(ਬਣਤਰ sshkey *k);

/*
 * Merge key options.
 */
ਬਣਤਰ sshauthopt *sshauthopt_ਮਿਲਾਓ(ਅਚਲ ਬਣਤਰ sshauthopt *primary,
    ਅਚਲ ਬਣਤਰ sshauthopt *additional, ਅਚਲ ਅੱਖਰ **errstrp);

#ਜੇ_ਅੰਤ
