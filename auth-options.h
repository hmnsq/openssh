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

সংরচনা passwd;
সংরচনা sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
সংরচনা sshauthopt {
	/* Feature flags */
	পূর্ণাঙ্ক permit_port_forwarding_flag;
	পূর্ণাঙ্ক permit_agent_forwarding_flag;
	পূর্ণাঙ্ক permit_x11_forwarding_flag;
	পূর্ণাঙ্ক permit_pty_flag;
	পূর্ণাঙ্ক permit_user_rc;

	/* "restrict" keyword was invoked */
	পূর্ণাঙ্ক restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	পূর্ণাঙ্ক cert_authority;
	ৱর্ণ *cert_principals;

	পূর্ণাঙ্ক force_tun_device;
	ৱর্ণ *force_command;

	/* Custom environment */
	size_t nenv;
	ৱর্ণ **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	ৱর্ণ **permitopen;

	/* Permitted listens (remote forwarding) */
	size_t npermitlisten;
	ৱর্ণ **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	ৱর্ণ *required_from_host_cert;
	ৱর্ণ *required_from_host_চাবিগুলি;

	/* Key requires user presence asserted */
	পূর্ণাঙ্ক no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	পূর্ণাঙ্ক require_verify;
};

সংরচনা sshauthopt *sshauthopt_new(শূন্য);
সংরচনা sshauthopt *sshauthopt_new_with_চাবিগুলি_defaults(শূন্য);
শূন্য sshauthopt_free(সংরচনা sshauthopt *opts);
সংরচনা sshauthopt *sshauthopt_copy(ধ্রুৱ সংরচনা sshauthopt *orig);
পূর্ণাঙ্ক sshauthopt_serialise(ধ্রুৱ সংরচনা sshauthopt *opts, সংরচনা sshbuf *m, পূর্ণাঙ্ক);
পূর্ণাঙ্ক sshauthopt_deserialise(সংরচনা sshbuf *m, সংরচনা sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
সংরচনা sshauthopt *sshauthopt_parse(ধ্রুৱ ৱর্ণ *s, ধ্রুৱ ৱর্ণ **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
সংরচনা sshauthopt *sshauthopt_from_cert(সংরচনা sshkey *k);

/*
 * Merge key options.
 */
সংরচনা sshauthopt *sshauthopt_merge(ধ্রুৱ সংরচনা sshauthopt *primary,
    ধ্রুৱ সংরচনা sshauthopt *additional, ধ্রুৱ ৱর্ণ **errstrp);

#endif
