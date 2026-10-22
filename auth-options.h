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

কাঠামো passwd;
কাঠামো sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
কাঠামো sshauthopt {
	/* Feature flags */
	পূর্ণসংখ্যা permit_port_forwarding_flag;
	পূর্ণসংখ্যা permit_agent_forwarding_flag;
	পূর্ণসংখ্যা permit_x11_forwarding_flag;
	পূর্ণসংখ্যা permit_pty_flag;
	পূর্ণসংখ্যা permit_user_rc;

	/* "restrict" keyword was invoked */
	পূর্ণসংখ্যা restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	পূর্ণসংখ্যা cert_authority;
	অক্ষর *cert_principals;

	পূর্ণসংখ্যা force_tun_device;
	অক্ষর *force_command;

	/* Custom environment */
	আকার_t nenv;
	অক্ষর **env;

	/* Permitted port forwardings */
	আকার_t npermitopen;
	অক্ষর **permitopen;

	/* Permitted listens (remote forwarding) */
	আকার_t npermitlisten;
	অক্ষর **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	অক্ষর *required_from_host_cert;
	অক্ষর *required_from_host_চাবিগুলি;

	/* Key requires user presence asserted */
	পূর্ণসংখ্যা no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	পূর্ণসংখ্যা require_verify;
};

কাঠামো sshauthopt *sshauthopt_new(শূন্য);
কাঠামো sshauthopt *sshauthopt_new_with_চাবিগুলি_defaults(শূন্য);
শূন্য sshauthopt_free(কাঠামো sshauthopt *opts);
কাঠামো sshauthopt *sshauthopt_copy(ধ্রুবক কাঠামো sshauthopt *orig);
পূর্ণসংখ্যা sshauthopt_serialise(ধ্রুবক কাঠামো sshauthopt *opts, কাঠামো sshbuf *m, পূর্ণসংখ্যা);
পূর্ণসংখ্যা sshauthopt_deserialise(কাঠামো sshbuf *m, কাঠামো sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
কাঠামো sshauthopt *sshauthopt_parse(ধ্রুবক অক্ষর *s, ধ্রুবক অক্ষর **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
কাঠামো sshauthopt *sshauthopt_from_cert(কাঠামো sshkey *k);

/*
 * Merge key options.
 */
কাঠামো sshauthopt *sshauthopt_merge(ধ্রুবক কাঠামো sshauthopt *primary,
    ধ্রুবক কাঠামো sshauthopt *additional, ধ্রুবক অক্ষর **errstrp);

#endif
