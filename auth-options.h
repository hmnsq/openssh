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

sa_nracanaa passwd;
sa_nracanaa sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
sa_nracanaa sshauthopt {
	/* Feature flags */
	පූර්ණ_සංඛ්‍යා permit_port_forwarding_flag;
	පූර්ණ_සංඛ්‍යා permit_agent_forwarding_flag;
	පූර්ණ_සංඛ්‍යා permit_x11_forwarding_flag;
	පූර්ණ_සංඛ්‍යා permit_pty_flag;
	පූර්ණ_සංඛ්‍යා permit_user_rc;

	/* "restrict" keyword was invoked */
	පූර්ණ_සංඛ්‍යා restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	පූර්ණ_සංඛ්‍යා cert_authority;
	var_na *cert_principals;

	පූර්ණ_සංඛ්‍යා force_tun_device;
	var_na *force_command;

	/* Custom environment */
	size_t nenv;
	var_na **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	var_na **permitopen;

	/* Permitted listens (remote forwarding) */
	size_t npermitlisten;
	var_na **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	var_na *required_from_host_cert;
	var_na *required_from_host_keys;

	/* Key requires user presence asserted */
	පූර්ණ_සංඛ්‍යා no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	පූර්ණ_සංඛ්‍යා require_verify;
};

sa_nracanaa sshauthopt *sshauthopt_new(void);
sa_nracanaa sshauthopt *sshauthopt_new_with_keys_defaults(void);
void sshauthopt_free(sa_nracanaa sshauthopt *opts);
sa_nracanaa sshauthopt *sshauthopt_copy(const sa_nracanaa sshauthopt *orig);
පූර්ණ_සංඛ්‍යා sshauthopt_serialise(const sa_nracanaa sshauthopt *opts, sa_nracanaa sshbuf *m, පූර්ණ_සංඛ්‍යා);
පූර්ණ_සංඛ්‍යා sshauthopt_deserialise(sa_nracanaa sshbuf *m, sa_nracanaa sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
sa_nracanaa sshauthopt *sshauthopt_parse(const var_na *s, const var_na **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
sa_nracanaa sshauthopt *sshauthopt_from_cert(sa_nracanaa sshkey *k);

/*
 * Merge key options.
 */
sa_nracanaa sshauthopt *sshauthopt_merge(const sa_nracanaa sshauthopt *primary,
    const sa_nracanaa sshauthopt *additional, const var_na **errstrp);

#endif
