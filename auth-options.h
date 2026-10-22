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

கட்டமைப்பு passwd;
கட்டமைப்பு sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
கட்டமைப்பு sshauthopt {
	/* Feature flags */
	முழு permit_port_forwarding_flag;
	முழு permit_agent_forwarding_flag;
	முழு permit_x11_forwarding_flag;
	முழு permit_pty_flag;
	முழு permit_user_rc;

	/* "restrict" keyword was invoked */
	முழு restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	முழு cert_authority;
	எழுத்து *cert_principals;

	முழு force_tun_device;
	எழுத்து *force_command;

	/* Custom environment */
	size_t nenv;
	எழுத்து **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	எழுத்து **permitopen;

	/* Permitted listens (remote forwarding) */
	size_t npermitlisten;
	எழுத்து **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	எழுத்து *required_from_host_cert;
	எழுத்து *required_from_host_சாவிகள்;

	/* Key requires user presence asserted */
	முழு no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	முழு require_verify;
};

கட்டமைப்பு sshauthopt *sshauthopt_new(வெறுமை);
கட்டமைப்பு sshauthopt *sshauthopt_new_with_சாவிகள்_defaults(வெறுமை);
வெறுமை sshauthopt_free(கட்டமைப்பு sshauthopt *opts);
கட்டமைப்பு sshauthopt *sshauthopt_copy(மாறிலி கட்டமைப்பு sshauthopt *orig);
முழு sshauthopt_serialise(மாறிலி கட்டமைப்பு sshauthopt *opts, கட்டமைப்பு sshbuf *m, முழு);
முழு sshauthopt_deserialise(கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
கட்டமைப்பு sshauthopt *sshauthopt_parse(மாறிலி எழுத்து *s, மாறிலி எழுத்து **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
கட்டமைப்பு sshauthopt *sshauthopt_from_cert(கட்டமைப்பு sshkey *k);

/*
 * Merge key options.
 */
கட்டமைப்பு sshauthopt *sshauthopt_merge(மாறிலி கட்டமைப்பு sshauthopt *primary,
    மாறிலி கட்டமைப்பு sshauthopt *additional, மாறிலி எழுத்து **errstrp);

#endif
