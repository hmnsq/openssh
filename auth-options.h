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

સંરચના passwd;
સંરચના sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
સંરચના sshauthopt {
	/* Feature flags */
	પૂર્ણાંક permit_port_forwarding_flag;
	પૂર્ણાંક permit_agent_forwarding_flag;
	પૂર્ણાંક permit_x11_forwarding_flag;
	પૂર્ણાંક permit_pty_flag;
	પૂર્ણાંક permit_user_rc;

	/* "restrict" keyword was invoked */
	પૂર્ણાંક restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	પૂર્ણાંક cert_authority;
	અક્ષર *cert_principals;

	પૂર્ણાંક force_tun_device;
	અક્ષર *force_command;

	/* Custom environment */
	size_t nenv;
	અક્ષર **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	અક્ષર **permitopen;

	/* Permitted listens (remote forwarding) */
	size_t npermitlisten;
	અક્ષર **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	અક્ષર *required_from_host_cert;
	અક્ષર *required_from_host_ચાવીઓ;

	/* Key requires user presence asserted */
	પૂર્ણાંક no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	પૂર્ણાંક require_verify;
};

સંરચના sshauthopt *sshauthopt_new(શૂન્ય);
સંરચના sshauthopt *sshauthopt_new_with_ચાવીઓ_defaults(શૂન્ય);
શૂન્ય sshauthopt_free(સંરચના sshauthopt *opts);
સંરચના sshauthopt *sshauthopt_copy(અચલ સંરચના sshauthopt *orig);
પૂર્ણાંક sshauthopt_serialise(અચલ સંરચના sshauthopt *opts, સંરચના sshbuf *m, પૂર્ણાંક);
પૂર્ણાંક sshauthopt_deserialise(સંરચના sshbuf *m, સંરચના sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
સંરચના sshauthopt *sshauthopt_parse(અચલ અક્ષર *s, અચલ અક્ષર **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
સંરચના sshauthopt *sshauthopt_from_cert(સંરચના sshkey *k);

/*
 * Merge key options.
 */
સંરચના sshauthopt *sshauthopt_merge(અચલ સંરચના sshauthopt *primary,
    અચલ સંરચના sshauthopt *additional, અચલ અક્ષર **errstrp);

#endif
