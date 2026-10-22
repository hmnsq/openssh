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

ഘടന passwd;
ഘടന sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
ഘടന sshauthopt {
	/* Feature flags */
	പൂർണ്ണസംഖ്യ permit_port_forwarding_flag;
	പൂർണ്ണസംഖ്യ permit_agent_forwarding_flag;
	പൂർണ്ണസംഖ്യ permit_x11_forwarding_flag;
	പൂർണ്ണസംഖ്യ permit_pty_flag;
	പൂർണ്ണസംഖ്യ permit_user_rc;

	/* "restrict" keyword was invoked */
	പൂർണ്ണസംഖ്യ restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	പൂർണ്ണസംഖ്യ cert_authority;
	അക്ഷരം *cert_principals;

	പൂർണ്ണസംഖ്യ force_tun_device;
	അക്ഷരം *force_command;

	/* Custom environment */
	size_t nenv;
	അക്ഷരം **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	അക്ഷരം **permitopen;

	/* Permitted listens (remote forwarding) */
	size_t npermitlisten;
	അക്ഷരം **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	അക്ഷരം *required_from_host_cert;
	അക്ഷരം *required_from_host_താക്കോലുകൾ;

	/* Key requires user presence asserted */
	പൂർണ്ണസംഖ്യ no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	പൂർണ്ണസംഖ്യ require_verify;
};

ഘടന sshauthopt *sshauthopt_new(ശൂന്യം);
ഘടന sshauthopt *sshauthopt_new_with_താക്കോലുകൾ_defaults(ശൂന്യം);
ശൂന്യം sshauthopt_free(ഘടന sshauthopt *opts);
ഘടന sshauthopt *sshauthopt_copy(സ്ഥിരം ഘടന sshauthopt *orig);
പൂർണ്ണസംഖ്യ sshauthopt_serialise(സ്ഥിരം ഘടന sshauthopt *opts, ഘടന sshbuf *m, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ sshauthopt_deserialise(ഘടന sshbuf *m, ഘടന sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
ഘടന sshauthopt *sshauthopt_parse(സ്ഥിരം അക്ഷരം *s, സ്ഥിരം അക്ഷരം **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
ഘടന sshauthopt *sshauthopt_from_cert(ഘടന sshkey *k);

/*
 * Merge key options.
 */
ഘടന sshauthopt *sshauthopt_merge(സ്ഥിരം ഘടന sshauthopt *primary,
    സ്ഥിരം ഘടന sshauthopt *additional, സ്ഥിരം അക്ഷരം **errstrp);

#endif
