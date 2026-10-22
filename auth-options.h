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

ସଂରଚନା passwd;
ସଂରଚନା sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#define SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#define SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
ସଂରଚନା sshauthopt {
	/* Feature flags */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା permit_port_forwarding_flag;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା permit_agent_forwarding_flag;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା permit_x11_forwarding_flag;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା permit_pty_flag;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା permit_user_rc;

	/* "restrict" keyword was invoked */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_authority;
	ଅକ୍ଷର *cert_principals;

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା force_tun_device;
	ଅକ୍ଷର *force_command;

	/* Custom environment */
	size_t nenv;
	ଅକ୍ଷର **env;

	/* Permitted port forwardings */
	size_t npermitopen;
	ଅକ୍ଷର **permitopen;

	/* Permitted listens (remote forwarding) */
	size_t npermitlisten;
	ଅକ୍ଷର **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	ଅକ୍ଷର *required_from_host_cert;
	ଅକ୍ଷର *required_from_host_ଚାବିଗୁଡ଼ିକ;

	/* Key requires user presence asserted */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା require_verify;
};

ସଂରଚନା sshauthopt *sshauthopt_new(ଶୂନ୍ୟ);
ସଂରଚନା sshauthopt *sshauthopt_new_with_ଚାବିଗୁଡ଼ିକ_defaults(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshauthopt_free(ସଂରଚନା sshauthopt *opts);
ସଂରଚନା sshauthopt *sshauthopt_copy(ଅଚଳ ସଂରଚନା sshauthopt *orig);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshauthopt_serialise(ଅଚଳ ସଂରଚନା sshauthopt *opts, ସଂରଚନା sshbuf *m, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshauthopt_deserialise(ସଂରଚନା sshbuf *m, ସଂରଚନା sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
ସଂରଚନା sshauthopt *sshauthopt_parse(ଅଚଳ ଅକ୍ଷର *s, ଅଚଳ ଅକ୍ଷର **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
ସଂରଚନା sshauthopt *sshauthopt_from_cert(ସଂରଚନା sshkey *k);

/*
 * Merge key options.
 */
ସଂରଚନା sshauthopt *sshauthopt_merge(ଅଚଳ ସଂରଚନା sshauthopt *primary,
    ଅଚଳ ସଂରଚନା sshauthopt *additional, ଅଚଳ ଅକ୍ଷର **errstrp);

#endif
