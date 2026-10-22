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

#నిర్వచితం_కాకపోతే AUTH_OPTIONS_H
#నిర్వచించు AUTH_OPTIONS_H

నిర్మాణం passwd;
నిర్మాణం sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#నిర్వచించు SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#నిర్వచించు SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
నిర్మాణం sshauthopt {
	/* Feature flags */
	పూర్ణాంకం permit_పోర్టు_forwarding_flag;
	పూర్ణాంకం permit_agent_forwarding_flag;
	పూర్ణాంకం permit_x11_forwarding_flag;
	పూర్ణాంకం permit_pty_flag;
	పూర్ణాంకం permit_user_rc;

	/* "restrict" keyword was invoked */
	పూర్ణాంకం restricted;

	/* key/principal expiry date */
	uint64_t valid_before;

	/* Certificate-related options */
	పూర్ణాంకం cert_authority;
	అక్షరం *cert_principals;

	పూర్ణాంకం force_tun_device;
	అక్షరం *force_command;

	/* Custom environment */
	కొలత_t nenv;
	అక్షరం **env;

	/* Permitted port forwardings */
	కొలత_t npermitopen;
	అక్షరం **permitopen;

	/* Permitted listens (remote forwarding) */
	కొలత_t npermitlisten;
	అక్షరం **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	అక్షరం *required_from_host_cert;
	అక్షరం *required_from_host_కీలకాలు;

	/* Key requires user presence asserted */
	పూర్ణాంకం no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	పూర్ణాంకం require_verify;
};

నిర్మాణం sshauthopt *sshauthopt_new(శూన్య);
నిర్మాణం sshauthopt *sshauthopt_new_with_కీలకాలు_defaults(శూన్య);
శూన్య sshauthopt_free(నిర్మాణం sshauthopt *opts);
నిర్మాణం sshauthopt *sshauthopt_copy(స్థిరరాశి నిర్మాణం sshauthopt *orig);
పూర్ణాంకం sshauthopt_serialise(స్థిరరాశి నిర్మాణం sshauthopt *opts, నిర్మాణం sshbuf *m, పూర్ణాంకం);
పూర్ణాంకం sshauthopt_deserialise(నిర్మాణం sshbuf *m, నిర్మాణం sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
నిర్మాణం sshauthopt *sshauthopt_parse(స్థిరరాశి అక్షరం *s, స్థిరరాశి అక్షరం **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
నిర్మాణం sshauthopt *sshauthopt_from_cert(నిర్మాణం sshkey *k);

/*
 * Merge key options.
 */
నిర్మాణం sshauthopt *sshauthopt_విలీనం(స్థిరరాశి నిర్మాణం sshauthopt *primary,
    స్థిరరాశి నిర్మాణం sshauthopt *additional, స్థిరరాశి అక్షరం **errstrp);

#అయితే_ముగింపు
