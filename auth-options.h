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

#اگر_غیر_تعریف_شدہ AUTH_OPTIONS_H
#تعریف_کرو AUTH_OPTIONS_H

ساخت passwd;
ساخت sshkey;

/* Maximum number of permitopen/permitlisten directives to accept */
#تعریف_کرو SSH_AUTHOPT_PERMIT_MAX	4096

/* Maximum number of environment directives to accept */
#تعریف_کرو SSH_AUTHOPT_ENV_MAX	1024

/*
 * sshauthopt represents key options parsed from authorized_keys or
 * from certificate extensions/options.
 */
ساخت sshauthopt {
	/* Feature flags */
	صحیح permit_پورٹ_forwarding_flag;
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
	حرف *cert_principals;

	صحیح force_tun_device;
	حرف *force_command;

	/* Custom environment */
	سائز_t nenv;
	حرف **env;

	/* Permitted port forwardings */
	سائز_t npermitopen;
	حرف **permitopen;

	/* Permitted listens (remote forwarding) */
	سائز_t npermitlisten;
	حرف **permitlisten;

	/*
	 * Permitted host/addresses (comma-separated)
	 * Caller must check source address matches both lists (if present).
	 */
	حرف *required_from_host_cert;
	حرف *required_from_host_کلیدیں;

	/* Key requires user presence asserted */
	صحیح no_require_user_presence;
	/* Key requires user verification (e.g. PIN) */
	صحیح require_verify;
};

ساخت sshauthopt *sshauthopt_new(خالی);
ساخت sshauthopt *sshauthopt_new_with_کلیدیں_defaults(خالی);
خالی sshauthopt_free(ساخت sshauthopt *opts);
ساخت sshauthopt *sshauthopt_copy(ثابت ساخت sshauthopt *orig);
صحیح sshauthopt_serialise(ثابت ساخت sshauthopt *opts, ساخت sshbuf *m, صحیح);
صحیح sshauthopt_deserialise(ساخت sshbuf *m, ساخت sshauthopt **opts);

/*
 * Parse authorized_keys options. Returns an options structure on success
 * or NULL on failure. Will set errstr on failure.
 */
ساخت sshauthopt *sshauthopt_parse(ثابت حرف *s, ثابت حرف **errstr);

/*
 * Parse certification options to a struct sshauthopt.
 * Returns options on success or NULL on failure.
 */
ساخت sshauthopt *sshauthopt_from_cert(ساخت sshkey *k);

/*
 * Merge key options.
 */
ساخت sshauthopt *sshauthopt_ملاؤ(ثابت ساخت sshauthopt *primary,
    ثابت ساخت sshauthopt *additional, ثابت حرف **errstrp);

#اگر_ختم
