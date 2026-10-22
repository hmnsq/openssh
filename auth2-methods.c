/*
 * Copyright (c) 2012,2023 Damien Miller <djm@mindrot.org>
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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "servconf.h"
#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"

বাহ্য ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
পূর্ণাঙ্ক none_enabled = 1;
সংরচনা authmethod_cfg methodcfg_none = {
	"none",
	রিক্ত,
	&none_enabled
};
সংরচনা authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
সংরচনা authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	রিক্ত,
	&options.gss_authentication
};
#endif
সংরচনা authmethod_cfg methodcfg_passwd = {
	"password",
	রিক্ত,
	&options.password_authentication
};
সংরচনা authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	রিক্ত,
	&options.kbd_interactive_authentication
};
সংরচনা authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	রিক্ত,
	&options.hostbased_authentication
};

স্থির সংরচনা authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	রিক্ত
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
পূর্ণাঙ্ক
auth2_methods_valid(ধ্রুৱ ৱর্ণ *_methods, পূর্ণাঙ্ক need_enable)
{
	ৱর্ণ *methods, *omethods, *method, *p;
	u_int i, found;
	পূর্ণাঙ্ক ret = -1;
	ধ্রুৱ সংরচনা authmethod_cfg *cfg;

	যদি (*_methods == '\0') {
		error("empty authentication method list");
		ঘূৰাই -1;
	}
	omethods = methods = xstrdup(_methods);
	যেতিয়ালৈ ((method = strsep(&methods, ",")) != রিক্ত) {
		বাবে (found = i = 0; !found && authmethod_cfgs[i] != রিক্ত; i++) {
			cfg = authmethod_cfgs[i];
			যদি ((p = strchr(method, ':')) != রিক্ত)
				*p = '\0';
			যদি (strcmp(method, cfg->name) != 0)
				অনুৱর্ত;
			যদি (need_enable) {
				যদি (cfg->enabled == রিক্ত ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					গচ্ছ out;
				}
			}
			found = 1;
			ভঙ্গ;
		}
		যদি (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			গচ্ছ out;
		}
	}
	ret = 0;
 out:
	মুক্ত(omethods);
	ঘূৰাই ret;
}
