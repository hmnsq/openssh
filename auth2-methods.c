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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"

ಬಾಹ್ಯ ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
ಪೂರ್ಣಾಙ್ಕ none_enabled = 1;
ಸಂರಚನಾ authmethod_cfg methodcfg_none = {
	"none",
	ರಿಕ್ತ,
	&none_enabled
};
ಸಂರಚನಾ authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
ಸಂರಚನಾ authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	ರಿಕ್ತ,
	&options.gss_authentication
};
#endif
ಸಂರಚನಾ authmethod_cfg methodcfg_passwd = {
	"password",
	ರಿಕ್ತ,
	&options.password_authentication
};
ಸಂರಚನಾ authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	ರಿಕ್ತ,
	&options.kbd_interactive_authentication
};
ಸಂರಚನಾ authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	ರಿಕ್ತ,
	&options.hostbased_authentication
};

ಸ್ಥಿರ ಸಂರಚನಾ authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	ರಿಕ್ತ
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
ಪೂರ್ಣಾಙ್ಕ
auth2_methods_valid(ಧ್ರುವ ವರ್ಣ *_methods, ಪೂರ್ಣಾಙ್ಕ need_enable)
{
	ವರ್ಣ *methods, *omethods, *method, *p;
	u_int i, found;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	ಧ್ರುವ ಸಂರಚನಾ authmethod_cfg *cfg;

	ಯದಿ (*_methods == '\0') {
		error("empty authentication method list");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	omethods = methods = xstrdup(_methods);
	ಯಾವತ್ ((method = strsep(&methods, ",")) != ರಿಕ್ತ) {
		ಪ್ರತಿ (found = i = 0; !found && authmethod_cfgs[i] != ರಿಕ್ತ; i++) {
			cfg = authmethod_cfgs[i];
			ಯದಿ ((p = strchr(method, ':')) != ರಿಕ್ತ)
				*p = '\0';
			ಯದಿ (strcmp(method, cfg->name) != 0)
				ಅನುವರ್ತ;
			ಯದಿ (need_enable) {
				ಯದಿ (cfg->enabled == ರಿಕ್ತ ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					ಗಚ್ಛ out;
				}
			}
			found = 1;
			ಭಙ್ಗ;
		}
		ಯದಿ (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			ಗಚ್ಛ out;
		}
	}
	ret = 0;
 out:
	ಮುಕ್ತ(omethods);
	ಪ್ರತ್ಯಾಗಮ ret;
}
