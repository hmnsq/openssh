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
ಪೂರ್ಣಾಂಕ none_enabled = 1;
ರಚನೆ authmethod_cfg methodcfg_none = {
	"none",
	ಖಾಲಿ,
	&none_enabled
};
ರಚನೆ authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
ರಚನೆ authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	ಖಾಲಿ,
	&options.gss_authentication
};
#ಆದರೆ_ಅಂತ್ಯ
ರಚನೆ authmethod_cfg methodcfg_passwd = {
	"password",
	ಖಾಲಿ,
	&options.password_authentication
};
ರಚನೆ authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	ಖಾಲಿ,
	&options.kbd_interactive_authentication
};
ರಚನೆ authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	ಖಾಲಿ,
	&options.hostbased_authentication
};

ಸ್ಥಿರ ರಚನೆ authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	&methodcfg_gssapi,
#ಆದರೆ_ಅಂತ್ಯ
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	ಖಾಲಿ
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
ಪೂರ್ಣಾಂಕ
auth2_methods_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *_methods, ಪೂರ್ಣಾಂಕ need_enable)
{
	ಅಕ್ಷರ *methods, *omethods, *ವಿಧಾನ, *p;
	u_int i, ಸಿಕ್ಕಿತು;
	ಪೂರ್ಣಾಂಕ ret = -1;
	ಸ್ಥಿರಾಂಕ ರಚನೆ authmethod_cfg *cfg;

	ಆದರೆ (*_methods == '\0') {
		error("empty authentication method list");
		ಹಿಂತಿರುಗಿ -1;
	}
	omethods = methods = xstrdup(_methods);
	ಆಗ ((ವಿಧಾನ = strsep(&methods, ",")) != ಖಾಲಿ) {
		ಗಾಗಿ (ಸಿಕ್ಕಿತು = i = 0; !ಸಿಕ್ಕಿತು && authmethod_cfgs[i] != ಖಾಲಿ; i++) {
			cfg = authmethod_cfgs[i];
			ಆದರೆ ((p = strchr(ವಿಧಾನ, ':')) != ಖಾಲಿ)
				*p = '\0';
			ಆದರೆ (strcmp(ವಿಧಾನ, cfg->name) != 0)
				ಮುಂದುವರಿ;
			ಆದರೆ (need_enable) {
				ಆದರೆ (cfg->enabled == ಖಾಲಿ ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    ವಿಧಾನ, _methods);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}
			ಸಿಕ್ಕಿತು = 1;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (!ಸಿಕ್ಕಿತು) {
			error("Unknown authentication method \"%s\" in list",
			    ವಿಧಾನ);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(omethods);
	ಹಿಂತಿರುಗಿ ret;
}
