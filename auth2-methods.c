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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"

ਬਾਹਰੀ ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
ਪੂਰਨ none_enabled = 1;
ਬਣਤਰ authmethod_cfg methodcfg_none = {
	"none",
	ਨਿਰਾ,
	&none_enabled
};
ਬਣਤਰ authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
ਬਣਤਰ authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	ਨਿਰਾ,
	&options.gss_authentication
};
#ਜੇ_ਅੰਤ
ਬਣਤਰ authmethod_cfg methodcfg_passwd = {
	"password",
	ਨਿਰਾ,
	&options.password_authentication
};
ਬਣਤਰ authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	ਨਿਰਾ,
	&options.kbd_interactive_authentication
};
ਬਣਤਰ authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	ਨਿਰਾ,
	&options.hostbased_authentication
};

ਸਥਿਰ ਬਣਤਰ authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	&methodcfg_gssapi,
#ਜੇ_ਅੰਤ
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	ਨਿਰਾ
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
ਪੂਰਨ
auth2_methods_valid(ਅਚਲ ਅੱਖਰ *_methods, ਪੂਰਨ need_enable)
{
	ਅੱਖਰ *methods, *omethods, *ਵਿਧੀ, *p;
	u_int i, ਮਿਲਿਆ;
	ਪੂਰਨ ret = -1;
	ਅਚਲ ਬਣਤਰ authmethod_cfg *cfg;

	ਜੇ (*_methods == '\0') {
		error("empty authentication method list");
		ਵਾਪਸ -1;
	}
	omethods = methods = xstrdup(_methods);
	ਜਦੋਂ ((ਵਿਧੀ = strsep(&methods, ",")) != ਨਿਰਾ) {
		ਲਈ (ਮਿਲਿਆ = i = 0; !ਮਿਲਿਆ && authmethod_cfgs[i] != ਨਿਰਾ; i++) {
			cfg = authmethod_cfgs[i];
			ਜੇ ((p = strchr(ਵਿਧੀ, ':')) != ਨਿਰਾ)
				*p = '\0';
			ਜੇ (strcmp(ਵਿਧੀ, cfg->name) != 0)
				ਜਾਰੀ;
			ਜੇ (need_enable) {
				ਜੇ (cfg->enabled == ਨਿਰਾ ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    ਵਿਧੀ, _methods);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}
			ਮਿਲਿਆ = 1;
			ਰੋਕੋ;
		}
		ਜੇ (!ਮਿਲਿਆ) {
			error("Unknown authentication method \"%s\" in list",
			    ਵਿਧੀ);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(omethods);
	ਵਾਪਸ ret;
}
