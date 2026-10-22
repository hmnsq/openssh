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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"

ബാഹ്യ ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
പൂർണ്ണസംഖ്യ none_enabled = 1;
ഘടന authmethod_cfg methodcfg_none = {
	"none",
	ശൂന്യ,
	&none_enabled
};
ഘടന authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
ഘടന authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	ശൂന്യ,
	&options.gss_authentication
};
#endif
ഘടന authmethod_cfg methodcfg_passwd = {
	"password",
	ശൂന്യ,
	&options.password_authentication
};
ഘടന authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	ശൂന്യ,
	&options.kbd_interactive_authentication
};
ഘടന authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	ശൂന്യ,
	&options.hostbased_authentication
};

സ്ഥിതം ഘടന authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	ശൂന്യ
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
പൂർണ്ണസംഖ്യ
auth2_methods_valid(സ്ഥിരം അക്ഷരം *_methods, പൂർണ്ണസംഖ്യ need_enable)
{
	അക്ഷരം *methods, *omethods, *method, *p;
	u_int i, found;
	പൂർണ്ണസംഖ്യ ret = -1;
	സ്ഥിരം ഘടന authmethod_cfg *cfg;

	എങ്കിൽ (*_methods == '\0') {
		error("empty authentication method list");
		തിരികെ -1;
	}
	omethods = methods = xstrdup(_methods);
	ആകുമ്പോൾ ((method = strsep(&methods, ",")) != ശൂന്യ) {
		വേണ്ടി (found = i = 0; !found && authmethod_cfgs[i] != ശൂന്യ; i++) {
			cfg = authmethod_cfgs[i];
			എങ്കിൽ ((p = strchr(method, ':')) != ശൂന്യ)
				*p = '\0';
			എങ്കിൽ (strcmp(method, cfg->name) != 0)
				തുടരുക;
			എങ്കിൽ (need_enable) {
				എങ്കിൽ (cfg->enabled == ശൂന്യ ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					പോകുക out;
				}
			}
			found = 1;
			നിർത്തുക;
		}
		എങ്കിൽ (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			പോകുക out;
		}
	}
	ret = 0;
 out:
	സ്വതന്ത്രം(omethods);
	തിരികെ ret;
}
