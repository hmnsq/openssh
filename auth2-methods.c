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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"

બાહ્ય ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
પૂર્ણાંક none_enabled = 1;
સંરચના authmethod_cfg methodcfg_none = {
	"none",
	ખાલી,
	&none_enabled
};
સંરચના authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
સંરચના authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	ખાલી,
	&options.gss_authentication
};
#endif
સંરચના authmethod_cfg methodcfg_passwd = {
	"password",
	ખાલી,
	&options.password_authentication
};
સંરચના authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	ખાલી,
	&options.kbd_interactive_authentication
};
સંરચના authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	ખાલી,
	&options.hostbased_authentication
};

સ્થિર સંરચના authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	ખાલી
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
પૂર્ણાંક
auth2_methods_valid(અચલ અક્ષર *_methods, પૂર્ણાંક need_enable)
{
	અક્ષર *methods, *omethods, *method, *p;
	u_int i, found;
	પૂર્ણાંક ret = -1;
	અચલ સંરચના authmethod_cfg *cfg;

	જો (*_methods == '\0') {
		error("empty authentication method list");
		પાછા -1;
	}
	omethods = methods = xstrdup(_methods);
	જ્યારે ((method = strsep(&methods, ",")) != ખાલી) {
		માટે (found = i = 0; !found && authmethod_cfgs[i] != ખાલી; i++) {
			cfg = authmethod_cfgs[i];
			જો ((p = strchr(method, ':')) != ખાલી)
				*p = '\0';
			જો (strcmp(method, cfg->name) != 0)
				ચાલુ;
			જો (need_enable) {
				જો (cfg->enabled == ખાલી ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					જાઓ out;
				}
			}
			found = 1;
			તોડો;
		}
		જો (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			જાઓ out;
		}
	}
	ret = 0;
 out:
	મુક્ત(omethods);
	પાછા ret;
}
