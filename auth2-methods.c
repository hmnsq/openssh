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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"

बाह्य ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
पूर्णाङ्क none_enabled = 1;
संरचना authmethod_cfg methodcfg_none = {
	"none",
	रिक्त,
	&none_enabled
};
संरचना authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
संरचना authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	रिक्त,
	&options.gss_authentication
};
#endif
संरचना authmethod_cfg methodcfg_passwd = {
	"password",
	रिक्त,
	&options.password_authentication
};
संरचना authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	रिक्त,
	&options.kbd_interactive_authentication
};
संरचना authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	रिक्त,
	&options.hostbased_authentication
};

स्थिर संरचना authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	रिक्त
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
पूर्णाङ्क
auth2_methods_valid(ध्रुव वर्ण *_methods, पूर्णाङ्क need_enable)
{
	वर्ण *methods, *omethods, *method, *p;
	u_int i, found;
	पूर्णाङ्क ret = -1;
	ध्रुव संरचना authmethod_cfg *cfg;

	यदि (*_methods == '\0') {
		error("empty authentication method list");
		प्रत्यागम -1;
	}
	omethods = methods = xstrdup(_methods);
	यावत् ((method = strsep(&methods, ",")) != रिक्त) {
		प्रति (found = i = 0; !found && authmethod_cfgs[i] != रिक्त; i++) {
			cfg = authmethod_cfgs[i];
			यदि ((p = strchr(method, ':')) != रिक्त)
				*p = '\0';
			यदि (strcmp(method, cfg->name) != 0)
				अनुवर्त;
			यदि (need_enable) {
				यदि (cfg->enabled == रिक्त ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					गच्छ out;
				}
			}
			found = 1;
			भङ्ग;
		}
		यदि (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			गच्छ out;
		}
	}
	ret = 0;
 out:
	मुक्त(omethods);
	प्रत्यागम ret;
}
