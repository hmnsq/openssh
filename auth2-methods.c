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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "xmalloc.h"
#ضمن "hostfile.h"
#ضمن "auth.h"

خارجي ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
صحيح none_enabled = 1;
بنية authmethod_cfg methodcfg_none = {
	"none",
	عدم,
	&none_enabled
};
بنية authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
بنية authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	عدم,
	&options.gss_authentication
};
#endif
بنية authmethod_cfg methodcfg_passwd = {
	"password",
	عدم,
	&options.password_authentication
};
بنية authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	عدم,
	&options.kbd_interactive_authentication
};
بنية authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	عدم,
	&options.hostbased_authentication
};

ساكن بنية authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	عدم
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
صحيح
auth2_methods_valid(ثابت حرف *_methods, صحيح need_enable)
{
	حرف *methods, *omethods, *method, *p;
	u_int i, found;
	صحيح ret = -1;
	ثابت بنية authmethod_cfg *cfg;

	ܐܢ (*_methods == '\0') {
		error("empty authentication method list");
		ܦܢܐ -1;
	}
	omethods = methods = xstrdup(_methods);
	ܟܡܐ ((method = strsep(&methods, ",")) != عدم) {
		لكل (found = i = 0; !found && authmethod_cfgs[i] != عدم; i++) {
			cfg = authmethod_cfgs[i];
			ܐܢ ((p = strchr(method, ':')) != عدم)
				*p = '\0';
			ܐܢ (strcmp(method, cfg->name) != 0)
				استمر;
			ܐܢ (need_enable) {
				ܐܢ (cfg->enabled == عدم ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					اذهب out;
				}
			}
			found = 1;
			اكسر;
		}
		ܐܢ (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			اذهب out;
		}
	}
	ret = 0;
 out:
	حرر(omethods);
	ܦܢܐ ret;
}
