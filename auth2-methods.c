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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdlib.h>
#شامل <string.h>

#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "xmalloc.h"
#شامل "hostfile.h"
#شامل "auth.h"

بیرونی ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
صحیح none_enabled = 1;
ساختار authmethod_cfg methodcfg_none = {
	"none",
	پوچ,
	&none_enabled
};
ساختار authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
ساختار authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	پوچ,
	&options.gss_authentication
};
#endif
ساختار authmethod_cfg methodcfg_passwd = {
	"password",
	پوچ,
	&options.password_authentication
};
ساختار authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	پوچ,
	&options.kbd_interactive_authentication
};
ساختار authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	پوچ,
	&options.hostbased_authentication
};

ایستا ساختار authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	پوچ
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
صحیح
auth2_methods_valid(ثابت نویسه *_methods, صحیح need_enable)
{
	نویسه *methods, *omethods, *method, *p;
	u_int i, found;
	صحیح ret = -1;
	ثابت ساختار authmethod_cfg *cfg;

	اگر (*_methods == '\0') {
		error("empty authentication method list");
		بازگشت -1;
	}
	omethods = methods = xstrdup(_methods);
	وقتی ((method = strsep(&methods, ",")) != پوچ) {
		برای (found = i = 0; !found && authmethod_cfgs[i] != پوچ; i++) {
			cfg = authmethod_cfgs[i];
			اگر ((p = strchr(method, ':')) != پوچ)
				*p = '\0';
			اگر (strcmp(method, cfg->name) != 0)
				ادامه;
			اگر (need_enable) {
				اگر (cfg->enabled == پوچ ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					برو out;
				}
			}
			found = 1;
			بشکن;
		}
		اگر (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			برو out;
		}
	}
	ret = 0;
 out:
	آزاد(omethods);
	بازگشت ret;
}
