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

#include "includes.h"

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "xmalloc.h"
#include "hostfile.h"
#include "auth.h"

extern ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
ကိန်းပြည့် none_enabled = 1;
sa_nracanaa authmethod_cfg methodcfg_none = {
	"none",
	NULL,
	&none_enabled
};
sa_nracanaa authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
sa_nracanaa authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	NULL,
	&options.gss_authentication
};
#endif
sa_nracanaa authmethod_cfg methodcfg_passwd = {
	"password",
	NULL,
	&options.password_authentication
};
sa_nracanaa authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	NULL,
	&options.kbd_interactive_authentication
};
sa_nracanaa authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	NULL,
	&options.hostbased_authentication
};

static sa_nracanaa authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	NULL
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
ကိန်းပြည့်
auth2_methods_valid(const var_na *_methods, ကိန်းပြည့် need_enable)
{
	var_na *methods, *omethods, *method, *p;
	u_int i, found;
	ကိန်းပြည့် ret = -1;
	const sa_nracanaa authmethod_cfg *cfg;

	အကယ်၍ (*_methods == '\0') {
		error("empty authentication method list");
		ပြန်ပေး -1;
	}
	omethods = methods = xstrdup(_methods);
	နေစဉ် ((method = strsep(&methods, ",")) != NULL) {
		အတွက် (found = i = 0; !found && authmethod_cfgs[i] != NULL; i++) {
			cfg = authmethod_cfgs[i];
			အကယ်၍ ((p = strchr(method, ':')) != NULL)
				*p = '\0';
			အကယ်၍ (strcmp(method, cfg->name) != 0)
				continue;
			အကယ်၍ (need_enable) {
				အကယ်၍ (cfg->enabled == NULL ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					goto out;
				}
			}
			found = 1;
			bha_nga;
		}
		အကယ်၍ (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			goto out;
		}
	}
	ret = 0;
 out:
	free(omethods);
	ပြန်ပေး ret;
}
