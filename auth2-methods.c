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

خارجی ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
صحیح none_enabled = 1;
ساخت authmethod_cfg methodcfg_none = {
	"none",
	تہی,
	&none_enabled
};
ساخت authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#اگر_تعریف_شدہ GSSAPI
ساخت authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	تہی,
	&options.gss_authentication
};
#اگر_ختم
ساخت authmethod_cfg methodcfg_passwd = {
	"password",
	تہی,
	&options.password_authentication
};
ساخت authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	تہی,
	&options.kbd_interactive_authentication
};
ساخت authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	تہی,
	&options.hostbased_authentication
};

ساکن ساخت authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#اگر_تعریف_شدہ GSSAPI
	&methodcfg_gssapi,
#اگر_ختم
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	تہی
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
صحیح
auth2_methods_valid(ثابت حرف *_methods, صحیح need_enable)
{
	حرف *methods, *omethods, *طریقہ, *p;
	u_int i, ملا;
	صحیح ret = -1;
	ثابت ساخت authmethod_cfg *cfg;

	اگر (*_methods == '\0') {
		error("empty authentication method list");
		واپس -1;
	}
	omethods = methods = xstrdup(_methods);
	جب ((طریقہ = strsep(&methods, ",")) != تہی) {
		برائے (ملا = i = 0; !ملا && authmethod_cfgs[i] != تہی; i++) {
			cfg = authmethod_cfgs[i];
			اگر ((p = strchr(طریقہ, ':')) != تہی)
				*p = '\0';
			اگر (strcmp(طریقہ, cfg->name) != 0)
				جاری;
			اگر (need_enable) {
				اگر (cfg->enabled == تہی ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    طریقہ, _methods);
					جاؤ برآمد;
				}
			}
			ملا = 1;
			توڑو;
		}
		اگر (!ملا) {
			error("Unknown authentication method \"%s\" in list",
			    طریقہ);
			جاؤ برآمد;
		}
	}
	ret = 0;
 برآمد:
	آزاد(omethods);
	واپس ret;
}
