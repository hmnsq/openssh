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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"

বাহ্যিক ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
পূর্ণসংখ্যা none_enabled = 1;
কাঠামো authmethod_cfg methodcfg_none = {
	"none",
	ফাঁকা,
	&none_enabled
};
কাঠামো authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
কাঠামো authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	ফাঁকা,
	&options.gss_authentication
};
#endif
কাঠামো authmethod_cfg methodcfg_passwd = {
	"password",
	ফাঁকা,
	&options.password_authentication
};
কাঠামো authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	ফাঁকা,
	&options.kbd_interactive_authentication
};
কাঠামো authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	ফাঁকা,
	&options.hostbased_authentication
};

স্থির কাঠামো authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	ফাঁকা
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
পূর্ণসংখ্যা
auth2_methods_valid(ধ্রুবক অক্ষর *_methods, পূর্ণসংখ্যা need_enable)
{
	অক্ষর *methods, *omethods, *method, *p;
	u_int i, found;
	পূর্ণসংখ্যা ret = -1;
	ধ্রুবক কাঠামো authmethod_cfg *cfg;

	যদি (*_methods == '\0') {
		error("empty authentication method list");
		ফেরত -1;
	}
	omethods = methods = xstrdup(_methods);
	যখন ((method = strsep(&methods, ",")) != ফাঁকা) {
		জন্য (found = i = 0; !found && authmethod_cfgs[i] != ফাঁকা; i++) {
			cfg = authmethod_cfgs[i];
			যদি ((p = strchr(method, ':')) != ফাঁকা)
				*p = '\0';
			যদি (strcmp(method, cfg->name) != 0)
				চালু;
			যদি (need_enable) {
				যদি (cfg->enabled == ফাঁকা ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					যাও out;
				}
			}
			found = 1;
			বিরতি;
		}
		যদি (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			যাও out;
		}
	}
	ret = 0;
 out:
	মুক্ত(omethods);
	ফেরত ret;
}
