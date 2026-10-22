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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"

வெளி ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
முழு none_enabled = 1;
கட்டமைப்பு authmethod_cfg methodcfg_none = {
	"none",
	வெற்று,
	&none_enabled
};
கட்டமைப்பு authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
கட்டமைப்பு authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	வெற்று,
	&options.gss_authentication
};
#endif
கட்டமைப்பு authmethod_cfg methodcfg_passwd = {
	"password",
	வெற்று,
	&options.password_authentication
};
கட்டமைப்பு authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	வெற்று,
	&options.kbd_interactive_authentication
};
கட்டமைப்பு authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	வெற்று,
	&options.hostbased_authentication
};

நிலையான கட்டமைப்பு authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	வெற்று
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
முழு
auth2_methods_valid(மாறிலி எழுத்து *_methods, முழு need_enable)
{
	எழுத்து *methods, *omethods, *method, *p;
	u_int i, found;
	முழு ret = -1;
	மாறிலி கட்டமைப்பு authmethod_cfg *cfg;

	எனில் (*_methods == '\0') {
		error("empty authentication method list");
		திரும்பு -1;
	}
	omethods = methods = xstrdup(_methods);
	போது ((method = strsep(&methods, ",")) != வெற்று) {
		க்கு (found = i = 0; !found && authmethod_cfgs[i] != வெற்று; i++) {
			cfg = authmethod_cfgs[i];
			எனில் ((p = strchr(method, ':')) != வெற்று)
				*p = '\0';
			எனில் (strcmp(method, cfg->name) != 0)
				தொடர்;
			எனில் (need_enable) {
				எனில் (cfg->enabled == வெற்று ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					செல் out;
				}
			}
			found = 1;
			நிறுத்து;
		}
		எனில் (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			செல் out;
		}
	}
	ret = 0;
 out:
	விடுவி(omethods);
	திரும்பு ret;
}
