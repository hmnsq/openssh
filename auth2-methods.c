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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"

బాహ్య ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
పూర్ణాంకం none_enabled = 1;
నిర్మాణం authmethod_cfg methodcfg_none = {
	"none",
	ఖాళీ,
	&none_enabled
};
నిర్మాణం authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#నిర్వచితమైతే GSSAPI
నిర్మాణం authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	ఖాళీ,
	&options.gss_authentication
};
#అయితే_ముగింపు
నిర్మాణం authmethod_cfg methodcfg_passwd = {
	"password",
	ఖాళీ,
	&options.password_authentication
};
నిర్మాణం authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	ఖాళీ,
	&options.kbd_interactive_authentication
};
నిర్మాణం authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	ఖాళీ,
	&options.hostbased_authentication
};

స్థిర నిర్మాణం authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#నిర్వచితమైతే GSSAPI
	&methodcfg_gssapi,
#అయితే_ముగింపు
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	ఖాళీ
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
పూర్ణాంకం
auth2_methods_valid(స్థిరరాశి అక్షరం *_methods, పూర్ణాంకం need_enable)
{
	అక్షరం *methods, *omethods, *పద్ధతి, *p;
	u_int i, దొరికింది;
	పూర్ణాంకం ret = -1;
	స్థిరరాశి నిర్మాణం authmethod_cfg *cfg;

	ఒకవేళ (*_methods == '\0') {
		error("empty authentication method list");
		తిరిగి -1;
	}
	omethods = methods = xstrdup(_methods);
	అయితే ((పద్ధతి = strsep(&methods, ",")) != ఖాళీ) {
		కొరకు (దొరికింది = i = 0; !దొరికింది && authmethod_cfgs[i] != ఖాళీ; i++) {
			cfg = authmethod_cfgs[i];
			ఒకవేళ ((p = strchr(పద్ధతి, ':')) != ఖాళీ)
				*p = '\0';
			ఒకవేళ (strcmp(పద్ధతి, cfg->name) != 0)
				కొనసాగు;
			ఒకవేళ (need_enable) {
				ఒకవేళ (cfg->enabled == ఖాళీ ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    పద్ధతి, _methods);
					వెళ్ళు బహిర్గతం;
				}
			}
			దొరికింది = 1;
			ఆపు;
		}
		ఒకవేళ (!దొరికింది) {
			error("Unknown authentication method \"%s\" in list",
			    పద్ధతి);
			వెళ్ళు బహిర్గతం;
		}
	}
	ret = 0;
 బహిర్గతం:
	విడుదల(omethods);
	తిరిగి ret;
}
