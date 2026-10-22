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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"

ବାହ୍ୟ ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା none_enabled = 1;
ସଂରଚନା authmethod_cfg methodcfg_none = {
	"none",
	ଖାଲି,
	&none_enabled
};
ସଂରଚନା authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#ifdef GSSAPI
ସଂରଚନା authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	ଖାଲି,
	&options.gss_authentication
};
#endif
ସଂରଚନା authmethod_cfg methodcfg_passwd = {
	"password",
	ଖାଲି,
	&options.password_authentication
};
ସଂରଚନା authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	ଖାଲି,
	&options.kbd_interactive_authentication
};
ସଂରଚନା authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	ଖାଲି,
	&options.hostbased_authentication
};

ସ୍ଥିର ସଂରଚନା authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	ଖାଲି
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth2_methods_valid(ଅଚଳ ଅକ୍ଷର *_methods, ପୂର୍ଣ୍ଣସଂଖ୍ୟା need_enable)
{
	ଅକ୍ଷର *methods, *omethods, *method, *p;
	u_int i, found;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	ଅଚଳ ସଂରଚନା authmethod_cfg *cfg;

	ଯଦି (*_methods == '\0') {
		error("empty authentication method list");
		ଫେରନ୍ତୁ -1;
	}
	omethods = methods = xstrdup(_methods);
	ଯେତେବେଳେ ((method = strsep(&methods, ",")) != ଖାଲି) {
		ପାଇଁ (found = i = 0; !found && authmethod_cfgs[i] != ଖାଲି; i++) {
			cfg = authmethod_cfgs[i];
			ଯଦି ((p = strchr(method, ':')) != ଖାଲି)
				*p = '\0';
			ଯଦି (strcmp(method, cfg->name) != 0)
				ଜାରି;
			ଯଦି (need_enable) {
				ଯଦି (cfg->enabled == ଖାଲି ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					ଯାଅ out;
				}
			}
			found = 1;
			ଭାଙ୍ଗ;
		}
		ଯଦି (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			ଯାଅ out;
		}
	}
	ret = 0;
 out:
	ମୁକ୍ତ(omethods);
	ଫେରନ୍ତୁ ret;
}
