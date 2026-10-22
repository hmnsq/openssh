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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "xmalloc.h"
#समावेश "hostfile.h"
#समावेश "auth.h"

बाह्य ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate from the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it is cleared by userauth_none() later */
पूर्णांक none_enabled = 1;
काष्ठा authmethod_cfg methodcfg_none = {
	"none",
	शून्य,
	&none_enabled
};
काष्ठा authmethod_cfg methodcfg_pubkey = {
	"publickey",
	"publickey-hostbound-v00@openssh.com",
	&options.pubkey_authentication
};
#अगर_घोषित GSSAPI
काष्ठा authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	शून्य,
	&options.gss_authentication
};
#पूर्ण_अगर
काष्ठा authmethod_cfg methodcfg_passwd = {
	"password",
	शून्य,
	&options.password_authentication
};
काष्ठा authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	शून्य,
	&options.kbd_interactive_authentication
};
काष्ठा authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	शून्य,
	&options.hostbased_authentication
};

अटल काष्ठा authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#अगर_घोषित GSSAPI
	&methodcfg_gssapi,
#पूर्ण_अगर
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	शून्य
};

/*
 * Check a comma-separated list of methods for validity. If need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
पूर्णांक
auth2_methods_valid(स्थिर अक्षर *_methods, पूर्णांक need_enable)
{
	अक्षर *methods, *omethods, *method, *p;
	u_int i, found;
	पूर्णांक ret = -1;
	स्थिर काष्ठा authmethod_cfg *cfg;

	अगर (*_methods == '\0') {
		error("empty authentication method list");
		वापस -1;
	}
	omethods = methods = xstrdup(_methods);
	जबतक ((method = strsep(&methods, ",")) != शून्य) {
		क्रम (found = i = 0; !found && authmethod_cfgs[i] != शून्य; i++) {
			cfg = authmethod_cfgs[i];
			अगर ((p = म_अक्षर(method, ':')) != शून्य)
				*p = '\0';
			अगर (म_भेद(method, cfg->name) != 0)
				जारी;
			अगर (need_enable) {
				अगर (cfg->enabled == शून्य ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					जाओ out;
				}
			}
			found = 1;
			अवरोध;
		}
		अगर (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			जाओ out;
		}
	}
	ret = 0;
 out:
	मुक्त(omethods);
	वापस ret;
}
