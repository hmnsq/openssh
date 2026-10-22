/*
 * Copyright (c) 2002 Chris Adams.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#அந்தர்பாவ "includes.h"

#ifdef HAVE_OSF_SIA
#அந்தர்பாவ <sia.h>
#அந்தர்பாவ <siad.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <setjmp.h>
#அந்தர்பாவ <sys/resource.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh_api.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-sia.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "uidswap.h"

வெளி ServerOptions options;
வெளி முழு saved_argc;
வெளி எழுத்து **saved_argv;

முழு
sys_auth_passwd(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *pass)
{
	முழு ret;
	SIAENTITY *ent = வெற்று;
	மாறிலி எழுத்து *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	எனில் (!authctxt->user || pass == வெற்று || pass[0] == '\0')
		திரும்பு (0);

	எனில் (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    வெற்று, 0, வெற்று) != SIASUCCESS)
		திரும்பு (0);

	எனில் ((ret = sia_ses_authent(வெற்று, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		எனில் (ret & SIASTOP)
			sia_ses_release(&ent);

		திரும்பு (0);
	}

	sia_ses_release(&ent);

	திரும்பு (1);
}

வெறுமை
session_setup_sia(கட்டமைப்பு passwd *pw, எழுத்து *tty)
{
	SIAENTITY *ent = வெற்று;
	மாறிலி எழுத்து *host;

	host = get_canonical_hostname(options.use_dns);

	எனில் (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, வெற்று) != SIASUCCESS)
		fatal("sia_ses_init failed");

	எனில் (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	எனில் (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	எனில் (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_set_uid(pw);
}

#endif /* HAVE_OSF_SIA */
