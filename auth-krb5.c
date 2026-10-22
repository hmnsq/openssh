/* $OpenBSD: auth-krb5.c,v 1.26 2026/02/08 19:54:31 dtucker Exp $ */
/*
 *    Kerberos v5 authentication and ticket-passing routines.
 *
 * From: FreeBSD: src/crypto/openssh/auth-krb5.c,v 1.6 2001/02/13 16:58:04 assar
 */
/*
 * Copyright (c) 2002 Daniel Kouril.  All rights reserved.
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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "uidswap.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"

#ifdef KRB5
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <krb5.h>

ബാഹ്യ ServerOptions	 options;

സ്ഥിതം പൂർണ്ണസംഖ്യ
krb5_init(ശൂന്യം *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	എങ്കിൽ (authctxt->krb5_ctx == ശൂന്യ) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		എങ്കിൽ (problem)
			തിരികെ (problem);
	}
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
auth_krb5_password(Authctxt *authctxt, സ്ഥിരം അക്ഷരം *password)
{
#ifndef HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#endif
	krb5_error_code problem;
	krb5_ccache ccache = ശൂന്യ;
	പൂർണ്ണസംഖ്യ len;
	അക്ഷരം *client, *platform_client;
	സ്ഥിരം അക്ഷരം *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	എങ്കിൽ (problem)
		പോകുക out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	എങ്കിൽ (problem)
		പോകുക out;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.prefix, ശൂന്യ, &ccache);
# അല്ലെങ്കിൽ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	എങ്കിൽ (problem)
		പോകുക out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	എങ്കിൽ (problem)
		പോകുക out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, ശൂന്യ);

	temporarily_use_uid(authctxt->pw);

	എങ്കിൽ (problem)
		പോകുക out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.prefix, ശൂന്യ, &authctxt->krb5_fwd_ccache);
# അല്ലെങ്കിൽ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	എങ്കിൽ (problem)
		പോകുക out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = ശൂന്യ;
	എങ്കിൽ (problem)
		പോകുക out;

#അല്ലെങ്കിൽ
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (അക്ഷരം *)password, ശൂന്യ, ശൂന്യ, 0, ശൂന്യ, ശൂന്യ);
	എങ്കിൽ (problem)
		പോകുക out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, ശൂന്യ, ശൂന്യ,
	    KRB5_NT_SRV_HST, &server);
	എങ്കിൽ (problem)
		പോകുക out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    ശൂന്യ, ശൂന്യ, ശൂന്യ);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	എങ്കിൽ (problem)
		പോകുക out;

	എങ്കിൽ (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		പോകുക out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	എങ്കിൽ (problem)
		പോകുക out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	എങ്കിൽ (problem)
		പോകുക out;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	എങ്കിൽ (problem)
		പോകുക out;
#endif

	authctxt->krb5_ticket_file = (അക്ഷരം *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = strlen(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ifdef USE_PAM
	എങ്കിൽ (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#endif

 out:
	restore_uid();
	
	സ്വതന്ത്രം(platform_client);

	എങ്കിൽ (problem) {
		എങ്കിൽ (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		എങ്കിൽ (authctxt->krb5_ctx != ശൂന്യ && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} അല്ലെങ്കിൽ
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		എങ്കിൽ (options.kerberos_or_local_passwd)
			തിരികെ (-1);
		അല്ലെങ്കിൽ
			തിരികെ (0);
	}
	തിരികെ (authctxt->valid ? 1 : 0);
}

ശൂന്യം
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	എങ്കിൽ (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = ശൂന്യ;
	}
	എങ്കിൽ (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = ശൂന്യ;
	}
	എങ്കിൽ (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = ശൂന്യ;
	}
}

#ifndef HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	പൂർണ്ണസംഖ്യ tmpfd, ret, oerrno;
	അക്ഷരം ccname[40];
	mode_t old_umask;

	ret = snprintf(ccname, വലുപ്പം(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	എങ്കിൽ (ret < 0 || (size_t)ret >= വലുപ്പം(ccname))
		തിരികെ ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + strlen("FILE:"));
	oerrno = errno;
	umask(old_umask);
	എങ്കിൽ (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		തിരികെ oerrno;
	}

	എങ്കിൽ (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		തിരികെ oerrno;
	}
	close(tmpfd);

	തിരികെ (krb5_cc_resolve(ctx, ccname, ccache));
}
#endif /* !HEIMDAL */
#endif /* KRB5 */
