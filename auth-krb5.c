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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <krb5.h>

ਬਾਹਰੀ ServerOptions	 options;

ਸਥਿਰ ਪੂਰਨ
krb5_init(ਖਾਲੀ *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_ਕੋਡ problem;

	ਜੇ (authctxt->krb5_ctx == ਨਿਰਾ) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		ਜੇ (problem)
			ਵਾਪਸ (problem);
	}
	ਵਾਪਸ (0);
}

ਪੂਰਨ
auth_krb5_password(Authctxt *authctxt, ਅਚਲ ਅੱਖਰ *password)
{
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#ਜੇ_ਅੰਤ
	krb5_error_ਕੋਡ problem;
	krb5_ccache ccache = ਨਿਰਾ;
	ਪੂਰਨ len;
	ਅੱਖਰ *client, *platform_client;
	ਅਚਲ ਅੱਖਰ *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.ਅਗੇਤਰ, ਨਿਰਾ, &ccache);
# ਨਹੀਂਤਾਂ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, ਨਿਰਾ);

	temporarily_use_uid(authctxt->pw);

	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.ਅਗੇਤਰ, ਨਿਰਾ, &authctxt->krb5_fwd_ccache);
# ਨਹੀਂਤਾਂ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = ਨਿਰਾ;
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

#ਨਹੀਂਤਾਂ
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (ਅੱਖਰ *)password, ਨਿਰਾ, ਨਿਰਾ, 0, ਨਿਰਾ, ਨਿਰਾ);
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

	problem = krb5_sname_ਮੰਜ਼ਿਲ_principal(authctxt->krb5_ctx, ਨਿਰਾ, ਨਿਰਾ,
	    KRB5_NT_SRV_HST, &server);
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	ਜੇ (problem)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਅੰਤ

	authctxt->krb5_ticket_file = (ਅੱਖਰ *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = ਲੜੀ_ਲੰਬਾਈ(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#ਜੇ_ਅੰਤ

 ਬਾਹਰਲਾ:
	restore_uid();
	
	ਮੁਕਤ(platform_client);

	ਜੇ (problem) {
		ਜੇ (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		ਜੇ (authctxt->krb5_ctx != ਨਿਰਾ && problem!=-1) {
			errmsg = krb5_get_error_ਸੁਨੇਹਾ(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_ਸੁਨੇਹਾ(authctxt->krb5_ctx, errmsg);
		} ਨਹੀਂਤਾਂ
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		ਜੇ (options.kerberos_or_local_passwd)
			ਵਾਪਸ (-1);
		ਨਹੀਂਤਾਂ
			ਵਾਪਸ (0);
	}
	ਵਾਪਸ (authctxt->valid ? 1 : 0);
}

ਖਾਲੀ
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	ਜੇ (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = ਨਿਰਾ;
	}
	ਜੇ (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = ਨਿਰਾ;
	}
	ਜੇ (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = ਨਿਰਾ;
	}
}

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HEIMDAL
krb5_error_ਕੋਡ
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	ਪੂਰਨ tmpfd, ret, oerrno;
	ਅੱਖਰ ccname[40];
	ਬਹੁਲਕ_t old_umask;

	ret = snprintf(ccname, ਆਕਾਰ(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	ਜੇ (ret < 0 || (ਮਾਪ_t)ret >= ਆਕਾਰ(ccname))
		ਵਾਪਸ ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + ਲੜੀ_ਲੰਬਾਈ("FILE:"));
	oerrno = errno;
	umask(old_umask);
	ਜੇ (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		ਵਾਪਸ oerrno;
	}

	ਜੇ (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		ਵਾਪਸ oerrno;
	}
	close(tmpfd);

	ਵਾਪਸ (krb5_cc_resolve(ctx, ccname, ccache));
}
#ਜੇ_ਅੰਤ /* !HEIMDAL */
#ਜੇ_ਅੰਤ /* KRB5 */
