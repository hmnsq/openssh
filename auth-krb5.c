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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"

#ifdef KRB5
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <krb5.h>

ಬಾಹ್ಯ ServerOptions	 options;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
krb5_init(ಶೂನ್ಯ *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	ಯದಿ (authctxt->krb5_ctx == ರಿಕ್ತ) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		ಯದಿ (problem)
			ಪ್ರತ್ಯಾಗಮ (problem);
	}
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
auth_krb5_password(Authctxt *authctxt, ಧ್ರುವ ವರ್ಣ *password)
{
#ifndef HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#endif
	krb5_error_code problem;
	krb5_ccache ccache = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ len;
	ವರ್ಣ *client, *platform_client;
	ಧ್ರುವ ವರ್ಣ *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	ಯದಿ (problem)
		ಗಚ್ಛ out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	ಯದಿ (problem)
		ಗಚ್ಛ out;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.prefix, ರಿಕ್ತ, &ccache);
# ಅನ್ಯಥಾ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	ಯದಿ (problem)
		ಗಚ್ಛ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	ಯದಿ (problem)
		ಗಚ್ಛ out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, ರಿಕ್ತ);

	temporarily_use_uid(authctxt->pw);

	ಯದಿ (problem)
		ಗಚ್ಛ out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.prefix, ರಿಕ್ತ, &authctxt->krb5_fwd_ccache);
# ಅನ್ಯಥಾ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	ಯದಿ (problem)
		ಗಚ್ಛ out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = ರಿಕ್ತ;
	ಯದಿ (problem)
		ಗಚ್ಛ out;

#ಅನ್ಯಥಾ
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (ವರ್ಣ *)password, ರಿಕ್ತ, ರಿಕ್ತ, 0, ರಿಕ್ತ, ರಿಕ್ತ);
	ಯದಿ (problem)
		ಗಚ್ಛ out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, ರಿಕ್ತ, ರಿಕ್ತ,
	    KRB5_NT_SRV_HST, &server);
	ಯದಿ (problem)
		ಗಚ್ಛ out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	ಯದಿ (problem)
		ಗಚ್ಛ out;

	ಯದಿ (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		ಗಚ್ಛ out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	ಯದಿ (problem)
		ಗಚ್ಛ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	ಯದಿ (problem)
		ಗಚ್ಛ out;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	ಯದಿ (problem)
		ಗಚ್ಛ out;
#endif

	authctxt->krb5_ticket_file = (ವರ್ಣ *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = strlen(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ifdef USE_PAM
	ಯದಿ (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#endif

 out:
	restore_uid();
	
	ಮುಕ್ತ(platform_client);

	ಯದಿ (problem) {
		ಯದಿ (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		ಯದಿ (authctxt->krb5_ctx != ರಿಕ್ತ && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} ಅನ್ಯಥಾ
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		ಯದಿ (options.kerberos_or_local_passwd)
			ಪ್ರತ್ಯಾಗಮ (-1);
		ಅನ್ಯಥಾ
			ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಪ್ರತ್ಯಾಗಮ (authctxt->valid ? 1 : 0);
}

ಶೂನ್ಯ
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	ಯದಿ (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = ರಿಕ್ತ;
	}
	ಯದಿ (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = ರಿಕ್ತ;
	}
	ಯದಿ (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = ರಿಕ್ತ;
	}
}

#ifndef HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	ಪೂರ್ಣಾಙ್ಕ tmpfd, ret, oerrno;
	ವರ್ಣ ccname[40];
	mode_t old_umask;

	ret = snprintf(ccname, ಪರಿಮಾಣ(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	ಯದಿ (ret < 0 || (size_t)ret >= ಪರಿಮಾಣ(ccname))
		ಪ್ರತ್ಯಾಗಮ ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + strlen("FILE:"));
	oerrno = errno;
	umask(old_umask);
	ಯದಿ (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		ಪ್ರತ್ಯಾಗಮ oerrno;
	}

	ಯದಿ (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		ಪ್ರತ್ಯಾಗಮ oerrno;
	}
	close(tmpfd);

	ಪ್ರತ್ಯಾಗಮ (krb5_cc_resolve(ctx, ccname, ccache));
}
#endif /* !HEIMDAL */
#endif /* KRB5 */
