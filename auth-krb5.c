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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <krb5.h>

ಬಾಹ್ಯ ServerOptions	 options;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
krb5_init(ಶೂನ್ಯ *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_ಸಂಕೇತ problem;

	ಆದರೆ (authctxt->krb5_ctx == ಖಾಲಿ) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		ಆದರೆ (problem)
			ಹಿಂತಿರುಗಿ (problem);
	}
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
auth_krb5_password(Authctxt *authctxt, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#ಆದರೆ_ಅಂತ್ಯ
	krb5_error_ಸಂಕೇತ problem;
	krb5_ccache ccache = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ len;
	ಅಕ್ಷರ *client, *platform_client;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.ಪೂರ್ವಪ್ರತ್ಯಯ, ಖಾಲಿ, &ccache);
# ಇಲ್ಲದಿದ್ದರೆ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, ಖಾಲಿ);

	temporarily_use_uid(authctxt->pw);

	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.ಪೂರ್ವಪ್ರತ್ಯಯ, ಖಾಲಿ, &authctxt->krb5_fwd_ccache);
# ಇಲ್ಲದಿದ್ದರೆ
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = ಖಾಲಿ;
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

#ಇಲ್ಲದಿದ್ದರೆ
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (ಅಕ್ಷರ *)password, ಖಾಲಿ, ಖಾಲಿ, 0, ಖಾಲಿ, ಖಾಲಿ);
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

	problem = krb5_sname_ಗಮ್ಯ_principal(authctxt->krb5_ctx, ಖಾಲಿ, ಖಾಲಿ,
	    KRB5_NT_SRV_HST, &server);
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	ಆದರೆ (problem)
		ಹೋಗು ಹೊರಹೋಗು;
#ಆದರೆ_ಅಂತ್ಯ

	authctxt->krb5_ticket_file = (ಅಕ್ಷರ *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#ಆದರೆ_ಅಂತ್ಯ

 ಹೊರಹೋಗು:
	restore_uid();
	
	ಬಿಡುಗಡೆ(platform_client);

	ಆದರೆ (problem) {
		ಆದರೆ (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		ಆದರೆ (authctxt->krb5_ctx != ಖಾಲಿ && problem!=-1) {
			errmsg = krb5_get_error_ಸಂದೇಶ(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_ಸಂದೇಶ(authctxt->krb5_ctx, errmsg);
		} ಇಲ್ಲದಿದ್ದರೆ
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		ಆದರೆ (options.kerberos_or_local_passwd)
			ಹಿಂತಿರುಗಿ (-1);
		ಇಲ್ಲದಿದ್ದರೆ
			ಹಿಂತಿರುಗಿ (0);
	}
	ಹಿಂತಿರುಗಿ (authctxt->valid ? 1 : 0);
}

ಶೂನ್ಯ
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	ಆದರೆ (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = ಖಾಲಿ;
	}
	ಆದರೆ (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = ಖಾಲಿ;
	}
	ಆದರೆ (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = ಖಾಲಿ;
	}
}

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HEIMDAL
krb5_error_ಸಂಕೇತ
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	ಪೂರ್ಣಾಂಕ tmpfd, ret, oerrno;
	ಅಕ್ಷರ ccname[40];
	ಬಹುಲಕ_t old_umask;

	ret = snprintf(ccname, ಗಾತ್ರ(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	ಆದರೆ (ret < 0 || (ಗಾತ್ರ_t)ret >= ಗಾತ್ರ(ccname))
		ಹಿಂತಿರುಗಿ ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ("FILE:"));
	oerrno = errno;
	umask(old_umask);
	ಆದರೆ (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		ಹಿಂತಿರುಗಿ oerrno;
	}

	ಆದರೆ (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		ಹಿಂತಿರುಗಿ oerrno;
	}
	close(tmpfd);

	ಹಿಂತಿರುಗಿ (krb5_cc_resolve(ctx, ccname, ccache));
}
#ಆದರೆ_ಅಂತ್ಯ /* !HEIMDAL */
#ಆದರೆ_ಅಂತ್ಯ /* KRB5 */
