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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"

#ifdef KRB5
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <krb5.h>

ବାହ୍ୟ ServerOptions	 options;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
krb5_init(ଶୂନ୍ୟ *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	ଯଦି (authctxt->krb5_ctx == ଖାଲି) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		ଯଦି (problem)
			ଫେରନ୍ତୁ (problem);
	}
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_krb5_password(Authctxt *authctxt, ଅଚଳ ଅକ୍ଷର *password)
{
#ifndef HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#endif
	krb5_error_code problem;
	krb5_ccache ccache = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା len;
	ଅକ୍ଷର *client, *platform_client;
	ଅଚଳ ଅକ୍ଷର *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	ଯଦି (problem)
		ଯାଅ out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	ଯଦି (problem)
		ଯାଅ out;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.prefix, ଖାଲି, &ccache);
# ଅନ୍ୟଥା
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	ଯଦି (problem)
		ଯାଅ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	ଯଦି (problem)
		ଯାଅ out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, ଖାଲି);

	temporarily_use_uid(authctxt->pw);

	ଯଦି (problem)
		ଯାଅ out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.prefix, ଖାଲି, &authctxt->krb5_fwd_ccache);
# ଅନ୍ୟଥା
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	ଯଦି (problem)
		ଯାଅ out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = ଖାଲି;
	ଯଦି (problem)
		ଯାଅ out;

#ଅନ୍ୟଥା
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (ଅକ୍ଷର *)password, ଖାଲି, ଖାଲି, 0, ଖାଲି, ଖାଲି);
	ଯଦି (problem)
		ଯାଅ out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, ଖାଲି, ଖାଲି,
	    KRB5_NT_SRV_HST, &server);
	ଯଦି (problem)
		ଯାଅ out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    ଖାଲି, ଖାଲି, ଖାଲି);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	ଯଦି (problem)
		ଯାଅ out;

	ଯଦି (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		ଯାଅ out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	ଯଦି (problem)
		ଯାଅ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	ଯଦି (problem)
		ଯାଅ out;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	ଯଦି (problem)
		ଯାଅ out;
#endif

	authctxt->krb5_ticket_file = (ଅକ୍ଷର *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = strlen(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ifdef USE_PAM
	ଯଦି (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#endif

 out:
	restore_uid();
	
	ମୁକ୍ତ(platform_client);

	ଯଦି (problem) {
		ଯଦି (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		ଯଦି (authctxt->krb5_ctx != ଖାଲି && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} ଅନ୍ୟଥା
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		ଯଦି (options.kerberos_or_local_passwd)
			ଫେରନ୍ତୁ (-1);
		ଅନ୍ୟଥା
			ଫେରନ୍ତୁ (0);
	}
	ଫେରନ୍ତୁ (authctxt->valid ? 1 : 0);
}

ଶୂନ୍ୟ
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	ଯଦି (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = ଖାଲି;
	}
	ଯଦି (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = ଖାଲି;
	}
	ଯଦି (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = ଖାଲି;
	}
}

#ifndef HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା tmpfd, ret, oerrno;
	ଅକ୍ଷର ccname[40];
	mode_t old_umask;

	ret = snprintf(ccname, ଆକାର(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	ଯଦି (ret < 0 || (size_t)ret >= ଆକାର(ccname))
		ଫେରନ୍ତୁ ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + strlen("FILE:"));
	oerrno = errno;
	umask(old_umask);
	ଯଦି (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		ଫେରନ୍ତୁ oerrno;
	}

	ଯଦି (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		ଫେରନ୍ତୁ oerrno;
	}
	close(tmpfd);

	ଫେରନ୍ତୁ (krb5_cc_resolve(ctx, ccname, ccache));
}
#endif /* !HEIMDAL */
#endif /* KRB5 */
