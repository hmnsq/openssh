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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "uidswap.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"

#నిర్వచితమైతే KRB5
#అన్తర్భావ <errno.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <krb5.h>

బాహ్య ServerOptions	 options;

స్థిర పూర్ణాంకం
krb5_init(శూన్య *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_సంకేతం problem;

	ఒకవేళ (authctxt->krb5_ctx == ఖాళీ) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		ఒకవేళ (problem)
			తిరిగి (problem);
	}
	తిరిగి (0);
}

పూర్ణాంకం
auth_krb5_password(Authctxt *authctxt, స్థిరరాశి అక్షరం *password)
{
#నిర్వచితం_కాకపోతే HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#అయితే_ముగింపు
	krb5_error_సంకేతం problem;
	krb5_ccache ccache = ఖాళీ;
	పూర్ణాంకం len;
	అక్షరం *client, *platform_client;
	స్థిరరాశి అక్షరం *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

#నిర్వచితమైతే HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.ఉపసర్గ, ఖాళీ, &ccache);
# లేకపోతే
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, ఖాళీ);

	temporarily_use_uid(authctxt->pw);

	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.ఉపసర్గ, ఖాళీ, &authctxt->krb5_fwd_ccache);
# లేకపోతే
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = ఖాళీ;
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

#లేకపోతే
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (అక్షరం *)password, ఖాళీ, ఖాళీ, 0, ఖాళీ, ఖాళీ);
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

	problem = krb5_sname_గమ్యం_principal(authctxt->krb5_ctx, ఖాళీ, ఖాళీ,
	    KRB5_NT_SRV_HST, &server);
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    ఖాళీ, ఖాళీ, ఖాళీ);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		వెళ్ళు బహిర్గతం;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	ఒకవేళ (problem)
		వెళ్ళు బహిర్గతం;
#అయితే_ముగింపు

	authctxt->krb5_ticket_file = (అక్షరం *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = అక్షరశ్రేణి_పొడవు(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#అయితే_ముగింపు

 బహిర్గతం:
	restore_uid();
	
	విడుదల(platform_client);

	ఒకవేళ (problem) {
		ఒకవేళ (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		ఒకవేళ (authctxt->krb5_ctx != ఖాళీ && problem!=-1) {
			errmsg = krb5_get_error_సందేశం(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_సందేశం(authctxt->krb5_ctx, errmsg);
		} లేకపోతే
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		ఒకవేళ (options.kerberos_or_local_passwd)
			తిరిగి (-1);
		లేకపోతే
			తిరిగి (0);
	}
	తిరిగి (authctxt->valid ? 1 : 0);
}

శూన్య
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	ఒకవేళ (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = ఖాళీ;
	}
	ఒకవేళ (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = ఖాళీ;
	}
	ఒకవేళ (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = ఖాళీ;
	}
}

#నిర్వచితం_కాకపోతే HEIMDAL
krb5_error_సంకేతం
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	పూర్ణాంకం tmpfd, ret, oerrno;
	అక్షరం ccname[40];
	బహుళకం_t old_umask;

	ret = snprintf(ccname, పరిమాణం(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	ఒకవేళ (ret < 0 || (కొలత_t)ret >= పరిమాణం(ccname))
		తిరిగి ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + అక్షరశ్రేణి_పొడవు("FILE:"));
	oerrno = errno;
	umask(old_umask);
	ఒకవేళ (tmpfd == -1) {
		logit("mkstemp(): %.100s", strerror(oerrno));
		తిరిగి oerrno;
	}

	ఒకవేళ (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = errno;
		logit("fchmod(): %.100s", strerror(oerrno));
		close(tmpfd);
		తిరిగి oerrno;
	}
	close(tmpfd);

	తిరిగి (krb5_cc_resolve(ctx, ccname, ccache));
}
#అయితే_ముగింపు /* !HEIMDAL */
#అయితే_ముగింపు /* KRB5 */
