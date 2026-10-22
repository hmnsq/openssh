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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"

#ifdef KRB5
#अन्तर्भाव <errno.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <krb5.h>

बाह्य ServerOptions	 options;

स्थिर पूर्णाङ्क
krb5_init(शून्य *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	यदि (authctxt->krb5_ctx == रिक्त) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		यदि (problem)
			प्रत्यागम (problem);
	}
	प्रत्यागम (0);
}

पूर्णाङ्क
auth_krb5_password(Authctxt *authctxt, ध्रुव वर्ण *password)
{
#ifndef HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#endif
	krb5_error_code problem;
	krb5_ccache ccache = रिक्त;
	पूर्णाङ्क len;
	वर्ण *client, *platform_client;
	ध्रुव वर्ण *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	यदि (problem)
		गच्छ out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	यदि (problem)
		गच्छ out;

#ifdef HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.prefix, रिक्त, &ccache);
# अन्यथा
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	यदि (problem)
		गच्छ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	यदि (problem)
		गच्छ out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, रिक्त);

	temporarily_use_uid(authctxt->pw);

	यदि (problem)
		गच्छ out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.prefix, रिक्त, &authctxt->krb5_fwd_ccache);
# अन्यथा
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	यदि (problem)
		गच्छ out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = रिक्त;
	यदि (problem)
		गच्छ out;

#अन्यथा
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (वर्ण *)password, रिक्त, रिक्त, 0, रिक्त, रिक्त);
	यदि (problem)
		गच्छ out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, रिक्त, रिक्त,
	    KRB5_NT_SRV_HST, &server);
	यदि (problem)
		गच्छ out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    रिक्त, रिक्त, रिक्त);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	यदि (problem)
		गच्छ out;

	यदि (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		गच्छ out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	यदि (problem)
		गच्छ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	यदि (problem)
		गच्छ out;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	यदि (problem)
		गच्छ out;
#endif

	authctxt->krb5_ticket_file = (वर्ण *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = म_माप(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#ifdef USE_PAM
	यदि (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#endif

 out:
	restore_uid();
	
	मुक्त(platform_client);

	यदि (problem) {
		यदि (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		यदि (authctxt->krb5_ctx != रिक्त && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} अन्यथा
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		यदि (options.kerberos_or_local_passwd)
			प्रत्यागम (-1);
		अन्यथा
			प्रत्यागम (0);
	}
	प्रत्यागम (authctxt->valid ? 1 : 0);
}

शून्य
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	यदि (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = रिक्त;
	}
	यदि (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = रिक्त;
	}
	यदि (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = रिक्त;
	}
}

#ifndef HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	पूर्णाङ्क tmpfd, ret, oerrno;
	वर्ण ccname[40];
	mode_t old_umask;

	ret = snprintf(ccname, परिमाण(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	यदि (ret < 0 || (माप_प्रकार)ret >= परिमाण(ccname))
		प्रत्यागम ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + म_माप("FILE:"));
	oerrno = त्रुटि_सं;
	umask(old_umask);
	यदि (tmpfd == -1) {
		logit("mkstemp(): %.100s", म_त्रुटि(oerrno));
		प्रत्यागम oerrno;
	}

	यदि (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = त्रुटि_सं;
		logit("fchmod(): %.100s", म_त्रुटि(oerrno));
		बंद(tmpfd);
		प्रत्यागम oerrno;
	}
	बंद(tmpfd);

	प्रत्यागम (krb5_cc_resolve(ctx, ccname, ccache));
}
#endif /* !HEIMDAL */
#endif /* KRB5 */
