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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <pwd.h>
#समावेश <stdarg.h>

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "packet.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "uidswap.h"
#समावेश "hostfile.h"
#समावेश "auth.h"

#अगर_घोषित KRB5
#समावेश <errno.h>
#समावेश <unistd.h>
#समावेश <string.h>
#समावेश <krb5.h>

बाह्य ServerOptions	 options;

अटल पूर्णांक
krb5_init(व्योम *context)
{
	Authctxt *authctxt = (Authctxt *)context;
	krb5_error_code problem;

	अगर (authctxt->krb5_ctx == शून्य) {
		problem = krb5_init_context(&authctxt->krb5_ctx);
		अगर (problem)
			वापस (problem);
	}
	वापस (0);
}

पूर्णांक
auth_krb5_password(Authctxt *authctxt, स्थिर अक्षर *password)
{
#अगर_अघोषित HEIMDAL
	krb5_creds creds;
	krb5_principal server;
#पूर्ण_अगर
	krb5_error_code problem;
	krb5_ccache ccache = शून्य;
	पूर्णांक len;
	अक्षर *client, *platform_client;
	स्थिर अक्षर *errmsg;

	/* get platform-specific kerberos client principal name (if it exists) */
	platform_client = platform_krb5_get_principal_name(authctxt->pw->pw_name);
	client = platform_client ? platform_client : authctxt->pw->pw_name;

	temporarily_use_uid(authctxt->pw);

	problem = krb5_init(authctxt);
	अगर (problem)
		जाओ out;

	problem = krb5_parse_name(authctxt->krb5_ctx, client,
		    &authctxt->krb5_user);
	अगर (problem)
		जाओ out;

#अगर_घोषित HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_mcc_ops.prefix, शून्य, &ccache);
# अन्यथा
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_mcc_ops, &ccache);
# endif
	अगर (problem)
		जाओ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx, ccache,
		authctxt->krb5_user);
	अगर (problem)
		जाओ out;

	restore_uid();

	problem = krb5_verify_user(authctxt->krb5_ctx, authctxt->krb5_user,
	    ccache, password, 1, शून्य);

	temporarily_use_uid(authctxt->pw);

	अगर (problem)
		जाओ out;

# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	problem = krb5_cc_new_unique(authctxt->krb5_ctx,
	    krb5_fcc_ops.prefix, शून्य, &authctxt->krb5_fwd_ccache);
# अन्यथा
	problem = krb5_cc_gen_new(authctxt->krb5_ctx, &krb5_fcc_ops,
	    &authctxt->krb5_fwd_ccache);
# endif
	अगर (problem)
		जाओ out;

	problem = krb5_cc_copy_cache(authctxt->krb5_ctx, ccache,
	    authctxt->krb5_fwd_ccache);
	krb5_cc_destroy(authctxt->krb5_ctx, ccache);
	ccache = शून्य;
	अगर (problem)
		जाओ out;

#अन्यथा
	problem = krb5_get_init_creds_password(authctxt->krb5_ctx, &creds,
	    authctxt->krb5_user, (अक्षर *)password, शून्य, शून्य, 0, शून्य, शून्य);
	अगर (problem)
		जाओ out;

	problem = krb5_sname_to_principal(authctxt->krb5_ctx, शून्य, शून्य,
	    KRB5_NT_SRV_HST, &server);
	अगर (problem)
		जाओ out;

	restore_uid();
	problem = krb5_verify_init_creds(authctxt->krb5_ctx, &creds, server,
	    शून्य, शून्य, शून्य);
	krb5_free_principal(authctxt->krb5_ctx, server);
	temporarily_use_uid(authctxt->pw);
	अगर (problem)
		जाओ out;

	अगर (!krb5_kuserok(authctxt->krb5_ctx, authctxt->krb5_user,
	    authctxt->pw->pw_name)) {
		problem = -1;
		जाओ out;
	}

	problem = ssh_krb5_cc_gen(authctxt->krb5_ctx,
	    &authctxt->krb5_fwd_ccache);
	अगर (problem)
		जाओ out;

	problem = krb5_cc_initialize(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, authctxt->krb5_user);
	अगर (problem)
		जाओ out;

	problem = krb5_cc_store_cred(authctxt->krb5_ctx,
	    authctxt->krb5_fwd_ccache, &creds);
	अगर (problem)
		जाओ out;
#पूर्ण_अगर

	authctxt->krb5_ticket_file = (अक्षर *)krb5_cc_get_name(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);

	len = म_माप(authctxt->krb5_ticket_file) + 6;
	authctxt->krb5_ccname = xmalloc(len);
	snprintf(authctxt->krb5_ccname, len, "FILE:%s",
	    authctxt->krb5_ticket_file);

#अगर_घोषित USE_PAM
	अगर (options.use_pam)
		do_pam_putenv("KRB5CCNAME", authctxt->krb5_ccname);
#पूर्ण_अगर

 out:
	restore_uid();
	
	मुक्त(platform_client);

	अगर (problem) {
		अगर (ccache)
			krb5_cc_destroy(authctxt->krb5_ctx, ccache);

		अगर (authctxt->krb5_ctx != शून्य && problem!=-1) {
			errmsg = krb5_get_error_message(authctxt->krb5_ctx,
			    problem);
			debug("Kerberos password authentication failed: %s",
			    errmsg);
			krb5_free_error_message(authctxt->krb5_ctx, errmsg);
		} अन्यथा
			debug("Kerberos password authentication failed: %d",
			    problem);

		krb5_cleanup_proc(authctxt);

		अगर (options.kerberos_or_local_passwd)
			वापस (-1);
		अन्यथा
			वापस (0);
	}
	वापस (authctxt->valid ? 1 : 0);
}

व्योम
krb5_cleanup_proc(Authctxt *authctxt)
{
	debug("krb5_cleanup_proc called");
	अगर (authctxt->krb5_fwd_ccache) {
		krb5_cc_destroy(authctxt->krb5_ctx, authctxt->krb5_fwd_ccache);
		authctxt->krb5_fwd_ccache = शून्य;
	}
	अगर (authctxt->krb5_user) {
		krb5_free_principal(authctxt->krb5_ctx, authctxt->krb5_user);
		authctxt->krb5_user = शून्य;
	}
	अगर (authctxt->krb5_ctx) {
		krb5_free_context(authctxt->krb5_ctx);
		authctxt->krb5_ctx = शून्य;
	}
}

#अगर_अघोषित HEIMDAL
krb5_error_code
ssh_krb5_cc_gen(krb5_context ctx, krb5_ccache *ccache) {
	पूर्णांक tmpfd, ret, oerrno;
	अक्षर ccname[40];
	mode_t old_umask;

	ret = snprintf(ccname, माप(ccname),
	    "FILE:/tmp/krb5cc_%d_XXXXXXXXXX", geteuid());
	अगर (ret < 0 || (माप_प्रकार)ret >= माप(ccname))
		वापस ENOMEM;

	old_umask = umask(0177);
	tmpfd = mkstemp(ccname + म_माप("FILE:"));
	oerrno = त्रुटि_सं;
	umask(old_umask);
	अगर (tmpfd == -1) {
		logit("mkstemp(): %.100s", म_त्रुटि(oerrno));
		वापस oerrno;
	}

	अगर (fchmod(tmpfd,S_IRUSR | S_IWUSR) == -1) {
		oerrno = त्रुटि_सं;
		logit("fchmod(): %.100s", म_त्रुटि(oerrno));
		बंद(tmpfd);
		वापस oerrno;
	}
	बंद(tmpfd);

	वापस (krb5_cc_resolve(ctx, ccname, ccache));
}
#पूर्ण_अगर /* !HEIMDAL */
#पूर्ण_अगर /* KRB5 */
