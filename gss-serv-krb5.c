/* $OpenBSD: gss-serv-krb5.c,v 1.10 2026/02/08 15:28:01 dtucker Exp $ */

/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
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

#अगर_घोषित GSSAPI
#अगर_घोषित KRB5

#समावेश <sys/types.h>

#समावेश <stdarg.h>
#समावेश <string.h>

#समावेश "xmalloc.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"

#समावेश "ssh-gss.h"

बाह्य ServerOptions options;

#अगर_घोषित HEIMDAL
# include <krb5.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_GSSAPI_KRB5_H
# include <gssapi_krb5.h>
#या_अगर HAVE_GSSAPI_GSSAPI_KRB5_H
# include <gssapi/gssapi_krb5.h>
#पूर्ण_अगर

अटल krb5_context krb_context = शून्य;

/* Initialise the krb5 library, for the stuff that GSSAPI won't do */

अटल पूर्णांक
ssh_gssapi_krb5_init(व्योम)
{
	krb5_error_code problem;

	अगर (krb_context != शून्य)
		वापस 1;

	problem = krb5_init_context(&krb_context);
	अगर (problem) {
		logit("Cannot initialize krb5 context");
		वापस 0;
	}

	वापस 1;
}

/* Check if this user is OK to login. This only works with krb5 - other
 * GSSAPI mechanisms will need their own.
 * Returns true if the user is OK to log in, otherwise returns 0
 */

अटल पूर्णांक
ssh_gssapi_krb5_userok(ssh_gssapi_client *client, अक्षर *name)
{
	krb5_principal princ;
	पूर्णांक retval;
	स्थिर अक्षर *errmsg;

	अगर (ssh_gssapi_krb5_init() == 0)
		वापस 0;

	अगर ((retval = krb5_parse_name(krb_context, client->exportedname.मूल्य,
	    &princ))) {
		errmsg = krb5_get_error_message(krb_context, retval);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_message(krb_context, errmsg);
		वापस 0;
	}
	अगर (krb5_kuserok(krb_context, princ, name)) {
		retval = 1;
		logit("Authorized to %s, krb5 principal %s (krb5_kuserok)",
		    name, (अक्षर *)client->displayname.मूल्य);
	} अन्यथा
		retval = 0;

	krb5_free_principal(krb_context, princ);
	वापस retval;
}


/* This writes out any forwarded credentials from the structure populated
 * during userauth. Called after we have setuid to the user */

अटल व्योम
ssh_gssapi_krb5_storecreds(ssh_gssapi_client *client)
{
	krb5_ccache ccache;
	krb5_error_code problem;
	krb5_principal princ;
	OM_uint32 maj_status, min_status;
	पूर्णांक len;
	स्थिर अक्षर *errmsg;

	अगर (client->creds == शून्य) {
		debug("No credentials stored");
		वापस;
	}

	अगर (ssh_gssapi_krb5_init() == 0)
		वापस;

#अगर_घोषित HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	अगर ((problem = krb5_cc_new_unique(krb_context, krb5_fcc_ops.prefix,
	    शून्य, &ccache)) != 0) {
		errmsg = krb5_get_error_message(krb_context, problem);
		logit("krb5_cc_new_unique(): %.100s", errmsg);
# अन्यथा
	अगर ((problem = krb5_cc_gen_new(krb_context, &krb5_fcc_ops, &ccache))) {
	    logit("krb5_cc_gen_new(): %.100s",
		krb5_get_err_text(krb_context, problem));
# endif
		krb5_free_error_message(krb_context, errmsg);
		वापस;
	}
#अन्यथा
	अगर ((problem = ssh_krb5_cc_gen(krb_context, &ccache))) {
		errmsg = krb5_get_error_message(krb_context, problem);
		logit("ssh_krb5_cc_gen(): %.100s", errmsg);
		krb5_free_error_message(krb_context, errmsg);
		वापस;
	}
#पूर्ण_अगर	/* #ifdef HEIMDAL */

	अगर ((problem = krb5_parse_name(krb_context,
	    client->exportedname.मूल्य, &princ))) {
		errmsg = krb5_get_error_message(krb_context, problem);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_message(krb_context, errmsg);
		वापस;
	}

	अगर ((problem = krb5_cc_initialize(krb_context, ccache, princ))) {
		errmsg = krb5_get_error_message(krb_context, problem);
		logit("krb5_cc_initialize(): %.100s", errmsg);
		krb5_free_error_message(krb_context, errmsg);
		krb5_free_principal(krb_context, princ);
		krb5_cc_destroy(krb_context, ccache);
		वापस;
	}

	krb5_free_principal(krb_context, princ);

	अगर ((maj_status = gss_krb5_copy_ccache(&min_status,
	    client->creds, ccache))) {
		logit("gss_krb5_copy_ccache() failed");
		krb5_cc_destroy(krb_context, ccache);
		वापस;
	}

	client->store.filename = xstrdup(krb5_cc_get_name(krb_context, ccache));
	client->store.envvar = "KRB5CCNAME";
	len = म_माप(client->store.filename) + 6;
	client->store.envval = xmalloc(len);
	snprintf(client->store.envval, len, "FILE:%s", client->store.filename);

#अगर_घोषित USE_PAM
	अगर (options.use_pam)
		do_pam_putenv(client->store.envvar, client->store.envval);
#पूर्ण_अगर

	krb5_cc_close(krb_context, ccache);

	वापस;
}

ssh_gssapi_mech gssapi_kerberos_mech = {
	"toWM5Slw5Ew8Mqkay+al2g==",
	"Kerberos",
	{9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"},
	शून्य,
	&ssh_gssapi_krb5_userok,
	शून्य,
	&ssh_gssapi_krb5_storecreds
};

#पूर्ण_अगर /* KRB5 */

#पूर्ण_अगर /* GSSAPI */
