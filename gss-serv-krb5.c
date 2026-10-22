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

#شامل "includes.h"

#اگر_تعریف_شدہ GSSAPI
#اگر_تعریف_شدہ KRB5

#شامل <sys/types.h>

#شامل <stdarg.h>
#شامل <string.h>

#شامل "xmalloc.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"

#شامل "ssh-gss.h"

خارجی ServerOptions options;

#اگر_تعریف_شدہ HEIMDAL
# include <krb5.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_GSSAPI_KRB5_H
# include <gssapi_krb5.h>
#وگرنہ_اگر HAVE_GSSAPI_GSSAPI_KRB5_H
# include <gssapi/gssapi_krb5.h>
#اگر_ختم

ساکن krb5_context krb_context = تہی;

/* Initialise the krb5 library, for the stuff that GSSAPI won't do */

ساکن صحیح
ssh_gssapi_krb5_init(خالی)
{
	krb5_error_رمز problem;

	اگر (krb_context != تہی)
		واپس 1;

	problem = krb5_init_context(&krb_context);
	اگر (problem) {
		logit("Cannot initialize krb5 context");
		واپس 0;
	}

	واپس 1;
}

/* Check if this user is OK to login. This only works with krb5 - other
 * GSSAPI mechanisms will need their own.
 * Returns true if the user is OK to log in, otherwise returns 0
 */

ساکن صحیح
ssh_gssapi_krb5_userok(ssh_gssapi_client *client, حرف *name)
{
	krb5_principal princ;
	صحیح retval;
	ثابت حرف *errmsg;

	اگر (ssh_gssapi_krb5_init() == 0)
		واپس 0;

	اگر ((retval = krb5_parse_name(krb_context, client->exportedname.قدر,
	    &princ))) {
		errmsg = krb5_get_error_پیغام(krb_context, retval);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_پیغام(krb_context, errmsg);
		واپس 0;
	}
	اگر (krb5_kuserok(krb_context, princ, name)) {
		retval = 1;
		logit("Authorized to %s, krb5 principal %s (krb5_kuserok)",
		    name, (حرف *)client->displayname.قدر);
	} ورنہ
		retval = 0;

	krb5_free_principal(krb_context, princ);
	واپس retval;
}


/* This writes out any forwarded credentials from the structure populated
 * during userauth. Called after we have setuid to the user */

ساکن خالی
ssh_gssapi_krb5_storecreds(ssh_gssapi_client *client)
{
	krb5_ccache ccache;
	krb5_error_رمز problem;
	krb5_principal princ;
	OM_uint32 maj_حالت, min_حالت;
	صحیح len;
	ثابت حرف *errmsg;

	اگر (client->creds == تہی) {
		debug("No credentials stored");
		واپس;
	}

	اگر (ssh_gssapi_krb5_init() == 0)
		واپس;

#اگر_تعریف_شدہ HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	اگر ((problem = krb5_cc_new_unique(krb_context, krb5_fcc_ops.سابقہ,
	    تہی, &ccache)) != 0) {
		errmsg = krb5_get_error_پیغام(krb_context, problem);
		logit("krb5_cc_new_unique(): %.100s", errmsg);
# ورنہ
	اگر ((problem = krb5_cc_gen_new(krb_context, &krb5_fcc_ops, &ccache))) {
	    logit("krb5_cc_gen_new(): %.100s",
		krb5_get_err_متن(krb_context, problem));
# endif
		krb5_free_error_پیغام(krb_context, errmsg);
		واپس;
	}
#ورنہ
	اگر ((problem = ssh_krb5_cc_gen(krb_context, &ccache))) {
		errmsg = krb5_get_error_پیغام(krb_context, problem);
		logit("ssh_krb5_cc_gen(): %.100s", errmsg);
		krb5_free_error_پیغام(krb_context, errmsg);
		واپس;
	}
#اگر_ختم	/* #ifdef HEIMDAL */

	اگر ((problem = krb5_parse_name(krb_context,
	    client->exportedname.قدر, &princ))) {
		errmsg = krb5_get_error_پیغام(krb_context, problem);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_پیغام(krb_context, errmsg);
		واپس;
	}

	اگر ((problem = krb5_cc_initialize(krb_context, ccache, princ))) {
		errmsg = krb5_get_error_پیغام(krb_context, problem);
		logit("krb5_cc_initialize(): %.100s", errmsg);
		krb5_free_error_پیغام(krb_context, errmsg);
		krb5_free_principal(krb_context, princ);
		krb5_cc_destroy(krb_context, ccache);
		واپس;
	}

	krb5_free_principal(krb_context, princ);

	اگر ((maj_حالت = gss_krb5_copy_ccache(&min_حالت,
	    client->creds, ccache))) {
		logit("gss_krb5_copy_ccache() failed");
		krb5_cc_destroy(krb_context, ccache);
		واپس;
	}

	client->store.filename = xstrdup(krb5_cc_get_name(krb_context, ccache));
	client->store.envvar = "KRB5CCNAME";
	len = لڑی_لمبائی(client->store.filename) + 6;
	client->store.envval = xmalloc(len);
	snprintf(client->store.envval, len, "FILE:%s", client->store.filename);

#اگر_تعریف_شدہ USE_PAM
	اگر (options.use_pam)
		do_pam_putenv(client->store.envvar, client->store.envval);
#اگر_ختم

	krb5_cc_close(krb_context, ccache);

	واپس;
}

ssh_gssapi_mech gssapi_kerberos_mech = {
	"toWM5Slw5Ew8Mqkay+al2g==",
	"Kerberos",
	{9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"},
	تہی,
	&ssh_gssapi_krb5_userok,
	تہی,
	&ssh_gssapi_krb5_storecreds
};

#اگر_ختم /* KRB5 */

#اگر_ختم /* GSSAPI */
