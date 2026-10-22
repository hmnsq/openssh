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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే GSSAPI
#నిర్వచితమైతే KRB5

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"

#అన్తర్భావ "ssh-gss.h"

బాహ్య ServerOptions options;

#నిర్వచితమైతే HEIMDAL
# include <krb5.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_GSSAPI_KRB5_H
# include <gssapi_krb5.h>
#లేదావేళ HAVE_GSSAPI_GSSAPI_KRB5_H
# include <gssapi/gssapi_krb5.h>
#అయితే_ముగింపు

స్థిర krb5_context krb_context = ఖాళీ;

/* Initialise the krb5 library, for the stuff that GSSAPI won't do */

స్థిర పూర్ణాంకం
ssh_gssapi_krb5_init(శూన్య)
{
	krb5_error_సంకేతం problem;

	ఒకవేళ (krb_context != ఖాళీ)
		తిరిగి 1;

	problem = krb5_init_context(&krb_context);
	ఒకవేళ (problem) {
		logit("Cannot initialize krb5 context");
		తిరిగి 0;
	}

	తిరిగి 1;
}

/* Check if this user is OK to login. This only works with krb5 - other
 * GSSAPI mechanisms will need their own.
 * Returns true if the user is OK to log in, otherwise returns 0
 */

స్థిర పూర్ణాంకం
ssh_gssapi_krb5_userok(ssh_gssapi_client *client, అక్షరం *name)
{
	krb5_principal princ;
	పూర్ణాంకం retval;
	స్థిరరాశి అక్షరం *errmsg;

	ఒకవేళ (ssh_gssapi_krb5_init() == 0)
		తిరిగి 0;

	ఒకవేళ ((retval = krb5_parse_name(krb_context, client->exportedname.విలువ,
	    &princ))) {
		errmsg = krb5_get_error_సందేశం(krb_context, retval);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_సందేశం(krb_context, errmsg);
		తిరిగి 0;
	}
	ఒకవేళ (krb5_kuserok(krb_context, princ, name)) {
		retval = 1;
		logit("Authorized to %s, krb5 principal %s (krb5_kuserok)",
		    name, (అక్షరం *)client->displayname.విలువ);
	} లేకపోతే
		retval = 0;

	krb5_free_principal(krb_context, princ);
	తిరిగి retval;
}


/* This writes out any forwarded credentials from the structure populated
 * during userauth. Called after we have setuid to the user */

స్థిర శూన్య
ssh_gssapi_krb5_storecreds(ssh_gssapi_client *client)
{
	krb5_ccache ccache;
	krb5_error_సంకేతం problem;
	krb5_principal princ;
	OM_uint32 maj_స్థితి, min_స్థితి;
	పూర్ణాంకం len;
	స్థిరరాశి అక్షరం *errmsg;

	ఒకవేళ (client->creds == ఖాళీ) {
		debug("No credentials stored");
		తిరిగి;
	}

	ఒకవేళ (ssh_gssapi_krb5_init() == 0)
		తిరిగి;

#నిర్వచితమైతే HEIMDAL
# ifdef HAVE_KRB5_CC_NEW_UNIQUE
	ఒకవేళ ((problem = krb5_cc_new_unique(krb_context, krb5_fcc_ops.ఉపసర్గ,
	    ఖాళీ, &ccache)) != 0) {
		errmsg = krb5_get_error_సందేశం(krb_context, problem);
		logit("krb5_cc_new_unique(): %.100s", errmsg);
# లేకపోతే
	ఒకవేళ ((problem = krb5_cc_gen_new(krb_context, &krb5_fcc_ops, &ccache))) {
	    logit("krb5_cc_gen_new(): %.100s",
		krb5_get_err_పాఠ్యం(krb_context, problem));
# endif
		krb5_free_error_సందేశం(krb_context, errmsg);
		తిరిగి;
	}
#లేకపోతే
	ఒకవేళ ((problem = ssh_krb5_cc_gen(krb_context, &ccache))) {
		errmsg = krb5_get_error_సందేశం(krb_context, problem);
		logit("ssh_krb5_cc_gen(): %.100s", errmsg);
		krb5_free_error_సందేశం(krb_context, errmsg);
		తిరిగి;
	}
#అయితే_ముగింపు	/* #ifdef HEIMDAL */

	ఒకవేళ ((problem = krb5_parse_name(krb_context,
	    client->exportedname.విలువ, &princ))) {
		errmsg = krb5_get_error_సందేశం(krb_context, problem);
		logit("krb5_parse_name(): %.100s", errmsg);
		krb5_free_error_సందేశం(krb_context, errmsg);
		తిరిగి;
	}

	ఒకవేళ ((problem = krb5_cc_initialize(krb_context, ccache, princ))) {
		errmsg = krb5_get_error_సందేశం(krb_context, problem);
		logit("krb5_cc_initialize(): %.100s", errmsg);
		krb5_free_error_సందేశం(krb_context, errmsg);
		krb5_free_principal(krb_context, princ);
		krb5_cc_destroy(krb_context, ccache);
		తిరిగి;
	}

	krb5_free_principal(krb_context, princ);

	ఒకవేళ ((maj_స్థితి = gss_krb5_copy_ccache(&min_స్థితి,
	    client->creds, ccache))) {
		logit("gss_krb5_copy_ccache() failed");
		krb5_cc_destroy(krb_context, ccache);
		తిరిగి;
	}

	client->store.filename = xstrdup(krb5_cc_get_name(krb_context, ccache));
	client->store.envvar = "KRB5CCNAME";
	len = అక్షరశ్రేణి_పొడవు(client->store.filename) + 6;
	client->store.envval = xmalloc(len);
	snprintf(client->store.envval, len, "FILE:%s", client->store.filename);

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam)
		do_pam_putenv(client->store.envvar, client->store.envval);
#అయితే_ముగింపు

	krb5_cc_close(krb_context, ccache);

	తిరిగి;
}

ssh_gssapi_mech gssapi_kerberos_mech = {
	"toWM5Slw5Ew8Mqkay+al2g==",
	"Kerberos",
	{9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"},
	ఖాళీ,
	&ssh_gssapi_krb5_userok,
	ఖాళీ,
	&ssh_gssapi_krb5_storecreds
};

#అయితే_ముగింపు /* KRB5 */

#అయితే_ముగింపు /* GSSAPI */
