/* $OpenBSD: auth2-pubkey.c,v 1.132 2026/10/11 20:41:20 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <glob.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "uidswap.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "canohost.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "channels.h" /* XXX for session.h */
#అన్తర్భావ "session.h" /* XXX for child_set_env(); refactor? */
#అన్తర్భావ "sk-api.h"

/* import */
బాహ్య ServerOptions options;
బాహ్య నిర్మాణం authmethod_cfg methodcfg_pubkey;

స్థిర అక్షరం *
format_కీలకం(స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	అక్షరం *ret, *fp = sshkey_fingerprint(కీలకం,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(కీలకం), fp);
	విడుదల(fp);
	తిరిగి ret;
}

/*
 * Verify that the hostkey in a publickey-hostbound-v00@openssh.com userauth
 * request matches the hostkey that was negotiated during initial KEX.
 */
స్థిర శూన్య
check_hostbound_hostkey(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *our_hostkey_blob, *their_hostkey_blob;

	ఒకవేళ (ssh->kex->initial_hostkey == ఖాళీ)
		fatal_f("internal error: initial hostkey not recorded");
	ఒకవేళ ((our_hostkey_blob = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshpkt_getb_froms(ssh, &their_hostkey_blob)) != 0)
		fatal_fr(r, "parse hostkey");
	ఒకవేళ ((r = sshkey_putb(ssh->kex->initial_hostkey, our_hostkey_blob)) != 0)
		fatal_fr(r, "serialise hostkey");
	ఒకవేళ ((r = sshbuf_equals(our_hostkey_blob, their_hostkey_blob)) != 0)
		fatal_f("packet contained wrong host key");
	sshbuf_free(our_hostkey_blob);
	sshbuf_free(their_hostkey_blob);
}

స్థిర పూర్ణాంకం
userauth_pubkey(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *పద్ధతి)
{
	Authctxt *authctxt = ssh->authctxt;
	నిర్మాణం passwd *pw = authctxt->pw;
	నిర్మాణం sshbuf *keyblob = ఖాళీ, *b = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ, *hostkey = ఖాళీ;
	అక్షరం *pkalg = ఖాళీ, *userstyle = ఖాళీ, *కీలకం_s = ఖాళీ, *ca_s = ఖాళీ;
	అక్షరం *keystring = ఖాళీ;
	u_char *sig = ఖాళీ, have_sig;
	కొలత_t slen;
	పూర్ణాంకం hostbound, r, pktype;
	పూర్ణాంకం req_presence = 0, req_verify = 0, authenticated = 0;
	నిర్మాణం sshauthopt *authopts = ఖాళీ;
	నిర్మాణం sshkey_sig_details *sig_details = ఖాళీ;

	hostbound = strcmp(పద్ధతి, "publickey-hostbound-v00@openssh.com") == 0;

	ఒకవేళ ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, ఖాళీ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0)
		fatal_fr(r, "parse %s packet", పద్ధతి);

	/* hostbound auth includes the hostkey offered at initial KEX */
	ఒకవేళ (hostbound)
		check_hostbound_hostkey(ssh); /* fatals on error */

	ఒకవేళ (log_level_get() >= SYSLOG_LEVEL_DEBUG2) {
		ఒకవేళ ((b = sshbuf_fromb(keyblob)) == ఖాళీ)
			fatal_f("sshbuf_fromb failed");
		ఒకవేళ ((keystring = sshbuf_dtob64_string(b, 0)) == ఖాళీ)
			fatal_f("sshbuf_dtob64 failed");
		debug2_f("%s user %s %s public key %s %s",
		    authctxt->valid ? "valid" : "invalid", authctxt->user,
		    have_sig ? "attempting" : "querying", pkalg, keystring);
		sshbuf_free(b);
		b = ఖాళీ;
	}

	pktype = sshkey_type_from_name(pkalg);
	ఒకవేళ (pktype == కీలకం_UNSPEC) {
		/* this is perfectly legal */
		verbose_f("unsupported public key algorithm: %s", pkalg);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (సరిపోలిక_నమూనా_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		logit_f("signature algorithm %s not in "
		    "PubkeyAcceptedAlgorithms", pkalg);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((b = sshbuf_fromb(keyblob)) == ఖాళీ)
		fatal_f("sshbuf_fromb failed");
	ఎంపిక ((r = sshkey_fromb_allowlist(b, &కీలకం,
	    options.pubkey_accepted_algos, options.ca_sign_algorithms))) {
	స్థితి 0:
		/* ok */
		ఆపు;
	స్థితి SSH_ERR_కీలకం_ALG_UNSUPPORTED:
		/* This shouldn't happen unless the client is being weird */
		logit_f("key algorithm differs from signature algorithm %s and "
		    "is not in PubkeyAcceptedAlgorithms", pkalg);
		వెళ్ళు పూర్తి;
	స్థితి SSH_ERR_SIGN_ALG_UNSUPPORTED:
		logit_fr(r, "certificate signature algorithm not in "
		    "CASignatureAlgorithm");
		వెళ్ళు పూర్తి;
	అప్రమేయ:
		error_fr(r, "parse key");
		వెళ్ళు పూర్తి;
	}
	sshbuf_free(b);
	b = ఖాళీ;

	/* USERAUTH_REQUEST signature type should match key's type */
	ఒకవేళ (కీలకం->type != pktype || (sshkey_type_plain(pktype) == కీలకం_ECDSA &&
	    sshkey_ecdsa_nid_from_name(pkalg) != కీలకం->ecdsa_nid)) {
		error_f("key type mismatch for decoded key "
		    "(received %s, expected %s)", sshkey_ssh_name(కీలకం), pkalg);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (auth2_కీలకం_already_వాడిన(authctxt, కీలకం)) {
		logit("refusing previously-used %s key", sshkey_type(కీలకం));
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshkey_check_rsa_నిడివి(కీలకం,
	    options.required_rsa_కొలత)) != 0) {
		logit_r(r, "refusing %s key", sshkey_type(కీలకం));
		వెళ్ళు పూర్తి;
	}
	కీలకం_s = format_కీలకం(కీలకం);
	ఒకవేళ (sshkey_is_cert(కీలకం))
		ca_s = format_కీలకం(కీలకం->cert->signature_కీలకం);

	ఒకవేళ (have_sig) {
		debug3_f("%s have %s signature for %s%s%s",
		    పద్ధతి, pkalg, కీలకం_s,
		    ca_s == ఖాళీ ? "" : " CA ", ca_s == ఖాళీ ? "" : ca_s);
		ఒకవేళ ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_చివర(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
			fatal_f("sshbuf_new failed");
		ఒకవేళ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "put session id");
		ఒకవేళ (!authctxt->valid || authctxt->user == ఖాళీ) {
			debug2_f("disabled because of invalid user");
			వెళ్ళు పూర్తి;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		ఒకవేళ ((r = sshbuf_put_u8(b, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, పద్ధతి)) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_stringb(b, keyblob)) != 0)
			fatal_fr(r, "reconstruct %s packet", పద్ధతి);
		ఒకవేళ (hostbound &&
		    (r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
			fatal_fr(r, "reconstruct %s packet", పద్ధతి);
#నిర్వచితమైతే DEBUG_PK
		sshbuf_dump(b, stderr);
#అయితే_ముగింపు
		/* test for correct signature */
		authenticated = 0;
		ఒకవేళ (mm_user_కీలకం_allowed(ssh, pw, కీలకం, 1, &authopts) &&
		    mm_sshkey_verify(కీలకం, sig, slen,
		    sshbuf_ptr(b), sshbuf_len(b),
		    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : ఖాళీ,
		    ssh->compat, &sig_details) == 0) {
			authenticated = 1;
		}
		ఒకవేళ (authenticated == 1 && sig_details != ఖాళీ) {
			auth2_రికార్డు_info(authctxt, "signature count = %u",
			    sig_details->sk_counter);
			debug_f("sk_counter = %u, sk_flags = 0x%02x",
			    sig_details->sk_counter, sig_details->sk_flags);
			req_presence = (options.pubkey_auth_options &
			    PUBKEYAUTH_TOUCH_REQUIRED) ||
			    !authopts->no_require_user_presence;
			ఒకవేళ (req_presence && (sig_details->sk_flags &
			    SSH_SK_USER_PRESENCE_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user presence "
				    "(authenticator touch) requirement "
				    "not met ", కీలకం_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_పోర్టు(ssh));
				authenticated = 0;
				వెళ్ళు పూర్తి;
			}
			req_verify = (options.pubkey_auth_options &
			    PUBKEYAUTH_VERIFY_REQUIRED) ||
			    authopts->require_verify;
			ఒకవేళ (req_verify && (sig_details->sk_flags &
			    SSH_SK_USER_VERIFICATION_REQD) == 0) {
				error("public key %s signature for %s%s from "
				    "%.128s port %d rejected: user "
				    "verification requirement not met ", కీలకం_s,
				    authctxt->valid ? "" : "invalid user ",
				    authctxt->user, ssh_remote_ipaddr(ssh),
				    ssh_remote_పోర్టు(ssh));
				authenticated = 0;
				వెళ్ళు పూర్తి;
			}
		}
		auth2_రికార్డు_కీలకం(authctxt, authenticated, కీలకం);
	} లేకపోతే {
		debug_f("%s test pkalg %s pkblob %s%s%s", పద్ధతి, pkalg, కీలకం_s,
		    ca_s == ఖాళీ ? "" : " CA ", ca_s == ఖాళీ ? "" : ca_s);

		ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
			fatal_fr(r, "parse packet");

		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		ఒకవేళ (authctxt->valid && authctxt->user != ఖాళీ &&
		    mm_user_కీలకం_allowed(ssh, pw, కీలకం, 0, ఖాళీ)) {
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_stringb(ssh, keyblob)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		} లేకపోతే {
			/*
			 * NB. invalid users must be accounted for in exactly
			 * the same way as valid users whose key was refused,
			 * otherwise MaxAuthTries becomes a username oracle.
			 */
			/*
			 * Don't count this as an authentication failure
			 * unless we have already used up the separate
			 * max-pk-ok budget (if any).
			 */
			ఒకవేళ (authctxt->pk_ok_failures++ < options.max_pubkey_ok)
				authctxt->auth_failure_already_counted = 1;
			debug3_f("pubkey test %d of %d%s",
			    authctxt->pk_ok_failures, options.max_pubkey_ok,
			    authctxt->auth_failure_already_counted ?
			    "" : ": treating as authentication failure");
		 }
	}
పూర్తి:
	ఒకవేళ (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshbuf_free(b);
	sshbuf_free(keyblob);
	sshauthopt_free(authopts);
	sshkey_free(కీలకం);
	sshkey_free(hostkey);
	విడుదల(keystring);
	విడుదల(userstyle);
	విడుదల(pkalg);
	విడుదల(కీలకం_s);
	విడుదల(ca_s);
	విడుదల(sig);
	sshkey_sig_details_free(sig_details);
	తిరిగి authenticated;
}

స్థిర పూర్ణాంకం
సరిపోలిక_principals_file(నిర్మాణం passwd *pw, అక్షరం *file,
    నిర్మాణం sshkey_cert *cert, నిర్మాణం sshauthopt **authoptsp)
{
	FILE *f;
	పూర్ణాంకం r, success = 0;
	కొలత_t i;
	glob_t gl;
	నిర్మాణం sshauthopt *opts = ఖాళీ;

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;

	temporarily_use_uid(pw);
	r = glob(file, 0, ఖాళీ, &gl);
	restore_uid();
	ఒకవేళ (r != 0) {
		ఒకవేళ (r != GLOB_NOMATCH) {
			logit_f("glob \"%s\" failed", file);
		}
		తిరిగి 0;
	} లేకపోతే ఒకవేళ (gl.gl_pathc > గరిష్ఠ_పూర్ణాంకం) {
		fatal_f("too many glob results for \"%s\"", file);
	} లేకపోతే ఒకవేళ (gl.gl_pathc > 1) {
		debug2_f("glob \"%s\" returned %zu matches", file,
		    gl.gl_pathc);
	}
	కొరకు (i = 0; !success && i < gl.gl_pathc; i++) {
		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", file);
		ఒకవేళ ((f = auth_openprincipals(gl.gl_pathv[i], pw,
		    options.strict_modes)) == ఖాళీ) {
			restore_uid();
			కొనసాగు;
		}
		success = auth_process_principals(f, gl.gl_pathv[i],
		    cert, &opts);
		fclose(f);
		restore_uid();
		ఒకవేళ (!success) {
			sshauthopt_free(opts);
			opts = ఖాళీ;
		}
	}
	globfree(&gl);
	ఒకవేళ (success && authoptsp != ఖాళీ) {
		*authoptsp = opts;
		opts = ఖాళీ;
	}
	sshauthopt_free(opts);
	తిరిగి success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
స్థిర పూర్ణాంకం
సరిపోలిక_principals_command(నిర్మాణం passwd *user_pw, స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి అక్షరం *conn_id, స్థిరరాశి అక్షరం *rdomain, నిర్మాణం sshauthopt **authoptsp)
{
	నిర్మాణం passwd *runas_pw = ఖాళీ;
	స్థిరరాశి నిర్మాణం sshkey_cert *cert = కీలకం->cert;
	FILE *f = ఖాళీ;
	పూర్ణాంకం r, ok, దొరికింది_principal = 0;
	పూర్ణాంకం i, ac = 0, uid_swapped = 0;
	pid_t pid;
	అక్షరం *tmp, *username = ఖాళీ, *command = ఖాళీ, **av = ఖాళీ;
	అక్షరం *ca_fp = ఖాళీ, *కీలకం_fp = ఖాళీ, *catext = ఖాళీ, *keytext = ఖాళీ;
	అక్షరం serial_s[32], uidstr[32];
	శూన్య (*osigchld)(పూర్ణాంకం);

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;
	ఒకవేళ (options.authorized_principals_command == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (options.authorized_principals_command_user == ఖాళీ) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		తిరిగి 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (అక్షరం *)ఖాళీ);
	runas_pw = getpwnam(username);
	ఒకవేళ (runas_pw == ఖాళీ) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}

	/* Turn the command into an argument vector */
	ఒకవేళ (argv_విభజించు(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ca_fp = sshkey_fingerprint(cert->signature_కీలకం,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ) {
		error_f("sshkey_fingerprint failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((కీలకం_fp = sshkey_fingerprint(కీలకం,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ) {
		error_f("sshkey_fingerprint failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_గమ్యం_base64(cert->signature_కీలకం, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_గమ్యం_base64(కీలకం, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		వెళ్ళు బహిర్గతం;
	}
	snprintf(serial_s, పరిమాణం(serial_s), "%llu",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)cert->serial);
	snprintf(uidstr, పరిమాణం(uidstr), "%llu",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)user_pw->pw_uid);
	కొరకు (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(కీలకం),
		    "T", sshkey_ssh_name(cert->signature_కీలకం),
		    "f", కీలకం_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->కీలకం_id,
		    "s", serial_s,
		    (అక్షరం *)ఖాళీ);
		ఒకవేళ (tmp == ఖాళీ)
			fatal_f("percent_expand failed");
		విడుదల(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	ఒకవేళ ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		వెళ్ళు బహిర్గతం;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = ఖాళీ;

	ఒకవేళ (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		వెళ్ళు బహిర్గతం;

	/* Read completed successfully */
	దొరికింది_principal = ok;
 బహిర్గతం:
	ఒకవేళ (f != ఖాళీ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	కొరకు (i = 0; i < ac; i++)
		విడుదల(av[i]);
	విడుదల(av);
	ఒకవేళ (uid_swapped)
		restore_uid();
	విడుదల(command);
	విడుదల(username);
	విడుదల(ca_fp);
	విడుదల(కీలకం_fp);
	విడుదల(catext);
	విడుదల(keytext);
	తిరిగి దొరికింది_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
స్థిర పూర్ణాంకం
user_cert_trusted_ca(నిర్మాణం passwd *pw, నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి అక్షరం *remote_ip, స్థిరరాశి అక్షరం *remote_host,
    స్థిరరాశి అక్షరం *conn_id, స్థిరరాశి అక్షరం *rdomain, నిర్మాణం sshauthopt **authoptsp)
{
	అక్షరం *ca_fp, *principals_file = ఖాళీ;
	స్థిరరాశి అక్షరం *reason;
	నిర్మాణం sshauthopt *principals_opts = ఖాళీ, *cert_opts = ఖాళీ;
	నిర్మాణం sshauthopt *final_opts = ఖాళీ;
	పూర్ణాంకం r, ret = 0, దొరికింది_principal = 0, use_authorized_principals;

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;

	ఒకవేళ (!sshkey_is_cert(కీలకం) || options.trusted_user_ca_కీలకాలు == ఖాళీ)
		తిరిగి 0;

	ఒకవేళ ((ca_fp = sshkey_fingerprint(కీలకం->cert->signature_కీలకం,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ)
		తిరిగి 0;

	ఒకవేళ ((r = sshkey_లోపల_file(కీలకం->cert->signature_కీలకం,
	    options.trusted_user_ca_కీలకాలు, 1, 0)) != 0) {
		debug2_fr(r, "CA %s %s is not listed in %s",
		    sshkey_type(కీలకం->cert->signature_కీలకం), ca_fp,
		    options.trusted_user_ca_కీలకాలు);
		వెళ్ళు బహిర్గతం;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	ఒకవేళ ((principals_file = authorized_principals_file(pw)) != ఖాళీ) {
		ఒకవేళ (సరిపోలిక_principals_file(pw, principals_file,
		    కీలకం->cert, &principals_opts))
			దొరికింది_principal = 1;
	}
	/* Try querying command if specified */
	ఒకవేళ (!దొరికింది_principal && సరిపోలిక_principals_command(pw, కీలకం,
	    conn_id, rdomain, &principals_opts))
		దొరికింది_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != ఖాళీ ||
	    options.authorized_principals_command != ఖాళీ;
	ఒకవేళ (!దొరికింది_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		వెళ్ళు fail_reason;
	}
	ఒకవేళ (use_authorized_principals && principals_opts == ఖాళీ)
		fatal_f("internal error: missing principals_opts");
	ఒకవేళ (sshkey_cert_check_authority_now(కీలకం, 0, 0,
	    use_authorized_principals ? ఖాళీ : pw->pw_name, &reason) != 0)
		వెళ్ళు fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	ఒకవేళ ((cert_opts = sshauthopt_from_cert(కీలకం)) == ఖాళీ) {
		reason = "Invalid certificate options";
		వెళ్ళు fail_reason;
	}
	ఒకవేళ (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		వెళ్ళు fail_reason;
	}
	ఒకవేళ (principals_opts == ఖాళీ) {
		final_opts = cert_opts;
		cert_opts = ఖాళీ;
	} లేకపోతే {
		ఒకవేళ (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			వెళ్ళు fail_reason;
		}
		ఒకవేళ ((final_opts = sshauthopt_విలీనం(principals_opts,
		    cert_opts, &reason)) == ఖాళీ) {
 fail_reason:
			error("Refusing certificate ID \"%s\" serial=%llu "
			    "signed by %s CA %s: %s", కీలకం->cert->కీలకం_id,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial,
			    sshkey_type(కీలకం->cert->signature_కీలకం), ca_fp,
			    reason);
			auth_debug_కూడు("Refused Certificate ID \"%s\" "
			    "serial=%llu: %s", కీలకం->cert->కీలకం_id,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial, reason);
			వెళ్ళు బహిర్గతం;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", కీలకం->cert->కీలకం_id,
	    (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial,
	    sshkey_type(కీలకం->cert->signature_కీలకం), ca_fp,
	    options.trusted_user_ca_కీలకాలు);
	ఒకవేళ (authoptsp != ఖాళీ) {
		*authoptsp = final_opts;
		final_opts = ఖాళీ;
	}
	ret = 1;
 బహిర్గతం:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	విడుదల(principals_file);
	విడుదల(ca_fp);
	తిరిగి ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
స్థిర పూర్ణాంకం
user_కీలకం_allowed2(నిర్మాణం passwd *pw, నిర్మాణం sshkey *కీలకం,
    అక్షరం *file, స్థిరరాశి అక్షరం *remote_ip, స్థిరరాశి అక్షరం *remote_host,
    నిర్మాణం sshauthopt **authoptsp)
{
	FILE *f;
	పూర్ణాంకం దొరికింది_కీలకం = 0;

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying public key file %s", file);
	ఒకవేళ ((f = auth_openkeyfile(file, pw, options.strict_modes)) != ఖాళీ) {
		దొరికింది_కీలకం = auth_check_authkeys_file(pw, f, file,
		    కీలకం, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	తిరిగి దొరికింది_కీలకం;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
స్థిర పూర్ణాంకం
user_కీలకం_command_allowed2(నిర్మాణం passwd *user_pw, నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి అక్షరం *remote_ip, స్థిరరాశి అక్షరం *remote_host,
    స్థిరరాశి అక్షరం *conn_id, స్థిరరాశి అక్షరం *rdomain, నిర్మాణం sshauthopt **authoptsp)
{
	నిర్మాణం passwd *runas_pw = ఖాళీ;
	FILE *f = ఖాళీ;
	పూర్ణాంకం r, ok, దొరికింది_కీలకం = 0;
	పూర్ణాంకం i, uid_swapped = 0, ac = 0;
	pid_t pid;
	అక్షరం *username = ఖాళీ, *కీలకం_fp = ఖాళీ, *keytext = ఖాళీ;
	అక్షరం uidstr[32], *tmp, *command = ఖాళీ, **av = ఖాళీ;
	శూన్య (*osigchld)(పూర్ణాంకం);

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;
	ఒకవేళ (options.authorized_కీలకాలు_command == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (options.authorized_కీలకాలు_command_user == ఖాళీ) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		తిరిగి 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_కీలకాలు_command_user,
	    "u", user_pw->pw_name, (అక్షరం *)ఖాళీ);
	runas_pw = getpwnam(username);
	ఒకవేళ (runas_pw == ఖాళీ) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}

	/* Prepare AuthorizedKeysCommand */
	ఒకవేళ ((కీలకం_fp = sshkey_fingerprint(కీలకం, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ఖాళీ) {
		error_f("sshkey_fingerprint failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_గమ్యం_base64(కీలకం, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		వెళ్ళు బహిర్గతం;
	}

	/* Turn the command into an argument vector */
	ఒకవేళ (argv_విభజించు(options.authorized_కీలకాలు_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_కీలకాలు_command);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_కీలకాలు_command);
		వెళ్ళు బహిర్గతం;
	}
	snprintf(uidstr, పరిమాణం(uidstr), "%llu",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)user_pw->pw_uid);
	కొరకు (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(కీలకం),
		    "f", కీలకం_fp,
		    "k", keytext,
		    (అక్షరం *)ఖాళీ);
		ఒకవేళ (tmp == ఖాళీ)
			fatal_f("percent_expand failed");
		విడుదల(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	ఒకవేళ (ac == 1) {
		av = xreallocarray(av, ac + 2, పరిమాణం(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = ఖాళీ;
		/* Fix up command too, since it is used in log messages */
		విడుదల(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	ఒకవేళ ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		వెళ్ళు బహిర్గతం;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_కీలకాలు_command, కీలకం, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = ఖాళీ;

	ఒకవేళ (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		వెళ్ళు బహిర్గతం;

	/* Read completed successfully */
	దొరికింది_కీలకం = ok;
 బహిర్గతం:
	ఒకవేళ (f != ఖాళీ)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	కొరకు (i = 0; i < ac; i++)
		విడుదల(av[i]);
	విడుదల(av);
	ఒకవేళ (uid_swapped)
		restore_uid();
	విడుదల(command);
	విడుదల(username);
	విడుదల(కీలకం_fp);
	విడుదల(keytext);
	తిరిగి దొరికింది_కీలకం;
}

/*
 * Check whether key authenticates and authorises the user.
 */
పూర్ణాంకం
user_కీలకం_allowed(నిర్మాణం ssh *ssh, నిర్మాణం passwd *pw, నిర్మాణం sshkey *కీలకం,
    పూర్ణాంకం auth_attempt, నిర్మాణం sshauthopt **authoptsp)
{
	u_int success = 0, i, j;
	అక్షరం *file = ఖాళీ, *conn_id;
	నిర్మాణం sshauthopt *opts = ఖాళీ;
	స్థిరరాశి అక్షరం *rdomain, *remote_ip, *remote_host;

	ఒకవేళ (authoptsp != ఖాళీ)
		*authoptsp = ఖాళీ;

	ఒకవేళ (auth_కీలకం_is_revoked(కీలకం))
		తిరిగి 0;
	ఒకవేళ (sshkey_is_cert(కీలకం) &&
	    auth_కీలకం_is_revoked(కీలకం->cert->signature_కీలకం))
		తిరిగి 0;

	ఒకవేళ ((rdomain = ssh_packet_rdomain_లోపల(ssh)) == ఖాళీ)
		rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);
	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_పోర్టు(ssh),
	    remote_ip, ssh_remote_పోర్టు(ssh));

	కొరకు (i = 0; !success && i < options.అంకె_authkeys_files; i++) {
		పూర్ణాంకం r;
		glob_t gl;

		ఒకవేళ (strcasecmp(options.authorized_కీలకాలు_files[i], "none") == 0)
			కొనసాగు;
		file = expand_authorized_కీలకాలు(
		    options.authorized_కీలకాలు_files[i], pw);
		temporarily_use_uid(pw);
		r = glob(file, 0, ఖాళీ, &gl);
		restore_uid();
		ఒకవేళ (r != 0) {
			ఒకవేళ (r != GLOB_NOMATCH) {
				logit_f("glob \"%s\" failed", file);
			}
			విడుదల(file);
			file = ఖాళీ;
			కొనసాగు;
		} లేకపోతే ఒకవేళ (gl.gl_pathc > గరిష్ఠ_పూర్ణాంకం) {
			fatal_f("too many glob results for \"%s\"", file);
		} లేకపోతే ఒకవేళ (gl.gl_pathc > 1) {
			debug2_f("glob \"%s\" returned %zu matches", file,
			    gl.gl_pathc);
		}
		కొరకు (j = 0; !success && j < gl.gl_pathc; j++) {
			success = user_కీలకం_allowed2(pw, కీలకం, gl.gl_pathv[j],
			    remote_ip, remote_host, &opts);
			ఒకవేళ (!success) {
				sshauthopt_free(opts);
				opts = ఖాళీ;
			}
		}
		విడుదల(file);
		file = ఖాళీ;
		globfree(&gl);
	}
	ఒకవేళ (success)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((success = user_cert_trusted_ca(pw, కీలకం, remote_ip, remote_host,
	    conn_id, rdomain, &opts)) != 0)
		వెళ్ళు బహిర్గతం;
	sshauthopt_free(opts);
	opts = ఖాళీ;

	ఒకవేళ ((success = user_కీలకం_command_allowed2(pw, కీలకం, remote_ip,
	    remote_host, conn_id, rdomain, &opts)) != 0)
		వెళ్ళు బహిర్గతం;
	sshauthopt_free(opts);
	opts = ఖాళీ;

 బహిర్గతం:
	విడుదల(conn_id);
	ఒకవేళ (success && authoptsp != ఖాళీ) {
		*authoptsp = opts;
		opts = ఖాళీ;
	}
	sshauthopt_free(opts);
	తిరిగి success;
}

Authmethod పద్ధతి_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey,
};
