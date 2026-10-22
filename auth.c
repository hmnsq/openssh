/* $OpenBSD: auth.c,v 1.165 2026/07/21 06:17:42 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/wait.h>

#అన్తర్భావ <netinet/in.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#నిర్వచితమైతే HAVE_LOGIN_H
#అన్తర్భావ <login.h>
#అయితే_ముగింపు
#నిర్వచితమైతే USE_SHADOW
#అన్తర్భావ <shadow.h>
#అయితే_ముగింపు
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <time.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "groupaccess.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "uidswap.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "loginrec.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "channels.h"

/* import */
బాహ్య ServerOptions options;
బాహ్య నిర్మాణం include_list includes;
బాహ్య నిర్మాణం sshbuf *loginmsg;
బాహ్య నిర్మాణం passwd *privsep_pw;
బాహ్య నిర్మాణం sshauthopt *auth_opts;

/* Debugging messages */
స్థిర నిర్మాణం sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
పూర్ణాంకం
allowed_user(నిర్మాణం ssh *ssh, నిర్మాణం passwd * pw)
{
	నిర్మాణం stat st;
	స్థిరరాశి అక్షరం *hostname = ఖాళీ, *ipaddr = ఖాళీ;
	పూర్ణాంకం r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	ఒకవేళ (!pw || !pw->pw_name)
		తిరిగి 0;

	ఒకవేళ (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		తిరిగి 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	ఒకవేళ (options.chroot_directory == ఖాళీ ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		అక్షరం *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		ఒకవేళ (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			విడుదల(shell);
			తిరిగి 0;
		}
		ఒకవేళ (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			విడుదల(shell);
			తిరిగి 0;
		}
		విడుదల(shell);
	}

	ఒకవేళ (options.అంకె_deny_users > 0 || options.అంకె_allow_users > 0 ||
	    options.అంకె_deny_groups > 0 || options.అంకె_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	ఒకవేళ (options.అంకె_deny_users > 0) {
		కొరకు (i = 0; i < options.అంకె_deny_users; i++) {
			r = సరిపోలిక_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			ఒకవేళ (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} లేకపోతే ఒకవేళ (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				తిరిగి 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	ఒకవేళ (options.అంకె_allow_users > 0) {
		కొరకు (i = 0; i < options.అంకె_allow_users; i++) {
			r = సరిపోలిక_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			ఒకవేళ (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} లేకపోతే ఒకవేళ (r == 1)
				ఆపు;
		}
		/* i < options.num_allow_users iff we break for loop */
		ఒకవేళ (i >= options.అంకె_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			తిరిగి 0;
		}
	}
	ఒకవేళ (options.అంకె_deny_groups > 0 || options.అంకె_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		ఒకవేళ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			తిరిగి 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		ఒకవేళ (options.అంకె_deny_groups > 0)
			ఒకవేళ (ga_సరిపోలిక(options.deny_groups,
			    options.అంకె_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				తిరిగి 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		ఒకవేళ (options.అంకె_allow_groups > 0)
			ఒకవేళ (!ga_సరిపోలిక(options.allow_groups,
			    options.అంకె_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				తిరిగి 0;
			}
		ga_free();
	}

#నిర్వచితమైతే CUSTOM_SYS_AUTH_ALLOWED_USER
	ఒకవేళ (!sys_auth_allowed_user(pw, loginmsg))
		తిరిగి 0;
#అయితే_ముగింపు

	/* We found no reason not to let this user try to log on... */
	తిరిగి 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
స్థిర అక్షరం *
format_పద్ధతి_కీలకం(Authctxt *authctxt)
{
	స్థిరరాశి నిర్మాణం sshkey *కీలకం = authctxt->auth_పద్ధతి_కీలకం;
	స్థిరరాశి అక్షరం *methinfo = authctxt->auth_పద్ధతి_info;
	అక్షరం *fp, *cafp, *ret = ఖాళీ;

	ఒకవేళ (కీలకం == ఖాళీ)
		తిరిగి ఖాళీ;

	ఒకవేళ (sshkey_is_cert(కీలకం)) {
		fp = sshkey_fingerprint(కీలకం,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(కీలకం->cert->signature_కీలకం,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(కీలకం), fp == ఖాళీ ? "(null)" : fp,
		    కీలకం->cert->కీలకం_id,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial,
		    sshkey_type(కీలకం->cert->signature_కీలకం),
		    cafp == ఖాళీ ? "(null)" : cafp,
		    methinfo == ఖాళీ ? "" : ", ",
		    methinfo == ఖాళీ ? "" : methinfo);
		విడుదల(fp);
		విడుదల(cafp);
	} లేకపోతే {
		fp = sshkey_fingerprint(కీలకం, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(కీలకం),
		    fp == ఖాళీ ? "(null)" : fp,
		    methinfo == ఖాళీ ? "" : ", ",
		    methinfo == ఖాళీ ? "" : methinfo);
		విడుదల(fp);
	}
	తిరిగి ret;
}

శూన్య
auth_log(నిర్మాణం ssh *ssh, పూర్ణాంకం authenticated, పూర్ణాంకం partial,
    స్థిరరాశి అక్షరం *పద్ధతి, స్థిరరాశి అక్షరం *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	పూర్ణాంకం level = SYSLOG_LEVEL_VERBOSE;
	స్థిరరాశి అక్షరం *authmsg;
	అక్షరం *extra = ఖాళీ;

	ఒకవేళ (!mm_is_monitor() && !authctxt->postponed)
		తిరిగి;

	/* Raise logging level */
	ఒకవేళ (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(పద్ధతి, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	ఒకవేళ (authctxt->postponed)
		authmsg = "Postponed";
	లేకపోతే ఒకవేళ (partial)
		authmsg = "Partial";
	లేకపోతే
		authmsg = authenticated ? "Accepted" : "Failed";

	ఒకవేళ ((extra = format_పద్ధతి_కీలకం(authctxt)) == ఖాళీ) {
		ఒకవేళ (authctxt->auth_పద్ధతి_info != ఖాళీ)
			extra = xstrdup(authctxt->auth_పద్ధతి_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    పద్ధతి,
	    submethod != ఖాళీ ? "/" : "", submethod == ఖాళీ ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_పోర్టు(ssh),
	    extra != ఖాళీ ? ": " : "",
	    extra != ఖాళీ ? extra : "");

	విడుదల(extra);

#ఒకవేళ defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	ఒకవేళ (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		ఒకవేళ (strcmp(పద్ధతి, "password") == 0 ||
		    అక్షరశ్రేణి_పోలిక(పద్ధతి, "keyboard-interactive", 20) == 0 ||
		    strcmp(పద్ధతి, "challenge-response") == 0)
			రికార్డు_failed_login(ssh, authctxt->user,
			    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
# endif
# ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, audit_classify_auth(పద్ధతి));
# endif
	}
#అయితే_ముగింపు
#ఒకవేళ defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	ఒకవేళ (authenticated)
		sys_auth_రికార్డు_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#అయితే_ముగింపు
}

శూన్య
auth_maxtries_exceeded(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	error("maximum authentication attempts exceeded for "
	    "%s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_పోర్టు(ssh));
	ssh_packet_disconnect(ssh, "Too many authentication failures");
	/* NOTREACHED */
}

/*
 * Check whether root logins are disallowed.
 */
పూర్ణాంకం
auth_మూలం_allowed(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *పద్ధతి)
{
	ఎంపిక (options.permit_మూలం_login) {
	స్థితి PERMIT_YES:
		తిరిగి 1;
	స్థితి PERMIT_NO_PASSWD:
		ఒకవేళ (strcmp(పద్ధతి, "publickey") == 0 ||
		    strcmp(పద్ధతి, "hostbased") == 0 ||
		    strcmp(పద్ధతి, "gssapi-with-mic") == 0)
			తిరిగి 1;
		ఆపు;
	స్థితి PERMIT_FORCED_ONLY:
		ఒకవేళ (auth_opts->force_command != ఖాళీ) {
			logit("Root login accepted for forced command.");
			తిరిగి 1;
		}
		ఆపు;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
	తిరిగి 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
అక్షరం *
expand_authorized_కీలకాలు(స్థిరరాశి అక్షరం *filename, నిర్మాణం passwd *pw)
{
	అక్షరం *file, uidstr[32], ret[PATH_MAX];
	పూర్ణాంకం i;

	snprintf(uidstr, పరిమాణం(uidstr), "%llu",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (అక్షరం *)ఖాళీ);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	ఒకవేళ (మార్గం_absolute(file))
		తిరిగి (file);

	i = snprintf(ret, పరిమాణం(ret), "%s/%s", pw->pw_dir, file);
	ఒకవేళ (i < 0 || (కొలత_t)i >= పరిమాణం(ret))
		fatal("expand_authorized_keys: path too long");
	విడుదల(file);
	తిరిగి (xstrdup(ret));
}

అక్షరం *
authorized_principals_file(నిర్మాణం passwd *pw)
{
	ఒకవేళ (options.authorized_principals_file == ఖాళీ)
		తిరిగి ఖాళీ;
	తిరిగి expand_authorized_కీలకాలు(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
Host_స్థితి
check_కీలకం_లోపల_hostfiles(నిర్మాణం passwd *pw, నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *host,
    స్థిరరాశి అక్షరం *sysfile, స్థిరరాశి అక్షరం *userfile)
{
	అక్షరం *user_hostfile;
	నిర్మాణం stat st;
	Host_స్థితి host_స్థితి;
	నిర్మాణం hostkeys *hostkeys;
	స్థిరరాశి నిర్మాణం hostkey_నమోదు *దొరికింది;

	hostkeys = init_hostkeys();
	ఎక్కించు_hostkeys(hostkeys, host, sysfile, 0);
	ఒకవేళ (userfile != ఖాళీ) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		ఒకవేళ (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_కూడు("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} లేకపోతే {
			temporarily_use_uid(pw);
			ఎక్కించు_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		విడుదల(user_hostfile);
	}
	host_స్థితి = check_కీలకం_లోపల_hostkeys(hostkeys, కీలకం, &దొరికింది);
	ఒకవేళ (host_స్థితి == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	లేకపోతే ఒకవేళ (host_స్థితి == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    దొరికింది->host, దొరికింది->file, దొరికింది->పంక్తి);
	లేకపోతే
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	తిరిగి host_స్థితి;
}

నిర్మాణం passwd *
getpwnamallow(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *user)
{
#నిర్వచితమైతే HAVE_LOGIN_CAP
	బాహ్య login_cap_t *lc;
#నిర్వచితమైతే HAVE_AUTH_HOSTOK
	స్థిరరాశి అక్షరం *from_host, *from_ip;
#అయితే_ముగింపు
#నిర్వచితమైతే BSD_AUTH
	auth_session_t *as;
#అయితే_ముగింపు
#అయితే_ముగింపు
	నిర్మాణం passwd *pw;
	నిర్మాణం connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == ఖాళీ;
	parse_server_సరిపోలిక_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	కొరకు (i = 0; i < options.అంకె_log_verbose; i++)
		log_verbose_కూడు(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_సమితి_rekey_limits(ssh, options.rekey_హద్దు,
	    options.rekey_interval);

#ఒకవేళ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#అయితే_ముగింపు

	pw = getpwnam(user);

#ఒకవేళ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#అయితే_ముగింపు
	ఒకవేళ (pw == ఖాళీ) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh));
#నిర్వచితమైతే CUSTOM_FAILED_LOGIN
		రికార్డు_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#అయితే_ముగింపు
#నిర్వచితమైతే SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#అయితే_ముగింపు /* SSH_AUDIT_EVENTS */
		తిరిగి (ఖాళీ);
	}
	ఒకవేళ (!allowed_user(ssh, pw))
		తిరిగి (ఖాళీ);
#నిర్వచితమైతే HAVE_LOGIN_CAP
	ఒకవేళ ((lc = login_getpwclass(pw)) == ఖాళీ) {
		debug("unable to get login class: %s", user);
		తిరిగి (ఖాళీ);
	}
#నిర్వచితమైతే HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	ఒకవేళ (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		తిరిగి (ఖాళీ);
	}
#అయితే_ముగింపు /* HAVE_AUTH_HOSTOK */
#నిర్వచితమైతే HAVE_AUTH_TIMEOK
	ఒకవేళ (!auth_timeok(lc, time(ఖాళీ))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		తిరిగి (ఖాళీ);
	}
#అయితే_ముగింపు /* HAVE_AUTH_TIMEOK */
#నిర్వచితమైతే BSD_AUTH
	ఒకవేళ ((as = auth_open()) == ఖాళీ || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = ఖాళీ;
	}
	ఒకవేళ (as != ఖాళీ)
		auth_close(as);
#అయితే_ముగింపు
#అయితే_ముగింపు
	ఒకవేళ (pw != ఖాళీ)
		తిరిగి (pwcopy(pw));
	తిరిగి (ఖాళీ);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
పూర్ణాంకం
auth_కీలకం_is_revoked(నిర్మాణం sshkey *కీలకం)
{
	అక్షరం *fp = ఖాళీ;
	u_int i;
	పూర్ణాంకం r;

	ఒకవేళ (options.అంకె_revoked_కీలకాలు_files == 0)
		తిరిగి 0;
	ఒకవేళ ((fp = sshkey_fingerprint(కీలకం, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		వెళ్ళు బహిర్గతం;
	}

	కొరకు (i = 0; i < options.అంకె_revoked_కీలకాలు_files; i++) {
		r = sshkey_check_revoked(కీలకం, options.revoked_కీలకాలు_files[i]);
		ఎంపిక (r) {
		స్థితి 0:
			ఆపు; /* not revoked */
		స్థితి SSH_ERR_కీలకం_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(కీలకం), fp,
			    options.revoked_కీలకాలు_files[i]);
			వెళ్ళు బహిర్గతం;
		అప్రమేయ:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(కీలకం), fp,
			    options.revoked_కీలకాలు_files[i]);
			వెళ్ళు బహిర్గతం;
		}
	}

	/* Success */
	r = 0;

 బహిర్గతం:
	విడుదల(fp);
	తిరిగి r == 0 ? 0 : 1;
}

శూన్య
auth_debug_కూడు(స్థిరరాశి అక్షరం *fmt,...)
{
	అక్షరం buf[1024];
	va_list వాదనలు;
	పూర్ణాంకం r;

	va_start(వాదనలు, fmt);
	vsnprintf(buf, పరిమాణం(buf), fmt, వాదనలు);
	va_end(వాదనలు);
	debug3("%s", buf);
	ఒకవేళ (auth_debug != ఖాళీ)
		ఒకవేళ ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

శూన్య
auth_debug_send(నిర్మాణం ssh *ssh)
{
	అక్షరం *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ (auth_debug == ఖాళీ)
		తిరిగి;
	అయితే (sshbuf_len(auth_debug) != 0) {
		ఒకవేళ ((r = sshbuf_get_cstring(auth_debug, &సందేశం, ఖాళీ)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", సందేశం);
		విడుదల(సందేశం);
	}
}

శూన్య
auth_debug_reset(శూన్య)
{
	ఒకవేళ (auth_debug != ఖాళీ)
		sshbuf_reset(auth_debug);
	లేకపోతే ఒకవేళ ((auth_debug = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
}

నిర్మాణం passwd *
fakepw(శూన్య)
{
	స్థిర పూర్ణాంకం పూర్తి = 0;
	స్థిర నిర్మాణం passwd fake;
	స్థిరరాశి అక్షరం hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	అక్షరం *cp;

	ఒకవేళ (పూర్తి)
		తిరిగి (&fake);

	memset(&fake, 0, పరిమాణం(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	కొరకు (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_ఏకరీతి(పరిమాణం(hashchars) - 1)];
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#అయితే_ముగింపు
	fake.pw_uid = privsep_pw == ఖాళీ ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == ఖాళీ ? (gid_t)-1 : privsep_pw->pw_gid;
#నిర్వచితమైతే HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#అయితే_ముగింపు
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	పూర్తి = 1;

	తిరిగి (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

స్థిరరాశి అక్షరం *
auth_get_canonical_hostname(నిర్మాణం ssh *ssh, పూర్ణాంకం use_dns)
{
	స్థిర అక్షరం *dnsname;

	ఒకవేళ (!use_dns)
		తిరిగి ssh_remote_ipaddr(ssh);
	ఒకవేళ (dnsname != ఖాళీ)
		తిరిగి dnsname;
	dnsname = ssh_remote_hostname(ssh);
	తిరిగి dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
శూన్య
auth_log_authopts(స్థిరరాశి అక్షరం *loc, స్థిరరాశి నిర్మాణం sshauthopt *opts, పూర్ణాంకం do_remote)
{
	పూర్ణాంకం do_env = options.permit_user_env && opts->nenv > 0;
	పూర్ణాంకం do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	పూర్ణాంకం do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	కొలత_t i;
	అక్షరం సందేశం[1024], buf[64];

	snprintf(buf, పరిమాణం(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(సందేశం, పరిమాణం(సందేశం), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == ఖాళీ ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_పోర్టు_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == ఖాళీ ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, సందేశం);
	ఒకవేళ (do_remote)
		auth_debug_కూడు("%s: %s", loc, సందేశం);

	ఒకవేళ (options.permit_user_env) {
		కొరకు (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			ఒకవేళ (do_remote) {
				auth_debug_కూడు("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	ఒకవేళ (opts->valid_before != 0) {
		format_absolute_సమయం(opts->valid_before, buf, పరిమాణం(buf));
		debug("%s: expires at %s", loc, buf);
	}
	ఒకవేళ (opts->cert_principals != ఖాళీ) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	ఒకవేళ (opts->force_command != ఖాళీ)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	ఒకవేళ (do_permitopen) {
		కొరకు (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	ఒకవేళ (do_permitlisten) {
		కొరకు (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
పూర్ణాంకం
auth_activate_options(నిర్మాణం ssh *ssh, నిర్మాణం sshauthopt *opts)
{
	నిర్మాణం sshauthopt *old = auth_opts;
	స్థిరరాశి అక్షరం *emsg = ఖాళీ;

	debug_f("setting new authentication options");
	ఒకవేళ ((auth_opts = sshauthopt_విలీనం(old, opts, &emsg)) == ఖాళీ) {
		error("Inconsistent authentication options: %s", emsg);
		తిరిగి -1;
	}
	sshauthopt_free(old);
	తిరిగి 0;
}

/* Disable forwarding, etc for the session */
శూన్య
auth_restrict_session(నిర్మాణం ssh *ssh)
{
	నిర్మాణం sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	ఒకవేళ ((restricted = sshauthopt_new()) == ఖాళీ)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	ఒకవేళ (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
