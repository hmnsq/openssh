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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ifdef HAVE_LOGIN_H
#ଅନ୍ତର୍ଭାଵ <login.h>
#endif
#ifdef USE_SHADOW
#ଅନ୍ତର୍ଭାଵ <shadow.h>
#endif
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <time.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "groupaccess.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "loginrec.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"

/* import */
ବାହ୍ୟ ServerOptions options;
ବାହ୍ୟ ସଂରଚନା include_list includes;
ବାହ୍ୟ ସଂରଚନା sshbuf *loginmsg;
ବାହ୍ୟ ସଂରଚନା passwd *privsep_pw;
ବାହ୍ୟ ସଂରଚନା sshauthopt *auth_opts;

/* Debugging messages */
ସ୍ଥିର ସଂରଚନା sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
allowed_user(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd * pw)
{
	ସଂରଚନା stat st;
	ଅଚଳ ଅକ୍ଷର *hostname = ଖାଲି, *ipaddr = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	ଯଦି (!pw || !pw->pw_name)
		ଫେରନ୍ତୁ 0;

	ଯଦି (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		ଫେରନ୍ତୁ 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	ଯଦି (options.chroot_directory == ଖାଲି ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		ଅକ୍ଷର *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		ଯଦି (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			ମୁକ୍ତ(shell);
			ଫେରନ୍ତୁ 0;
		}
		ଯଦି (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			ମୁକ୍ତ(shell);
			ଫେରନ୍ତୁ 0;
		}
		ମୁକ୍ତ(shell);
	}

	ଯଦି (options.ଅଙ୍କ_deny_users > 0 || options.ଅଙ୍କ_allow_users > 0 ||
	    options.ଅଙ୍କ_deny_groups > 0 || options.ଅଙ୍କ_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	ଯଦି (options.ଅଙ୍କ_deny_users > 0) {
		ପାଇଁ (i = 0; i < options.ଅଙ୍କ_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			ଯଦି (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} ଅନ୍ୟଥା ଯଦି (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				ଫେରନ୍ତୁ 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	ଯଦି (options.ଅଙ୍କ_allow_users > 0) {
		ପାଇଁ (i = 0; i < options.ଅଙ୍କ_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			ଯଦି (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} ଅନ୍ୟଥା ଯଦି (r == 1)
				ଭାଙ୍ଗ;
		}
		/* i < options.num_allow_users iff we break for loop */
		ଯଦି (i >= options.ଅଙ୍କ_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			ଫେରନ୍ତୁ 0;
		}
	}
	ଯଦି (options.ଅଙ୍କ_deny_groups > 0 || options.ଅଙ୍କ_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		ଯଦି (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			ଫେରନ୍ତୁ 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		ଯଦି (options.ଅଙ୍କ_deny_groups > 0)
			ଯଦି (ga_match(options.deny_groups,
			    options.ଅଙ୍କ_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				ଫେରନ୍ତୁ 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		ଯଦି (options.ଅଙ୍କ_allow_groups > 0)
			ଯଦି (!ga_match(options.allow_groups,
			    options.ଅଙ୍କ_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				ଫେରନ୍ତୁ 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	ଯଦି (!sys_auth_allowed_user(pw, loginmsg))
		ଫେରନ୍ତୁ 0;
#endif

	/* We found no reason not to let this user try to log on... */
	ଫେରନ୍ତୁ 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
ସ୍ଥିର ଅକ୍ଷର *
format_method_ଚାବି(Authctxt *authctxt)
{
	ଅଚଳ ସଂରଚନା sshkey *ଚାବି = authctxt->auth_method_ଚାବି;
	ଅଚଳ ଅକ୍ଷର *methinfo = authctxt->auth_method_info;
	ଅକ୍ଷର *fp, *cafp, *ret = ଖାଲି;

	ଯଦି (ଚାବି == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	ଯଦି (sshkey_is_cert(ଚାବି)) {
		fp = sshkey_fingerprint(ଚାବି,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(ଚାବି->cert->signature_ଚାବି,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(ଚାବି), fp == ଖାଲି ? "(null)" : fp,
		    ଚାବି->cert->ଚାବି_id,
		    (unsigned long long)ଚାବି->cert->serial,
		    sshkey_type(ଚାବି->cert->signature_ଚାବି),
		    cafp == ଖାଲି ? "(null)" : cafp,
		    methinfo == ଖାଲି ? "" : ", ",
		    methinfo == ଖାଲି ? "" : methinfo);
		ମୁକ୍ତ(fp);
		ମୁକ୍ତ(cafp);
	} ଅନ୍ୟଥା {
		fp = sshkey_fingerprint(ଚାବି, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(ଚାବି),
		    fp == ଖାଲି ? "(null)" : fp,
		    methinfo == ଖାଲି ? "" : ", ",
		    methinfo == ଖାଲି ? "" : methinfo);
		ମୁକ୍ତ(fp);
	}
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
auth_log(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା authenticated, ପୂର୍ଣ୍ଣସଂଖ୍ୟା partial,
    ଅଚଳ ଅକ୍ଷର *method, ଅଚଳ ଅକ୍ଷର *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା level = SYSLOG_LEVEL_VERBOSE;
	ଅଚଳ ଅକ୍ଷର *authmsg;
	ଅକ୍ଷର *extra = ଖାଲି;

	ଯଦି (!mm_is_monitor() && !authctxt->postponed)
		ଫେରନ୍ତୁ;

	/* Raise logging level */
	ଯଦି (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	ଯଦି (authctxt->postponed)
		authmsg = "Postponed";
	ଅନ୍ୟଥା ଯଦି (partial)
		authmsg = "Partial";
	ଅନ୍ୟଥା
		authmsg = authenticated ? "Accepted" : "Failed";

	ଯଦି ((extra = format_method_ଚାବି(authctxt)) == ଖାଲି) {
		ଯଦି (authctxt->auth_method_info != ଖାଲି)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != ଖାଲି ? "/" : "", submethod == ଖାଲି ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != ଖାଲି ? ": " : "",
	    extra != ଖାଲି ? extra : "");

	ମୁକ୍ତ(extra);

#ଯଦି defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	ଯଦି (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		ଯଦି (strcmp(method, "password") == 0 ||
		    strncmp(method, "keyboard-interactive", 20) == 0 ||
		    strcmp(method, "challenge-response") == 0)
			record_failed_login(ssh, authctxt->user,
			    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
# endif
# ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, audit_classify_auth(method));
# endif
	}
#endif
#ଯଦି defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	ଯଦି (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

ଶୂନ୍ୟ
auth_maxtries_exceeded(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	error("maximum authentication attempts exceeded for "
	    "%s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh));
	ssh_packet_disconnect(ssh, "Too many authentication failures");
	/* NOTREACHED */
}

/*
 * Check whether root logins are disallowed.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_ମୂଳ_allowed(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *method)
{
	ବାଛ (options.permit_ମୂଳ_login) {
	ସ୍ଥିତି PERMIT_YES:
		ଫେରନ୍ତୁ 1;
	ସ୍ଥିତି PERMIT_NO_PASSWD:
		ଯଦି (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			ଫେରନ୍ତୁ 1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି PERMIT_FORCED_ONLY:
		ଯଦି (auth_opts->force_command != ଖାଲି) {
			logit("Root login accepted for forced command.");
			ଫେରନ୍ତୁ 1;
		}
		ଭାଙ୍ଗ;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	ଫେରନ୍ତୁ 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
ଅକ୍ଷର *
expand_authorized_ଚାବିଗୁଡ଼ିକ(ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା passwd *pw)
{
	ଅକ୍ଷର *file, uidstr[32], ret[PATH_MAX];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	snprintf(uidstr, ଆକାର(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (ଅକ୍ଷର *)ଖାଲି);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	ଯଦି (path_absolute(file))
		ଫେରନ୍ତୁ (file);

	i = snprintf(ret, ଆକାର(ret), "%s/%s", pw->pw_dir, file);
	ଯଦି (i < 0 || (size_t)i >= ଆକାର(ret))
		fatal("expand_authorized_keys: path too long");
	ମୁକ୍ତ(file);
	ଫେରନ୍ତୁ (xstrdup(ret));
}

ଅକ୍ଷର *
authorized_principals_file(ସଂରଚନା passwd *pw)
{
	ଯଦି (options.authorized_principals_file == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଫେରନ୍ତୁ expand_authorized_ଚାବିଗୁଡ଼ିକ(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_ଚାବି_in_hostfiles(ସଂରଚନା passwd *pw, ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *host,
    ଅଚଳ ଅକ୍ଷର *sysfile, ଅଚଳ ଅକ୍ଷର *userfile)
{
	ଅକ୍ଷର *user_hostfile;
	ସଂରଚନା stat st;
	HostStatus host_status;
	ସଂରଚନା hostkeys *hostkeys;
	ଅଚଳ ସଂରଚନା hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	ଯଦି (userfile != ଖାଲି) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		ଯଦି (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} ଅନ୍ୟଥା {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		ମୁକ୍ତ(user_hostfile);
	}
	host_status = check_ଚାବି_in_hostkeys(hostkeys, ଚାବି, &found);
	ଯଦି (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	ଅନ୍ୟଥା ଯଦି (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->ଧାଡ଼ି);
	ଅନ୍ୟଥା
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	ଫେରନ୍ତୁ host_status;
}

ସଂରଚନା passwd *
getpwnamallow(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *user)
{
#ifdef HAVE_LOGIN_CAP
	ବାହ୍ୟ login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	ଅଚଳ ଅକ୍ଷର *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	ସଂରଚନା passwd *pw;
	ସଂରଚନା connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == ଖାଲି;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#ଯଦି defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#ଯଦି defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	ଯଦି (pw == ଖାଲି) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		ଫେରନ୍ତୁ (ଖାଲି);
	}
	ଯଦି (!allowed_user(ssh, pw))
		ଫେରନ୍ତୁ (ଖାଲି);
#ifdef HAVE_LOGIN_CAP
	ଯଦି ((lc = login_getpwclass(pw)) == ଖାଲି) {
		debug("unable to get login class: %s", user);
		ଫେରନ୍ତୁ (ଖାଲି);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	ଯଦି (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		ଫେରନ୍ତୁ (ଖାଲି);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	ଯଦି (!auth_timeok(lc, time(ଖାଲି))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		ଫେରନ୍ତୁ (ଖାଲି);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	ଯଦି ((as = auth_open()) == ଖାଲି || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = ଖାଲି;
	}
	ଯଦି (as != ଖାଲି)
		auth_close(as);
#endif
#endif
	ଯଦି (pw != ଖାଲି)
		ଫେରନ୍ତୁ (pwcopy(pw));
	ଫେରନ୍ତୁ (ଖାଲି);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_ଚାବି_is_revoked(ସଂରଚନା sshkey *ଚାବି)
{
	ଅକ୍ଷର *fp = ଖାଲି;
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (options.ଅଙ୍କ_revoked_ଚାବିଗୁଡ଼ିକ_files == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((fp = sshkey_fingerprint(ଚାବି, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		ଯାଅ out;
	}

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_revoked_ଚାବିଗୁଡ଼ିକ_files; i++) {
		r = sshkey_check_revoked(ଚାବି, options.revoked_ଚାବିଗୁଡ଼ିକ_files[i]);
		ବାଛ (r) {
		ସ୍ଥିତି 0:
			ଭାଙ୍ଗ; /* not revoked */
		ସ୍ଥିତି SSH_ERR_ଚାବି_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(ଚାବି), fp,
			    options.revoked_ଚାବିଗୁଡ଼ିକ_files[i]);
			ଯାଅ out;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(ଚାବି), fp,
			    options.revoked_ଚାବିଗୁଡ଼ିକ_files[i]);
			ଯାଅ out;
		}
	}

	/* Success */
	r = 0;

 out:
	ମୁକ୍ତ(fp);
	ଫେରନ୍ତୁ r == 0 ? 0 : 1;
}

ଶୂନ୍ୟ
auth_debug_add(ଅଚଳ ଅକ୍ଷର *fmt,...)
{
	ଅକ୍ଷର buf[1024];
	va_list args;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	va_start(args, fmt);
	vsnprintf(buf, ଆକାର(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	ଯଦି (auth_debug != ଖାଲି)
		ଯଦି ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

ଶୂନ୍ୟ
auth_debug_send(ସଂରଚନା ssh *ssh)
{
	ଅକ୍ଷର *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (auth_debug == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯେତେବେଳେ (sshbuf_len(auth_debug) != 0) {
		ଯଦି ((r = sshbuf_get_cstring(auth_debug, &ସନ୍ଦେଶ, ଖାଲି)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", ସନ୍ଦେଶ);
		ମୁକ୍ତ(ସନ୍ଦେଶ);
	}
}

ଶୂନ୍ୟ
auth_debug_reset(ଶୂନ୍ୟ)
{
	ଯଦି (auth_debug != ଖାଲି)
		sshbuf_reset(auth_debug);
	ଅନ୍ୟଥା ଯଦି ((auth_debug = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
}

ସଂରଚନା passwd *
fakepw(ଶୂନ୍ୟ)
{
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା done = 0;
	ସ୍ଥିର ସଂରଚନା passwd fake;
	ଅଚଳ ଅକ୍ଷର hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	ଅକ୍ଷର *cp;

	ଯଦି (done)
		ଫେରନ୍ତୁ (&fake);

	memset(&fake, 0, ଆକାର(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	ପାଇଁ (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(ଆକାର(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == ଖାଲି ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == ଖାଲି ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	ଫେରନ୍ତୁ (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ଅଚଳ ଅକ୍ଷର *
auth_get_canonical_hostname(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା use_dns)
{
	ସ୍ଥିର ଅକ୍ଷର *dnsname;

	ଯଦି (!use_dns)
		ଫେରନ୍ତୁ ssh_remote_ipaddr(ssh);
	ଯଦି (dnsname != ଖାଲି)
		ଫେରନ୍ତୁ dnsname;
	dnsname = ssh_remote_hostname(ssh);
	ଫେରନ୍ତୁ dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
ଶୂନ୍ୟ
auth_log_authopts(ଅଚଳ ଅକ୍ଷର *loc, ଅଚଳ ସଂରଚନା sshauthopt *opts, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_remote)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_env = options.permit_user_env && opts->nenv > 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	ଅକ୍ଷର ସନ୍ଦେଶ[1024], buf[64];

	snprintf(buf, ଆକାର(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(ସନ୍ଦେଶ, ଆକାର(ସନ୍ଦେଶ), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == ଖାଲି ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == ଖାଲି ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, ସନ୍ଦେଶ);
	ଯଦି (do_remote)
		auth_debug_add("%s: %s", loc, ସନ୍ଦେଶ);

	ଯଦି (options.permit_user_env) {
		ପାଇଁ (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			ଯଦି (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	ଯଦି (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, ଆକାର(buf));
		debug("%s: expires at %s", loc, buf);
	}
	ଯଦି (opts->cert_principals != ଖାଲି) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	ଯଦି (opts->force_command != ଖାଲି)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	ଯଦି (do_permitopen) {
		ପାଇଁ (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	ଯଦି (do_permitlisten) {
		ପାଇଁ (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
auth_activate_options(ସଂରଚନା ssh *ssh, ସଂରଚନା sshauthopt *opts)
{
	ସଂରଚନା sshauthopt *old = auth_opts;
	ଅଚଳ ଅକ୍ଷର *emsg = ଖାଲି;

	debug_f("setting new authentication options");
	ଯଦି ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == ଖାଲି) {
		error("Inconsistent authentication options: %s", emsg);
		ଫେରନ୍ତୁ -1;
	}
	sshauthopt_free(old);
	ଫେରନ୍ତୁ 0;
}

/* Disable forwarding, etc for the session */
ଶୂନ୍ୟ
auth_restrict_session(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	ଯଦି ((restricted = sshauthopt_new()) == ଖାଲି)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	ଯଦି (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
