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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ifdef HAVE_LOGIN_H
#ಅನ್ತರ್ಭಾವ <login.h>
#endif
#ifdef USE_SHADOW
#ಅನ್ತರ್ಭಾವ <shadow.h>
#endif
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <time.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "groupaccess.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "loginrec.h"
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "channels.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ಸಂರಚನಾ include_list includes;
ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *loginmsg;
ಬಾಹ್ಯ ಸಂರಚನಾ passwd *privsep_pw;
ಬಾಹ್ಯ ಸಂರಚನಾ sshauthopt *auth_opts;

/* Debugging messages */
ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
ಪೂರ್ಣಾಙ್ಕ
allowed_user(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd * pw)
{
	ಸಂರಚನಾ stat st;
	ಧ್ರುವ ವರ್ಣ *hostname = ರಿಕ್ತ, *ipaddr = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	ಯದಿ (!pw || !pw->pw_name)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಯದಿ (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	ಯದಿ (options.chroot_directory == ರಿಕ್ತ ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		ವರ್ಣ *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		ಯದಿ (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			ಮುಕ್ತ(shell);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		ಯದಿ (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			ಮುಕ್ತ(shell);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		ಮುಕ್ತ(shell);
	}

	ಯದಿ (options.ಅಂಕೆ_deny_users > 0 || options.ಅಂಕೆ_allow_users > 0 ||
	    options.ಅಂಕೆ_deny_groups > 0 || options.ಅಂಕೆ_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	ಯದಿ (options.ಅಂಕೆ_deny_users > 0) {
		ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			ಯದಿ (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} ಅನ್ಯಥಾ ಯದಿ (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				ಪ್ರತ್ಯಾಗಮ 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	ಯದಿ (options.ಅಂಕೆ_allow_users > 0) {
		ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			ಯದಿ (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} ಅನ್ಯಥಾ ಯದಿ (r == 1)
				ಭಙ್ಗ;
		}
		/* i < options.num_allow_users iff we break for loop */
		ಯದಿ (i >= options.ಅಂಕೆ_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}
	ಯದಿ (options.ಅಂಕೆ_deny_groups > 0 || options.ಅಂಕೆ_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		ಯದಿ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			ಪ್ರತ್ಯಾಗಮ 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		ಯದಿ (options.ಅಂಕೆ_deny_groups > 0)
			ಯದಿ (ga_match(options.deny_groups,
			    options.ಅಂಕೆ_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				ಪ್ರತ್ಯಾಗಮ 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		ಯದಿ (options.ಅಂಕೆ_allow_groups > 0)
			ಯದಿ (!ga_match(options.allow_groups,
			    options.ಅಂಕೆ_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				ಪ್ರತ್ಯಾಗಮ 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	ಯದಿ (!sys_auth_allowed_user(pw, loginmsg))
		ಪ್ರತ್ಯಾಗಮ 0;
#endif

	/* We found no reason not to let this user try to log on... */
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
ಸ್ಥಿರ ವರ್ಣ *
format_method_ಕೀಲಿ(Authctxt *authctxt)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ = authctxt->auth_method_ಕೀಲಿ;
	ಧ್ರುವ ವರ್ಣ *methinfo = authctxt->auth_method_info;
	ವರ್ಣ *fp, *cafp, *ret = ರಿಕ್ತ;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	ಯದಿ (sshkey_is_cert(ಕೀಲಿ)) {
		fp = sshkey_fingerprint(ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(ಕೀಲಿ), fp == ರಿಕ್ತ ? "(null)" : fp,
		    ಕೀಲಿ->cert->ಕೀಲಿ_id,
		    (unsigned long long)ಕೀಲಿ->cert->serial,
		    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ),
		    cafp == ರಿಕ್ತ ? "(null)" : cafp,
		    methinfo == ರಿಕ್ತ ? "" : ", ",
		    methinfo == ರಿಕ್ತ ? "" : methinfo);
		ಮುಕ್ತ(fp);
		ಮುಕ್ತ(cafp);
	} ಅನ್ಯಥಾ {
		fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(ಕೀಲಿ),
		    fp == ರಿಕ್ತ ? "(null)" : fp,
		    methinfo == ರಿಕ್ತ ? "" : ", ",
		    methinfo == ರಿಕ್ತ ? "" : methinfo);
		ಮುಕ್ತ(fp);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
auth_log(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ authenticated, ಪೂರ್ಣಾಙ್ಕ partial,
    ಧ್ರುವ ವರ್ಣ *method, ಧ್ರುವ ವರ್ಣ *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ಪೂರ್ಣಾಙ್ಕ level = SYSLOG_LEVEL_VERBOSE;
	ಧ್ರುವ ವರ್ಣ *authmsg;
	ವರ್ಣ *extra = ರಿಕ್ತ;

	ಯದಿ (!mm_is_monitor() && !authctxt->postponed)
		ಪ್ರತ್ಯಾಗಮ;

	/* Raise logging level */
	ಯದಿ (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	ಯದಿ (authctxt->postponed)
		authmsg = "Postponed";
	ಅನ್ಯಥಾ ಯದಿ (partial)
		authmsg = "Partial";
	ಅನ್ಯಥಾ
		authmsg = authenticated ? "Accepted" : "Failed";

	ಯದಿ ((extra = format_method_ಕೀಲಿ(authctxt)) == ರಿಕ್ತ) {
		ಯದಿ (authctxt->auth_method_info != ರಿಕ್ತ)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != ರಿಕ್ತ ? "/" : "", submethod == ರಿಕ್ತ ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != ರಿಕ್ತ ? ": " : "",
	    extra != ರಿಕ್ತ ? extra : "");

	ಮುಕ್ತ(extra);

#ಯದಿ defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	ಯದಿ (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		ಯದಿ (strcmp(method, "password") == 0 ||
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
#ಯದಿ defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	ಯದಿ (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

ಶೂನ್ಯ
auth_maxtries_exceeded(ಸಂರಚನಾ ssh *ssh)
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
ಪೂರ್ಣಾಙ್ಕ
auth_ಬೇರು_allowed(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *method)
{
	ವಿಕಲ್ಪ (options.permit_ಬೇರು_login) {
	ಪಕ್ಷ PERMIT_YES:
		ಪ್ರತ್ಯಾಗಮ 1;
	ಪಕ್ಷ PERMIT_NO_PASSWD:
		ಯದಿ (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			ಪ್ರತ್ಯಾಗಮ 1;
		ಭಙ್ಗ;
	ಪಕ್ಷ PERMIT_FORCED_ONLY:
		ಯದಿ (auth_opts->force_command != ರಿಕ್ತ) {
			logit("Root login accepted for forced command.");
			ಪ್ರತ್ಯಾಗಮ 1;
		}
		ಭಙ್ಗ;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	ಪ್ರತ್ಯಾಗಮ 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
ವರ್ಣ *
expand_authorized_ಕೀಲಿಗಳು(ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ passwd *pw)
{
	ವರ್ಣ *file, uidstr[32], ret[PATH_MAX];
	ಪೂರ್ಣಾಙ್ಕ i;

	snprintf(uidstr, ಪರಿಮಾಣ(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (ವರ್ಣ *)ರಿಕ್ತ);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	ಯದಿ (path_absolute(file))
		ಪ್ರತ್ಯಾಗಮ (file);

	i = snprintf(ret, ಪರಿಮಾಣ(ret), "%s/%s", pw->pw_dir, file);
	ಯದಿ (i < 0 || (size_t)i >= ಪರಿಮಾಣ(ret))
		fatal("expand_authorized_keys: path too long");
	ಮುಕ್ತ(file);
	ಪ್ರತ್ಯಾಗಮ (xstrdup(ret));
}

ವರ್ಣ *
authorized_principals_file(ಸಂರಚನಾ passwd *pw)
{
	ಯದಿ (options.authorized_principals_file == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ expand_authorized_ಕೀಲಿಗಳು(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_ಕೀಲಿ_in_hostfiles(ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *host,
    ಧ್ರುವ ವರ್ಣ *sysfile, ಧ್ರುವ ವರ್ಣ *userfile)
{
	ವರ್ಣ *user_hostfile;
	ಸಂರಚನಾ stat st;
	HostStatus host_status;
	ಸಂರಚನಾ hostkeys *hostkeys;
	ಧ್ರುವ ಸಂರಚನಾ hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	ಯದಿ (userfile != ರಿಕ್ತ) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		ಯದಿ (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} ಅನ್ಯಥಾ {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		ಮುಕ್ತ(user_hostfile);
	}
	host_status = check_ಕೀಲಿ_in_hostkeys(hostkeys, ಕೀಲಿ, &found);
	ಯದಿ (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	ಅನ್ಯಥಾ ಯದಿ (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->ಸಾಲು);
	ಅನ್ಯಥಾ
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	ಪ್ರತ್ಯಾಗಮ host_status;
}

ಸಂರಚನಾ passwd *
getpwnamallow(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *user)
{
#ifdef HAVE_LOGIN_CAP
	ಬಾಹ್ಯ login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	ಧ್ರುವ ವರ್ಣ *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	ಸಂರಚನಾ passwd *pw;
	ಸಂರಚನಾ connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == ರಿಕ್ತ;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#ಯದಿ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#ಯದಿ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	ಯದಿ (pw == ರಿಕ್ತ) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
	ಯದಿ (!allowed_user(ssh, pw))
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
#ifdef HAVE_LOGIN_CAP
	ಯದಿ ((lc = login_getpwclass(pw)) == ರಿಕ್ತ) {
		debug("unable to get login class: %s", user);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	ಯದಿ (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	ಯದಿ (!auth_timeok(lc, time(ರಿಕ್ತ))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	ಯದಿ ((as = auth_open()) == ರಿಕ್ತ || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = ರಿಕ್ತ;
	}
	ಯದಿ (as != ರಿಕ್ತ)
		auth_close(as);
#endif
#endif
	ಯದಿ (pw != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (pwcopy(pw));
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
ಪೂರ್ಣಾಙ್ಕ
auth_ಕೀಲಿ_is_revoked(ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ವರ್ಣ *fp = ರಿಕ್ತ;
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (options.ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		ಗಚ್ಛ out;
	}

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files; i++) {
		r = sshkey_check_revoked(ಕೀಲಿ, options.revoked_ಕೀಲಿಗಳು_files[i]);
		ವಿಕಲ್ಪ (r) {
		ಪಕ್ಷ 0:
			ಭಙ್ಗ; /* not revoked */
		ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(ಕೀಲಿ), fp,
			    options.revoked_ಕೀಲಿಗಳು_files[i]);
			ಗಚ್ಛ out;
		ಸ್ವಭಾವ:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(ಕೀಲಿ), fp,
			    options.revoked_ಕೀಲಿಗಳು_files[i]);
			ಗಚ್ಛ out;
		}
	}

	/* Success */
	r = 0;

 out:
	ಮುಕ್ತ(fp);
	ಪ್ರತ್ಯಾಗಮ r == 0 ? 0 : 1;
}

ಶೂನ್ಯ
auth_debug_add(ಧ್ರುವ ವರ್ಣ *fmt,...)
{
	ವರ್ಣ buf[1024];
	va_list args;
	ಪೂರ್ಣಾಙ್ಕ r;

	va_start(args, fmt);
	vsnprintf(buf, ಪರಿಮಾಣ(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	ಯದಿ (auth_debug != ರಿಕ್ತ)
		ಯದಿ ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

ಶೂನ್ಯ
auth_debug_send(ಸಂರಚನಾ ssh *ssh)
{
	ವರ್ಣ *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (auth_debug == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯಾವತ್ (sshbuf_len(auth_debug) != 0) {
		ಯದಿ ((r = sshbuf_get_cstring(auth_debug, &ಸಂದೇಶ, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", ಸಂದೇಶ);
		ಮುಕ್ತ(ಸಂದೇಶ);
	}
}

ಶೂನ್ಯ
auth_debug_reset(ಶೂನ್ಯ)
{
	ಯದಿ (auth_debug != ರಿಕ್ತ)
		sshbuf_reset(auth_debug);
	ಅನ್ಯಥಾ ಯದಿ ((auth_debug = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
}

ಸಂರಚನಾ passwd *
fakepw(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ done = 0;
	ಸ್ಥಿರ ಸಂರಚನಾ passwd fake;
	ಧ್ರುವ ವರ್ಣ hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	ವರ್ಣ *cp;

	ಯದಿ (done)
		ಪ್ರತ್ಯಾಗಮ (&fake);

	memset(&fake, 0, ಪರಿಮಾಣ(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	ಪ್ರತಿ (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(ಪರಿಮಾಣ(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == ರಿಕ್ತ ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == ರಿಕ್ತ ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	ಪ್ರತ್ಯಾಗಮ (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ಧ್ರುವ ವರ್ಣ *
auth_get_canonical_hostname(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ use_dns)
{
	ಸ್ಥಿರ ವರ್ಣ *dnsname;

	ಯದಿ (!use_dns)
		ಪ್ರತ್ಯಾಗಮ ssh_remote_ipaddr(ssh);
	ಯದಿ (dnsname != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ dnsname;
	dnsname = ssh_remote_hostname(ssh);
	ಪ್ರತ್ಯಾಗಮ dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
ಶೂನ್ಯ
auth_log_authopts(ಧ್ರುವ ವರ್ಣ *loc, ಧ್ರುವ ಸಂರಚನಾ sshauthopt *opts, ಪೂರ್ಣಾಙ್ಕ do_remote)
{
	ಪೂರ್ಣಾಙ್ಕ do_env = options.permit_user_env && opts->nenv > 0;
	ಪೂರ್ಣಾಙ್ಕ do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	ಪೂರ್ಣಾಙ್ಕ do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	ವರ್ಣ ಸಂದೇಶ[1024], buf[64];

	snprintf(buf, ಪರಿಮಾಣ(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == ರಿಕ್ತ ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == ರಿಕ್ತ ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, ಸಂದೇಶ);
	ಯದಿ (do_remote)
		auth_debug_add("%s: %s", loc, ಸಂದೇಶ);

	ಯದಿ (options.permit_user_env) {
		ಪ್ರತಿ (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			ಯದಿ (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	ಯದಿ (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, ಪರಿಮಾಣ(buf));
		debug("%s: expires at %s", loc, buf);
	}
	ಯದಿ (opts->cert_principals != ರಿಕ್ತ) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	ಯದಿ (opts->force_command != ರಿಕ್ತ)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	ಯದಿ (do_permitopen) {
		ಪ್ರತಿ (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	ಯದಿ (do_permitlisten) {
		ಪ್ರತಿ (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
ಪೂರ್ಣಾಙ್ಕ
auth_activate_options(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshauthopt *opts)
{
	ಸಂರಚನಾ sshauthopt *old = auth_opts;
	ಧ್ರುವ ವರ್ಣ *emsg = ರಿಕ್ತ;

	debug_f("setting new authentication options");
	ಯದಿ ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == ರಿಕ್ತ) {
		error("Inconsistent authentication options: %s", emsg);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	sshauthopt_free(old);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Disable forwarding, etc for the session */
ಶೂನ್ಯ
auth_restrict_session(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	ಯದಿ ((restricted = sshauthopt_new()) == ರಿಕ್ತ)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	ಯದಿ (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
