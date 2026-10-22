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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <sys/wait.h>

#অন্তর্ভাৱ <netinet/in.h>

#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <paths.h>
#অন্তর্ভাৱ <pwd.h>
#ifdef HAVE_LOGIN_H
#অন্তর্ভাৱ <login.h>
#endif
#ifdef USE_SHADOW
#অন্তর্ভাৱ <shadow.h>
#endif
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <netdb.h>
#অন্তর্ভাৱ <time.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "groupaccess.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "servconf.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "auth-options.h"
#অন্তর্ভাৱ "canohost.h"
#অন্তর্ভাৱ "uidswap.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "loginrec.h"
#ifdef GSSAPI
#অন্তর্ভাৱ "ssh-gss.h"
#endif
#অন্তর্ভাৱ "authfile.h"
#অন্তর্ভাৱ "monitor_wrap.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "channels.h"

/* import */
বাহ্য ServerOptions options;
বাহ্য সংরচনা include_list includes;
বাহ্য সংরচনা sshbuf *loginmsg;
বাহ্য সংরচনা passwd *privsep_pw;
বাহ্য সংরচনা sshauthopt *auth_opts;

/* Debugging messages */
স্থির সংরচনা sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
পূর্ণাঙ্ক
allowed_user(সংরচনা ssh *ssh, সংরচনা passwd * pw)
{
	সংরচনা stat st;
	ধ্রুৱ ৱর্ণ *hostname = রিক্ত, *ipaddr = রিক্ত;
	পূর্ণাঙ্ক r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	যদি (!pw || !pw->pw_name)
		ঘূৰাই 0;

	যদি (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		ঘূৰাই 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	যদি (options.chroot_directory == রিক্ত ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		ৱর্ণ *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		যদি (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			মুক্ত(shell);
			ঘূৰাই 0;
		}
		যদি (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			মুক্ত(shell);
			ঘূৰাই 0;
		}
		মুক্ত(shell);
	}

	যদি (options.অঙ্ক_deny_users > 0 || options.অঙ্ক_allow_users > 0 ||
	    options.অঙ্ক_deny_groups > 0 || options.অঙ্ক_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	যদি (options.অঙ্ক_deny_users > 0) {
		বাবে (i = 0; i < options.অঙ্ক_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			যদি (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} অন্যথা যদি (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				ঘূৰাই 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	যদি (options.অঙ্ক_allow_users > 0) {
		বাবে (i = 0; i < options.অঙ্ক_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			যদি (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} অন্যথা যদি (r == 1)
				ভঙ্গ;
		}
		/* i < options.num_allow_users iff we break for loop */
		যদি (i >= options.অঙ্ক_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			ঘূৰাই 0;
		}
	}
	যদি (options.অঙ্ক_deny_groups > 0 || options.অঙ্ক_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		যদি (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			ঘূৰাই 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		যদি (options.অঙ্ক_deny_groups > 0)
			যদি (ga_match(options.deny_groups,
			    options.অঙ্ক_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				ঘূৰাই 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		যদি (options.অঙ্ক_allow_groups > 0)
			যদি (!ga_match(options.allow_groups,
			    options.অঙ্ক_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				ঘূৰাই 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	যদি (!sys_auth_allowed_user(pw, loginmsg))
		ঘূৰাই 0;
#endif

	/* We found no reason not to let this user try to log on... */
	ঘূৰাই 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
স্থির ৱর্ণ *
format_method_চাবি(Authctxt *authctxt)
{
	ধ্রুৱ সংরচনা sshkey *চাবি = authctxt->auth_method_চাবি;
	ধ্রুৱ ৱর্ণ *methinfo = authctxt->auth_method_info;
	ৱর্ণ *fp, *cafp, *ret = রিক্ত;

	যদি (চাবি == রিক্ত)
		ঘূৰাই রিক্ত;

	যদি (sshkey_is_cert(চাবি)) {
		fp = sshkey_fingerprint(চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(চাবি->cert->signature_চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(চাবি), fp == রিক্ত ? "(null)" : fp,
		    চাবি->cert->চাবি_id,
		    (unsigned long long)চাবি->cert->serial,
		    sshkey_type(চাবি->cert->signature_চাবি),
		    cafp == রিক্ত ? "(null)" : cafp,
		    methinfo == রিক্ত ? "" : ", ",
		    methinfo == রিক্ত ? "" : methinfo);
		মুক্ত(fp);
		মুক্ত(cafp);
	} অন্যথা {
		fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(চাবি),
		    fp == রিক্ত ? "(null)" : fp,
		    methinfo == রিক্ত ? "" : ", ",
		    methinfo == রিক্ত ? "" : methinfo);
		মুক্ত(fp);
	}
	ঘূৰাই ret;
}

শূন্য
auth_log(সংরচনা ssh *ssh, পূর্ণাঙ্ক authenticated, পূর্ণাঙ্ক partial,
    ধ্রুৱ ৱর্ণ *method, ধ্রুৱ ৱর্ণ *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	পূর্ণাঙ্ক level = SYSLOG_LEVEL_VERBOSE;
	ধ্রুৱ ৱর্ণ *authmsg;
	ৱর্ণ *extra = রিক্ত;

	যদি (!mm_is_monitor() && !authctxt->postponed)
		ঘূৰাই;

	/* Raise logging level */
	যদি (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	যদি (authctxt->postponed)
		authmsg = "Postponed";
	অন্যথা যদি (partial)
		authmsg = "Partial";
	অন্যথা
		authmsg = authenticated ? "Accepted" : "Failed";

	যদি ((extra = format_method_চাবি(authctxt)) == রিক্ত) {
		যদি (authctxt->auth_method_info != রিক্ত)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != রিক্ত ? "/" : "", submethod == রিক্ত ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != রিক্ত ? ": " : "",
	    extra != রিক্ত ? extra : "");

	মুক্ত(extra);

#যদি defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	যদি (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		যদি (strcmp(method, "password") == 0 ||
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
#যদি defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	যদি (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

শূন্য
auth_maxtries_exceeded(সংরচনা ssh *ssh)
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
পূর্ণাঙ্ক
auth_মূল_allowed(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *method)
{
	ৱিকল্প (options.permit_মূল_login) {
	পক্ষ PERMIT_YES:
		ঘূৰাই 1;
	পক্ষ PERMIT_NO_PASSWD:
		যদি (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			ঘূৰাই 1;
		ভঙ্গ;
	পক্ষ PERMIT_FORCED_ONLY:
		যদি (auth_opts->force_command != রিক্ত) {
			logit("Root login accepted for forced command.");
			ঘূৰাই 1;
		}
		ভঙ্গ;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	ঘূৰাই 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
ৱর্ণ *
expand_authorized_চাবিগুলি(ধ্রুৱ ৱর্ণ *filename, সংরচনা passwd *pw)
{
	ৱর্ণ *file, uidstr[32], ret[PATH_MAX];
	পূর্ণাঙ্ক i;

	snprintf(uidstr, পরিমাণ(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (ৱর্ণ *)রিক্ত);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	যদি (path_absolute(file))
		ঘূৰাই (file);

	i = snprintf(ret, পরিমাণ(ret), "%s/%s", pw->pw_dir, file);
	যদি (i < 0 || (size_t)i >= পরিমাণ(ret))
		fatal("expand_authorized_keys: path too long");
	মুক্ত(file);
	ঘূৰাই (xstrdup(ret));
}

ৱর্ণ *
authorized_principals_file(সংরচনা passwd *pw)
{
	যদি (options.authorized_principals_file == রিক্ত)
		ঘূৰাই রিক্ত;
	ঘূৰাই expand_authorized_চাবিগুলি(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_চাবি_in_hostfiles(সংরচনা passwd *pw, সংরচনা sshkey *চাবি, ধ্রুৱ ৱর্ণ *host,
    ধ্রুৱ ৱর্ণ *sysfile, ধ্রুৱ ৱর্ণ *userfile)
{
	ৱর্ণ *user_hostfile;
	সংরচনা stat st;
	HostStatus host_status;
	সংরচনা hostkeys *hostkeys;
	ধ্রুৱ সংরচনা hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	যদি (userfile != রিক্ত) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		যদি (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} অন্যথা {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		মুক্ত(user_hostfile);
	}
	host_status = check_চাবি_in_hostkeys(hostkeys, চাবি, &found);
	যদি (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	অন্যথা যদি (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->সাৰি);
	অন্যথা
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	ঘূৰাই host_status;
}

সংরচনা passwd *
getpwnamallow(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *user)
{
#ifdef HAVE_LOGIN_CAP
	বাহ্য login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	ধ্রুৱ ৱর্ণ *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	সংরচনা passwd *pw;
	সংরচনা connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == রিক্ত;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	বাবে (i = 0; i < options.অঙ্ক_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#যদি defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#যদি defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	যদি (pw == রিক্ত) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		ঘূৰাই (রিক্ত);
	}
	যদি (!allowed_user(ssh, pw))
		ঘূৰাই (রিক্ত);
#ifdef HAVE_LOGIN_CAP
	যদি ((lc = login_getpwclass(pw)) == রিক্ত) {
		debug("unable to get login class: %s", user);
		ঘূৰাই (রিক্ত);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	যদি (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		ঘূৰাই (রিক্ত);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	যদি (!auth_timeok(lc, time(রিক্ত))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		ঘূৰাই (রিক্ত);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	যদি ((as = auth_open()) == রিক্ত || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = রিক্ত;
	}
	যদি (as != রিক্ত)
		auth_close(as);
#endif
#endif
	যদি (pw != রিক্ত)
		ঘূৰাই (pwcopy(pw));
	ঘূৰাই (রিক্ত);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
পূর্ণাঙ্ক
auth_চাবি_is_revoked(সংরচনা sshkey *চাবি)
{
	ৱর্ণ *fp = রিক্ত;
	u_int i;
	পূর্ণাঙ্ক r;

	যদি (options.অঙ্ক_revoked_চাবিগুলি_files == 0)
		ঘূৰাই 0;
	যদি ((fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		গচ্ছ out;
	}

	বাবে (i = 0; i < options.অঙ্ক_revoked_চাবিগুলি_files; i++) {
		r = sshkey_check_revoked(চাবি, options.revoked_চাবিগুলি_files[i]);
		ৱিকল্প (r) {
		পক্ষ 0:
			ভঙ্গ; /* not revoked */
		পক্ষ SSH_ERR_চাবি_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(চাবি), fp,
			    options.revoked_চাবিগুলি_files[i]);
			গচ্ছ out;
		স্ৱভাৱ:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(চাবি), fp,
			    options.revoked_চাবিগুলি_files[i]);
			গচ্ছ out;
		}
	}

	/* Success */
	r = 0;

 out:
	মুক্ত(fp);
	ঘূৰাই r == 0 ? 0 : 1;
}

শূন্য
auth_debug_add(ধ্রুৱ ৱর্ণ *fmt,...)
{
	ৱর্ণ buf[1024];
	va_list args;
	পূর্ণাঙ্ক r;

	va_start(args, fmt);
	vsnprintf(buf, পরিমাণ(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	যদি (auth_debug != রিক্ত)
		যদি ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

শূন্য
auth_debug_send(সংরচনা ssh *ssh)
{
	ৱর্ণ *বাৰ্তা;
	পূর্ণাঙ্ক r;

	যদি (auth_debug == রিক্ত)
		ঘূৰাই;
	যেতিয়ালৈ (sshbuf_len(auth_debug) != 0) {
		যদি ((r = sshbuf_get_cstring(auth_debug, &বাৰ্তা, রিক্ত)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", বাৰ্তা);
		মুক্ত(বাৰ্তা);
	}
}

শূন্য
auth_debug_reset(শূন্য)
{
	যদি (auth_debug != রিক্ত)
		sshbuf_reset(auth_debug);
	অন্যথা যদি ((auth_debug = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
}

সংরচনা passwd *
fakepw(শূন্য)
{
	স্থির পূর্ণাঙ্ক done = 0;
	স্থির সংরচনা passwd fake;
	ধ্রুৱ ৱর্ণ hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	ৱর্ণ *cp;

	যদি (done)
		ঘূৰাই (&fake);

	memset(&fake, 0, পরিমাণ(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	বাবে (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(পরিমাণ(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == রিক্ত ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == রিক্ত ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	ঘূৰাই (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ধ্রুৱ ৱর্ণ *
auth_get_canonical_hostname(সংরচনা ssh *ssh, পূর্ণাঙ্ক use_dns)
{
	স্থির ৱর্ণ *dnsname;

	যদি (!use_dns)
		ঘূৰাই ssh_remote_ipaddr(ssh);
	যদি (dnsname != রিক্ত)
		ঘূৰাই dnsname;
	dnsname = ssh_remote_hostname(ssh);
	ঘূৰাই dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
শূন্য
auth_log_authopts(ধ্রুৱ ৱর্ণ *loc, ধ্রুৱ সংরচনা sshauthopt *opts, পূর্ণাঙ্ক do_remote)
{
	পূর্ণাঙ্ক do_env = options.permit_user_env && opts->nenv > 0;
	পূর্ণাঙ্ক do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	পূর্ণাঙ্ক do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	ৱর্ণ বাৰ্তা[1024], buf[64];

	snprintf(buf, পরিমাণ(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(বাৰ্তা, পরিমাণ(বাৰ্তা), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == রিক্ত ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == রিক্ত ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, বাৰ্তা);
	যদি (do_remote)
		auth_debug_add("%s: %s", loc, বাৰ্তা);

	যদি (options.permit_user_env) {
		বাবে (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			যদি (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	যদি (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, পরিমাণ(buf));
		debug("%s: expires at %s", loc, buf);
	}
	যদি (opts->cert_principals != রিক্ত) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	যদি (opts->force_command != রিক্ত)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	যদি (do_permitopen) {
		বাবে (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	যদি (do_permitlisten) {
		বাবে (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
পূর্ণাঙ্ক
auth_activate_options(সংরচনা ssh *ssh, সংরচনা sshauthopt *opts)
{
	সংরচনা sshauthopt *old = auth_opts;
	ধ্রুৱ ৱর্ণ *emsg = রিক্ত;

	debug_f("setting new authentication options");
	যদি ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == রিক্ত) {
		error("Inconsistent authentication options: %s", emsg);
		ঘূৰাই -1;
	}
	sshauthopt_free(old);
	ঘূৰাই 0;
}

/* Disable forwarding, etc for the session */
শূন্য
auth_restrict_session(সংরচনা ssh *ssh)
{
	সংরচনা sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	যদি ((restricted = sshauthopt_new()) == রিক্ত)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	যদি (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
