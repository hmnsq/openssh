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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/wait.h>

#অন্তর্ভাব <netinet/in.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#ifdef HAVE_LOGIN_H
#অন্তর্ভাব <login.h>
#endif
#ifdef USE_SHADOW
#অন্তর্ভাব <shadow.h>
#endif
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <time.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "groupaccess.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "uidswap.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "loginrec.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "monitor_wrap.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "channels.h"

/* import */
বাহ্যিক ServerOptions options;
বাহ্যিক কাঠামো include_list includes;
বাহ্যিক কাঠামো sshbuf *loginmsg;
বাহ্যিক কাঠামো passwd *privsep_pw;
বাহ্যিক কাঠামো sshauthopt *auth_opts;

/* Debugging messages */
স্থির কাঠামো sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
পূর্ণসংখ্যা
allowed_user(কাঠামো ssh *ssh, কাঠামো passwd * pw)
{
	কাঠামো stat st;
	ধ্রুবক অক্ষর *hostname = ফাঁকা, *ipaddr = ফাঁকা;
	পূর্ণসংখ্যা r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	যদি (!pw || !pw->pw_name)
		ফেরত 0;

	যদি (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		ফেরত 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	যদি (options.chroot_directory == ফাঁকা ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		অক্ষর *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		যদি (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			মুক্ত(shell);
			ফেরত 0;
		}
		যদি (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			মুক্ত(shell);
			ফেরত 0;
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
		জন্য (i = 0; i < options.অঙ্ক_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			যদি (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} অন্যথা যদি (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				ফেরত 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	যদি (options.অঙ্ক_allow_users > 0) {
		জন্য (i = 0; i < options.অঙ্ক_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			যদি (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} অন্যথা যদি (r == 1)
				বিরতি;
		}
		/* i < options.num_allow_users iff we break for loop */
		যদি (i >= options.অঙ্ক_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			ফেরত 0;
		}
	}
	যদি (options.অঙ্ক_deny_groups > 0 || options.অঙ্ক_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		যদি (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			ফেরত 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		যদি (options.অঙ্ক_deny_groups > 0)
			যদি (ga_match(options.deny_groups,
			    options.অঙ্ক_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				ফেরত 0;
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
				ফেরত 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	যদি (!sys_auth_allowed_user(pw, loginmsg))
		ফেরত 0;
#endif

	/* We found no reason not to let this user try to log on... */
	ফেরত 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
স্থির অক্ষর *
format_method_চাবি(Authctxt *authctxt)
{
	ধ্রুবক কাঠামো sshkey *চাবি = authctxt->auth_method_চাবি;
	ধ্রুবক অক্ষর *methinfo = authctxt->auth_method_info;
	অক্ষর *fp, *cafp, *ret = ফাঁকা;

	যদি (চাবি == ফাঁকা)
		ফেরত ফাঁকা;

	যদি (sshkey_is_cert(চাবি)) {
		fp = sshkey_fingerprint(চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(চাবি->cert->signature_চাবি,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(চাবি), fp == ফাঁকা ? "(null)" : fp,
		    চাবি->cert->চাবি_id,
		    (unsigned long long)চাবি->cert->serial,
		    sshkey_type(চাবি->cert->signature_চাবি),
		    cafp == ফাঁকা ? "(null)" : cafp,
		    methinfo == ফাঁকা ? "" : ", ",
		    methinfo == ফাঁকা ? "" : methinfo);
		মুক্ত(fp);
		মুক্ত(cafp);
	} অন্যথা {
		fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(চাবি),
		    fp == ফাঁকা ? "(null)" : fp,
		    methinfo == ফাঁকা ? "" : ", ",
		    methinfo == ফাঁকা ? "" : methinfo);
		মুক্ত(fp);
	}
	ফেরত ret;
}

শূন্য
auth_log(কাঠামো ssh *ssh, পূর্ণসংখ্যা authenticated, পূর্ণসংখ্যা partial,
    ধ্রুবক অক্ষর *method, ধ্রুবক অক্ষর *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	পূর্ণসংখ্যা level = SYSLOG_LEVEL_VERBOSE;
	ধ্রুবক অক্ষর *authmsg;
	অক্ষর *extra = ফাঁকা;

	যদি (!mm_is_monitor() && !authctxt->postponed)
		ফেরত;

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

	যদি ((extra = format_method_চাবি(authctxt)) == ফাঁকা) {
		যদি (authctxt->auth_method_info != ফাঁকা)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != ফাঁকা ? "/" : "", submethod == ফাঁকা ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != ফাঁকা ? ": " : "",
	    extra != ফাঁকা ? extra : "");

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
auth_maxtries_exceeded(কাঠামো ssh *ssh)
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
পূর্ণসংখ্যা
auth_মূল_allowed(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *method)
{
	নির্বাচন (options.permit_মূল_login) {
	ক্ষেত্র PERMIT_YES:
		ফেরত 1;
	ক্ষেত্র PERMIT_NO_PASSWD:
		যদি (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			ফেরত 1;
		বিরতি;
	ক্ষেত্র PERMIT_FORCED_ONLY:
		যদি (auth_opts->force_command != ফাঁকা) {
			logit("Root login accepted for forced command.");
			ফেরত 1;
		}
		বিরতি;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	ফেরত 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
অক্ষর *
expand_authorized_চাবিগুলি(ধ্রুবক অক্ষর *filename, কাঠামো passwd *pw)
{
	অক্ষর *file, uidstr[32], ret[PATH_MAX];
	পূর্ণসংখ্যা i;

	snprintf(uidstr, আকার(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (অক্ষর *)ফাঁকা);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	যদি (path_absolute(file))
		ফেরত (file);

	i = snprintf(ret, আকার(ret), "%s/%s", pw->pw_dir, file);
	যদি (i < 0 || (আকার_t)i >= আকার(ret))
		fatal("expand_authorized_keys: path too long");
	মুক্ত(file);
	ফেরত (xstrdup(ret));
}

অক্ষর *
authorized_principals_file(কাঠামো passwd *pw)
{
	যদি (options.authorized_principals_file == ফাঁকা)
		ফেরত ফাঁকা;
	ফেরত expand_authorized_চাবিগুলি(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_চাবি_in_hostfiles(কাঠামো passwd *pw, কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *host,
    ধ্রুবক অক্ষর *sysfile, ধ্রুবক অক্ষর *userfile)
{
	অক্ষর *user_hostfile;
	কাঠামো stat st;
	HostStatus host_status;
	কাঠামো hostkeys *hostkeys;
	ধ্রুবক কাঠামো hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	যদি (userfile != ফাঁকা) {
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
		    found->host, found->file, found->সারি);
	অন্যথা
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	ফেরত host_status;
}

কাঠামো passwd *
getpwnamallow(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *user)
{
#ifdef HAVE_LOGIN_CAP
	বাহ্যিক login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	ধ্রুবক অক্ষর *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	কাঠামো passwd *pw;
	কাঠামো connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == ফাঁকা;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	জন্য (i = 0; i < options.অঙ্ক_log_verbose; i++)
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
	যদি (pw == ফাঁকা) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		ফেরত (ফাঁকা);
	}
	যদি (!allowed_user(ssh, pw))
		ফেরত (ফাঁকা);
#ifdef HAVE_LOGIN_CAP
	যদি ((lc = login_getpwclass(pw)) == ফাঁকা) {
		debug("unable to get login class: %s", user);
		ফেরত (ফাঁকা);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	যদি (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		ফেরত (ফাঁকা);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	যদি (!auth_timeok(lc, time(ফাঁকা))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		ফেরত (ফাঁকা);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	যদি ((as = auth_open()) == ফাঁকা || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = ফাঁকা;
	}
	যদি (as != ফাঁকা)
		auth_close(as);
#endif
#endif
	যদি (pw != ফাঁকা)
		ফেরত (pwcopy(pw));
	ফেরত (ফাঁকা);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
পূর্ণসংখ্যা
auth_চাবি_is_revoked(কাঠামো sshkey *চাবি)
{
	অক্ষর *fp = ফাঁকা;
	u_int i;
	পূর্ণসংখ্যা r;

	যদি (options.অঙ্ক_revoked_চাবিগুলি_files == 0)
		ফেরত 0;
	যদি ((fp = sshkey_fingerprint(চাবি, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		যাও out;
	}

	জন্য (i = 0; i < options.অঙ্ক_revoked_চাবিগুলি_files; i++) {
		r = sshkey_check_revoked(চাবি, options.revoked_চাবিগুলি_files[i]);
		নির্বাচন (r) {
		ক্ষেত্র 0:
			বিরতি; /* not revoked */
		ক্ষেত্র SSH_ERR_চাবি_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(চাবি), fp,
			    options.revoked_চাবিগুলি_files[i]);
			যাও out;
		পূর্বনির্ধারিত:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(চাবি), fp,
			    options.revoked_চাবিগুলি_files[i]);
			যাও out;
		}
	}

	/* Success */
	r = 0;

 out:
	মুক্ত(fp);
	ফেরত r == 0 ? 0 : 1;
}

শূন্য
auth_debug_add(ধ্রুবক অক্ষর *fmt,...)
{
	অক্ষর buf[1024];
	va_list args;
	পূর্ণসংখ্যা r;

	va_start(args, fmt);
	vsnprintf(buf, আকার(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	যদি (auth_debug != ফাঁকা)
		যদি ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

শূন্য
auth_debug_send(কাঠামো ssh *ssh)
{
	অক্ষর *বার্তা;
	পূর্ণসংখ্যা r;

	যদি (auth_debug == ফাঁকা)
		ফেরত;
	যখন (sshbuf_len(auth_debug) != 0) {
		যদি ((r = sshbuf_get_cstring(auth_debug, &বার্তা, ফাঁকা)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", বার্তা);
		মুক্ত(বার্তা);
	}
}

শূন্য
auth_debug_reset(শূন্য)
{
	যদি (auth_debug != ফাঁকা)
		sshbuf_reset(auth_debug);
	অন্যথা যদি ((auth_debug = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
}

কাঠামো passwd *
fakepw(শূন্য)
{
	স্থির পূর্ণসংখ্যা done = 0;
	স্থির কাঠামো passwd fake;
	ধ্রুবক অক্ষর hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	অক্ষর *cp;

	যদি (done)
		ফেরত (&fake);

	memset(&fake, 0, আকার(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	জন্য (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(আকার(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == ফাঁকা ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == ফাঁকা ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	ফেরত (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ধ্রুবক অক্ষর *
auth_get_canonical_hostname(কাঠামো ssh *ssh, পূর্ণসংখ্যা use_dns)
{
	স্থির অক্ষর *dnsname;

	যদি (!use_dns)
		ফেরত ssh_remote_ipaddr(ssh);
	যদি (dnsname != ফাঁকা)
		ফেরত dnsname;
	dnsname = ssh_remote_hostname(ssh);
	ফেরত dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
শূন্য
auth_log_authopts(ধ্রুবক অক্ষর *loc, ধ্রুবক কাঠামো sshauthopt *opts, পূর্ণসংখ্যা do_remote)
{
	পূর্ণসংখ্যা do_env = options.permit_user_env && opts->nenv > 0;
	পূর্ণসংখ্যা do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	পূর্ণসংখ্যা do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	আকার_t i;
	অক্ষর বার্তা[1024], buf[64];

	snprintf(buf, আকার(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(বার্তা, আকার(বার্তা), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == ফাঁকা ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == ফাঁকা ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, বার্তা);
	যদি (do_remote)
		auth_debug_add("%s: %s", loc, বার্তা);

	যদি (options.permit_user_env) {
		জন্য (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			যদি (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	যদি (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, আকার(buf));
		debug("%s: expires at %s", loc, buf);
	}
	যদি (opts->cert_principals != ফাঁকা) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	যদি (opts->force_command != ফাঁকা)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	যদি (do_permitopen) {
		জন্য (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	যদি (do_permitlisten) {
		জন্য (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
পূর্ণসংখ্যা
auth_activate_options(কাঠামো ssh *ssh, কাঠামো sshauthopt *opts)
{
	কাঠামো sshauthopt *old = auth_opts;
	ধ্রুবক অক্ষর *emsg = ফাঁকা;

	debug_f("setting new authentication options");
	যদি ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == ফাঁকা) {
		error("Inconsistent authentication options: %s", emsg);
		ফেরত -1;
	}
	sshauthopt_free(old);
	ফেরত 0;
}

/* Disable forwarding, etc for the session */
শূন্য
auth_restrict_session(কাঠামো ssh *ssh)
{
	কাঠামো sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	যদি ((restricted = sshauthopt_new()) == ফাঁকা)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	যদি (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
