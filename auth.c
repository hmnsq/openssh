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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <sys/socket.h>
#شامل <sys/wait.h>

#شامل <netinet/in.h>

#شامل <stdlib.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <paths.h>
#شامل <pwd.h>
#ifdef HAVE_LOGIN_H
#شامل <login.h>
#endif
#ifdef USE_SHADOW
#شامل <shadow.h>
#endif
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <limits.h>
#شامل <netdb.h>
#شامل <time.h>

#شامل "xmalloc.h"
#شامل "match.h"
#شامل "groupaccess.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-options.h"
#شامل "canohost.h"
#شامل "uidswap.h"
#شامل "packet.h"
#شامل "loginrec.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "authfile.h"
#شامل "monitor_wrap.h"
#شامل "ssherr.h"
#شامل "channels.h"

/* import */
بیرونی ServerOptions options;
بیرونی ساختار include_list includes;
بیرونی ساختار sshbuf *loginmsg;
بیرونی ساختار passwd *privsep_pw;
بیرونی ساختار sshauthopt *auth_opts;

/* Debugging messages */
ایستا ساختار sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
صحیح
allowed_user(ساختار ssh *ssh, ساختار passwd * pw)
{
	ساختار stat st;
	ثابت نویسه *hostname = پوچ, *ipaddr = پوچ;
	صحیح r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	اگر (!pw || !pw->pw_name)
		بازگشت 0;

	اگر (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		بازگشت 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	اگر (options.chroot_directory == پوچ ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		نویسه *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		اگر (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			آزاد(shell);
			بازگشت 0;
		}
		اگر (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			آزاد(shell);
			بازگشت 0;
		}
		آزاد(shell);
	}

	اگر (options.رقم_deny_users > 0 || options.رقم_allow_users > 0 ||
	    options.رقم_deny_groups > 0 || options.رقم_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	اگر (options.رقم_deny_users > 0) {
		برای (i = 0; i < options.رقم_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			اگر (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} وگرنه اگر (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				بازگشت 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	اگر (options.رقم_allow_users > 0) {
		برای (i = 0; i < options.رقم_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			اگر (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} وگرنه اگر (r == 1)
				بشکن;
		}
		/* i < options.num_allow_users iff we break for loop */
		اگر (i >= options.رقم_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			بازگشت 0;
		}
	}
	اگر (options.رقم_deny_groups > 0 || options.رقم_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		اگر (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			بازگشت 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		اگر (options.رقم_deny_groups > 0)
			اگر (ga_match(options.deny_groups,
			    options.رقم_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				بازگشت 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		اگر (options.رقم_allow_groups > 0)
			اگر (!ga_match(options.allow_groups,
			    options.رقم_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				بازگشت 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	اگر (!sys_auth_allowed_user(pw, loginmsg))
		بازگشت 0;
#endif

	/* We found no reason not to let this user try to log on... */
	بازگشت 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
ایستا نویسه *
format_method_کلید(Authctxt *authctxt)
{
	ثابت ساختار sshkey *کلید = authctxt->auth_method_کلید;
	ثابت نویسه *methinfo = authctxt->auth_method_info;
	نویسه *fp, *cafp, *ret = پوچ;

	اگر (کلید == پوچ)
		بازگشت پوچ;

	اگر (sshkey_is_cert(کلید)) {
		fp = sshkey_fingerprint(کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(کلید->cert->signature_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(کلید), fp == پوچ ? "(null)" : fp,
		    کلید->cert->کلید_id,
		    (unsigned long long)کلید->cert->serial,
		    sshkey_type(کلید->cert->signature_کلید),
		    cafp == پوچ ? "(null)" : cafp,
		    methinfo == پوچ ? "" : ", ",
		    methinfo == پوچ ? "" : methinfo);
		آزاد(fp);
		آزاد(cafp);
	} وگرنه {
		fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(کلید),
		    fp == پوچ ? "(null)" : fp,
		    methinfo == پوچ ? "" : ", ",
		    methinfo == پوچ ? "" : methinfo);
		آزاد(fp);
	}
	بازگشت ret;
}

تهی
auth_log(ساختار ssh *ssh, صحیح authenticated, صحیح partial,
    ثابت نویسه *method, ثابت نویسه *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحیح level = SYSLOG_LEVEL_VERBOSE;
	ثابت نویسه *authmsg;
	نویسه *extra = پوچ;

	اگر (!mm_is_monitor() && !authctxt->postponed)
		بازگشت;

	/* Raise logging level */
	اگر (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	اگر (authctxt->postponed)
		authmsg = "Postponed";
	وگرنه اگر (partial)
		authmsg = "Partial";
	وگرنه
		authmsg = authenticated ? "Accepted" : "Failed";

	اگر ((extra = format_method_کلید(authctxt)) == پوچ) {
		اگر (authctxt->auth_method_info != پوچ)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != پوچ ? "/" : "", submethod == پوچ ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != پوچ ? ": " : "",
	    extra != پوچ ? extra : "");

	آزاد(extra);

#اگر defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	اگر (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		اگر (strcmp(method, "password") == 0 ||
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
#اگر defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	اگر (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

تهی
auth_maxtries_exceeded(ساختار ssh *ssh)
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
صحیح
auth_ریشه_allowed(ساختار ssh *ssh, ثابت نویسه *method)
{
	انتخاب (options.permit_ریشه_login) {
	حالت PERMIT_YES:
		بازگشت 1;
	حالت PERMIT_NO_PASSWD:
		اگر (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			بازگشت 1;
		بشکن;
	حالت PERMIT_FORCED_ONLY:
		اگر (auth_opts->force_command != پوچ) {
			logit("Root login accepted for forced command.");
			بازگشت 1;
		}
		بشکن;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	بازگشت 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
نویسه *
expand_authorized_کلیدها(ثابت نویسه *filename, ساختار passwd *pw)
{
	نویسه *file, uidstr[32], ret[PATH_MAX];
	صحیح i;

	snprintf(uidstr, اندازه(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (نویسه *)پوچ);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	اگر (path_absolute(file))
		بازگشت (file);

	i = snprintf(ret, اندازه(ret), "%s/%s", pw->pw_dir, file);
	اگر (i < 0 || (size_t)i >= اندازه(ret))
		fatal("expand_authorized_keys: path too long");
	آزاد(file);
	بازگشت (xstrdup(ret));
}

نویسه *
authorized_principals_file(ساختار passwd *pw)
{
	اگر (options.authorized_principals_file == پوچ)
		بازگشت پوچ;
	بازگشت expand_authorized_کلیدها(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_کلید_in_hostfiles(ساختار passwd *pw, ساختار sshkey *کلید, ثابت نویسه *host,
    ثابت نویسه *sysfile, ثابت نویسه *userfile)
{
	نویسه *user_hostfile;
	ساختار stat st;
	HostStatus host_status;
	ساختار hostkeys *hostkeys;
	ثابت ساختار hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	اگر (userfile != پوچ) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		اگر (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} وگرنه {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		آزاد(user_hostfile);
	}
	host_status = check_کلید_in_hostkeys(hostkeys, کلید, &found);
	اگر (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	وگرنه اگر (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->سطر);
	وگرنه
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	بازگشت host_status;
}

ساختار passwd *
getpwnamallow(ساختار ssh *ssh, ثابت نویسه *user)
{
#ifdef HAVE_LOGIN_CAP
	بیرونی login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	ثابت نویسه *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	ساختار passwd *pw;
	ساختار connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == پوچ;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	برای (i = 0; i < options.رقم_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#اگر defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#اگر defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	اگر (pw == پوچ) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		بازگشت (پوچ);
	}
	اگر (!allowed_user(ssh, pw))
		بازگشت (پوچ);
#ifdef HAVE_LOGIN_CAP
	اگر ((lc = login_getpwclass(pw)) == پوچ) {
		debug("unable to get login class: %s", user);
		بازگشت (پوچ);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	اگر (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		بازگشت (پوچ);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	اگر (!auth_timeok(lc, time(پوچ))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		بازگشت (پوچ);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	اگر ((as = auth_open()) == پوچ || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = پوچ;
	}
	اگر (as != پوچ)
		auth_close(as);
#endif
#endif
	اگر (pw != پوچ)
		بازگشت (pwcopy(pw));
	بازگشت (پوچ);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
صحیح
auth_کلید_is_revoked(ساختار sshkey *کلید)
{
	نویسه *fp = پوچ;
	u_int i;
	صحیح r;

	اگر (options.رقم_revoked_کلیدها_files == 0)
		بازگشت 0;
	اگر ((fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		برو out;
	}

	برای (i = 0; i < options.رقم_revoked_کلیدها_files; i++) {
		r = sshkey_check_revoked(کلید, options.revoked_کلیدها_files[i]);
		انتخاب (r) {
		حالت 0:
			بشکن; /* not revoked */
		حالت SSH_ERR_کلید_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(کلید), fp,
			    options.revoked_کلیدها_files[i]);
			برو out;
		پیشفرض:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(کلید), fp,
			    options.revoked_کلیدها_files[i]);
			برو out;
		}
	}

	/* Success */
	r = 0;

 out:
	آزاد(fp);
	بازگشت r == 0 ? 0 : 1;
}

تهی
auth_debug_add(ثابت نویسه *fmt,...)
{
	نویسه buf[1024];
	va_list args;
	صحیح r;

	va_start(args, fmt);
	vsnprintf(buf, اندازه(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	اگر (auth_debug != پوچ)
		اگر ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

تهی
auth_debug_send(ساختار ssh *ssh)
{
	نویسه *پیام;
	صحیح r;

	اگر (auth_debug == پوچ)
		بازگشت;
	وقتی (sshbuf_len(auth_debug) != 0) {
		اگر ((r = sshbuf_get_cstring(auth_debug, &پیام, پوچ)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", پیام);
		آزاد(پیام);
	}
}

تهی
auth_debug_reset(تهی)
{
	اگر (auth_debug != پوچ)
		sshbuf_reset(auth_debug);
	وگرنه اگر ((auth_debug = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
}

ساختار passwd *
fakepw(تهی)
{
	ایستا صحیح done = 0;
	ایستا ساختار passwd fake;
	ثابت نویسه hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	نویسه *cp;

	اگر (done)
		بازگشت (&fake);

	memset(&fake, 0, اندازه(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	برای (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(اندازه(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == پوچ ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == پوچ ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	بازگشت (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ثابت نویسه *
auth_get_canonical_hostname(ساختار ssh *ssh, صحیح use_dns)
{
	ایستا نویسه *dnsname;

	اگر (!use_dns)
		بازگشت ssh_remote_ipaddr(ssh);
	اگر (dnsname != پوچ)
		بازگشت dnsname;
	dnsname = ssh_remote_hostname(ssh);
	بازگشت dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
تهی
auth_log_authopts(ثابت نویسه *loc, ثابت ساختار sshauthopt *opts, صحیح do_remote)
{
	صحیح do_env = options.permit_user_env && opts->nenv > 0;
	صحیح do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	صحیح do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	نویسه پیام[1024], buf[64];

	snprintf(buf, اندازه(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(پیام, اندازه(پیام), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == پوچ ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == پوچ ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, پیام);
	اگر (do_remote)
		auth_debug_add("%s: %s", loc, پیام);

	اگر (options.permit_user_env) {
		برای (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			اگر (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	اگر (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, اندازه(buf));
		debug("%s: expires at %s", loc, buf);
	}
	اگر (opts->cert_principals != پوچ) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	اگر (opts->force_command != پوچ)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	اگر (do_permitopen) {
		برای (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	اگر (do_permitlisten) {
		برای (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
صحیح
auth_activate_options(ساختار ssh *ssh, ساختار sshauthopt *opts)
{
	ساختار sshauthopt *old = auth_opts;
	ثابت نویسه *emsg = پوچ;

	debug_f("setting new authentication options");
	اگر ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == پوچ) {
		error("Inconsistent authentication options: %s", emsg);
		بازگشت -1;
	}
	sshauthopt_free(old);
	بازگشت 0;
}

/* Disable forwarding, etc for the session */
تهی
auth_restrict_session(ساختار ssh *ssh)
{
	ساختار sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	اگر ((restricted = sshauthopt_new()) == پوچ)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	اگر (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
