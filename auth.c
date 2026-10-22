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
#اگر_تعریف_شدہ HAVE_LOGIN_H
#شامل <login.h>
#اگر_ختم
#اگر_تعریف_شدہ USE_SHADOW
#شامل <shadow.h>
#اگر_ختم
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
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "authfile.h"
#شامل "monitor_wrap.h"
#شامل "ssherr.h"
#شامل "channels.h"

/* import */
خارجی ServerOptions options;
خارجی ساخت include_list includes;
خارجی ساخت sshbuf *loginmsg;
خارجی ساخت passwd *privsep_pw;
خارجی ساخت sshauthopt *auth_opts;

/* Debugging messages */
ساکن ساخت sshbuf *auth_debug;

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
allowed_user(ساخت ssh *ssh, ساخت passwd * pw)
{
	ساخت stat st;
	ثابت حرف *hostname = تہی, *ipaddr = تہی;
	صحیح r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	اگر (!pw || !pw->pw_name)
		واپس 0;

	اگر (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		واپس 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	اگر (options.chroot_directory == تہی ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		حرف *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		اگر (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			آزاد(shell);
			واپس 0;
		}
		اگر (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			آزاد(shell);
			واپس 0;
		}
		آزاد(shell);
	}

	اگر (options.عدد_deny_users > 0 || options.عدد_allow_users > 0 ||
	    options.عدد_deny_groups > 0 || options.عدد_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	اگر (options.عدد_deny_users > 0) {
		برائے (i = 0; i < options.عدد_deny_users; i++) {
			r = مطابقت_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			اگر (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} ورنہ اگر (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				واپس 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	اگر (options.عدد_allow_users > 0) {
		برائے (i = 0; i < options.عدد_allow_users; i++) {
			r = مطابقت_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			اگر (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} ورنہ اگر (r == 1)
				توڑو;
		}
		/* i < options.num_allow_users iff we break for loop */
		اگر (i >= options.عدد_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			واپس 0;
		}
	}
	اگر (options.عدد_deny_groups > 0 || options.عدد_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		اگر (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			واپس 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		اگر (options.عدد_deny_groups > 0)
			اگر (ga_مطابقت(options.deny_groups,
			    options.عدد_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				واپس 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		اگر (options.عدد_allow_groups > 0)
			اگر (!ga_مطابقت(options.allow_groups,
			    options.عدد_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				واپس 0;
			}
		ga_free();
	}

#اگر_تعریف_شدہ CUSTOM_SYS_AUTH_ALLOWED_USER
	اگر (!sys_auth_allowed_user(pw, loginmsg))
		واپس 0;
#اگر_ختم

	/* We found no reason not to let this user try to log on... */
	واپس 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
ساکن حرف *
format_طریقہ_کلید(Authctxt *authctxt)
{
	ثابت ساخت sshkey *کلید = authctxt->auth_طریقہ_کلید;
	ثابت حرف *methinfo = authctxt->auth_طریقہ_info;
	حرف *fp, *cafp, *ret = تہی;

	اگر (کلید == تہی)
		واپس تہی;

	اگر (sshkey_is_cert(کلید)) {
		fp = sshkey_fingerprint(کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(کلید->cert->signature_کلید,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(کلید), fp == تہی ? "(null)" : fp,
		    کلید->cert->کلید_id,
		    (غیرعلامتی طویل طویل)کلید->cert->serial,
		    sshkey_type(کلید->cert->signature_کلید),
		    cafp == تہی ? "(null)" : cafp,
		    methinfo == تہی ? "" : ", ",
		    methinfo == تہی ? "" : methinfo);
		آزاد(fp);
		آزاد(cafp);
	} ورنہ {
		fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(کلید),
		    fp == تہی ? "(null)" : fp,
		    methinfo == تہی ? "" : ", ",
		    methinfo == تہی ? "" : methinfo);
		آزاد(fp);
	}
	واپس ret;
}

خالی
auth_log(ساخت ssh *ssh, صحیح authenticated, صحیح partial,
    ثابت حرف *طریقہ, ثابت حرف *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحیح level = SYSLOG_LEVEL_VERBOSE;
	ثابت حرف *authmsg;
	حرف *extra = تہی;

	اگر (!mm_is_monitor() && !authctxt->postponed)
		واپس;

	/* Raise logging level */
	اگر (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(طریقہ, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	اگر (authctxt->postponed)
		authmsg = "Postponed";
	ورنہ اگر (partial)
		authmsg = "Partial";
	ورنہ
		authmsg = authenticated ? "Accepted" : "Failed";

	اگر ((extra = format_طریقہ_کلید(authctxt)) == تہی) {
		اگر (authctxt->auth_طریقہ_info != تہی)
			extra = xstrdup(authctxt->auth_طریقہ_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    طریقہ,
	    submethod != تہی ? "/" : "", submethod == تہی ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_پورٹ(ssh),
	    extra != تہی ? ": " : "",
	    extra != تہی ? extra : "");

	آزاد(extra);

#اگر defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	اگر (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		اگر (strcmp(طریقہ, "password") == 0 ||
		    لڑی_موازنہ(طریقہ, "keyboard-interactive", 20) == 0 ||
		    strcmp(طریقہ, "challenge-response") == 0)
			ریکارڈ_failed_login(ssh, authctxt->user,
			    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
# endif
# ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, audit_classify_auth(طریقہ));
# endif
	}
#اگر_ختم
#اگر defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	اگر (authenticated)
		sys_auth_ریکارڈ_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#اگر_ختم
}

خالی
auth_maxtries_exceeded(ساخت ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	error("maximum authentication attempts exceeded for "
	    "%s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_پورٹ(ssh));
	ssh_packet_disconnect(ssh, "Too many authentication failures");
	/* NOTREACHED */
}

/*
 * Check whether root logins are disallowed.
 */
صحیح
auth_جڑ_allowed(ساخت ssh *ssh, ثابت حرف *طریقہ)
{
	انتخاب (options.permit_جڑ_login) {
	حالت PERMIT_YES:
		واپس 1;
	حالت PERMIT_NO_PASSWD:
		اگر (strcmp(طریقہ, "publickey") == 0 ||
		    strcmp(طریقہ, "hostbased") == 0 ||
		    strcmp(طریقہ, "gssapi-with-mic") == 0)
			واپس 1;
		توڑو;
	حالت PERMIT_FORCED_ONLY:
		اگر (auth_opts->force_command != تہی) {
			logit("Root login accepted for forced command.");
			واپس 1;
		}
		توڑو;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
	واپس 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
حرف *
expand_authorized_کلیدیں(ثابت حرف *filename, ساخت passwd *pw)
{
	حرف *file, uidstr[32], ret[PATH_MAX];
	صحیح i;

	snprintf(uidstr, حجم(uidstr), "%llu",
	    (غیرعلامتی طویل طویل)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (حرف *)تہی);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	اگر (راستہ_absolute(file))
		واپس (file);

	i = snprintf(ret, حجم(ret), "%s/%s", pw->pw_dir, file);
	اگر (i < 0 || (سائز_t)i >= حجم(ret))
		fatal("expand_authorized_keys: path too long");
	آزاد(file);
	واپس (xstrdup(ret));
}

حرف *
authorized_principals_file(ساخت passwd *pw)
{
	اگر (options.authorized_principals_file == تہی)
		واپس تہی;
	واپس expand_authorized_کلیدیں(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
Host_حالت
check_کلید_اندر_hostfiles(ساخت passwd *pw, ساخت sshkey *کلید, ثابت حرف *host,
    ثابت حرف *sysfile, ثابت حرف *userfile)
{
	حرف *user_hostfile;
	ساخت stat st;
	Host_حالت host_حالت;
	ساخت hostkeys *hostkeys;
	ثابت ساخت hostkey_اندراج *ملا;

	hostkeys = init_hostkeys();
	بھرو_hostkeys(hostkeys, host, sysfile, 0);
	اگر (userfile != تہی) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		اگر (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_جوڑو("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} ورنہ {
			temporarily_use_uid(pw);
			بھرو_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		آزاد(user_hostfile);
	}
	host_حالت = check_کلید_اندر_hostkeys(hostkeys, کلید, &ملا);
	اگر (host_حالت == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	ورنہ اگر (host_حالت == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    ملا->host, ملا->file, ملا->سطر);
	ورنہ
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	واپس host_حالت;
}

ساخت passwd *
getpwnamallow(ساخت ssh *ssh, ثابت حرف *user)
{
#اگر_تعریف_شدہ HAVE_LOGIN_CAP
	خارجی login_cap_t *lc;
#اگر_تعریف_شدہ HAVE_AUTH_HOSTOK
	ثابت حرف *from_host, *from_ip;
#اگر_ختم
#اگر_تعریف_شدہ BSD_AUTH
	auth_session_t *as;
#اگر_ختم
#اگر_ختم
	ساخت passwd *pw;
	ساخت connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == تہی;
	parse_server_مطابقت_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	برائے (i = 0; i < options.عدد_log_verbose; i++)
		log_verbose_جوڑو(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_سیٹ_rekey_limits(ssh, options.rekey_حد_بندی,
	    options.rekey_interval);

#اگر defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#اگر_ختم

	pw = getpwnam(user);

#اگر defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#اگر_ختم
	اگر (pw == تہی) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh));
#اگر_تعریف_شدہ CUSTOM_FAILED_LOGIN
		ریکارڈ_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#اگر_ختم
#اگر_تعریف_شدہ SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#اگر_ختم /* SSH_AUDIT_EVENTS */
		واپس (تہی);
	}
	اگر (!allowed_user(ssh, pw))
		واپس (تہی);
#اگر_تعریف_شدہ HAVE_LOGIN_CAP
	اگر ((lc = login_getpwclass(pw)) == تہی) {
		debug("unable to get login class: %s", user);
		واپس (تہی);
	}
#اگر_تعریف_شدہ HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	اگر (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		واپس (تہی);
	}
#اگر_ختم /* HAVE_AUTH_HOSTOK */
#اگر_تعریف_شدہ HAVE_AUTH_TIMEOK
	اگر (!auth_timeok(lc, time(تہی))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		واپس (تہی);
	}
#اگر_ختم /* HAVE_AUTH_TIMEOK */
#اگر_تعریف_شدہ BSD_AUTH
	اگر ((as = auth_open()) == تہی || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = تہی;
	}
	اگر (as != تہی)
		auth_close(as);
#اگر_ختم
#اگر_ختم
	اگر (pw != تہی)
		واپس (pwcopy(pw));
	واپس (تہی);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
صحیح
auth_کلید_is_revoked(ساخت sshkey *کلید)
{
	حرف *fp = تہی;
	u_int i;
	صحیح r;

	اگر (options.عدد_revoked_کلیدیں_files == 0)
		واپس 0;
	اگر ((fp = sshkey_fingerprint(کلید, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		جاؤ برآمد;
	}

	برائے (i = 0; i < options.عدد_revoked_کلیدیں_files; i++) {
		r = sshkey_check_revoked(کلید, options.revoked_کلیدیں_files[i]);
		انتخاب (r) {
		حالت 0:
			توڑو; /* not revoked */
		حالت SSH_ERR_کلید_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(کلید), fp,
			    options.revoked_کلیدیں_files[i]);
			جاؤ برآمد;
		طےشدہ:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(کلید), fp,
			    options.revoked_کلیدیں_files[i]);
			جاؤ برآمد;
		}
	}

	/* Success */
	r = 0;

 برآمد:
	آزاد(fp);
	واپس r == 0 ? 0 : 1;
}

خالی
auth_debug_جوڑو(ثابت حرف *fmt,...)
{
	حرف buf[1024];
	va_list دلائل;
	صحیح r;

	va_start(دلائل, fmt);
	vsnprintf(buf, حجم(buf), fmt, دلائل);
	va_end(دلائل);
	debug3("%s", buf);
	اگر (auth_debug != تہی)
		اگر ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

خالی
auth_debug_send(ساخت ssh *ssh)
{
	حرف *پیغام;
	صحیح r;

	اگر (auth_debug == تہی)
		واپس;
	جب (sshbuf_len(auth_debug) != 0) {
		اگر ((r = sshbuf_get_cstring(auth_debug, &پیغام, تہی)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", پیغام);
		آزاد(پیغام);
	}
}

خالی
auth_debug_reset(خالی)
{
	اگر (auth_debug != تہی)
		sshbuf_reset(auth_debug);
	ورنہ اگر ((auth_debug = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
}

ساخت passwd *
fakepw(خالی)
{
	ساکن صحیح مکمل = 0;
	ساکن ساخت passwd fake;
	ثابت حرف hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	حرف *cp;

	اگر (مکمل)
		واپس (&fake);

	memset(&fake, 0, حجم(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	برائے (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_یکساں(حجم(hashchars) - 1)];
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#اگر_ختم
	fake.pw_uid = privsep_pw == تہی ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == تہی ? (gid_t)-1 : privsep_pw->pw_gid;
#اگر_تعریف_شدہ HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#اگر_ختم
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	مکمل = 1;

	واپس (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ثابت حرف *
auth_get_canonical_hostname(ساخت ssh *ssh, صحیح use_dns)
{
	ساکن حرف *dnsname;

	اگر (!use_dns)
		واپس ssh_remote_ipaddr(ssh);
	اگر (dnsname != تہی)
		واپس dnsname;
	dnsname = ssh_remote_hostname(ssh);
	واپس dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
خالی
auth_log_authopts(ثابت حرف *loc, ثابت ساخت sshauthopt *opts, صحیح do_remote)
{
	صحیح do_env = options.permit_user_env && opts->nenv > 0;
	صحیح do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	صحیح do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	سائز_t i;
	حرف پیغام[1024], buf[64];

	snprintf(buf, حجم(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(پیغام, حجم(پیغام), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == تہی ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_پورٹ_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == تہی ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, پیغام);
	اگر (do_remote)
		auth_debug_جوڑو("%s: %s", loc, پیغام);

	اگر (options.permit_user_env) {
		برائے (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			اگر (do_remote) {
				auth_debug_جوڑو("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	اگر (opts->valid_before != 0) {
		format_absolute_وقت(opts->valid_before, buf, حجم(buf));
		debug("%s: expires at %s", loc, buf);
	}
	اگر (opts->cert_principals != تہی) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	اگر (opts->force_command != تہی)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	اگر (do_permitopen) {
		برائے (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	اگر (do_permitlisten) {
		برائے (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
صحیح
auth_activate_options(ساخت ssh *ssh, ساخت sshauthopt *opts)
{
	ساخت sshauthopt *old = auth_opts;
	ثابت حرف *emsg = تہی;

	debug_f("setting new authentication options");
	اگر ((auth_opts = sshauthopt_ملاؤ(old, opts, &emsg)) == تہی) {
		error("Inconsistent authentication options: %s", emsg);
		واپس -1;
	}
	sshauthopt_free(old);
	واپس 0;
}

/* Disable forwarding, etc for the session */
خالی
auth_restrict_session(ساخت ssh *ssh)
{
	ساخت sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	اگر ((restricted = sshauthopt_new()) == تہی)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	اگر (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
