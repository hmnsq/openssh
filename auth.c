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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <sys/socket.h>
#ضمن <sys/wait.h>

#ضمن <netinet/in.h>

#ضمن <stdlib.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ifdef HAVE_LOGIN_H
#ضمن <login.h>
#endif
#ifdef USE_SHADOW
#ضمن <shadow.h>
#endif
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <limits.h>
#ضمن <netdb.h>
#ضمن <time.h>

#ضمن "xmalloc.h"
#ضمن "match.h"
#ضمن "groupaccess.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-options.h"
#ضمن "canohost.h"
#ضمن "uidswap.h"
#ضمن "packet.h"
#ضمن "loginrec.h"
#ifdef GSSAPI
#ضمن "ssh-gss.h"
#endif
#ضمن "authfile.h"
#ضمن "monitor_wrap.h"
#ضمن "ssherr.h"
#ضمن "channels.h"

/* import */
خارجي ServerOptions options;
خارجي بنية include_list includes;
خارجي بنية sshbuf *loginmsg;
خارجي بنية passwd *privsep_pw;
خارجي بنية sshauthopt *auth_opts;

/* Debugging messages */
ساكن بنية sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
صحيح
allowed_user(بنية ssh *ssh, بنية passwd * pw)
{
	بنية stat st;
	ثابت حرف *hostname = عدم, *ipaddr = عدم;
	صحيح r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	إذا (!pw || !pw->pw_name)
		أرجع 0;

	إذا (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		أرجع 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	إذا (options.chroot_directory == عدم ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		حرف *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		إذا (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			حرر(shell);
			أرجع 0;
		}
		إذا (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			حرر(shell);
			أرجع 0;
		}
		حرر(shell);
	}

	إذا (options.ژمارە_deny_users > 0 || options.ژمارە_allow_users > 0 ||
	    options.ژمارە_deny_groups > 0 || options.ژمارە_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	إذا (options.ژمارە_deny_users > 0) {
		لكل (i = 0; i < options.ژمارە_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			إذا (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} وإلا إذا (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				أرجع 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	إذا (options.ژمارە_allow_users > 0) {
		لكل (i = 0; i < options.ژمارە_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			إذا (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} وإلا إذا (r == 1)
				اكسر;
		}
		/* i < options.num_allow_users iff we break for loop */
		إذا (i >= options.ژمارە_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			أرجع 0;
		}
	}
	إذا (options.ژمارە_deny_groups > 0 || options.ژمارە_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		إذا (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			أرجع 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		إذا (options.ژمارە_deny_groups > 0)
			إذا (ga_match(options.deny_groups,
			    options.ژمارە_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				أرجع 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		إذا (options.ژمارە_allow_groups > 0)
			إذا (!ga_match(options.allow_groups,
			    options.ژمارە_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				أرجع 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	إذا (!sys_auth_allowed_user(pw, loginmsg))
		أرجع 0;
#endif

	/* We found no reason not to let this user try to log on... */
	أرجع 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
ساكن حرف *
format_method_کلیل(Authctxt *authctxt)
{
	ثابت بنية sshkey *کلیل = authctxt->auth_method_کلیل;
	ثابت حرف *methinfo = authctxt->auth_method_info;
	حرف *fp, *cafp, *ret = عدم;

	إذا (کلیل == عدم)
		أرجع عدم;

	إذا (sshkey_is_cert(کلیل)) {
		fp = sshkey_fingerprint(کلیل,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(کلیل->cert->signature_کلیل,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(کلیل), fp == عدم ? "(null)" : fp,
		    کلیل->cert->کلیل_id,
		    (unsigned long long)کلیل->cert->serial,
		    sshkey_type(کلیل->cert->signature_کلیل),
		    cafp == عدم ? "(null)" : cafp,
		    methinfo == عدم ? "" : ", ",
		    methinfo == عدم ? "" : methinfo);
		حرر(fp);
		حرر(cafp);
	} وإلا {
		fp = sshkey_fingerprint(کلیل, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(کلیل),
		    fp == عدم ? "(null)" : fp,
		    methinfo == عدم ? "" : ", ",
		    methinfo == عدم ? "" : methinfo);
		حرر(fp);
	}
	أرجع ret;
}

فراغ
auth_log(بنية ssh *ssh, صحيح authenticated, صحيح partial,
    ثابت حرف *method, ثابت حرف *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	صحيح level = SYSLOG_LEVEL_VERBOSE;
	ثابت حرف *authmsg;
	حرف *extra = عدم;

	إذا (!mm_is_monitor() && !authctxt->postponed)
		أرجع;

	/* Raise logging level */
	إذا (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	إذا (authctxt->postponed)
		authmsg = "Postponed";
	وإلا إذا (partial)
		authmsg = "Partial";
	وإلا
		authmsg = authenticated ? "Accepted" : "Failed";

	إذا ((extra = format_method_کلیل(authctxt)) == عدم) {
		إذا (authctxt->auth_method_info != عدم)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != عدم ? "/" : "", submethod == عدم ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != عدم ? ": " : "",
	    extra != عدم ? extra : "");

	حرر(extra);

#إذا defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	إذا (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		إذا (strcmp(method, "password") == 0 ||
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
#إذا defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	إذا (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

فراغ
auth_maxtries_exceeded(بنية ssh *ssh)
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
صحيح
auth_ڕەگ_allowed(بنية ssh *ssh, ثابت حرف *method)
{
	بدل (options.permit_ڕەگ_login) {
	حالة PERMIT_YES:
		أرجع 1;
	حالة PERMIT_NO_PASSWD:
		إذا (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			أرجع 1;
		اكسر;
	حالة PERMIT_FORCED_ONLY:
		إذا (auth_opts->force_command != عدم) {
			logit("Root login accepted for forced command.");
			أرجع 1;
		}
		اكسر;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	أرجع 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
حرف *
expand_authorized_کلیلەکان(ثابت حرف *filename, بنية passwd *pw)
{
	حرف *file, uidstr[32], ret[PATH_MAX];
	صحيح i;

	snprintf(uidstr, حجم(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (حرف *)عدم);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	إذا (path_absolute(file))
		أرجع (file);

	i = snprintf(ret, حجم(ret), "%s/%s", pw->pw_dir, file);
	إذا (i < 0 || (size_t)i >= حجم(ret))
		fatal("expand_authorized_keys: path too long");
	حرر(file);
	أرجع (xstrdup(ret));
}

حرف *
authorized_principals_file(بنية passwd *pw)
{
	إذا (options.authorized_principals_file == عدم)
		أرجع عدم;
	أرجع expand_authorized_کلیلەکان(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_کلیل_in_hostfiles(بنية passwd *pw, بنية sshkey *کلیل, ثابت حرف *host,
    ثابت حرف *sysfile, ثابت حرف *userfile)
{
	حرف *user_hostfile;
	بنية stat st;
	HostStatus host_status;
	بنية hostkeys *hostkeys;
	ثابت بنية hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	إذا (userfile != عدم) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		إذا (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} وإلا {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		حرر(user_hostfile);
	}
	host_status = check_کلیل_in_hostkeys(hostkeys, کلیل, &found);
	إذا (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	وإلا إذا (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->هێڵ);
	وإلا
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	أرجع host_status;
}

بنية passwd *
getpwnamallow(بنية ssh *ssh, ثابت حرف *user)
{
#ifdef HAVE_LOGIN_CAP
	خارجي login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	ثابت حرف *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	بنية passwd *pw;
	بنية connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == عدم;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	لكل (i = 0; i < options.ژمارە_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#إذا defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#إذا defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	إذا (pw == عدم) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		أرجع (عدم);
	}
	إذا (!allowed_user(ssh, pw))
		أرجع (عدم);
#ifdef HAVE_LOGIN_CAP
	إذا ((lc = login_getpwclass(pw)) == عدم) {
		debug("unable to get login class: %s", user);
		أرجع (عدم);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	إذا (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		أرجع (عدم);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	إذا (!auth_timeok(lc, time(عدم))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		أرجع (عدم);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	إذا ((as = auth_open()) == عدم || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = عدم;
	}
	إذا (as != عدم)
		auth_close(as);
#endif
#endif
	إذا (pw != عدم)
		أرجع (pwcopy(pw));
	أرجع (عدم);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
صحيح
auth_کلیل_is_revoked(بنية sshkey *کلیل)
{
	حرف *fp = عدم;
	u_int i;
	صحيح r;

	إذا (options.ژمارە_revoked_کلیلەکان_files == 0)
		أرجع 0;
	إذا ((fp = sshkey_fingerprint(کلیل, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		اذهب out;
	}

	لكل (i = 0; i < options.ژمارە_revoked_کلیلەکان_files; i++) {
		r = sshkey_check_revoked(کلیل, options.revoked_کلیلەکان_files[i]);
		بدل (r) {
		حالة 0:
			اكسر; /* not revoked */
		حالة SSH_ERR_کلیل_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(کلیل), fp,
			    options.revoked_کلیلەکان_files[i]);
			اذهب out;
		افتراضي:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(کلیل), fp,
			    options.revoked_کلیلەکان_files[i]);
			اذهب out;
		}
	}

	/* Success */
	r = 0;

 out:
	حرر(fp);
	أرجع r == 0 ? 0 : 1;
}

فراغ
auth_debug_add(ثابت حرف *fmt,...)
{
	حرف buf[1024];
	va_list args;
	صحيح r;

	va_start(args, fmt);
	vsnprintf(buf, حجم(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	إذا (auth_debug != عدم)
		إذا ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

فراغ
auth_debug_send(بنية ssh *ssh)
{
	حرف *پەیام;
	صحيح r;

	إذا (auth_debug == عدم)
		أرجع;
	طالما (sshbuf_len(auth_debug) != 0) {
		إذا ((r = sshbuf_get_cstring(auth_debug, &پەیام, عدم)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", پەیام);
		حرر(پەیام);
	}
}

فراغ
auth_debug_reset(فراغ)
{
	إذا (auth_debug != عدم)
		sshbuf_reset(auth_debug);
	وإلا إذا ((auth_debug = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
}

بنية passwd *
fakepw(فراغ)
{
	ساكن صحيح done = 0;
	ساكن بنية passwd fake;
	ثابت حرف hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	حرف *cp;

	إذا (done)
		أرجع (&fake);

	memset(&fake, 0, حجم(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	لكل (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(حجم(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == عدم ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == عدم ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	أرجع (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ثابت حرف *
auth_get_canonical_hostname(بنية ssh *ssh, صحيح use_dns)
{
	ساكن حرف *dnsname;

	إذا (!use_dns)
		أرجع ssh_remote_ipaddr(ssh);
	إذا (dnsname != عدم)
		أرجع dnsname;
	dnsname = ssh_remote_hostname(ssh);
	أرجع dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
فراغ
auth_log_authopts(ثابت حرف *loc, ثابت بنية sshauthopt *opts, صحيح do_remote)
{
	صحيح do_env = options.permit_user_env && opts->nenv > 0;
	صحيح do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	صحيح do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	حرف پەیام[1024], buf[64];

	snprintf(buf, حجم(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(پەیام, حجم(پەیام), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == عدم ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == عدم ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, پەیام);
	إذا (do_remote)
		auth_debug_add("%s: %s", loc, پەیام);

	إذا (options.permit_user_env) {
		لكل (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			إذا (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	إذا (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, حجم(buf));
		debug("%s: expires at %s", loc, buf);
	}
	إذا (opts->cert_principals != عدم) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	إذا (opts->force_command != عدم)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	إذا (do_permitopen) {
		لكل (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	إذا (do_permitlisten) {
		لكل (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
صحيح
auth_activate_options(بنية ssh *ssh, بنية sshauthopt *opts)
{
	بنية sshauthopt *old = auth_opts;
	ثابت حرف *emsg = عدم;

	debug_f("setting new authentication options");
	إذا ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == عدم) {
		error("Inconsistent authentication options: %s", emsg);
		أرجع -1;
	}
	sshauthopt_free(old);
	أرجع 0;
}

/* Disable forwarding, etc for the session */
فراغ
auth_restrict_session(بنية ssh *ssh)
{
	بنية sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	إذا ((restricted = sshauthopt_new()) == عدم)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	إذا (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
