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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <sys/socket.h>
#समावेश <sys/wait.h>

#समावेश <netinet/in.h>

#समावेश <stdlib.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#अगर_घोषित HAVE_LOGIN_H
#समावेश <login.h>
#पूर्ण_अगर
#अगर_घोषित USE_SHADOW
#समावेश <shadow.h>
#पूर्ण_अगर
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <limits.h>
#समावेश <netdb.h>
#समावेश <time.h>

#समावेश "xmalloc.h"
#समावेश "match.h"
#समावेश "groupaccess.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "auth-options.h"
#समावेश "canohost.h"
#समावेश "uidswap.h"
#समावेश "packet.h"
#समावेश "loginrec.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "authfile.h"
#समावेश "monitor_wrap.h"
#समावेश "ssherr.h"
#समावेश "channels.h"

/* import */
बाह्य ServerOptions options;
बाह्य काष्ठा include_list includes;
बाह्य काष्ठा sshbuf *loginmsg;
बाह्य काष्ठा passwd *privsep_pw;
बाह्य काष्ठा sshauthopt *auth_opts;

/* Debugging messages */
अटल काष्ठा sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
पूर्णांक
allowed_user(काष्ठा ssh *ssh, काष्ठा passwd * pw)
{
	काष्ठा stat st;
	स्थिर अक्षर *hostname = शून्य, *ipaddr = शून्य;
	पूर्णांक r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	अगर (!pw || !pw->pw_name)
		वापस 0;

	अगर (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		वापस 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	अगर (options.chroot_directory == शून्य ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		अक्षर *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		अगर (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			मुक्त(shell);
			वापस 0;
		}
		अगर (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			मुक्त(shell);
			वापस 0;
		}
		मुक्त(shell);
	}

	अगर (options.अंक_deny_users > 0 || options.अंक_allow_users > 0 ||
	    options.अंक_deny_groups > 0 || options.अंक_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	अगर (options.अंक_deny_users > 0) {
		क्रम (i = 0; i < options.अंक_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			अगर (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} अन्यथा अगर (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				वापस 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	अगर (options.अंक_allow_users > 0) {
		क्रम (i = 0; i < options.अंक_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			अगर (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} अन्यथा अगर (r == 1)
				अवरोध;
		}
		/* i < options.num_allow_users iff we break for loop */
		अगर (i >= options.अंक_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			वापस 0;
		}
	}
	अगर (options.अंक_deny_groups > 0 || options.अंक_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		अगर (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			वापस 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		अगर (options.अंक_deny_groups > 0)
			अगर (ga_match(options.deny_groups,
			    options.अंक_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				वापस 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		अगर (options.अंक_allow_groups > 0)
			अगर (!ga_match(options.allow_groups,
			    options.अंक_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				वापस 0;
			}
		ga_free();
	}

#अगर_घोषित CUSTOM_SYS_AUTH_ALLOWED_USER
	अगर (!sys_auth_allowed_user(pw, loginmsg))
		वापस 0;
#पूर्ण_अगर

	/* We found no reason not to let this user try to log on... */
	वापस 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
अटल अक्षर *
format_method_कुंजी(Authctxt *authctxt)
{
	स्थिर काष्ठा sshkey *कुंजी = authctxt->auth_method_कुंजी;
	स्थिर अक्षर *methinfo = authctxt->auth_method_info;
	अक्षर *fp, *cafp, *ret = शून्य;

	अगर (कुंजी == शून्य)
		वापस शून्य;

	अगर (sshkey_is_cert(कुंजी)) {
		fp = sshkey_fingerprint(कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(कुंजी->cert->signature_कुंजी,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(कुंजी), fp == शून्य ? "(null)" : fp,
		    कुंजी->cert->कुंजी_id,
		    (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial,
		    sshkey_type(कुंजी->cert->signature_कुंजी),
		    cafp == शून्य ? "(null)" : cafp,
		    methinfo == शून्य ? "" : ", ",
		    methinfo == शून्य ? "" : methinfo);
		मुक्त(fp);
		मुक्त(cafp);
	} अन्यथा {
		fp = sshkey_fingerprint(कुंजी, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(कुंजी),
		    fp == शून्य ? "(null)" : fp,
		    methinfo == शून्य ? "" : ", ",
		    methinfo == शून्य ? "" : methinfo);
		मुक्त(fp);
	}
	वापस ret;
}

व्योम
auth_log(काष्ठा ssh *ssh, पूर्णांक authenticated, पूर्णांक partial,
    स्थिर अक्षर *method, स्थिर अक्षर *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	पूर्णांक level = SYSLOG_LEVEL_VERBOSE;
	स्थिर अक्षर *authmsg;
	अक्षर *extra = शून्य;

	अगर (!mm_is_monitor() && !authctxt->postponed)
		वापस;

	/* Raise logging level */
	अगर (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    म_भेद(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	अगर (authctxt->postponed)
		authmsg = "Postponed";
	अन्यथा अगर (partial)
		authmsg = "Partial";
	अन्यथा
		authmsg = authenticated ? "Accepted" : "Failed";

	अगर ((extra = format_method_कुंजी(authctxt)) == शून्य) {
		अगर (authctxt->auth_method_info != शून्य)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != शून्य ? "/" : "", submethod == शून्य ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != शून्य ? ": " : "",
	    extra != शून्य ? extra : "");

	मुक्त(extra);

#अगर defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	अगर (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		अगर (म_भेद(method, "password") == 0 ||
		    म_भेदन(method, "keyboard-interactive", 20) == 0 ||
		    म_भेद(method, "challenge-response") == 0)
			record_failed_login(ssh, authctxt->user,
			    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
# endif
# ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, audit_classify_auth(method));
# endif
	}
#पूर्ण_अगर
#अगर defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	अगर (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#पूर्ण_अगर
}

व्योम
auth_maxtries_exceeded(काष्ठा ssh *ssh)
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
पूर्णांक
auth_मूल_allowed(काष्ठा ssh *ssh, स्थिर अक्षर *method)
{
	चयन (options.permit_मूल_login) {
	हाल PERMIT_YES:
		वापस 1;
	हाल PERMIT_NO_PASSWD:
		अगर (म_भेद(method, "publickey") == 0 ||
		    म_भेद(method, "hostbased") == 0 ||
		    म_भेद(method, "gssapi-with-mic") == 0)
			वापस 1;
		अवरोध;
	हाल PERMIT_FORCED_ONLY:
		अगर (auth_opts->force_command != शून्य) {
			logit("Root login accepted for forced command.");
			वापस 1;
		}
		अवरोध;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	वापस 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
अक्षर *
expand_authorized_कुंजियाँ(स्थिर अक्षर *filename, काष्ठा passwd *pw)
{
	अक्षर *file, uidstr[32], ret[PATH_MAX];
	पूर्णांक i;

	snprintf(uidstr, माप(uidstr), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (अक्षर *)शून्य);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	अगर (path_absolute(file))
		वापस (file);

	i = snprintf(ret, माप(ret), "%s/%s", pw->pw_dir, file);
	अगर (i < 0 || (माप_प्रकार)i >= माप(ret))
		fatal("expand_authorized_keys: path too long");
	मुक्त(file);
	वापस (xstrdup(ret));
}

अक्षर *
authorized_principals_file(काष्ठा passwd *pw)
{
	अगर (options.authorized_principals_file == शून्य)
		वापस शून्य;
	वापस expand_authorized_कुंजियाँ(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_कुंजी_in_hostfiles(काष्ठा passwd *pw, काष्ठा sshkey *कुंजी, स्थिर अक्षर *host,
    स्थिर अक्षर *sysfile, स्थिर अक्षर *userfile)
{
	अक्षर *user_hostfile;
	काष्ठा stat st;
	HostStatus host_status;
	काष्ठा hostkeys *hostkeys;
	स्थिर काष्ठा hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	अगर (userfile != शून्य) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		अगर (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} अन्यथा {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		मुक्त(user_hostfile);
	}
	host_status = check_कुंजी_in_hostkeys(hostkeys, कुंजी, &found);
	अगर (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	अन्यथा अगर (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->पंक्ति);
	अन्यथा
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	वापस host_status;
}

काष्ठा passwd *
getpwnamallow(काष्ठा ssh *ssh, स्थिर अक्षर *user)
{
#अगर_घोषित HAVE_LOGIN_CAP
	बाह्य login_cap_t *lc;
#अगर_घोषित HAVE_AUTH_HOSTOK
	स्थिर अक्षर *from_host, *from_ip;
#पूर्ण_अगर
#अगर_घोषित BSD_AUTH
	auth_session_t *as;
#पूर्ण_अगर
#पूर्ण_अगर
	काष्ठा passwd *pw;
	काष्ठा connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == शून्य;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	क्रम (i = 0; i < options.अंक_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#अगर defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#पूर्ण_अगर

	pw = getpwnam(user);

#अगर defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#पूर्ण_अगर
	अगर (pw == शून्य) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#अगर_घोषित CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#पूर्ण_अगर
#अगर_घोषित SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#पूर्ण_अगर /* SSH_AUDIT_EVENTS */
		वापस (शून्य);
	}
	अगर (!allowed_user(ssh, pw))
		वापस (शून्य);
#अगर_घोषित HAVE_LOGIN_CAP
	अगर ((lc = login_getpwclass(pw)) == शून्य) {
		debug("unable to get login class: %s", user);
		वापस (शून्य);
	}
#अगर_घोषित HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	अगर (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		वापस (शून्य);
	}
#पूर्ण_अगर /* HAVE_AUTH_HOSTOK */
#अगर_घोषित HAVE_AUTH_TIMEOK
	अगर (!auth_timeok(lc, समय(शून्य))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		वापस (शून्य);
	}
#पूर्ण_अगर /* HAVE_AUTH_TIMEOK */
#अगर_घोषित BSD_AUTH
	अगर ((as = auth_open()) == शून्य || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = शून्य;
	}
	अगर (as != शून्य)
		auth_close(as);
#पूर्ण_अगर
#पूर्ण_अगर
	अगर (pw != शून्य)
		वापस (pwcopy(pw));
	वापस (शून्य);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
पूर्णांक
auth_कुंजी_is_revoked(काष्ठा sshkey *कुंजी)
{
	अक्षर *fp = शून्य;
	u_int i;
	पूर्णांक r;

	अगर (options.अंक_revoked_कुंजियाँ_files == 0)
		वापस 0;
	अगर ((fp = sshkey_fingerprint(कुंजी, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		जाओ out;
	}

	क्रम (i = 0; i < options.अंक_revoked_कुंजियाँ_files; i++) {
		r = sshkey_check_revoked(कुंजी, options.revoked_कुंजियाँ_files[i]);
		चयन (r) {
		हाल 0:
			अवरोध; /* not revoked */
		हाल SSH_ERR_कुंजी_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(कुंजी), fp,
			    options.revoked_कुंजियाँ_files[i]);
			जाओ out;
		शेष:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(कुंजी), fp,
			    options.revoked_कुंजियाँ_files[i]);
			जाओ out;
		}
	}

	/* Success */
	r = 0;

 out:
	मुक्त(fp);
	वापस r == 0 ? 0 : 1;
}

व्योम
auth_debug_add(स्थिर अक्षर *fmt,...)
{
	अक्षर buf[1024];
	बहु_सूची args;
	पूर्णांक r;

	बहु_शुरू(args, fmt);
	vsnprintf(buf, माप(buf), fmt, args);
	बहु_पूर्ण(args);
	debug3("%s", buf);
	अगर (auth_debug != शून्य)
		अगर ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

व्योम
auth_debug_send(काष्ठा ssh *ssh)
{
	अक्षर *संदेश;
	पूर्णांक r;

	अगर (auth_debug == शून्य)
		वापस;
	जबतक (sshbuf_len(auth_debug) != 0) {
		अगर ((r = sshbuf_get_cstring(auth_debug, &संदेश, शून्य)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", संदेश);
		मुक्त(संदेश);
	}
}

व्योम
auth_debug_reset(व्योम)
{
	अगर (auth_debug != शून्य)
		sshbuf_reset(auth_debug);
	अन्यथा अगर ((auth_debug = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
}

काष्ठा passwd *
fakepw(व्योम)
{
	अटल पूर्णांक done = 0;
	अटल काष्ठा passwd fake;
	स्थिर अक्षर hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	अक्षर *cp;

	अगर (done)
		वापस (&fake);

	स_रखो(&fake, 0, माप(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	क्रम (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(माप(hashchars) - 1)];
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#पूर्ण_अगर
	fake.pw_uid = privsep_pw == शून्य ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == शून्य ? (gid_t)-1 : privsep_pw->pw_gid;
#अगर_घोषित HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#पूर्ण_अगर
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	वापस (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

स्थिर अक्षर *
auth_get_canonical_hostname(काष्ठा ssh *ssh, पूर्णांक use_dns)
{
	अटल अक्षर *dnsname;

	अगर (!use_dns)
		वापस ssh_remote_ipaddr(ssh);
	अगर (dnsname != शून्य)
		वापस dnsname;
	dnsname = ssh_remote_hostname(ssh);
	वापस dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
व्योम
auth_log_authopts(स्थिर अक्षर *loc, स्थिर काष्ठा sshauthopt *opts, पूर्णांक do_remote)
{
	पूर्णांक do_env = options.permit_user_env && opts->nenv > 0;
	पूर्णांक do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	पूर्णांक do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	माप_प्रकार i;
	अक्षर संदेश[1024], buf[64];

	snprintf(buf, माप(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(संदेश, माप(संदेश), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == शून्य ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == शून्य ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, संदेश);
	अगर (do_remote)
		auth_debug_add("%s: %s", loc, संदेश);

	अगर (options.permit_user_env) {
		क्रम (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			अगर (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	अगर (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, माप(buf));
		debug("%s: expires at %s", loc, buf);
	}
	अगर (opts->cert_principals != शून्य) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	अगर (opts->force_command != शून्य)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	अगर (do_permitopen) {
		क्रम (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	अगर (do_permitlisten) {
		क्रम (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
पूर्णांक
auth_activate_options(काष्ठा ssh *ssh, काष्ठा sshauthopt *opts)
{
	काष्ठा sshauthopt *old = auth_opts;
	स्थिर अक्षर *emsg = शून्य;

	debug_f("setting new authentication options");
	अगर ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == शून्य) {
		error("Inconsistent authentication options: %s", emsg);
		वापस -1;
	}
	sshauthopt_free(old);
	वापस 0;
}

/* Disable forwarding, etc for the session */
व्योम
auth_restrict_session(काष्ठा ssh *ssh)
{
	काष्ठा sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	अगर ((restricted = sshauthopt_new()) == शून्य)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	अगर (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
