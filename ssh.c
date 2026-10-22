/* $OpenBSD: ssh.c,v 1.642 2026/09/23 21:42:39 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Ssh client program.  This program can be used to log into a remote machine.
 * The software supports strong authentication, encryption, and forwarding
 * of X11, TCP/IP, and authentication connections.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 1999 Niels Provos.  All rights reserved.
 * Copyright (c) 2000, 2001, 2002, 2003 Markus Friedl.  All rights reserved.
 *
 * Modified to work with SSLeay by Niels Provos <provos@citi.umich.edu>
 * in Canada (German citizen).
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
#شامل <sys/socket.h>
#شامل <sys/stat.h>
#شامل <sys/wait.h>
#شامل <sys/utsname.h>

#شامل <ctype.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <limits.h>
#شامل <locale.h>

#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/evp.h>
#شامل <openssl/err.h>
#اگر_ختم
#شامل "openbsd-compat/openssl-compat.h"

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "compat.h"
#شامل "cipher.h"
#شامل "packet.h"
#شامل "sshbuf.h"
#شامل "channels.h"
#شامل "sshkey.h"
#شامل "authfd.h"
#شامل "authfile.h"
#شامل "pathnames.h"
#شامل "clientloop.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "readconf.h"
#شامل "sshconnect.h"
#شامل "kex.h"
#شامل "mac.h"
#شامل "match.h"
#شامل "version.h"
#شامل "ssherr.h"
#شامل "utf8.h"

#اگر_تعریف_شدہ ENABLE_PKCS11
#شامل "ssh-pkcs11.h"
#اگر_ختم

خارجی حرف *__progname;

/* Saves a copy of argv for setproctitle emulation */
#اگر_غیر_تعریف_شدہ HAVE_SETPROCTITLE
ساکن حرف **saved_av;
#اگر_ختم

/* Flag indicating whether debug mode is on.  May be set on the command line. */
صحیح debug_flag = 0;

/* Flag indicating whether a tty should be requested */
صحیح tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
ساکن صحیح need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
ساکن صحیح ostdin_null_flag, osession_type, otty_flag, orequest_tty;
ساکن صحیح ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
حرف *config = تہی;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
حرف *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
حرف *forward_agent_sock_راستہ = تہی;

/* socket address the host resolves to */
ساخت sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_ڈیٹا;

/* command to be executed */
ساخت sshbuf *command;

/* # of replies received for global requests */
ساکن صحیح forward_confirms_pending = -1;

/* mux.c */
خارجی صحیح muxserver_sock;
خارجی u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

ساکن خالی
usage(خالی)
{
	fprintf(stderr,
"usage: ssh [-46AaCfGgKkMNnqsTtVvXxYyZ] [-B bind_interface] [-b bind_address]\n"
"           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n"
"           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n"
"           [-J destination] [-L address] [-l login_name] [-m mac_spec]\n"
"           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]\n"
"           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]\n"
"           destination [command [argument ...]]\n"
"       ssh [-Q query_option]\n"
	);
	باہر_نکلو(255);
}

ساکن صحیح ssh_session2(ساخت ssh *, ثابت ساخت ssh_conn_info *);
ساکن خالی بھرو_عوامی_شناختی_عنصر_files(ثابت ساخت ssh_conn_info *);
ساکن خالی main_sigchld_handler(صحیح);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
ساکن خالی
tilde_expand_paths(حرف **paths, u_int عدد_paths)
{
	u_int i;
	حرف *cp;

	برائے (i = 0; i < عدد_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		آزاد(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
ساکن حرف *
default_client_percent_expand(ثابت حرف *str,
    ثابت ساخت ssh_conn_info *cinfo)
{
	واپس percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_دلائل(cinfo),
	    (حرف *)تہی);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
ساکن حرف *
default_client_percent_dollar_expand(ثابت حرف *str,
    ثابت ساخت ssh_conn_info *cinfo)
{
	حرف *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_دلائل(cinfo),
	    (حرف *)تہی);
	اگر (ret == تہی)
		fatal("invalid environment variable expansion");
	واپس ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ساکن ساخت addrinfo *
resolve_host(ثابت حرف *name, صحیح پورٹ, صحیح logerr, حرف *cname, سائز_t clen)
{
	حرف strport[NI_MAXSERV];
	ثابت حرف *errstr = تہی;
	ساخت addrinfo hints, *res;
	صحیح gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	اگر (پورٹ <= 0)
		پورٹ = default_ssh_پورٹ();
	اگر (cname != تہی)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, پورٹ);

	snprintf(strport, حجم strport, "%d", پورٹ);
	memset(&hints, 0, حجم(hints));
	hints.ai_family = options.پتہ_family == -1 ?
	    AF_UNSPEC : options.پتہ_family;
	hints.ai_socktype = SOCK_STREAM;
	اگر (cname != تہی)
		hints.ai_flags = AI_CANONNAME;
	اگر ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		اگر (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		واپس تہی;
	}
	اگر (cname != تہی && res->ai_canonname != تہی) {
		اگر (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} ورنہ اگر (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			اگر (clen > 0)
				*cname = '\0';
		}
	}
	واپس res;
}

/* Returns non-zero if name can only be an address and not a hostname */
ساکن صحیح
is_addr_fast(ثابت حرف *name)
{
	واپس (strchr(name, '%') != تہی || strchr(name, ':') != تہی ||
	    strspn(name, "0123456789.") == لڑی_لمبائی(name));
}

/* Returns non-zero if name represents a valid, single address */
ساکن صحیح
is_addr(ثابت حرف *name)
{
	حرف strport[NI_MAXSERV];
	ساخت addrinfo hints, *res;

	اگر (is_addr_fast(name))
		واپس 1;

	snprintf(strport, حجم strport, "%u", default_ssh_پورٹ());
	memset(&hints, 0, حجم(hints));
	hints.ai_family = options.پتہ_family == -1 ?
	    AF_UNSPEC : options.پتہ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	اگر (getaddrinfo(name, strport, &hints, &res) != 0)
		واپس 0;
	اگر (res == تہی || res->ai_next != تہی) {
		freeaddrinfo(res);
		واپس 0;
	}
	freeaddrinfo(res);
	واپس 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ساکن ساخت addrinfo *
resolve_addr(ثابت حرف *name, صحیح پورٹ, حرف *caddr, سائز_t clen)
{
	حرف addr[NI_MAXHOST], strport[NI_MAXSERV];
	ساخت addrinfo hints, *res;
	صحیح gaierr;

	اگر (پورٹ <= 0)
		پورٹ = default_ssh_پورٹ();
	snprintf(strport, حجم strport, "%u", پورٹ);
	memset(&hints, 0, حجم(hints));
	hints.ai_family = options.پتہ_family == -1 ?
	    AF_UNSPEC : options.پتہ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	اگر ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		واپس تہی;
	}
	اگر (res == تہی) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		واپس تہی;
	}
	اگر (res->ai_next != تہی) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		جاؤ fail;
	}
	اگر ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, حجم(addr), تہی, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		جاؤ fail;
	}
	اگر (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		اگر (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		واپس تہی;
	}
	واپس res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
ساکن صحیح
check_follow_cname(صحیح direct, حرف **namep, ثابت حرف *cname)
{
	صحیح i;
	ساخت allowed_cname *قاعدہ;

	اگر (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		واپس 0;
	اگر (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		واپس 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	اگر (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		واپس 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	برائے (i = 0; i < options.عدد_permitted_cnames; i++) {
		قاعدہ = options.permitted_cnames + i;
		اگر (مطابقت_نمونہ_list(*namep, قاعدہ->ماخذ_list, 1) != 1 ||
		    مطابقت_نمونہ_list(cname, قاعدہ->ہدف_list, 1) != 1)
			جاری;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		آزاد(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		واپس 1;
	}
	واپس 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
ساکن ساخت addrinfo *
resolve_canonicalize(حرف **hostp, صحیح پورٹ)
{
	صحیح i, direct, ndots;
	حرف *cp, *fullhost, newname[NI_MAXHOST];
	ساخت addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	اگر ((addrs = resolve_addr(*hostp, پورٹ,
	    newname, حجم(newname))) != تہی) {
		debug2_f("hostname %.100s is address", *hostp);
		اگر (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			آزاد(*hostp);
			*hostp = xstrdup(newname);
		}
		واپس addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	اگر (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		واپس تہی;
	}

	اگر (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		واپس تہی;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	اگر (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		واپس تہی;

	/* If domain name is anchored, then resolve it now */
	اگر ((*hostp)[لڑی_لمبائی(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		اگر ((addrs = resolve_host(fullhost, پورٹ, 0,
		    newname, حجم(newname))) != تہی)
			جاؤ ملا;
		آزاد(fullhost);
		جاؤ notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	برائے (cp = *hostp; *cp != '\0'; cp++) {
		اگر (*cp == '.')
			ndots++;
	}
	اگر (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		واپس تہی;
	}
	/* Attempt each supplied suffix */
	برائے (i = 0; i < options.عدد_canonical_domains; i++) {
		اگر (strcasecmp(options.canonical_domains[i], "none") == 0)
			توڑو;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		اگر ((addrs = resolve_host(fullhost, پورٹ, 0,
		    newname, حجم(newname))) == تہی) {
			آزاد(fullhost);
			جاری;
		}
 ملا:
		/* Remove trailing '.' */
		fullhost[لڑی_لمبائی(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		اگر (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		آزاد(*hostp);
		*hostp = fullhost;
		واپس addrs;
	}
 notfound:
	اگر (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	واپس تہی;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
ساکن خالی
check_بھرو(صحیح r, ساخت sshkey **k, ثابت حرف *راستہ, ثابت حرف *پیغام_2)
{
	حرف *fp;

	انتخاب (r) {
	حالت 0:
		اگر (k == تہی || *k == تہی)
			واپس;
		/* Check RSA keys size and discard if undersized */
		اگر ((r = sshkey_check_rsa_لمبائی(*k,
		    options.required_rsa_سائز)) != 0) {
			error_r(r, "load %s \"%s\"", پیغام_2, راستہ);
			آزاد(*k);
			*k = تہی;
			توڑو;
		}
		اگر ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == تہی) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), پیغام_2, راستہ);
		}
		debug("loaded %s from %s: %s %s", پیغام_2, راستہ,
		    sshkey_type(*k), fp);
		آزاد(fp);
		توڑو;
	حالت SSH_ERR_اندرونی_ERROR:
	حالت SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", پیغام_2, راستہ);
	حالت SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		اگر (errno == ENOENT)
			توڑو;
		/* FALLTHROUGH */
	طےشدہ:
		error_r(r, "load %s \"%s\"", پیغام_2, راستہ);
		توڑو;
	}
	اگر (k != تہی && *k == تہی)
		debug("no %s loaded from %s", پیغام_2, راستہ);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
ساکن خالی
process_config_files(ثابت حرف *host_name, ساخت passwd *pw,
    صحیح final_pass, صحیح *want_final_pass)
{
	حرف *cmd, buf[PATH_MAX];
	صحیح r;

	اگر ((cmd = sshbuf_dup_string(command)) == تہی)
		fatal_f("sshbuf_dup_string failed");
	اگر (config != تہی) {
		اگر (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} ورنہ {
		r = snprintf(buf, حجم buf, "%s/%s", pw->pw_dir,
		    راستہ_SSH_USER_CONFFILE);
		اگر (r > 0 && (سائز_t)r < حجم(buf))
			(خالی)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(خالی)read_config_file(راستہ_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	آزاد(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
ساکن خالی
سیٹ_addrinfo_پورٹ(ساخت addrinfo *addrs, صحیح پورٹ)
{
	ساخت addrinfo *addr;

	برائے (addr = addrs; addr != تہی; addr = addr->ai_next) {
		انتخاب (addr->ai_family) {
		حالت AF_INET:
			((ساخت sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(پورٹ);
			توڑو;
		حالت AF_INET6:
			((ساخت sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(پورٹ);
			توڑو;
		}
	}
}

/*
 * Main program for the ssh client.
 */
صحیح
مین(صحیح ac, حرف **av)
{
	ساخت ssh *ssh = تہی;
	صحیح i, r, opt, exit_حالت, use_syslog, direct, timeout_ms;
	صحیح was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	صحیح user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	حرف *p, *cp, *سطر, *argv0, *logfile, *دلائل;
	حرف cname[NI_MAXHOST], thishost[NI_MAXHOST];
	ساخت stat st;
	ساخت passwd *pw;
	خارجی صحیح optind, optreset;
	خارجی حرف *optarg;
	ساخت Forward fwd;
	ساخت addrinfo *addrs = تہی;
	سائز_t n, len;
	u_int j;
	ساخت utsname utsname;
	ساخت ssh_conn_info *cinfo = تہی;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/*
	 * Discard other fds that are hanging around. These can cause problem
	 * with backgrounded ssh processes started by ControlPersist.
	 */
	closefrom(STDERR_FILENO + 1);

	__progname = ssh_get_progname(av[0]);

#اگر_غیر_تعریف_شدہ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	/* Save argv so it isn't clobbered by setproctitle() emulation */
	saved_av = xcalloc(ac + 1, حجم(*saved_av));
	برائے (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = تہی;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#اگر_ختم

	بیج_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	اگر (!pw) {
		logit("No user exists for uid %lu", (u_long)getuid());
		باہر_نکلو(255);
	}
	/* Take a copy of the returned structure. */
	pw = pwcopy(pw);

	/*
	 * Set our umask to something reasonable, as some files are created
	 * with the default umask.  This will make them world-readable but
	 * writable only by the owner, which is ok for all files for which we
	 * don't set the modes explicitly.
	 */
	umask(022 | umask(077));

	msetlocale();

	/*
	 * Initialize option structure to indicate that no values have been
	 * set.
	 */
	initialize_options(&options);

	/*
	 * Prepare main ssh transport/connection structures
	 */
	اگر ((ssh = ssh_alloc_session_state()) == تہی)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	دلائل = argv_assemble(ac, av); /* logged later */
	host = تہی;
	use_syslog = 0;
	logfile = تہی;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	جب ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		انتخاب (opt) {
		حالت '1':
			fatal("SSH protocol v.1 is no longer supported");
			توڑو;
		حالت '2':
			/* Ignored */
			توڑو;
		حالت '4':
			options.پتہ_family = AF_INET;
			توڑو;
		حالت '6':
			options.پتہ_family = AF_INET6;
			توڑو;
		حالت 'n':
			options.stdin_null = 1;
			توڑو;
		حالت 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			توڑو;
		حالت 'x':
			options.forward_x11 = 0;
			توڑو;
		حالت 'X':
			options.forward_x11 = 1;
			توڑو;
		حالت 'y':
			use_syslog = 1;
			توڑو;
		حالت 'E':
			logfile = optarg;
			توڑو;
		حالت 'G':
			config_test = 1;
			توڑو;
		حالت 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			توڑو;
		حالت 'Z':
			dump_pubkeys = 1;
			توڑو;
		حالت 'g':
			options.fwd_opts.gateway_ports = 1;
			توڑو;
		حالت 'O':
			اگر (options.stdio_forward_host != تہی)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			ورنہ اگر (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			اگر (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			ورنہ اگر (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			ورنہ اگر (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			ورنہ اگر (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			ورنہ اگر (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			ورنہ اگر (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			ورنہ اگر (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			ورنہ اگر (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			ورنہ
				fatal("Invalid multiplex command.");
			توڑو;
		حالت 'P':
			اگر (options.لیبل == تہی)
				options.لیبل = xstrdup(optarg);
			توڑو;
		حالت 'Q':
			cp = تہی;
			اگر (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			ورنہ اگر (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			ورنہ اگر (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			ورنہ اگر (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			ورنہ اگر (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			ورنہ اگر (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			ورنہ اگر (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			ورنہ اگر (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ورنہ اگر (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			ورنہ اگر (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ورنہ اگر (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			ورنہ اگر (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = لڑی_لمبائی(cp);
				برائے (n = 0; n < len; n++)
					اگر (cp[n] == ',')
						cp[n] = '\n';
			} ورنہ اگر (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			اگر (cp == تہی)
				fatal("Unsupported query \"%s\"", optarg);
			لکھو("%s\n", cp);
			آزاد(cp);
			باہر_نکلو(0);
			توڑو;
		حالت 'a':
			options.forward_agent = 0;
			توڑو;
		حالت 'A':
			options.forward_agent = 1;
			توڑو;
		حالت 'k':
			options.gss_deleg_creds = 0;
			توڑو;
		حالت 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			توڑو;
		حالت 'i':
			p = tilde_expand_filename(optarg, getuid());
			اگر (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			ورنہ
				جوڑو_شناختی_عنصر_file(&options, تہی, p, 1);
			آزاد(p);
			توڑو;
		حالت 'I':
#اگر_تعریف_شدہ ENABLE_PKCS11
			آزاد(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#ورنہ
			fprintf(stderr, "no support for PKCS#11.\n");
#اگر_ختم
			توڑو;
		حالت 'J':
			اگر (options.jump_host != تہی) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			اگر (options.proxy_command != تہی)
				fatal("Cannot specify -J with ProxyCommand");
			اگر (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			توڑو;
		حالت 't':
			اگر (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			ورنہ
				options.request_tty = REQUEST_TTY_YES;
			توڑو;
		حالت 'v':
			اگر (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ورنہ {
				اگر (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			توڑو;
		حالت 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_نسخہ);
			باہر_نکلو(0);
			توڑو;
		حالت 'w':
			اگر (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			اگر (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				باہر_نکلو(255);
			}
			توڑو;
		حالت 'W':
			اگر (options.stdio_forward_host != تہی)
				fatal("stdio forward already specified");
			اگر (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			اگر (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_پورٹ == پورٹ_STREAMLOCAL ?
				    fwd.listen_راستہ : fwd.listen_host;
				options.stdio_forward_پورٹ = fwd.listen_پورٹ;
				آزاد(fwd.connect_host);
			} ورنہ {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				باہر_نکلو(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			توڑو;
		حالت 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			توڑو;
		حالت 'e':
			اگر (لڑی_لمبائی(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			ورنہ اگر (لڑی_لمبائی(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			ورنہ اگر (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			ورنہ {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				باہر_نکلو(255);
			}
			توڑو;
		حالت 'c':
			اگر (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				باہر_نکلو(255);
			}
			آزاد(options.ciphers);
			options.ciphers = xstrdup(optarg);
			توڑو;
		حالت 'm':
			اگر (mac_valid(optarg)) {
				آزاد(options.macs);
				options.macs = xstrdup(optarg);
			} ورنہ {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				باہر_نکلو(255);
			}
			توڑو;
		حالت 'M':
			اگر (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			ورنہ
				options.control_master = SSHCTL_MASTER_YES;
			توڑو;
		حالت 'p':
			اگر (options.پورٹ == -1) {
				options.پورٹ = a2port(optarg);
				اگر (options.پورٹ <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					باہر_نکلو(255);
				}
			}
			توڑو;
		حالت 'l':
			اگر (options.user == تہی) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			توڑو;

		حالت 'L':
			اگر (parse_forward(&fwd, optarg, 0, 0))
				جوڑو_local_forward(&options, &fwd);
			ورنہ {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				باہر_نکلو(255);
			}
			توڑو;

		حالت 'R':
			اگر (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				جوڑو_remote_forward(&options, &fwd);
			} ورنہ {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				باہر_نکلو(255);
			}
			توڑو;

		حالت 'D':
			اگر (parse_forward(&fwd, optarg, 1, 0)) {
				جوڑو_local_forward(&options, &fwd);
			} ورنہ {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				باہر_نکلو(255);
			}
			توڑو;

		حالت 'C':
#اگر_تعریف_شدہ WITH_ZLIB
			options.compression = 1;
#ورنہ
			error("Compression not supported, disabling.");
#اگر_ختم
			توڑو;
		حالت 'N':
			اگر (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			توڑو;
		حالت 'T':
			options.request_tty = REQUEST_TTY_NO;
			توڑو;
		حالت 'o':
			سطر = xstrdup(optarg);
			اگر (process_config_سطر(&options, pw,
			    host ? host : "", host ? host : "", "", سطر,
			    "command-line", 0, تہی, SSHCONF_USERCONF) != 0)
				باہر_نکلو(255);
			آزاد(سطر);
			توڑو;
		حالت 's':
			اگر (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			توڑو;
		حالت 'S':
			آزاد(options.control_راستہ);
			options.control_راستہ = xstrdup(optarg);
			توڑو;
		حالت 'b':
			options.bind_پتہ = optarg;
			توڑو;
		حالت 'B':
			options.bind_interface = optarg;
			توڑو;
		حالت 'F':
			config = optarg;
			توڑو;
		طےشدہ:
			usage();
		}
	}

	اگر (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	اگر (ac > 0 && !host) {
		صحیح tport;
		حرف *tuser;
		انتخاب (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		حالت -1:
			usage();
			توڑو;
		حالت 0:
			اگر (options.user == تہی) {
				options.user = tuser;
				tuser = تہی;
				user_on_commandline = 1;
			}
			آزاد(tuser);
			اگر (options.پورٹ == -1 && tport != -1)
				options.پورٹ = tport;
			توڑو;
		طےشدہ:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			اگر (cp != تہی) {
				اگر (cp == p)
					usage();
				اگر (options.user == تہی) {
					options.user = p;
					p = تہی;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				آزاد(p);
			} ورنہ
				host = p;
			توڑو;
		}
		اگر (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			جاؤ again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	اگر (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	اگر (options.user != تہی && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	اگر (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	اگر ((command = sshbuf_new()) == تہی)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	اگر (!ac) {
		/* No command specified - execute shell on a tty. */
		اگر (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} ورنہ {
		/* A command has been specified.  Store it into the buffer. */
		برائے (i = 0; i < ac; i++) {
			اگر ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	اگر (use_syslog && logfile != تہی)
		fatal("Can't specify both -y and -E");
	اگر (logfile != تہی)
		log_redirect_stderr_مقصد(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_سیٹ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_سیٹ ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_نسخہ);
	اگر (uname(&utsname) != 0) {
		memset(&utsname, 0, حجم(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", حجم(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.نسخہ, utsname.machine);
	debug3("Started with: %s", دلائل);
	آزاد(دلائل);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	اگر (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	اگر (options.hostname != تہی) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (حرف *)تہی);
		آزاد(host);
		host = cp;
		آزاد(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	اگر ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	اگر (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
		addrs = resolve_canonicalize(&host, options.پورٹ);

	/*
	 * If CanonicalizePermittedCNAMEs have been specified but
	 * other canonicalization did not happen (by not being requested
	 * or by failing with fallback) then the hostname may still be changed
	 * as a result of CNAME following.
	 *
	 * Try to resolve the bare hostname name using the system resolver's
	 * usual search rules and then apply the CNAME follow rules.
	 *
	 * Skip the lookup if a ProxyCommand is being used unless the user
	 * has specifically requested canonicalisation for this case via
	 * CanonicalizeHostname=always
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	اگر (addrs == تہی && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		اگر ((addrs = resolve_host(host, options.پورٹ,
		    direct, cname, حجم(cname))) == تہی) {
			/* Don't fatal proxied host names not in the DNS */
			اگر (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} ورنہ
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	اگر (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	اگر (want_final_pass) {
		debug("re-parsing configuration");
		آزاد(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, تہی);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		اگر (addrs != تہی && options.پورٹ > 0)
			سیٹ_addrinfo_پورٹ(addrs, options.پورٹ);
	}

	/* Fill configuration defaults. */
	اگر (fill_default_options(&options) != 0)
		cleanup_exit(255);

	اگر (options.user == تہی) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	اگر (options.jump_host != تہی) {
		حرف پورٹ_s[8];
		ثابت حرف *jumpuser = options.jump_user, *sshbin = argv0;
		صحیح پورٹ = options.پورٹ, jumpport = options.jump_پورٹ;

		اگر (پورٹ <= 0)
			پورٹ = default_ssh_پورٹ();
		اگر (jumpport <= 0)
			jumpport = default_ssh_پورٹ();
		اگر (jumpuser == تہی)
			jumpuser = options.user;
		اگر (strcmp(options.jump_host, host) == 0 && پورٹ == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		اگر (strchr(argv0, '/') != تہی && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		اگر (options.proxy_command != تہی &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(پورٹ_s, حجم(پورٹ_s), "%d", options.jump_پورٹ);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == تہی ? "" : " -l ",
		    options.jump_user == تہی ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_پورٹ <= 0 ? "" : " -p ",
		    options.jump_پورٹ <= 0 ? "" : پورٹ_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == تہی ? "" : " -J ",
		    options.jump_extra == تہی ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == تہی ? "" : " -F ",
		    config == تہی ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	اگر (options.پورٹ == 0)
		options.پورٹ = default_ssh_پورٹ();
	channel_سیٹ_af(ssh, options.پتہ_family);
	ssh_packet_سیٹ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	اگر (options.host_کلید_alias != تہی)
		lowercase(options.host_کلید_alias);
	اگر (options.proxy_command != تہی &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	اگر (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		اگر (options.control_persist && options.control_راستہ != تہی) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} ورنہ اگر (sshbuf_len(command) != 0 ||
		    options.remote_command != تہی ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} ورنہ اگر (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	اگر (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	اگر (sshbuf_len(command) != 0 && options.remote_command != تہی)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	اگر (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == تہی &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	برائے (j = 0; j < options.عدد_log_verbose; j++) {
		اگر (strcasecmp(options.log_verbose[j], "none") == 0)
			توڑو;
		log_verbose_جوڑو(options.log_verbose[j]);
	}

	اگر (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	اگر (sshbuf_len(command) == 0 && options.remote_command == تہی)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	اگر (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	اگر ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		اگر (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, حجم(*cinfo));
	اگر (gethostname(thishost, حجم(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.پورٹ);
	xasprintf(&cinfo->uidstr, "%llu",
	    (غیرعلامتی طویل طویل)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_کلید_alias ?
	    options.host_کلید_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == تہی ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	اگر (!user_on_commandline && !user_was_default) {
		اگر ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_دلائل_NOUSER(cinfo),
		    (حرف *)تہی)) == تہی)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		آزاد(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	اگر ((user_on_commandline || user_expanded) &&
	    !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");

	/* Now User is expanded, store it and calculate hash. */
	cinfo->remuser = xstrdup(options.user);
	cinfo->conn_hash_hex = ssh_connection_hash(cinfo->thishost,
	    cinfo->remhost, cinfo->portstr, cinfo->remuser, cinfo->jmphost);

	/*
	 * Expand tokens in arguments. NB. LocalCommand is expanded later,
	 * after port-forwarding is set up, so it may pick up any local
	 * tunnel interface name allocated.
	 */
	اگر (options.remote_command != تہی) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		آزاد(cp);
		اگر ((r = sshbuf_put(command, options.remote_command,
		    لڑی_لمبائی(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	اگر (options.control_راستہ != تہی) {
		cp = tilde_expand_filename(options.control_راستہ, getuid());
		آزاد(options.control_راستہ);
		options.control_راستہ = default_client_percent_dollar_expand(cp,
		    cinfo);
		آزاد(cp);
	}

	اگر (options.شناختی_عنصر_agent != تہی) {
		p = tilde_expand_filename(options.شناختی_عنصر_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		آزاد(p);
		آزاد(options.شناختی_عنصر_agent);
		options.شناختی_عنصر_agent = cp;
	}

	برائے (j = 0; j < options.عدد_revoked_host_کلیدیں; j++) {
		p = tilde_expand_filename(options.revoked_host_کلیدیں[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		آزاد(p);
		آزاد(options.revoked_host_کلیدیں[j]);
		options.revoked_host_کلیدیں[j] = cp;
	}

	اگر (options.forward_agent_sock_راستہ != تہی) {
		p = tilde_expand_filename(options.forward_agent_sock_راستہ,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		آزاد(p);
		آزاد(options.forward_agent_sock_راستہ);
		options.forward_agent_sock_راستہ = cp;
		اگر (stat(options.forward_agent_sock_راستہ, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_راستہ, strerror(errno));
			اگر (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	اگر (options.نسخہ_addendum != تہی) {
		cp = default_client_percent_dollar_expand(
		    options.نسخہ_addendum, cinfo);
		آزاد(options.نسخہ_addendum);
		options.نسخہ_addendum = cp;
	}

	اگر (options.عدد_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		اگر (options.عدد_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		آزاد(options.system_hostfiles[0]);
		options.system_hostfiles[0] = تہی;
		options.عدد_system_hostfiles = 0;
	}

	اگر (options.عدد_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		اگر (options.عدد_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		آزاد(options.user_hostfiles[0]);
		options.user_hostfiles[0] = تہی;
		options.عدد_user_hostfiles = 0;
	}
	برائے (j = 0; j < options.عدد_user_hostfiles; j++) {
		اگر (options.user_hostfiles[j] == تہی)
			جاری;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		اگر (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		آزاد(options.user_hostfiles[j]);
		آزاد(cp);
		options.user_hostfiles[j] = p;
	}

	برائے (j = 0; j < options.عدد_setenv; j++) {
		حرف *name = options.setenv[j], *قدر;

		اگر (name == تہی)
			جاری;
		/* Expand only the value portion, not the variable name. */
		اگر ((قدر = strchr(name, '=')) == تہی) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*قدر++ = '\0';
		cp = default_client_percent_dollar_expand(قدر, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		اگر (strcmp(قدر, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, قدر, cp);
		}
		آزاد(options.setenv[j]);
		آزاد(cp);
		options.setenv[j] = p;
	}

	برائے (i = 0; i < options.عدد_local_forwards; i++) {
		اگر (options.local_forwards[i].listen_راستہ != تہی) {
			cp = options.local_forwards[i].listen_راستہ;
			p = options.local_forwards[i].listen_راستہ =
			    default_client_percent_expand(cp, cinfo);
			اگر (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			آزاد(cp);
		}
		اگر (options.local_forwards[i].connect_راستہ != تہی) {
			cp = options.local_forwards[i].connect_راستہ;
			p = options.local_forwards[i].connect_راستہ =
			    default_client_percent_expand(cp, cinfo);
			اگر (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			آزاد(cp);
		}
	}

	برائے (i = 0; i < options.عدد_remote_forwards; i++) {
		اگر (options.remote_forwards[i].listen_راستہ != تہی) {
			cp = options.remote_forwards[i].listen_راستہ;
			p = options.remote_forwards[i].listen_راستہ =
			    default_client_percent_expand(cp, cinfo);
			اگر (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			آزاد(cp);
		}
		اگر (options.remote_forwards[i].connect_راستہ != تہی) {
			cp = options.remote_forwards[i].connect_راستہ;
			p = options.remote_forwards[i].connect_راستہ =
			    default_client_percent_expand(cp, cinfo);
			اگر (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			آزاد(cp);
		}
	}

	اگر (config_test) {
		dump_client_config(&options, host);
		باہر_نکلو(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	اگر (options.sk_provider != تہی && *options.sk_provider == '$' &&
	    لڑی_لمبائی(options.sk_provider) > 1) {
		اگر ((cp = getenv(options.sk_provider + 1)) == تہی) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			آزاد(options.sk_provider);
			options.sk_provider = تہی;
		} ورنہ {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			آزاد(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	اگر (muxclient_command != 0 && options.control_راستہ == تہی)
		fatal("No ControlPath specified for \"-O\" command");
	اگر (options.control_راستہ != تہی) {
		صحیح sock;
		اگر ((sock = muxclient(options.control_راستہ)) >= 0) {
			اگر (ssh_packet_سیٹ_connection(ssh, sock, sock) == تہی)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_سیٹ_mux(ssh);
			جاؤ skip_connect;
		}
	}

	/* load options.identity_files */
	بھرو_عوامی_شناختی_عنصر_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	اگر (options.شناختی_عنصر_agent &&
	    strcmp(options.شناختی_عنصر_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		اگر (strcmp(options.شناختی_عنصر_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} ورنہ {
			cp = options.شناختی_عنصر_agent;
			/* legacy (limited) format */
			اگر (cp[0] == '$' && cp[1] != '{') {
				اگر (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				اگر ((p = getenv(cp + 1)) == تہی)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				ورنہ
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} ورنہ {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	اگر (dump_pubkeys) {
		pubkey_dump(ssh);
		باہر_نکلو(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	اگر (addrs == تہی && options.proxy_command == تہی) {
		debug2("resolving \"%s\" port %d", host, options.پورٹ);
		اگر ((addrs = resolve_host(host, options.پورٹ, 1,
		    cname, حجم(cname))) == تہی)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	اگر (options.connection_timeout >= زیادہ_سے_زیادہ_عدد/1000)
		timeout_ms = زیادہ_سے_زیادہ_عدد;
	ورنہ
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	برائے (j = 0; j < options.عدد_channel_timeouts; j++) {
		دوہرا timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		اگر (parse_نمونہ_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_جوڑو_timeout(ssh, cp, timeout);
		آزاد(cp);
	}
	channel_سیٹ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	اگر (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.پورٹ, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		باہر_نکلو(255);


	ssh_packet_سیٹ_timeout(ssh, options.server_alive_interval,
	    options.server_alive_گنتی_max);

	اگر (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_ڈیٹا.nkeys = 0;
	sensitive_ڈیٹا.کلیدیں = تہی;
	اگر (options.hostbased_authentication) {
		صحیح loaded = 0;

		sensitive_ڈیٹا.nkeys = 10;
		sensitive_ڈیٹا.کلیدیں = xcalloc(sensitive_ڈیٹا.nkeys,
		    حجم(*sensitive_ڈیٹا.کلیدیں));

		/* XXX check errors? */
#تعریف_کرو L_PUBKEY(p,o) کرو { \
	اگر ((o) >= sensitive_ڈیٹا.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_بھرو(sshkey_بھرو_عوامی(p, &(sensitive_ڈیٹا.کلیدیں[o]), تہی), \
	    &(sensitive_ڈیٹا.کلیدیں[o]), p, "hostbased pubkey"); \
	اگر (sensitive_ڈیٹا.کلیدیں[o] != تہی) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} جب (0)
#تعریف_کرو L_CERT(p,o) کرو { \
	اگر ((o) >= sensitive_ڈیٹا.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_بھرو(sshkey_بھرو_cert(p, &(sensitive_ڈیٹا.کلیدیں[o])), \
	    &(sensitive_ڈیٹا.کلیدیں[o]), p, "hostbased cert"); \
	اگر (sensitive_ڈیٹا.کلیدیں[o] != تہی) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} جب (0)

		اگر (options.hostbased_authentication == 1) {
			L_CERT(راستہ_HOST_ECDSA_کلید_FILE, 0);
			L_CERT(راستہ_HOST_ED25519_کلید_FILE, 1);
			L_CERT(راستہ_HOST_RSA_کلید_FILE, 2);
			L_CERT(راستہ_HOST_MLDSA44_ED25519_کلید_FILE, 3);
			L_PUBKEY(راستہ_HOST_ECDSA_کلید_FILE, 4);
			L_PUBKEY(راستہ_HOST_ED25519_کلید_FILE, 5);
			L_PUBKEY(راستہ_HOST_RSA_کلید_FILE, 6);
			L_PUBKEY(راستہ_HOST_MLDSA44_ED25519_کلید_FILE, 7);
			اگر (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	اگر (options.forward_agent && options.forward_agent_sock_راستہ != تہی) {
		cp = options.forward_agent_sock_راستہ;
		اگر (cp[0] == '$') {
			اگر (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			اگر ((p = getenv(cp + 1)) != تہی)
				forward_agent_sock_راستہ = xstrdup(p);
			ورنہ
				options.forward_agent = 0;
			آزاد(cp);
		} ورنہ {
			forward_agent_sock_راستہ = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.عدد_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.عدد_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_ڈیٹا, host, &hostaddr, options.پورٹ,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	اگر (sensitive_ڈیٹا.nkeys != 0) {
		برائے (i = 0; i < sensitive_ڈیٹا.nkeys; i++) {
			اگر (sensitive_ڈیٹا.کلیدیں[i] != تہی) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_ڈیٹا.کلیدیں[i]);
				sensitive_ڈیٹا.کلیدیں[i] = تہی;
			}
		}
		آزاد(sensitive_ڈیٹا.کلیدیں);
	}
	برائے (i = 0; i < options.عدد_شناختی_عنصر_files; i++) {
		آزاد(options.شناختی_عنصر_files[i]);
		options.شناختی_عنصر_files[i] = تہی;
		اگر (options.شناختی_عنصر_کلیدیں[i]) {
			sshkey_free(options.شناختی_عنصر_کلیدیں[i]);
			options.شناختی_عنصر_کلیدیں[i] = تہی;
		}
	}
	برائے (i = 0; i < options.عدد_certificate_files; i++) {
		آزاد(options.certificate_files[i]);
		options.certificate_files[i] = تہی;
	}

#اگر_تعریف_شدہ ENABLE_PKCS11
	(خالی)pkcs11_del_provider(options.pkcs11_provider);
#اگر_ختم

 skip_connect:
	اگر (addrs != تہی)
		freeaddrinfo(addrs);
	exit_حالت = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	اگر (options.control_راستہ != تہی && muxserver_sock != -1)
		unlink(options.control_راستہ);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	واپس exit_حالت;
}

ساکن خالی
control_persist_detach(خالی)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	انتخاب ((pid = fork())) {
	حالت -1:
		fatal_f("fork: %s", strerror(errno));
	حالت 0:
		/* Child: master process continues mainloop */
		توڑو;
	طےشدہ:
		/*
		 * Parent: set up mux client to connect to backgrounded
		 * master.
		 */
		debug2_f("background process is %ld", (طویل)pid);
		options.stdin_null = ostdin_null_flag;
		options.request_tty = orequest_tty;
		tty_flag = otty_flag;
		options.fork_after_authentication = ofork_after_authentication;
		options.session_type = osession_type;
		close(muxserver_sock);
		muxserver_sock = -1;
		options.control_master = SSHCTL_MASTER_NO;
		(خالی)muxclient(options.control_راستہ);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	اگر (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_راستہ);
}

/* Do fork() after authentication. Used by "ssh -f" */
ساکن خالی
fork_postauth(خالی)
{
	اگر (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	اگر (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	اگر (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

ساکن خالی
forwarding_success(خالی)
{
	اگر (forward_confirms_pending == -1)
		واپس;
	اگر (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		اگر (options.fork_after_authentication)
			fork_postauth();
	} ورنہ {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

ساخت rfwd_confirm_ctx {
	صحیح fid;
};

/* Callback for remote forward global requests */
ساکن خالی
ssh_confirm_remote_forward(ساخت ssh *ssh, صحیح type, uint32_t seq, خالی *ctxt)
{
	ساخت rfwd_confirm_ctx *rctx = (ساخت rfwd_confirm_ctx *)ctxt;
	ساخت Forward *rfwd;
	u_int پورٹ;
	صحیح r;

	اگر (rctx->fid < 0 || rctx->fid >= options.عدد_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, حجم(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_پیغام_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_راستہ ? rfwd->listen_راستہ :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_راستہ || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_پورٹ, rfwd->connect_راستہ ? rfwd->connect_راستہ :
	    rfwd->connect_host, rfwd->connect_پورٹ);
	اگر (rfwd->listen_راستہ == تہی && rfwd->listen_پورٹ == 0) {
		اگر (type == SSH2_پیغام_REQUEST_SUCCESS) {
			اگر ((r = sshpkt_get_u32(ssh, &پورٹ)) != 0)
				fatal_fr(r, "parse packet");
			اگر (پورٹ > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", پورٹ,
				    rfwd->connect_host, rfwd->connect_پورٹ);
				/* Ensure failure processing runs below */
				type = SSH2_پیغام_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} ورنہ {
				rfwd->allocated_پورٹ = (صحیح)پورٹ;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_پورٹ, rfwd->connect_راستہ ?
				    rfwd->connect_راستہ : rfwd->connect_host,
				    rfwd->connect_پورٹ);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_پورٹ);
			}
		} ورنہ {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	اگر (type == SSH2_پیغام_REQUEST_FAILURE) {
		اگر (options.exit_on_forward_failure) {
			اگر (rfwd->listen_راستہ != تہی)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_راستہ);
			ورنہ
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_پورٹ);
		} ورنہ {
			اگر (rfwd->listen_راستہ != تہی)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_راستہ);
			ورنہ
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_پورٹ);
		}
	}
	forwarding_success();
}

ساکن خالی
client_cleanup_stdio_fwd(ساخت ssh *ssh, صحیح id, صحیح force, خالی *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

ساکن خالی
ssh_stdio_confirm(ساخت ssh *ssh, صحیح id, صحیح success, خالی *arg)
{
	اگر (!success)
		fatal("stdio forwarding failed");
}

ساکن خالی
ssh_tun_confirm(ساخت ssh *ssh, صحیح id, صحیح success, خالی *arg)
{
	اگر (!success) {
		error("Tunnel forwarding failed");
		اگر (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

ساکن خالی
ssh_init_stdio_forwarding(ساخت ssh *ssh)
{
	Channel *c;
	صحیح اندر, برآمد;

	اگر (options.stdio_forward_host == تہی)
		واپس;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_پورٹ);

	اگر ((اندر = dup(STDIN_FILENO)) == -1 ||
	    (برآمد = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	اگر ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_پورٹ, اندر, برآمد,
	    CHANNEL_NONBLOCK_STDIO)) == تہی)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_رجسٹر_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_رجسٹر_open_confirm(ssh, c->self, ssh_stdio_confirm, تہی);
}

ساکن خالی
ssh_init_forward_permissions(ساخت ssh *ssh, ثابت حرف *what, حرف **opens,
    u_int عدد_opens)
{
	u_int i;
	صحیح پورٹ;
	حرف *addr, *arg, *oarg;
	صحیح where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	اگر (عدد_opens == 0)
		واپس; /* permit any */

	/* handle keywords: "any" / "none" */
	اگر (عدد_opens == 1 && strcmp(opens[0], "any") == 0)
		واپس;
	اگر (عدد_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		واپس;
	}
	/* Otherwise treat it as a list of permitted host:port */
	برائے (i = 0; i < عدد_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		اگر (addr == تہی)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		اگر (arg == تہی || ((پورٹ = permitopen_پورٹ(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_جوڑو_permission(ssh, FORWARD_ADM,
		    where, addr, پورٹ);
		آزاد(oarg);
	}
}

ساکن خالی
ssh_init_forwarding(ساخت ssh *ssh, حرف **ifname)
{
	صحیح success = 0;
	صحیح i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.عدد_permitted_remote_opens);

	اگر (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	برائے (i = 0; i < options.عدد_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_راستہ != تہی) ?
		    options.local_forwards[i].listen_راستہ :
		    (options.local_forwards[i].listen_host == تہی) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_پورٹ,
		    (options.local_forwards[i].connect_راستہ != تہی) ?
		    options.local_forwards[i].connect_راستہ :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_پورٹ);
		success += channel_تیاری_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	اگر (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	اگر (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	برائے (i = 0; i < options.عدد_remote_forwards; i++) {
		ساخت rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_راستہ != تہی) ?
		    options.remote_forwards[i].listen_راستہ :
		    (options.remote_forwards[i].listen_host == تہی) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_پورٹ,
		    (options.remote_forwards[i].connect_راستہ != تہی) ?
		    options.remote_forwards[i].connect_راستہ :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_پورٹ);
		اگر ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, حجم(*rctx));
			rctx->fid = i;
			client_رجسٹر_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} ورنہ اگر (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		ورنہ
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	اگر (options.tun_open != SSH_TUNMODE_NO) {
		اگر ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, تہی)) != تہی)
			forward_confirms_pending++;
		ورنہ اگر (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		ورنہ
			error("Could not request tunnel forwarding.");
	}
	اگر (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

ساکن خالی
check_agent_present(خالی)
{
	صحیح r;

	اگر (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		اگر ((r = ssh_get_authentication_socket(تہی)) != 0) {
			options.forward_agent = 0;
			اگر (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

ساکن خالی
ssh_session2_تیاری(ساخت ssh *ssh, صحیح id, صحیح success, خالی *arg)
{
	خارجی حرف **environ;
	ثابت حرف *display, *رکن;
	حرف *proto = تہی, *ڈیٹا = تہی;

	اگر (!success)
		واپس; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	اگر (display == تہی && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	اگر (options.forward_x11 && client_x11_get_proto(ssh, display,
	    options.xauth_location, options.forward_x11_trusted,
	    options.forward_x11_timeout, &proto, &ڈیٹا) == 0) {
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(ssh, id, display, proto,
		    ڈیٹا, 1);
		client_expect_confirm(ssh, id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
	}

	check_agent_present();
	اگر (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	اگر ((رکن = lookup_env_اندر_list("TERM", options.setenv,
	    options.عدد_setenv)) == تہی || *رکن == '\0')
		رکن = getenv("TERM");
	client_session2_تیاری(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, رکن,
	    تہی, fileno(stdin), command, environ);
}

/* open new channel for a session */
ساکن صحیح
ssh_session2_open(ساخت ssh *ssh)
{
	Channel *c;
	صحیح کھڑکی, packetmax, اندر, برآمد, err;

	اگر (options.stdin_null) {
		اندر = open(_PATH_DEVNULL, O_RDONLY);
	} ورنہ {
		اندر = dup(STDIN_FILENO);
	}
	برآمد = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	اگر (اندر == -1 || برآمد == -1 || err == -1)
		fatal("dup() in/out/err failed");

	کھڑکی = CHAN_SES_کھڑکی_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	اگر (tty_flag) {
		کھڑکی >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, اندر, برآمد, err,
	    کھڑکی, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	اگر (tty_flag)
		channel_سیٹ_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	اگر (options.session_type != SESSION_TYPE_NONE)
		channel_رجسٹر_open_confirm(ssh, c->self,
		    ssh_session2_تیاری, تہی);

	واپس c->self;
}

ساکن صحیح
ssh_session2(ساخت ssh *ssh, ثابت ساخت ssh_conn_info *cinfo)
{
	صحیح r, id = -1;
	حرف *cp, *tun_fwd_ifname = تہی;

	/* XXX should be pre-session */
	اگر (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	اگر (options.local_command != تہی) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_دلائل(cinfo),
		    "T", tun_fwd_ifname == تہی ? "NONE" : tun_fwd_ifname,
		    (حرف *)تہی);
		debug3("expanded LocalCommand: %s", options.local_command);
		آزاد(cp);
	}

	/* Start listening for multiplex clients */
	اگر (!ssh_packet_get_mux(ssh))
		muxserver_listen(ssh);

	/*
	 * If we are in control persist mode and have a working mux listen
	 * socket, then prepare to background ourselves and have a foreground
	 * client attach as a control client.
	 * NB. we must save copies of the flags that we override for
	 * the backgrounding, since we defer attachment of the client until
	 * after the connection is fully established (in particular,
	 * async rfwd replies have been received for ExitOnForwardFailure).
	 */
	اگر (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		اگر ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != تہی))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	اگر (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	اگر (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	اگر (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	اگر (options.local_command != تہی &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	اگر (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	اگر (options.fork_after_authentication) {
		اگر (options.exit_on_forward_failure &&
		    options.عدد_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} ورنہ
			fork_postauth();
	}

	واپس client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
ساکن خالی
بھرو_عوامی_شناختی_عنصر_files(ثابت ساخت ssh_conn_info *cinfo)
{
	حرف *filename, *cp;
	ساخت sshkey *عوامی;
	صحیح i;
	u_int n_ids, n_certs;
	حرف *شناختی_عنصر_files[SSH_MAX_شناختی_عنصر_FILES];
	ساخت sshkey *شناختی_عنصر_کلیدیں[SSH_MAX_شناختی_عنصر_FILES];
	صحیح شناختی_عنصر_file_userprovided[SSH_MAX_شناختی_عنصر_FILES];
	حرف *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ساخت sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	صحیح certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#اگر_تعریف_شدہ ENABLE_PKCS11
	ساخت sshkey **کلیدیں = تہی;
	حرف **comments = تہی;
	صحیح nkeys;
#اگر_ختم /* PKCS11 */

	n_ids = n_certs = 0;
	memset(شناختی_عنصر_files, 0, حجم(شناختی_عنصر_files));
	memset(شناختی_عنصر_کلیدیں, 0, حجم(شناختی_عنصر_کلیدیں));
	memset(شناختی_عنصر_file_userprovided, 0,
	    حجم(شناختی_عنصر_file_userprovided));
	memset(certificate_files, 0, حجم(certificate_files));
	memset(certificates, 0, حجم(certificates));
	memset(certificate_file_userprovided, 0,
	    حجم(certificate_file_userprovided));

#اگر_تعریف_شدہ ENABLE_PKCS11
	اگر (options.pkcs11_provider != تہی &&
	    options.عدد_شناختی_عنصر_files < SSH_MAX_شناختی_عنصر_FILES &&
	    (pkcs11_init(!options.batch_منوال) == 0) &&
	    (nkeys = pkcs11_جوڑو_provider(options.pkcs11_provider, تہی,
	    &کلیدیں, &comments)) > 0) {
		برائے (i = 0; i < nkeys; i++) {
			اگر (n_ids >= SSH_MAX_شناختی_عنصر_FILES) {
				sshkey_free(کلیدیں[i]);
				آزاد(comments[i]);
				جاری;
			}
			شناختی_عنصر_کلیدیں[n_ids] = کلیدیں[i];
			شناختی_عنصر_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		آزاد(کلیدیں);
		آزاد(comments);
	}
#اگر_ختم /* ENABLE_PKCS11 */
	برائے (i = 0; i < options.عدد_شناختی_عنصر_files; i++) {
		اگر (n_ids >= SSH_MAX_شناختی_عنصر_FILES ||
		    strcasecmp(options.شناختی_عنصر_files[i], "none") == 0) {
			آزاد(options.شناختی_عنصر_files[i]);
			options.شناختی_عنصر_files[i] = تہی;
			جاری;
		}
		cp = tilde_expand_filename(options.شناختی_عنصر_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		آزاد(cp);
		check_بھرو(sshkey_بھرو_عوامی(filename, &عوامی, تہی),
		    &عوامی, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    عوامی ? عوامی->type : -1);
		آزاد(options.شناختی_عنصر_files[i]);
		شناختی_عنصر_files[n_ids] = filename;
		شناختی_عنصر_کلیدیں[n_ids] = عوامی;
		شناختی_عنصر_file_userprovided[n_ids] =
		    options.شناختی_عنصر_file_userprovided[i];
		اگر (++n_ids >= SSH_MAX_شناختی_عنصر_FILES)
			جاری;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		اگر (options.عدد_certificate_files != 0)
			جاری;
		xasprintf(&cp, "%s-cert", filename);
		check_بھرو(sshkey_بھرو_عوامی(cp, &عوامی, تہی),
		    &عوامی, filename, "identity pubkey");
		اگر (عوامی == تہی) {
			آزاد(cp);
			جاری;
		}
		اگر (!sshkey_is_cert(عوامی)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(عوامی));
			sshkey_free(عوامی);
			آزاد(cp);
			جاری;
		}
		آزاد(cp);
		/* NB. leave filename pointing to private key */
		شناختی_عنصر_files[n_ids] = xstrdup(filename);
		شناختی_عنصر_کلیدیں[n_ids] = عوامی;
		شناختی_عنصر_file_userprovided[n_ids] =
		    options.شناختی_عنصر_file_userprovided[i];
		n_ids++;
	}

	اگر (options.عدد_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	برائے (i = 0; i < options.عدد_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		آزاد(cp);

		check_بھرو(sshkey_بھرو_عوامی(filename, &عوامی, تہی),
		    &عوامی, filename, "identity cert");
		آزاد(options.certificate_files[i]);
		options.certificate_files[i] = تہی;
		اگر (عوامی == تہی) {
			آزاد(filename);
			جاری;
		}
		اگر (!sshkey_is_cert(عوامی)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(عوامی));
			sshkey_free(عوامی);
			آزاد(filename);
			جاری;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = عوامی;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.عدد_شناختی_عنصر_files = n_ids;
	حافظہ_نقل(options.شناختی_عنصر_files, شناختی_عنصر_files, حجم(شناختی_عنصر_files));
	حافظہ_نقل(options.شناختی_عنصر_کلیدیں, شناختی_عنصر_کلیدیں, حجم(شناختی_عنصر_کلیدیں));
	حافظہ_نقل(options.شناختی_عنصر_file_userprovided,
	    شناختی_عنصر_file_userprovided, حجم(شناختی_عنصر_file_userprovided));

	options.عدد_certificate_files = n_certs;
	حافظہ_نقل(options.certificate_files,
	    certificate_files, حجم(certificate_files));
	حافظہ_نقل(options.certificates, certificates, حجم(certificates));
	حافظہ_نقل(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    حجم(certificate_file_userprovided));
}

ساکن خالی
main_sigchld_handler(صحیح sig)
{
	صحیح save_errno = errno;
	pid_t pid;
	صحیح حالت_2;

	جب ((pid = waitpid(-1, &حالت_2, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
