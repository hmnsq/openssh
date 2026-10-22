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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/stat.h>
#ضمن <sys/wait.h>
#ضمن <sys/utsname.h>

#ضمن <ctype.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <netdb.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <limits.h>
#ضمن <locale.h>

#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/evp.h>
#ضمن <openssl/err.h>
#جے_انت
#ضمن "openbsd-compat/openssl-compat.h"

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "compat.h"
#ضمن "cipher.h"
#ضمن "packet.h"
#ضمن "sshbuf.h"
#ضمن "channels.h"
#ضمن "sshkey.h"
#ضمن "authfd.h"
#ضمن "authfile.h"
#ضمن "pathnames.h"
#ضمن "clientloop.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "readconf.h"
#ضمن "sshconnect.h"
#ضمن "kex.h"
#ضمن "mac.h"
#ضمن "match.h"
#ضمن "version.h"
#ضمن "ssherr.h"
#ضمن "utf8.h"

#جے_تعریف_شدہ ENABLE_PKCS11
#ضمن "ssh-pkcs11.h"
#جے_انت

خارجي حرف *__progname;

/* Saves a copy of argv for setproctitle emulation */
#جے_بنا_تعریف HAVE_SETPROCTITLE
ساكن حرف **saved_av;
#جے_انت

/* Flag indicating whether debug mode is on.  May be set on the command line. */
صحيح debug_flag = 0;

/* Flag indicating whether a tty should be requested */
صحيح tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
ساكن صحيح need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
ساكن صحيح ostdin_null_flag, osession_type, otty_flag, orequest_tty;
ساكن صحيح ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
حرف *config = عدم;

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
حرف *forward_agent_sock_رستہ = عدم;

/* socket address the host resolves to */
بنية sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_انکڑے;

/* command to be executed */
بنية sshbuf *command;

/* # of replies received for global requests */
ساكن صحيح forward_confirms_pending = -1;

/* mux.c */
خارجي صحيح muxserver_sock;
خارجي u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

ساكن فراغ
usage(فراغ)
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

ساكن صحيح ssh_session2(بنية ssh *, ثابت بنية ssh_conn_info *);
ساكن فراغ لدو_عوامی_پچھان_تت_files(ثابت بنية ssh_conn_info *);
ساكن فراغ main_sigchld_handler(صحيح);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
ساكن فراغ
tilde_expand_paths(حرف **paths, u_int عدد_paths)
{
	u_int i;
	حرف *cp;

	لكل (i = 0; i < عدد_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		حرر(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
ساكن حرف *
default_client_percent_expand(ثابت حرف *str,
    ثابت بنية ssh_conn_info *cinfo)
{
	أرجع percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_دلیلاں(cinfo),
	    (حرف *)عدم);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
ساكن حرف *
default_client_percent_dollar_expand(ثابت حرف *str,
    ثابت بنية ssh_conn_info *cinfo)
{
	حرف *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_دلیلاں(cinfo),
	    (حرف *)عدم);
	إذا (ret == عدم)
		fatal("invalid environment variable expansion");
	أرجع ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ساكن بنية addrinfo *
resolve_host(ثابت حرف *name, صحيح پورٹ, صحيح logerr, حرف *cname, ناپ_t clen)
{
	حرف strport[NI_MAXSERV];
	ثابت حرف *errstr = عدم;
	بنية addrinfo hints, *res;
	صحيح gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	إذا (پورٹ <= 0)
		پورٹ = default_ssh_پورٹ();
	إذا (cname != عدم)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, پورٹ);

	snprintf(strport, حجم strport, "%d", پورٹ);
	memset(&hints, 0, حجم(hints));
	hints.ai_family = options.پتہ_family == -1 ?
	    AF_UNSPEC : options.پتہ_family;
	hints.ai_socktype = SOCK_STREAM;
	إذا (cname != عدم)
		hints.ai_flags = AI_CANONNAME;
	إذا ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		إذا (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		أرجع عدم;
	}
	إذا (cname != عدم && res->ai_canonname != عدم) {
		إذا (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} وإلا إذا (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			إذا (clen > 0)
				*cname = '\0';
		}
	}
	أرجع res;
}

/* Returns non-zero if name can only be an address and not a hostname */
ساكن صحيح
is_addr_fast(ثابت حرف *name)
{
	أرجع (strchr(name, '%') != عدم || strchr(name, ':') != عدم ||
	    strspn(name, "0123456789.") == لڑی_لمبائی(name));
}

/* Returns non-zero if name represents a valid, single address */
ساكن صحيح
is_addr(ثابت حرف *name)
{
	حرف strport[NI_MAXSERV];
	بنية addrinfo hints, *res;

	إذا (is_addr_fast(name))
		أرجع 1;

	snprintf(strport, حجم strport, "%u", default_ssh_پورٹ());
	memset(&hints, 0, حجم(hints));
	hints.ai_family = options.پتہ_family == -1 ?
	    AF_UNSPEC : options.پتہ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	إذا (getaddrinfo(name, strport, &hints, &res) != 0)
		أرجع 0;
	إذا (res == عدم || res->ai_next != عدم) {
		freeaddrinfo(res);
		أرجع 0;
	}
	freeaddrinfo(res);
	أرجع 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ساكن بنية addrinfo *
resolve_addr(ثابت حرف *name, صحيح پورٹ, حرف *caddr, ناپ_t clen)
{
	حرف addr[NI_MAXHOST], strport[NI_MAXSERV];
	بنية addrinfo hints, *res;
	صحيح gaierr;

	إذا (پورٹ <= 0)
		پورٹ = default_ssh_پورٹ();
	snprintf(strport, حجم strport, "%u", پورٹ);
	memset(&hints, 0, حجم(hints));
	hints.ai_family = options.پتہ_family == -1 ?
	    AF_UNSPEC : options.پتہ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	إذا ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		أرجع عدم;
	}
	إذا (res == عدم) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		أرجع عدم;
	}
	إذا (res->ai_next != عدم) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		اذهب fail;
	}
	إذا ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, حجم(addr), عدم, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		اذهب fail;
	}
	إذا (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		إذا (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		أرجع عدم;
	}
	أرجع res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
ساكن صحيح
check_follow_cname(صحيح direct, حرف **namep, ثابت حرف *cname)
{
	صحيح i;
	بنية allowed_cname *قاعدہ;

	إذا (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		أرجع 0;
	إذا (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		أرجع 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	إذا (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		أرجع 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	لكل (i = 0; i < options.عدد_permitted_cnames; i++) {
		قاعدہ = options.permitted_cnames + i;
		إذا (میل_نمونہ_list(*namep, قاعدہ->سروت_list, 1) != 1 ||
		    میل_نمونہ_list(cname, قاعدہ->نشانہ_list, 1) != 1)
			استمر;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		حرر(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		أرجع 1;
	}
	أرجع 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
ساكن بنية addrinfo *
resolve_canonicalize(حرف **hostp, صحيح پورٹ)
{
	صحيح i, direct, ndots;
	حرف *cp, *fullhost, newname[NI_MAXHOST];
	بنية addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	إذا ((addrs = resolve_addr(*hostp, پورٹ,
	    newname, حجم(newname))) != عدم) {
		debug2_f("hostname %.100s is address", *hostp);
		إذا (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			حرر(*hostp);
			*hostp = xstrdup(newname);
		}
		أرجع addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	إذا (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		أرجع عدم;
	}

	إذا (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		أرجع عدم;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	إذا (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		أرجع عدم;

	/* If domain name is anchored, then resolve it now */
	إذا ((*hostp)[لڑی_لمبائی(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		إذا ((addrs = resolve_host(fullhost, پورٹ, 0,
		    newname, حجم(newname))) != عدم)
			اذهب لبھیا;
		حرر(fullhost);
		اذهب notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	لكل (cp = *hostp; *cp != '\0'; cp++) {
		إذا (*cp == '.')
			ndots++;
	}
	إذا (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		أرجع عدم;
	}
	/* Attempt each supplied suffix */
	لكل (i = 0; i < options.عدد_canonical_domains; i++) {
		إذا (strcasecmp(options.canonical_domains[i], "none") == 0)
			اكسر;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		إذا ((addrs = resolve_host(fullhost, پورٹ, 0,
		    newname, حجم(newname))) == عدم) {
			حرر(fullhost);
			استمر;
		}
 لبھیا:
		/* Remove trailing '.' */
		fullhost[لڑی_لمبائی(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		إذا (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		حرر(*hostp);
		*hostp = fullhost;
		أرجع addrs;
	}
 notfound:
	إذا (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	أرجع عدم;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
ساكن فراغ
check_لدو(صحيح r, بنية sshkey **k, ثابت حرف *رستہ, ثابت حرف *سنیہا)
{
	حرف *fp;

	بدل (r) {
	حالة 0:
		إذا (k == عدم || *k == عدم)
			أرجع;
		/* Check RSA keys size and discard if undersized */
		إذا ((r = sshkey_check_rsa_لمائی(*k,
		    options.required_rsa_ناپ)) != 0) {
			error_r(r, "load %s \"%s\"", سنیہا, رستہ);
			حرر(*k);
			*k = عدم;
			اكسر;
		}
		إذا ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == عدم) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), سنیہا, رستہ);
		}
		debug("loaded %s from %s: %s %s", سنیہا, رستہ,
		    sshkey_type(*k), fp);
		حرر(fp);
		اكسر;
	حالة SSH_ERR_اندرونی_ERROR:
	حالة SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", سنیہا, رستہ);
	حالة SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		إذا (errno == ENOENT)
			اكسر;
		/* FALLTHROUGH */
	افتراضي:
		error_r(r, "load %s \"%s\"", سنیہا, رستہ);
		اكسر;
	}
	إذا (k != عدم && *k == عدم)
		debug("no %s loaded from %s", سنیہا, رستہ);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
ساكن فراغ
process_config_files(ثابت حرف *host_name, بنية passwd *pw,
    صحيح final_pass, صحيح *want_final_pass)
{
	حرف *cmd, buf[PATH_MAX];
	صحيح r;

	إذا ((cmd = sshbuf_dup_string(command)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	إذا (config != عدم) {
		إذا (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} وإلا {
		r = snprintf(buf, حجم buf, "%s/%s", pw->pw_dir,
		    رستہ_SSH_USER_CONFFILE);
		إذا (r > 0 && (ناپ_t)r < حجم(buf))
			(فراغ)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(فراغ)read_config_file(رستہ_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	حرر(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
ساكن فراغ
سیٹ_addrinfo_پورٹ(بنية addrinfo *addrs, صحيح پورٹ)
{
	بنية addrinfo *addr;

	لكل (addr = addrs; addr != عدم; addr = addr->ai_next) {
		بدل (addr->ai_family) {
		حالة AF_INET:
			((بنية sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(پورٹ);
			اكسر;
		حالة AF_INET6:
			((بنية sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(پورٹ);
			اكسر;
		}
	}
}

/*
 * Main program for the ssh client.
 */
صحيح
مکھ(صحيح ac, حرف **av)
{
	بنية ssh *ssh = عدم;
	صحيح i, r, opt, exit_حالت, use_syslog, direct, timeout_ms;
	صحيح was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	صحيح user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	حرف *p, *cp, *سطر, *argv0, *logfile, *دلیلاں;
	حرف cname[NI_MAXHOST], thishost[NI_MAXHOST];
	بنية stat st;
	بنية passwd *pw;
	خارجي صحيح optind, optreset;
	خارجي حرف *optarg;
	بنية Forward fwd;
	بنية addrinfo *addrs = عدم;
	ناپ_t n, len;
	u_int j;
	بنية utsname utsname;
	بنية ssh_conn_info *cinfo = عدم;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/*
	 * Discard other fds that are hanging around. These can cause problem
	 * with backgrounded ssh processes started by ControlPersist.
	 */
	closefrom(STDERR_FILENO + 1);

	__progname = ssh_get_progname(av[0]);

#جے_بنا_تعریف HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	/* Save argv so it isn't clobbered by setproctitle() emulation */
	saved_av = xcalloc(ac + 1, حجم(*saved_av));
	لكل (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = عدم;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#جے_انت

	بیج_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	إذا (!pw) {
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
	إذا ((ssh = ssh_alloc_session_state()) == عدم)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	دلیلاں = argv_assemble(ac, av); /* logged later */
	host = عدم;
	use_syslog = 0;
	logfile = عدم;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	طالما ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		بدل (opt) {
		حالة '1':
			fatal("SSH protocol v.1 is no longer supported");
			اكسر;
		حالة '2':
			/* Ignored */
			اكسر;
		حالة '4':
			options.پتہ_family = AF_INET;
			اكسر;
		حالة '6':
			options.پتہ_family = AF_INET6;
			اكسر;
		حالة 'n':
			options.stdin_null = 1;
			اكسر;
		حالة 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			اكسر;
		حالة 'x':
			options.forward_x11 = 0;
			اكسر;
		حالة 'X':
			options.forward_x11 = 1;
			اكسر;
		حالة 'y':
			use_syslog = 1;
			اكسر;
		حالة 'E':
			logfile = optarg;
			اكسر;
		حالة 'G':
			config_test = 1;
			اكسر;
		حالة 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			اكسر;
		حالة 'Z':
			dump_pubkeys = 1;
			اكسر;
		حالة 'g':
			options.fwd_opts.gateway_ports = 1;
			اكسر;
		حالة 'O':
			إذا (options.stdio_forward_host != عدم)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			وإلا إذا (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			إذا (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			وإلا إذا (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			وإلا إذا (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			وإلا إذا (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			وإلا إذا (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			وإلا إذا (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			وإلا إذا (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			وإلا إذا (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			وإلا
				fatal("Invalid multiplex command.");
			اكسر;
		حالة 'P':
			إذا (options.ٹیگ == عدم)
				options.ٹیگ = xstrdup(optarg);
			اكسر;
		حالة 'Q':
			cp = عدم;
			إذا (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			وإلا إذا (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			وإلا إذا (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			وإلا إذا (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			وإلا إذا (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			وإلا إذا (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			وإلا إذا (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			وإلا إذا (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			وإلا إذا (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			وإلا إذا (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			وإلا إذا (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			وإلا إذا (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = لڑی_لمبائی(cp);
				لكل (n = 0; n < len; n++)
					إذا (cp[n] == ',')
						cp[n] = '\n';
			} وإلا إذا (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			إذا (cp == عدم)
				fatal("Unsupported query \"%s\"", optarg);
			لکھو("%s\n", cp);
			حرر(cp);
			باہر_نکلو(0);
			اكسر;
		حالة 'a':
			options.forward_agent = 0;
			اكسر;
		حالة 'A':
			options.forward_agent = 1;
			اكسر;
		حالة 'k':
			options.gss_deleg_creds = 0;
			اكسر;
		حالة 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			اكسر;
		حالة 'i':
			p = tilde_expand_filename(optarg, getuid());
			إذا (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			وإلا
				جوڑو_پچھان_تت_file(&options, عدم, p, 1);
			حرر(p);
			اكسر;
		حالة 'I':
#جے_تعریف_شدہ ENABLE_PKCS11
			حرر(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#وإلا
			fprintf(stderr, "no support for PKCS#11.\n");
#جے_انت
			اكسر;
		حالة 'J':
			إذا (options.jump_host != عدم) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			إذا (options.proxy_command != عدم)
				fatal("Cannot specify -J with ProxyCommand");
			إذا (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			اكسر;
		حالة 't':
			إذا (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			وإلا
				options.request_tty = REQUEST_TTY_YES;
			اكسر;
		حالة 'v':
			إذا (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} وإلا {
				إذا (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			اكسر;
		حالة 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_نسخہ);
			باہر_نکلو(0);
			اكسر;
		حالة 'w':
			إذا (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			إذا (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				باہر_نکلو(255);
			}
			اكسر;
		حالة 'W':
			إذا (options.stdio_forward_host != عدم)
				fatal("stdio forward already specified");
			إذا (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			إذا (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_پورٹ == پورٹ_STREAMLOCAL ?
				    fwd.listen_رستہ : fwd.listen_host;
				options.stdio_forward_پورٹ = fwd.listen_پورٹ;
				حرر(fwd.connect_host);
			} وإلا {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				باہر_نکلو(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			اكسر;
		حالة 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			اكسر;
		حالة 'e':
			إذا (لڑی_لمبائی(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			وإلا إذا (لڑی_لمبائی(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			وإلا إذا (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			وإلا {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				باہر_نکلو(255);
			}
			اكسر;
		حالة 'c':
			إذا (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				باہر_نکلو(255);
			}
			حرر(options.ciphers);
			options.ciphers = xstrdup(optarg);
			اكسر;
		حالة 'm':
			إذا (mac_valid(optarg)) {
				حرر(options.macs);
				options.macs = xstrdup(optarg);
			} وإلا {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				باہر_نکلو(255);
			}
			اكسر;
		حالة 'M':
			إذا (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			وإلا
				options.control_master = SSHCTL_MASTER_YES;
			اكسر;
		حالة 'p':
			إذا (options.پورٹ == -1) {
				options.پورٹ = a2port(optarg);
				إذا (options.پورٹ <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					باہر_نکلو(255);
				}
			}
			اكسر;
		حالة 'l':
			إذا (options.user == عدم) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			اكسر;

		حالة 'L':
			إذا (parse_forward(&fwd, optarg, 0, 0))
				جوڑو_local_forward(&options, &fwd);
			وإلا {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				باہر_نکلو(255);
			}
			اكسر;

		حالة 'R':
			إذا (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				جوڑو_remote_forward(&options, &fwd);
			} وإلا {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				باہر_نکلو(255);
			}
			اكسر;

		حالة 'D':
			إذا (parse_forward(&fwd, optarg, 1, 0)) {
				جوڑو_local_forward(&options, &fwd);
			} وإلا {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				باہر_نکلو(255);
			}
			اكسر;

		حالة 'C':
#جے_تعریف_شدہ WITH_ZLIB
			options.compression = 1;
#وإلا
			error("Compression not supported, disabling.");
#جے_انت
			اكسر;
		حالة 'N':
			إذا (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			اكسر;
		حالة 'T':
			options.request_tty = REQUEST_TTY_NO;
			اكسر;
		حالة 'o':
			سطر = xstrdup(optarg);
			إذا (process_config_سطر(&options, pw,
			    host ? host : "", host ? host : "", "", سطر,
			    "command-line", 0, عدم, SSHCONF_USERCONF) != 0)
				باہر_نکلو(255);
			حرر(سطر);
			اكسر;
		حالة 's':
			إذا (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			اكسر;
		حالة 'S':
			حرر(options.control_رستہ);
			options.control_رستہ = xstrdup(optarg);
			اكسر;
		حالة 'b':
			options.bind_پتہ = optarg;
			اكسر;
		حالة 'B':
			options.bind_interface = optarg;
			اكسر;
		حالة 'F':
			config = optarg;
			اكسر;
		افتراضي:
			usage();
		}
	}

	إذا (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	إذا (ac > 0 && !host) {
		صحيح tport;
		حرف *tuser;
		بدل (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		حالة -1:
			usage();
			اكسر;
		حالة 0:
			إذا (options.user == عدم) {
				options.user = tuser;
				tuser = عدم;
				user_on_commandline = 1;
			}
			حرر(tuser);
			إذا (options.پورٹ == -1 && tport != -1)
				options.پورٹ = tport;
			اكسر;
		افتراضي:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			إذا (cp != عدم) {
				إذا (cp == p)
					usage();
				إذا (options.user == عدم) {
					options.user = p;
					p = عدم;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				حرر(p);
			} وإلا
				host = p;
			اكسر;
		}
		إذا (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			اذهب again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	إذا (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	إذا (options.user != عدم && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	إذا (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	إذا ((command = sshbuf_new()) == عدم)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	إذا (!ac) {
		/* No command specified - execute shell on a tty. */
		إذا (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} وإلا {
		/* A command has been specified.  Store it into the buffer. */
		لكل (i = 0; i < ac; i++) {
			إذا ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	إذا (use_syslog && logfile != عدم)
		fatal("Can't specify both -y and -E");
	إذا (logfile != عدم)
		log_redirect_stderr_منزل(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_سیٹ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_سیٹ ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_نسخہ);
	إذا (uname(&utsname) != 0) {
		memset(&utsname, 0, حجم(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", حجم(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.نسخہ, utsname.machine);
	debug3("Started with: %s", دلیلاں);
	حرر(دلیلاں);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	إذا (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	إذا (options.hostname != عدم) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (حرف *)عدم);
		حرر(host);
		host = cp;
		حرر(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	إذا ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	إذا (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
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
	إذا (addrs == عدم && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		إذا ((addrs = resolve_host(host, options.پورٹ,
		    direct, cname, حجم(cname))) == عدم) {
			/* Don't fatal proxied host names not in the DNS */
			إذا (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} وإلا
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	إذا (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	إذا (want_final_pass) {
		debug("re-parsing configuration");
		حرر(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, عدم);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		إذا (addrs != عدم && options.پورٹ > 0)
			سیٹ_addrinfo_پورٹ(addrs, options.پورٹ);
	}

	/* Fill configuration defaults. */
	إذا (fill_default_options(&options) != 0)
		cleanup_exit(255);

	إذا (options.user == عدم) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	إذا (options.jump_host != عدم) {
		حرف پورٹ_s[8];
		ثابت حرف *jumpuser = options.jump_user, *sshbin = argv0;
		صحيح پورٹ = options.پورٹ, jumpport = options.jump_پورٹ;

		إذا (پورٹ <= 0)
			پورٹ = default_ssh_پورٹ();
		إذا (jumpport <= 0)
			jumpport = default_ssh_پورٹ();
		إذا (jumpuser == عدم)
			jumpuser = options.user;
		إذا (strcmp(options.jump_host, host) == 0 && پورٹ == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		إذا (strchr(argv0, '/') != عدم && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		إذا (options.proxy_command != عدم &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(پورٹ_s, حجم(پورٹ_s), "%d", options.jump_پورٹ);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == عدم ? "" : " -l ",
		    options.jump_user == عدم ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_پورٹ <= 0 ? "" : " -p ",
		    options.jump_پورٹ <= 0 ? "" : پورٹ_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == عدم ? "" : " -J ",
		    options.jump_extra == عدم ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == عدم ? "" : " -F ",
		    config == عدم ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	إذا (options.پورٹ == 0)
		options.پورٹ = default_ssh_پورٹ();
	channel_سیٹ_af(ssh, options.پتہ_family);
	ssh_packet_سیٹ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	إذا (options.host_کلید_alias != عدم)
		lowercase(options.host_کلید_alias);
	إذا (options.proxy_command != عدم &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	إذا (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		إذا (options.control_persist && options.control_رستہ != عدم) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} وإلا إذا (sshbuf_len(command) != 0 ||
		    options.remote_command != عدم ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} وإلا إذا (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	إذا (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	إذا (sshbuf_len(command) != 0 && options.remote_command != عدم)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	إذا (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == عدم &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	لكل (j = 0; j < options.عدد_log_verbose; j++) {
		إذا (strcasecmp(options.log_verbose[j], "none") == 0)
			اكسر;
		log_verbose_جوڑو(options.log_verbose[j]);
	}

	إذا (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	إذا (sshbuf_len(command) == 0 && options.remote_command == عدم)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	إذا (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	إذا ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		إذا (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, حجم(*cinfo));
	إذا (gethostname(thishost, حجم(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.پورٹ);
	xasprintf(&cinfo->uidstr, "%llu",
	    (بنانشانی لما لما)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_کلید_alias ?
	    options.host_کلید_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == عدم ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	إذا (!user_on_commandline && !user_was_default) {
		إذا ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_دلیلاں_NOUSER(cinfo),
		    (حرف *)عدم)) == عدم)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		حرر(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	إذا ((user_on_commandline || user_expanded) &&
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
	إذا (options.remote_command != عدم) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		حرر(cp);
		إذا ((r = sshbuf_put(command, options.remote_command,
		    لڑی_لمبائی(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	إذا (options.control_رستہ != عدم) {
		cp = tilde_expand_filename(options.control_رستہ, getuid());
		حرر(options.control_رستہ);
		options.control_رستہ = default_client_percent_dollar_expand(cp,
		    cinfo);
		حرر(cp);
	}

	إذا (options.پچھان_تت_agent != عدم) {
		p = tilde_expand_filename(options.پچھان_تت_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		حرر(p);
		حرر(options.پچھان_تت_agent);
		options.پچھان_تت_agent = cp;
	}

	لكل (j = 0; j < options.عدد_revoked_host_کلیدیں; j++) {
		p = tilde_expand_filename(options.revoked_host_کلیدیں[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		حرر(p);
		حرر(options.revoked_host_کلیدیں[j]);
		options.revoked_host_کلیدیں[j] = cp;
	}

	إذا (options.forward_agent_sock_رستہ != عدم) {
		p = tilde_expand_filename(options.forward_agent_sock_رستہ,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		حرر(p);
		حرر(options.forward_agent_sock_رستہ);
		options.forward_agent_sock_رستہ = cp;
		إذا (stat(options.forward_agent_sock_رستہ, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_رستہ, strerror(errno));
			إذا (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	إذا (options.نسخہ_addendum != عدم) {
		cp = default_client_percent_dollar_expand(
		    options.نسخہ_addendum, cinfo);
		حرر(options.نسخہ_addendum);
		options.نسخہ_addendum = cp;
	}

	إذا (options.عدد_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		إذا (options.عدد_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		حرر(options.system_hostfiles[0]);
		options.system_hostfiles[0] = عدم;
		options.عدد_system_hostfiles = 0;
	}

	إذا (options.عدد_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		إذا (options.عدد_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		حرر(options.user_hostfiles[0]);
		options.user_hostfiles[0] = عدم;
		options.عدد_user_hostfiles = 0;
	}
	لكل (j = 0; j < options.عدد_user_hostfiles; j++) {
		إذا (options.user_hostfiles[j] == عدم)
			استمر;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		إذا (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		حرر(options.user_hostfiles[j]);
		حرر(cp);
		options.user_hostfiles[j] = p;
	}

	لكل (j = 0; j < options.عدد_setenv; j++) {
		حرف *name = options.setenv[j], *قدر;

		إذا (name == عدم)
			استمر;
		/* Expand only the value portion, not the variable name. */
		إذا ((قدر = strchr(name, '=')) == عدم) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*قدر++ = '\0';
		cp = default_client_percent_dollar_expand(قدر, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		إذا (strcmp(قدر, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, قدر, cp);
		}
		حرر(options.setenv[j]);
		حرر(cp);
		options.setenv[j] = p;
	}

	لكل (i = 0; i < options.عدد_local_forwards; i++) {
		إذا (options.local_forwards[i].listen_رستہ != عدم) {
			cp = options.local_forwards[i].listen_رستہ;
			p = options.local_forwards[i].listen_رستہ =
			    default_client_percent_expand(cp, cinfo);
			إذا (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			حرر(cp);
		}
		إذا (options.local_forwards[i].connect_رستہ != عدم) {
			cp = options.local_forwards[i].connect_رستہ;
			p = options.local_forwards[i].connect_رستہ =
			    default_client_percent_expand(cp, cinfo);
			إذا (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			حرر(cp);
		}
	}

	لكل (i = 0; i < options.عدد_remote_forwards; i++) {
		إذا (options.remote_forwards[i].listen_رستہ != عدم) {
			cp = options.remote_forwards[i].listen_رستہ;
			p = options.remote_forwards[i].listen_رستہ =
			    default_client_percent_expand(cp, cinfo);
			إذا (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			حرر(cp);
		}
		إذا (options.remote_forwards[i].connect_رستہ != عدم) {
			cp = options.remote_forwards[i].connect_رستہ;
			p = options.remote_forwards[i].connect_رستہ =
			    default_client_percent_expand(cp, cinfo);
			إذا (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			حرر(cp);
		}
	}

	إذا (config_test) {
		dump_client_config(&options, host);
		باہر_نکلو(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	إذا (options.sk_provider != عدم && *options.sk_provider == '$' &&
	    لڑی_لمبائی(options.sk_provider) > 1) {
		إذا ((cp = getenv(options.sk_provider + 1)) == عدم) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			حرر(options.sk_provider);
			options.sk_provider = عدم;
		} وإلا {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			حرر(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	إذا (muxclient_command != 0 && options.control_رستہ == عدم)
		fatal("No ControlPath specified for \"-O\" command");
	إذا (options.control_رستہ != عدم) {
		صحيح sock;
		إذا ((sock = muxclient(options.control_رستہ)) >= 0) {
			إذا (ssh_packet_سیٹ_connection(ssh, sock, sock) == عدم)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_سیٹ_mux(ssh);
			اذهب skip_connect;
		}
	}

	/* load options.identity_files */
	لدو_عوامی_پچھان_تت_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	إذا (options.پچھان_تت_agent &&
	    strcmp(options.پچھان_تت_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		إذا (strcmp(options.پچھان_تت_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} وإلا {
			cp = options.پچھان_تت_agent;
			/* legacy (limited) format */
			إذا (cp[0] == '$' && cp[1] != '{') {
				إذا (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				إذا ((p = getenv(cp + 1)) == عدم)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				وإلا
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} وإلا {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	إذا (dump_pubkeys) {
		pubkey_dump(ssh);
		باہر_نکلو(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	إذا (addrs == عدم && options.proxy_command == عدم) {
		debug2("resolving \"%s\" port %d", host, options.پورٹ);
		إذا ((addrs = resolve_host(host, options.پورٹ, 1,
		    cname, حجم(cname))) == عدم)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	إذا (options.connection_timeout >= ودھ_توں_ودھ_عدد/1000)
		timeout_ms = ودھ_توں_ودھ_عدد;
	وإلا
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	لكل (j = 0; j < options.عدد_channel_timeouts; j++) {
		مزدوج timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		إذا (parse_نمونہ_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_جوڑو_timeout(ssh, cp, timeout);
		حرر(cp);
	}
	channel_سیٹ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	إذا (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.پورٹ, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		باہر_نکلو(255);


	ssh_packet_سیٹ_timeout(ssh, options.server_alive_interval,
	    options.server_alive_گنتی_max);

	إذا (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_انکڑے.nkeys = 0;
	sensitive_انکڑے.کلیدیں = عدم;
	إذا (options.hostbased_authentication) {
		صحيح loaded = 0;

		sensitive_انکڑے.nkeys = 10;
		sensitive_انکڑے.کلیدیں = xcalloc(sensitive_انکڑے.nkeys,
		    حجم(*sensitive_انکڑے.کلیدیں));

		/* XXX check errors? */
#تعریف_کرو L_PUBKEY(p,o) افعل { \
	إذا ((o) >= sensitive_انکڑے.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_لدو(sshkey_لدو_عوامی(p, &(sensitive_انکڑے.کلیدیں[o]), عدم), \
	    &(sensitive_انکڑے.کلیدیں[o]), p, "hostbased pubkey"); \
	إذا (sensitive_انکڑے.کلیدیں[o] != عدم) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} طالما (0)
#تعریف_کرو L_CERT(p,o) افعل { \
	إذا ((o) >= sensitive_انکڑے.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_لدو(sshkey_لدو_cert(p, &(sensitive_انکڑے.کلیدیں[o])), \
	    &(sensitive_انکڑے.کلیدیں[o]), p, "hostbased cert"); \
	إذا (sensitive_انکڑے.کلیدیں[o] != عدم) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} طالما (0)

		إذا (options.hostbased_authentication == 1) {
			L_CERT(رستہ_HOST_ECDSA_کلید_FILE, 0);
			L_CERT(رستہ_HOST_ED25519_کلید_FILE, 1);
			L_CERT(رستہ_HOST_RSA_کلید_FILE, 2);
			L_CERT(رستہ_HOST_MLDSA44_ED25519_کلید_FILE, 3);
			L_PUBKEY(رستہ_HOST_ECDSA_کلید_FILE, 4);
			L_PUBKEY(رستہ_HOST_ED25519_کلید_FILE, 5);
			L_PUBKEY(رستہ_HOST_RSA_کلید_FILE, 6);
			L_PUBKEY(رستہ_HOST_MLDSA44_ED25519_کلید_FILE, 7);
			إذا (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	إذا (options.forward_agent && options.forward_agent_sock_رستہ != عدم) {
		cp = options.forward_agent_sock_رستہ;
		إذا (cp[0] == '$') {
			إذا (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			إذا ((p = getenv(cp + 1)) != عدم)
				forward_agent_sock_رستہ = xstrdup(p);
			وإلا
				options.forward_agent = 0;
			حرر(cp);
		} وإلا {
			forward_agent_sock_رستہ = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.عدد_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.عدد_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_انکڑے, host, &hostaddr, options.پورٹ,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	إذا (sensitive_انکڑے.nkeys != 0) {
		لكل (i = 0; i < sensitive_انکڑے.nkeys; i++) {
			إذا (sensitive_انکڑے.کلیدیں[i] != عدم) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_انکڑے.کلیدیں[i]);
				sensitive_انکڑے.کلیدیں[i] = عدم;
			}
		}
		حرر(sensitive_انکڑے.کلیدیں);
	}
	لكل (i = 0; i < options.عدد_پچھان_تت_files; i++) {
		حرر(options.پچھان_تت_files[i]);
		options.پچھان_تت_files[i] = عدم;
		إذا (options.پچھان_تت_کلیدیں[i]) {
			sshkey_free(options.پچھان_تت_کلیدیں[i]);
			options.پچھان_تت_کلیدیں[i] = عدم;
		}
	}
	لكل (i = 0; i < options.عدد_certificate_files; i++) {
		حرر(options.certificate_files[i]);
		options.certificate_files[i] = عدم;
	}

#جے_تعریف_شدہ ENABLE_PKCS11
	(فراغ)pkcs11_del_provider(options.pkcs11_provider);
#جے_انت

 skip_connect:
	إذا (addrs != عدم)
		freeaddrinfo(addrs);
	exit_حالت = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	إذا (options.control_رستہ != عدم && muxserver_sock != -1)
		unlink(options.control_رستہ);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	أرجع exit_حالت;
}

ساكن فراغ
control_persist_detach(فراغ)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	بدل ((pid = fork())) {
	حالة -1:
		fatal_f("fork: %s", strerror(errno));
	حالة 0:
		/* Child: master process continues mainloop */
		اكسر;
	افتراضي:
		/*
		 * Parent: set up mux client to connect to backgrounded
		 * master.
		 */
		debug2_f("background process is %ld", (لما)pid);
		options.stdin_null = ostdin_null_flag;
		options.request_tty = orequest_tty;
		tty_flag = otty_flag;
		options.fork_after_authentication = ofork_after_authentication;
		options.session_type = osession_type;
		close(muxserver_sock);
		muxserver_sock = -1;
		options.control_master = SSHCTL_MASTER_NO;
		(فراغ)muxclient(options.control_رستہ);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	إذا (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_رستہ);
}

/* Do fork() after authentication. Used by "ssh -f" */
ساكن فراغ
fork_postauth(فراغ)
{
	إذا (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	إذا (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	إذا (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

ساكن فراغ
forwarding_success(فراغ)
{
	إذا (forward_confirms_pending == -1)
		أرجع;
	إذا (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		إذا (options.fork_after_authentication)
			fork_postauth();
	} وإلا {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

بنية rfwd_confirm_ctx {
	صحيح fid;
};

/* Callback for remote forward global requests */
ساكن فراغ
ssh_confirm_remote_forward(بنية ssh *ssh, صحيح type, uint32_t seq, فراغ *ctxt)
{
	بنية rfwd_confirm_ctx *rctx = (بنية rfwd_confirm_ctx *)ctxt;
	بنية Forward *rfwd;
	u_int پورٹ;
	صحيح r;

	إذا (rctx->fid < 0 || rctx->fid >= options.عدد_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, حجم(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_پیغام_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_رستہ ? rfwd->listen_رستہ :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_رستہ || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_پورٹ, rfwd->connect_رستہ ? rfwd->connect_رستہ :
	    rfwd->connect_host, rfwd->connect_پورٹ);
	إذا (rfwd->listen_رستہ == عدم && rfwd->listen_پورٹ == 0) {
		إذا (type == SSH2_پیغام_REQUEST_SUCCESS) {
			إذا ((r = sshpkt_get_u32(ssh, &پورٹ)) != 0)
				fatal_fr(r, "parse packet");
			إذا (پورٹ > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", پورٹ,
				    rfwd->connect_host, rfwd->connect_پورٹ);
				/* Ensure failure processing runs below */
				type = SSH2_پیغام_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} وإلا {
				rfwd->allocated_پورٹ = (صحيح)پورٹ;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_پورٹ, rfwd->connect_رستہ ?
				    rfwd->connect_رستہ : rfwd->connect_host,
				    rfwd->connect_پورٹ);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_پورٹ);
			}
		} وإلا {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	إذا (type == SSH2_پیغام_REQUEST_FAILURE) {
		إذا (options.exit_on_forward_failure) {
			إذا (rfwd->listen_رستہ != عدم)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_رستہ);
			وإلا
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_پورٹ);
		} وإلا {
			إذا (rfwd->listen_رستہ != عدم)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_رستہ);
			وإلا
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_پورٹ);
		}
	}
	forwarding_success();
}

ساكن فراغ
client_cleanup_stdio_fwd(بنية ssh *ssh, صحيح id, صحيح force, فراغ *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

ساكن فراغ
ssh_stdio_confirm(بنية ssh *ssh, صحيح id, صحيح success, فراغ *arg)
{
	إذا (!success)
		fatal("stdio forwarding failed");
}

ساكن فراغ
ssh_tun_confirm(بنية ssh *ssh, صحيح id, صحيح success, فراغ *arg)
{
	إذا (!success) {
		error("Tunnel forwarding failed");
		إذا (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

ساكن فراغ
ssh_init_stdio_forwarding(بنية ssh *ssh)
{
	Channel *c;
	صحيح وچ, باہرلا;

	إذا (options.stdio_forward_host == عدم)
		أرجع;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_پورٹ);

	إذا ((وچ = dup(STDIN_FILENO)) == -1 ||
	    (باہرلا = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	إذا ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_پورٹ, وچ, باہرلا,
	    CHANNEL_NONBLOCK_STDIO)) == عدم)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_رجسٹر_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_رجسٹر_open_confirm(ssh, c->self, ssh_stdio_confirm, عدم);
}

ساكن فراغ
ssh_init_forward_permissions(بنية ssh *ssh, ثابت حرف *what, حرف **opens,
    u_int عدد_opens)
{
	u_int i;
	صحيح پورٹ;
	حرف *addr, *arg, *oarg;
	صحيح where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	إذا (عدد_opens == 0)
		أرجع; /* permit any */

	/* handle keywords: "any" / "none" */
	إذا (عدد_opens == 1 && strcmp(opens[0], "any") == 0)
		أرجع;
	إذا (عدد_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		أرجع;
	}
	/* Otherwise treat it as a list of permitted host:port */
	لكل (i = 0; i < عدد_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		إذا (addr == عدم)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		إذا (arg == عدم || ((پورٹ = permitopen_پورٹ(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_جوڑو_permission(ssh, FORWARD_ADM,
		    where, addr, پورٹ);
		حرر(oarg);
	}
}

ساكن فراغ
ssh_init_forwarding(بنية ssh *ssh, حرف **ifname)
{
	صحيح success = 0;
	صحيح i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.عدد_permitted_remote_opens);

	إذا (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	لكل (i = 0; i < options.عدد_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_رستہ != عدم) ?
		    options.local_forwards[i].listen_رستہ :
		    (options.local_forwards[i].listen_host == عدم) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_پورٹ,
		    (options.local_forwards[i].connect_رستہ != عدم) ?
		    options.local_forwards[i].connect_رستہ :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_پورٹ);
		success += channel_تیاری_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	إذا (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	إذا (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	لكل (i = 0; i < options.عدد_remote_forwards; i++) {
		بنية rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_رستہ != عدم) ?
		    options.remote_forwards[i].listen_رستہ :
		    (options.remote_forwards[i].listen_host == عدم) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_پورٹ,
		    (options.remote_forwards[i].connect_رستہ != عدم) ?
		    options.remote_forwards[i].connect_رستہ :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_پورٹ);
		إذا ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, حجم(*rctx));
			rctx->fid = i;
			client_رجسٹر_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} وإلا إذا (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		وإلا
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	إذا (options.tun_open != SSH_TUNMODE_NO) {
		إذا ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, عدم)) != عدم)
			forward_confirms_pending++;
		وإلا إذا (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		وإلا
			error("Could not request tunnel forwarding.");
	}
	إذا (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

ساكن فراغ
check_agent_present(فراغ)
{
	صحيح r;

	إذا (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		إذا ((r = ssh_get_authentication_socket(عدم)) != 0) {
			options.forward_agent = 0;
			إذا (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

ساكن فراغ
ssh_session2_تیاری(بنية ssh *ssh, صحيح id, صحيح success, فراغ *arg)
{
	خارجي حرف **environ;
	ثابت حرف *display, *رکن;
	حرف *proto = عدم, *انکڑے = عدم;

	إذا (!success)
		أرجع; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	إذا (display == عدم && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	إذا (options.forward_x11 && client_x11_get_proto(ssh, display,
	    options.xauth_location, options.forward_x11_trusted,
	    options.forward_x11_timeout, &proto, &انکڑے) == 0) {
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(ssh, id, display, proto,
		    انکڑے, 1);
		client_expect_confirm(ssh, id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
	}

	check_agent_present();
	إذا (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	إذا ((رکن = lookup_env_وچ_list("TERM", options.setenv,
	    options.عدد_setenv)) == عدم || *رکن == '\0')
		رکن = getenv("TERM");
	client_session2_تیاری(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, رکن,
	    عدم, fileno(stdin), command, environ);
}

/* open new channel for a session */
ساكن صحيح
ssh_session2_open(بنية ssh *ssh)
{
	Channel *c;
	صحيح کھڑکی, packetmax, وچ, باہرلا, err;

	إذا (options.stdin_null) {
		وچ = open(_PATH_DEVNULL, O_RDONLY);
	} وإلا {
		وچ = dup(STDIN_FILENO);
	}
	باہرلا = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	إذا (وچ == -1 || باہرلا == -1 || err == -1)
		fatal("dup() in/out/err failed");

	کھڑکی = CHAN_SES_کھڑکی_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	إذا (tty_flag) {
		کھڑکی >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, وچ, باہرلا, err,
	    کھڑکی, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	إذا (tty_flag)
		channel_سیٹ_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	إذا (options.session_type != SESSION_TYPE_NONE)
		channel_رجسٹر_open_confirm(ssh, c->self,
		    ssh_session2_تیاری, عدم);

	أرجع c->self;
}

ساكن صحيح
ssh_session2(بنية ssh *ssh, ثابت بنية ssh_conn_info *cinfo)
{
	صحيح r, id = -1;
	حرف *cp, *tun_fwd_ifname = عدم;

	/* XXX should be pre-session */
	إذا (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	إذا (options.local_command != عدم) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_دلیلاں(cinfo),
		    "T", tun_fwd_ifname == عدم ? "NONE" : tun_fwd_ifname,
		    (حرف *)عدم);
		debug3("expanded LocalCommand: %s", options.local_command);
		حرر(cp);
	}

	/* Start listening for multiplex clients */
	إذا (!ssh_packet_get_mux(ssh))
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
	إذا (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		إذا ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != عدم))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	إذا (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	إذا (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	إذا (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	إذا (options.local_command != عدم &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	إذا (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	إذا (options.fork_after_authentication) {
		إذا (options.exit_on_forward_failure &&
		    options.عدد_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} وإلا
			fork_postauth();
	}

	أرجع client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
ساكن فراغ
لدو_عوامی_پچھان_تت_files(ثابت بنية ssh_conn_info *cinfo)
{
	حرف *filename, *cp;
	بنية sshkey *عام;
	صحيح i;
	u_int n_ids, n_certs;
	حرف *پچھان_تت_files[SSH_MAX_پچھان_تت_FILES];
	بنية sshkey *پچھان_تت_کلیدیں[SSH_MAX_پچھان_تت_FILES];
	صحيح پچھان_تت_file_userprovided[SSH_MAX_پچھان_تت_FILES];
	حرف *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	بنية sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	صحيح certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#جے_تعریف_شدہ ENABLE_PKCS11
	بنية sshkey **کلیدیں = عدم;
	حرف **comments = عدم;
	صحيح nkeys;
#جے_انت /* PKCS11 */

	n_ids = n_certs = 0;
	memset(پچھان_تت_files, 0, حجم(پچھان_تت_files));
	memset(پچھان_تت_کلیدیں, 0, حجم(پچھان_تت_کلیدیں));
	memset(پچھان_تت_file_userprovided, 0,
	    حجم(پچھان_تت_file_userprovided));
	memset(certificate_files, 0, حجم(certificate_files));
	memset(certificates, 0, حجم(certificates));
	memset(certificate_file_userprovided, 0,
	    حجم(certificate_file_userprovided));

#جے_تعریف_شدہ ENABLE_PKCS11
	إذا (options.pkcs11_provider != عدم &&
	    options.عدد_پچھان_تت_files < SSH_MAX_پچھان_تت_FILES &&
	    (pkcs11_init(!options.batch_منوال) == 0) &&
	    (nkeys = pkcs11_جوڑو_provider(options.pkcs11_provider, عدم,
	    &کلیدیں, &comments)) > 0) {
		لكل (i = 0; i < nkeys; i++) {
			إذا (n_ids >= SSH_MAX_پچھان_تت_FILES) {
				sshkey_free(کلیدیں[i]);
				حرر(comments[i]);
				استمر;
			}
			پچھان_تت_کلیدیں[n_ids] = کلیدیں[i];
			پچھان_تت_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		حرر(کلیدیں);
		حرر(comments);
	}
#جے_انت /* ENABLE_PKCS11 */
	لكل (i = 0; i < options.عدد_پچھان_تت_files; i++) {
		إذا (n_ids >= SSH_MAX_پچھان_تت_FILES ||
		    strcasecmp(options.پچھان_تت_files[i], "none") == 0) {
			حرر(options.پچھان_تت_files[i]);
			options.پچھان_تت_files[i] = عدم;
			استمر;
		}
		cp = tilde_expand_filename(options.پچھان_تت_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		حرر(cp);
		check_لدو(sshkey_لدو_عوامی(filename, &عام, عدم),
		    &عام, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    عام ? عام->type : -1);
		حرر(options.پچھان_تت_files[i]);
		پچھان_تت_files[n_ids] = filename;
		پچھان_تت_کلیدیں[n_ids] = عام;
		پچھان_تت_file_userprovided[n_ids] =
		    options.پچھان_تت_file_userprovided[i];
		إذا (++n_ids >= SSH_MAX_پچھان_تت_FILES)
			استمر;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		إذا (options.عدد_certificate_files != 0)
			استمر;
		xasprintf(&cp, "%s-cert", filename);
		check_لدو(sshkey_لدو_عوامی(cp, &عام, عدم),
		    &عام, filename, "identity pubkey");
		إذا (عام == عدم) {
			حرر(cp);
			استمر;
		}
		إذا (!sshkey_is_cert(عام)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(عام));
			sshkey_free(عام);
			حرر(cp);
			استمر;
		}
		حرر(cp);
		/* NB. leave filename pointing to private key */
		پچھان_تت_files[n_ids] = xstrdup(filename);
		پچھان_تت_کلیدیں[n_ids] = عام;
		پچھان_تت_file_userprovided[n_ids] =
		    options.پچھان_تت_file_userprovided[i];
		n_ids++;
	}

	إذا (options.عدد_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	لكل (i = 0; i < options.عدد_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		حرر(cp);

		check_لدو(sshkey_لدو_عوامی(filename, &عام, عدم),
		    &عام, filename, "identity cert");
		حرر(options.certificate_files[i]);
		options.certificate_files[i] = عدم;
		إذا (عام == عدم) {
			حرر(filename);
			استمر;
		}
		إذا (!sshkey_is_cert(عام)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(عام));
			sshkey_free(عام);
			حرر(filename);
			استمر;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = عام;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.عدد_پچھان_تت_files = n_ids;
	حافظہ_نقل(options.پچھان_تت_files, پچھان_تت_files, حجم(پچھان_تت_files));
	حافظہ_نقل(options.پچھان_تت_کلیدیں, پچھان_تت_کلیدیں, حجم(پچھان_تت_کلیدیں));
	حافظہ_نقل(options.پچھان_تت_file_userprovided,
	    پچھان_تت_file_userprovided, حجم(پچھان_تت_file_userprovided));

	options.عدد_certificate_files = n_certs;
	حافظہ_نقل(options.certificate_files,
	    certificate_files, حجم(certificate_files));
	حافظہ_نقل(options.certificates, certificates, حجم(certificates));
	حافظہ_نقل(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    حجم(certificate_file_userprovided));
}

ساكن فراغ
main_sigchld_handler(صحيح sig)
{
	صحيح save_errno = errno;
	pid_t pid;
	صحيح حالت;

	طالما ((pid = waitpid(-1, &حالت, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
