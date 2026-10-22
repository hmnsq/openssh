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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <locale.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#endif
#include "openbsd-compat/openssl-compat.h"

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "compat.h"
#include "cipher.h"
#include "packet.h"
#include "sshbuf.h"
#include "channels.h"
#include "sshkey.h"
#include "authfd.h"
#include "authfile.h"
#include "pathnames.h"
#include "clientloop.h"
#include "log.h"
#include "misc.h"
#include "readconf.h"
#include "sshconnect.h"
#include "kex.h"
#include "mac.h"
#include "match.h"
#include "version.h"
#include "ssherr.h"
#include "utf8.h"

#ifdef ENABLE_PKCS11
#include "ssh-pkcs11.h"
#endif

extern char *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
static char **saved_av;
#endif

/* Flag indicating whether debug mode is on.  May be set on the command line. */
整数 debug_flag = 0;

/* Flag indicating whether a tty should be requested */
整数 tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
static 整数 need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
static 整数 ostdin_null_flag, osession_type, otty_flag, orequest_tty;
static 整数 ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
char *config = NULL;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
char *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
char *forward_agent_sock_path = NULL;

/* socket address the host resolves to */
struct sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_data;

/* command to be executed */
struct sshbuf *command;

/* # of replies received for global requests */
static 整数 forward_confirms_pending = -1;

/* mux.c */
extern 整数 muxserver_sock;
extern u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

static void
usage(void)
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
	exit(255);
}

static 整数 ssh_session2(struct ssh *, const struct ssh_conn_info *);
static void load_public_identity_files(const struct ssh_conn_info *);
static void main_sigchld_handler(整数);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
static void
tilde_expand_paths(char **paths, u_int num_paths)
{
	u_int i;
	char *cp;

	ために (i = 0; i < num_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		free(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
static char *
default_client_percent_expand(const char *str,
    const struct ssh_conn_info *cinfo)
{
	戻る percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (char *)NULL);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
static char *
default_client_percent_dollar_expand(const char *str,
    const struct ssh_conn_info *cinfo)
{
	char *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (char *)NULL);
	もし (ret == NULL)
		fatal("invalid environment variable expansion");
	戻る ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
static struct addrinfo *
resolve_host(const char *name, 整数 port, 整数 logerr, char *cname, size_t clen)
{
	char strport[NI_MAXSERV];
	const char *errstr = NULL;
	struct addrinfo hints, *res;
	整数 gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	もし (port <= 0)
		port = default_ssh_port();
	もし (cname != NULL)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, port);

	snprintf(strport, sizeof strport, "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	もし (cname != NULL)
		hints.ai_flags = AI_CANONNAME;
	もし ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		もし (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		戻る NULL;
	}
	もし (cname != NULL && res->ai_canonname != NULL) {
		もし (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} 否则 もし (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			もし (clen > 0)
				*cname = '\0';
		}
	}
	戻る res;
}

/* Returns non-zero if name can only be an address and not a hostname */
static 整数
is_addr_fast(const char *name)
{
	戻る (strchr(name, '%') != NULL || strchr(name, ':') != NULL ||
	    strspn(name, "0123456789.") == strlen(name));
}

/* Returns non-zero if name represents a valid, single address */
static 整数
is_addr(const char *name)
{
	char strport[NI_MAXSERV];
	struct addrinfo hints, *res;

	もし (is_addr_fast(name))
		戻る 1;

	snprintf(strport, sizeof strport, "%u", default_ssh_port());
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	もし (getaddrinfo(name, strport, &hints, &res) != 0)
		戻る 0;
	もし (res == NULL || res->ai_next != NULL) {
		freeaddrinfo(res);
		戻る 0;
	}
	freeaddrinfo(res);
	戻る 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
static struct addrinfo *
resolve_addr(const char *name, 整数 port, char *caddr, size_t clen)
{
	char addr[NI_MAXHOST], strport[NI_MAXSERV];
	struct addrinfo hints, *res;
	整数 gaierr;

	もし (port <= 0)
		port = default_ssh_port();
	snprintf(strport, sizeof strport, "%u", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	もし ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		戻る NULL;
	}
	もし (res == NULL) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		戻る NULL;
	}
	もし (res->ai_next != NULL) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		goto fail;
	}
	もし ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, sizeof(addr), NULL, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		goto fail;
	}
	もし (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		もし (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		戻る NULL;
	}
	戻る res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
static 整数
check_follow_cname(整数 direct, char **namep, const char *cname)
{
	整数 i;
	struct allowed_cname *rule;

	もし (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		戻る 0;
	もし (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		戻る 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	もし (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		戻る 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	ために (i = 0; i < options.num_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		もし (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			continue;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		free(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		戻る 1;
	}
	戻る 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
static struct addrinfo *
resolve_canonicalize(char **hostp, 整数 port)
{
	整数 i, direct, ndots;
	char *cp, *fullhost, newname[NI_MAXHOST];
	struct addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	もし ((addrs = resolve_addr(*hostp, port,
	    newname, sizeof(newname))) != NULL) {
		debug2_f("hostname %.100s is address", *hostp);
		もし (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			free(*hostp);
			*hostp = xstrdup(newname);
		}
		戻る addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	もし (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		戻る NULL;
	}

	もし (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		戻る NULL;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	もし (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		戻る NULL;

	/* If domain name is anchored, then resolve it now */
	もし ((*hostp)[strlen(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		もし ((addrs = resolve_host(fullhost, port, 0,
		    newname, sizeof(newname))) != NULL)
			goto found;
		free(fullhost);
		goto notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	ために (cp = *hostp; *cp != '\0'; cp++) {
		もし (*cp == '.')
			ndots++;
	}
	もし (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		戻る NULL;
	}
	/* Attempt each supplied suffix */
	ために (i = 0; i < options.num_canonical_domains; i++) {
		もし (strcasecmp(options.canonical_domains[i], "none") == 0)
			break;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		もし ((addrs = resolve_host(fullhost, port, 0,
		    newname, sizeof(newname))) == NULL) {
			free(fullhost);
			continue;
		}
 found:
		/* Remove trailing '.' */
		fullhost[strlen(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		もし (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		free(*hostp);
		*hostp = fullhost;
		戻る addrs;
	}
 notfound:
	もし (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	戻る NULL;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
static void
check_load(整数 r, struct sshkey **k, const char *path, const char *message)
{
	char *fp;

	switch (r) {
	case 0:
		もし (k == NULL || *k == NULL)
			戻る;
		/* Check RSA keys size and discard if undersized */
		もし ((r = sshkey_check_rsa_length(*k,
		    options.required_rsa_size)) != 0) {
			error_r(r, "load %s \"%s\"", message, path);
			free(*k);
			*k = NULL;
			break;
		}
		もし ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), message, path);
		}
		debug("loaded %s from %s: %s %s", message, path,
		    sshkey_type(*k), fp);
		free(fp);
		break;
	case SSH_ERR_INTERNAL_ERROR:
	case SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", message, path);
	case SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		もし (errno == ENOENT)
			break;
		/* FALLTHROUGH */
	default:
		error_r(r, "load %s \"%s\"", message, path);
		break;
	}
	もし (k != NULL && *k == NULL)
		debug("no %s loaded from %s", message, path);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
static void
process_config_files(const char *host_name, struct passwd *pw,
    整数 final_pass, 整数 *want_final_pass)
{
	char *cmd, buf[PATH_MAX];
	整数 r;

	もし ((cmd = sshbuf_dup_string(command)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	もし (config != NULL) {
		もし (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} 否则 {
		r = snprintf(buf, sizeof buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		もし (r > 0 && (size_t)r < sizeof(buf))
			(void)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(void)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	free(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
static void
set_addrinfo_port(struct addrinfo *addrs, 整数 port)
{
	struct addrinfo *addr;

	ために (addr = addrs; addr != NULL; addr = addr->ai_next) {
		switch (addr->ai_family) {
		case AF_INET:
			((struct sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			break;
		}
	}
}

/*
 * Main program for the ssh client.
 */
整数
メインページ(整数 ac, char **av)
{
	struct ssh *ssh = NULL;
	整数 i, r, opt, exit_status, use_syslog, direct, timeout_ms;
	整数 was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	整数 user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	char *p, *cp, *line, *argv0, *logfile, *args;
	char cname[NI_MAXHOST], thishost[NI_MAXHOST];
	struct stat st;
	struct passwd *pw;
	extern 整数 optind, optreset;
	extern char *optarg;
	struct Forward fwd;
	struct addrinfo *addrs = NULL;
	size_t n, len;
	u_int j;
	struct utsname utsname;
	struct ssh_conn_info *cinfo = NULL;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/*
	 * Discard other fds that are hanging around. These can cause problem
	 * with backgrounded ssh processes started by ControlPersist.
	 */
	closefrom(STDERR_FILENO + 1);

	__progname = ssh_get_progname(av[0]);

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	/* Save argv so it isn't clobbered by setproctitle() emulation */
	saved_av = xcalloc(ac + 1, sizeof(*saved_av));
	ために (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = NULL;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#endif

	seed_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	もし (!pw) {
		logit("No user exists for uid %lu", (u_long)getuid());
		exit(255);
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
	もし ((ssh = ssh_alloc_session_state()) == NULL)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	host = NULL;
	use_syslog = 0;
	logfile = NULL;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	ながら ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		switch (opt) {
		case '1':
			fatal("SSH protocol v.1 is no longer supported");
			break;
		case '2':
			/* Ignored */
			break;
		case '4':
			options.address_family = AF_INET;
			break;
		case '6':
			options.address_family = AF_INET6;
			break;
		case 'n':
			options.stdin_null = 1;
			break;
		case 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			break;
		case 'x':
			options.forward_x11 = 0;
			break;
		case 'X':
			options.forward_x11 = 1;
			break;
		case 'y':
			use_syslog = 1;
			break;
		case 'E':
			logfile = optarg;
			break;
		case 'G':
			config_test = 1;
			break;
		case 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			break;
		case 'Z':
			dump_pubkeys = 1;
			break;
		case 'g':
			options.fwd_opts.gateway_ports = 1;
			break;
		case 'O':
			もし (options.stdio_forward_host != NULL)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			否则 もし (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			もし (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			否则 もし (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			否则 もし (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			否则 もし (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			否则 もし (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			否则 もし (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			否则 もし (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			否则 もし (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			否则
				fatal("Invalid multiplex command.");
			break;
		case 'P':
			もし (options.tag == NULL)
				options.tag = xstrdup(optarg);
			break;
		case 'Q':
			cp = NULL;
			もし (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			否则 もし (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			否则 もし (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			否则 もし (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			否则 もし (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			否则 もし (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			否则 もし (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			否则 もし (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			否则 もし (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			否则 もし (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			否则 もし (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			否则 もし (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = strlen(cp);
				ために (n = 0; n < len; n++)
					もし (cp[n] == ',')
						cp[n] = '\n';
			} 否则 もし (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			もし (cp == NULL)
				fatal("Unsupported query \"%s\"", optarg);
			printf("%s\n", cp);
			free(cp);
			exit(0);
			break;
		case 'a':
			options.forward_agent = 0;
			break;
		case 'A':
			options.forward_agent = 1;
			break;
		case 'k':
			options.gss_deleg_creds = 0;
			break;
		case 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			break;
		case 'i':
			p = tilde_expand_filename(optarg, getuid());
			もし (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			否则
				add_identity_file(&options, NULL, p, 1);
			free(p);
			break;
		case 'I':
#ifdef ENABLE_PKCS11
			free(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#否则
			fprintf(stderr, "no support for PKCS#11.\n");
#endif
			break;
		case 'J':
			もし (options.jump_host != NULL) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			もし (options.proxy_command != NULL)
				fatal("Cannot specify -J with ProxyCommand");
			もし (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			break;
		case 't':
			もし (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			否则
				options.request_tty = REQUEST_TTY_YES;
			break;
		case 'v':
			もし (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} 否则 {
				もし (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			break;
		case 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
			break;
		case 'w':
			もし (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			もし (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				exit(255);
			}
			break;
		case 'W':
			もし (options.stdio_forward_host != NULL)
				fatal("stdio forward already specified");
			もし (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			もし (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_port == PORT_STREAMLOCAL ?
				    fwd.listen_path : fwd.listen_host;
				options.stdio_forward_port = fwd.listen_port;
				free(fwd.connect_host);
			} 否则 {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			break;
		case 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			break;
		case 'e':
			もし (strlen(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			否则 もし (strlen(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			否则 もし (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			否则 {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				exit(255);
			}
			break;
		case 'c':
			もし (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				exit(255);
			}
			free(options.ciphers);
			options.ciphers = xstrdup(optarg);
			break;
		case 'm':
			もし (mac_valid(optarg)) {
				free(options.macs);
				options.macs = xstrdup(optarg);
			} 否则 {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				exit(255);
			}
			break;
		case 'M':
			もし (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			否则
				options.control_master = SSHCTL_MASTER_YES;
			break;
		case 'p':
			もし (options.port == -1) {
				options.port = a2port(optarg);
				もし (options.port <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					exit(255);
				}
			}
			break;
		case 'l':
			もし (options.user == NULL) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			break;

		case 'L':
			もし (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			否则 {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			break;

		case 'R':
			もし (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				add_remote_forward(&options, &fwd);
			} 否则 {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			break;

		case 'D':
			もし (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} 否则 {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			break;

		case 'C':
#ifdef WITH_ZLIB
			options.compression = 1;
#否则
			error("Compression not supported, disabling.");
#endif
			break;
		case 'N':
			もし (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			break;
		case 'T':
			options.request_tty = REQUEST_TTY_NO;
			break;
		case 'o':
			line = xstrdup(optarg);
			もし (process_config_line(&options, pw,
			    host ? host : "", host ? host : "", "", line,
			    "command-line", 0, NULL, SSHCONF_USERCONF) != 0)
				exit(255);
			free(line);
			break;
		case 's':
			もし (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			break;
		case 'S':
			free(options.control_path);
			options.control_path = xstrdup(optarg);
			break;
		case 'b':
			options.bind_address = optarg;
			break;
		case 'B':
			options.bind_interface = optarg;
			break;
		case 'F':
			config = optarg;
			break;
		default:
			usage();
		}
	}

	もし (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	もし (ac > 0 && !host) {
		整数 tport;
		char *tuser;
		switch (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		case -1:
			usage();
			break;
		case 0:
			もし (options.user == NULL) {
				options.user = tuser;
				tuser = NULL;
				user_on_commandline = 1;
			}
			free(tuser);
			もし (options.port == -1 && tport != -1)
				options.port = tport;
			break;
		default:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			もし (cp != NULL) {
				もし (cp == p)
					usage();
				もし (options.user == NULL) {
					options.user = p;
					p = NULL;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				free(p);
			} 否则
				host = p;
			break;
		}
		もし (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			goto again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	もし (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	もし (options.user != NULL && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	もし (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	もし ((command = sshbuf_new()) == NULL)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	もし (!ac) {
		/* No command specified - execute shell on a tty. */
		もし (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} 否则 {
		/* A command has been specified.  Store it into the buffer. */
		ために (i = 0; i < ac; i++) {
			もし ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	もし (use_syslog && logfile != NULL)
		fatal("Can't specify both -y and -E");
	もし (logfile != NULL)
		log_redirect_stderr_to(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_VERSION);
	もし (uname(&utsname) != 0) {
		memset(&utsname, 0, sizeof(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", sizeof(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	free(args);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	もし (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	もし (options.hostname != NULL) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (char *)NULL);
		free(host);
		host = cp;
		free(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	もし ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	もし (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
		addrs = resolve_canonicalize(&host, options.port);

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
	もし (addrs == NULL && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		もし ((addrs = resolve_host(host, options.port,
		    direct, cname, sizeof(cname))) == NULL) {
			/* Don't fatal proxied host names not in the DNS */
			もし (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} 否则
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	もし (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	もし (want_final_pass) {
		debug("re-parsing configuration");
		free(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, NULL);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		もし (addrs != NULL && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	もし (fill_default_options(&options) != 0)
		cleanup_exit(255);

	もし (options.user == NULL) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	もし (options.jump_host != NULL) {
		char port_s[8];
		const char *jumpuser = options.jump_user, *sshbin = argv0;
		整数 port = options.port, jumpport = options.jump_port;

		もし (port <= 0)
			port = default_ssh_port();
		もし (jumpport <= 0)
			jumpport = default_ssh_port();
		もし (jumpuser == NULL)
			jumpuser = options.user;
		もし (strcmp(options.jump_host, host) == 0 && port == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		もし (strchr(argv0, '/') != NULL && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		もし (options.proxy_command != NULL &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(port_s, sizeof(port_s), "%d", options.jump_port);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == NULL ? "" : " -l ",
		    options.jump_user == NULL ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_port <= 0 ? "" : " -p ",
		    options.jump_port <= 0 ? "" : port_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == NULL ? "" : " -J ",
		    options.jump_extra == NULL ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == NULL ? "" : " -F ",
		    config == NULL ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	もし (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(ssh, options.address_family);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	もし (options.host_key_alias != NULL)
		lowercase(options.host_key_alias);
	もし (options.proxy_command != NULL &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	もし (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		もし (options.control_persist && options.control_path != NULL) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} 否则 もし (sshbuf_len(command) != 0 ||
		    options.remote_command != NULL ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} 否则 もし (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	もし (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	もし (sshbuf_len(command) != 0 && options.remote_command != NULL)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	もし (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == NULL &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	ために (j = 0; j < options.num_log_verbose; j++) {
		もし (strcasecmp(options.log_verbose[j], "none") == 0)
			break;
		log_verbose_add(options.log_verbose[j]);
	}

	もし (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	もし (sshbuf_len(command) == 0 && options.remote_command == NULL)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	もし (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	もし ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		もし (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, sizeof(*cinfo));
	もし (gethostname(thishost, sizeof(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.port);
	xasprintf(&cinfo->uidstr, "%llu",
	    (unsigned long long)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_key_alias ?
	    options.host_key_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == NULL ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	もし (!user_on_commandline && !user_was_default) {
		もし ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(cinfo),
		    (char *)NULL)) == NULL)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		free(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	もし ((user_on_commandline || user_expanded) &&
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
	もし (options.remote_command != NULL) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		free(cp);
		もし ((r = sshbuf_put(command, options.remote_command,
		    strlen(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	もし (options.control_path != NULL) {
		cp = tilde_expand_filename(options.control_path, getuid());
		free(options.control_path);
		options.control_path = default_client_percent_dollar_expand(cp,
		    cinfo);
		free(cp);
	}

	もし (options.identity_agent != NULL) {
		p = tilde_expand_filename(options.identity_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		free(p);
		free(options.identity_agent);
		options.identity_agent = cp;
	}

	ために (j = 0; j < options.num_revoked_host_keys; j++) {
		p = tilde_expand_filename(options.revoked_host_keys[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		free(p);
		free(options.revoked_host_keys[j]);
		options.revoked_host_keys[j] = cp;
	}

	もし (options.forward_agent_sock_path != NULL) {
		p = tilde_expand_filename(options.forward_agent_sock_path,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		free(p);
		free(options.forward_agent_sock_path);
		options.forward_agent_sock_path = cp;
		もし (stat(options.forward_agent_sock_path, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_path, strerror(errno));
			もし (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	もし (options.version_addendum != NULL) {
		cp = default_client_percent_dollar_expand(
		    options.version_addendum, cinfo);
		free(options.version_addendum);
		options.version_addendum = cp;
	}

	もし (options.num_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		もし (options.num_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		free(options.system_hostfiles[0]);
		options.system_hostfiles[0] = NULL;
		options.num_system_hostfiles = 0;
	}

	もし (options.num_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		もし (options.num_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		free(options.user_hostfiles[0]);
		options.user_hostfiles[0] = NULL;
		options.num_user_hostfiles = 0;
	}
	ために (j = 0; j < options.num_user_hostfiles; j++) {
		もし (options.user_hostfiles[j] == NULL)
			continue;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		もし (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		free(options.user_hostfiles[j]);
		free(cp);
		options.user_hostfiles[j] = p;
	}

	ために (j = 0; j < options.num_setenv; j++) {
		char *name = options.setenv[j], *value;

		もし (name == NULL)
			continue;
		/* Expand only the value portion, not the variable name. */
		もし ((value = strchr(name, '=')) == NULL) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*value++ = '\0';
		cp = default_client_percent_dollar_expand(value, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		もし (strcmp(value, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, value, cp);
		}
		free(options.setenv[j]);
		free(cp);
		options.setenv[j] = p;
	}

	ために (i = 0; i < options.num_local_forwards; i++) {
		もし (options.local_forwards[i].listen_path != NULL) {
			cp = options.local_forwards[i].listen_path;
			p = options.local_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			もし (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			free(cp);
		}
		もし (options.local_forwards[i].connect_path != NULL) {
			cp = options.local_forwards[i].connect_path;
			p = options.local_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			もし (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			free(cp);
		}
	}

	ために (i = 0; i < options.num_remote_forwards; i++) {
		もし (options.remote_forwards[i].listen_path != NULL) {
			cp = options.remote_forwards[i].listen_path;
			p = options.remote_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			もし (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			free(cp);
		}
		もし (options.remote_forwards[i].connect_path != NULL) {
			cp = options.remote_forwards[i].connect_path;
			p = options.remote_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			もし (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			free(cp);
		}
	}

	もし (config_test) {
		dump_client_config(&options, host);
		exit(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	もし (options.sk_provider != NULL && *options.sk_provider == '$' &&
	    strlen(options.sk_provider) > 1) {
		もし ((cp = getenv(options.sk_provider + 1)) == NULL) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			free(options.sk_provider);
			options.sk_provider = NULL;
		} 否则 {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			free(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	もし (muxclient_command != 0 && options.control_path == NULL)
		fatal("No ControlPath specified for \"-O\" command");
	もし (options.control_path != NULL) {
		整数 sock;
		もし ((sock = muxclient(options.control_path)) >= 0) {
			もし (ssh_packet_set_connection(ssh, sock, sock) == NULL)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_set_mux(ssh);
			goto skip_connect;
		}
	}

	/* load options.identity_files */
	load_public_identity_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	もし (options.identity_agent &&
	    strcmp(options.identity_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		もし (strcmp(options.identity_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} 否则 {
			cp = options.identity_agent;
			/* legacy (limited) format */
			もし (cp[0] == '$' && cp[1] != '{') {
				もし (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				もし ((p = getenv(cp + 1)) == NULL)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				否则
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} 否则 {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	もし (dump_pubkeys) {
		pubkey_dump(ssh);
		exit(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	もし (addrs == NULL && options.proxy_command == NULL) {
		debug2("resolving \"%s\" port %d", host, options.port);
		もし ((addrs = resolve_host(host, options.port, 1,
		    cname, sizeof(cname))) == NULL)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	もし (options.connection_timeout >= INT_MAX/1000)
		timeout_ms = INT_MAX;
	否则
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	ために (j = 0; j < options.num_channel_timeouts; j++) {
		double timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		もし (parse_pattern_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_add_timeout(ssh, cp, timeout);
		free(cp);
	}
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	もし (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.port, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		exit(255);


	ssh_packet_set_timeout(ssh, options.server_alive_interval,
	    options.server_alive_count_max);

	もし (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_data.nkeys = 0;
	sensitive_data.keys = NULL;
	もし (options.hostbased_authentication) {
		整数 loaded = 0;

		sensitive_data.nkeys = 10;
		sensitive_data.keys = xcalloc(sensitive_data.nkeys,
		    sizeof(*sensitive_data.keys));

		/* XXX check errors? */
#define L_PUBKEY(p,o) do { \
	もし ((o) >= sensitive_data.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_load(sshkey_load_public(p, &(sensitive_data.keys[o]), NULL), \
	    &(sensitive_data.keys[o]), p, "hostbased pubkey"); \
	もし (sensitive_data.keys[o] != NULL) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ながら (0)
#define L_CERT(p,o) do { \
	もし ((o) >= sensitive_data.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_load(sshkey_load_cert(p, &(sensitive_data.keys[o])), \
	    &(sensitive_data.keys[o]), p, "hostbased cert"); \
	もし (sensitive_data.keys[o] != NULL) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ながら (0)

		もし (options.hostbased_authentication == 1) {
			L_CERT(_PATH_HOST_ECDSA_KEY_FILE, 0);
			L_CERT(_PATH_HOST_ED25519_KEY_FILE, 1);
			L_CERT(_PATH_HOST_RSA_KEY_FILE, 2);
			L_CERT(_PATH_HOST_MLDSA44_ED25519_KEY_FILE, 3);
			L_PUBKEY(_PATH_HOST_ECDSA_KEY_FILE, 4);
			L_PUBKEY(_PATH_HOST_ED25519_KEY_FILE, 5);
			L_PUBKEY(_PATH_HOST_RSA_KEY_FILE, 6);
			L_PUBKEY(_PATH_HOST_MLDSA44_ED25519_KEY_FILE, 7);
			もし (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	もし (options.forward_agent && options.forward_agent_sock_path != NULL) {
		cp = options.forward_agent_sock_path;
		もし (cp[0] == '$') {
			もし (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			もし ((p = getenv(cp + 1)) != NULL)
				forward_agent_sock_path = xstrdup(p);
			否则
				options.forward_agent = 0;
			free(cp);
		} 否则 {
			forward_agent_sock_path = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.num_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.num_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_data, host, &hostaddr, options.port,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	もし (sensitive_data.nkeys != 0) {
		ために (i = 0; i < sensitive_data.nkeys; i++) {
			もし (sensitive_data.keys[i] != NULL) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_data.keys[i]);
				sensitive_data.keys[i] = NULL;
			}
		}
		free(sensitive_data.keys);
	}
	ために (i = 0; i < options.num_identity_files; i++) {
		free(options.identity_files[i]);
		options.identity_files[i] = NULL;
		もし (options.identity_keys[i]) {
			sshkey_free(options.identity_keys[i]);
			options.identity_keys[i] = NULL;
		}
	}
	ために (i = 0; i < options.num_certificate_files; i++) {
		free(options.certificate_files[i]);
		options.certificate_files[i] = NULL;
	}

#ifdef ENABLE_PKCS11
	(void)pkcs11_del_provider(options.pkcs11_provider);
#endif

 skip_connect:
	もし (addrs != NULL)
		freeaddrinfo(addrs);
	exit_status = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	もし (options.control_path != NULL && muxserver_sock != -1)
		unlink(options.control_path);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	戻る exit_status;
}

static void
control_persist_detach(void)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	switch ((pid = fork())) {
	case -1:
		fatal_f("fork: %s", strerror(errno));
	case 0:
		/* Child: master process continues mainloop */
		break;
	default:
		/*
		 * Parent: set up mux client to connect to backgrounded
		 * master.
		 */
		debug2_f("background process is %ld", (long)pid);
		options.stdin_null = ostdin_null_flag;
		options.request_tty = orequest_tty;
		tty_flag = otty_flag;
		options.fork_after_authentication = ofork_after_authentication;
		options.session_type = osession_type;
		close(muxserver_sock);
		muxserver_sock = -1;
		options.control_master = SSHCTL_MASTER_NO;
		(void)muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	もし (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
}

/* Do fork() after authentication. Used by "ssh -f" */
static void
fork_postauth(void)
{
	もし (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	もし (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	もし (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

static void
forwarding_success(void)
{
	もし (forward_confirms_pending == -1)
		戻る;
	もし (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		もし (options.fork_after_authentication)
			fork_postauth();
	} 否则 {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

struct rfwd_confirm_ctx {
	整数 fid;
};

/* Callback for remote forward global requests */
static void
ssh_confirm_remote_forward(struct ssh *ssh, 整数 type, uint32_t seq, void *ctxt)
{
	struct rfwd_confirm_ctx *rctx = (struct rfwd_confirm_ctx *)ctxt;
	struct Forward *rfwd;
	u_int port;
	整数 r;

	もし (rctx->fid < 0 || rctx->fid >= options.num_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, sizeof(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_MSG_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	もし (rfwd->listen_path == NULL && rfwd->listen_port == 0) {
		もし (type == SSH2_MSG_REQUEST_SUCCESS) {
			もし ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse packet");
			もし (port > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
				/* Ensure failure processing runs below */
				type = SSH2_MSG_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} 否则 {
				rfwd->allocated_port = (整数)port;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_port, rfwd->connect_path ?
				    rfwd->connect_path : rfwd->connect_host,
				    rfwd->connect_port);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_port);
			}
		} 否则 {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	もし (type == SSH2_MSG_REQUEST_FAILURE) {
		もし (options.exit_on_forward_failure) {
			もし (rfwd->listen_path != NULL)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			否则
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} 否则 {
			もし (rfwd->listen_path != NULL)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			否则
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	forwarding_success();
}

static void
client_cleanup_stdio_fwd(struct ssh *ssh, 整数 id, 整数 force, void *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

static void
ssh_stdio_confirm(struct ssh *ssh, 整数 id, 整数 success, void *arg)
{
	もし (!success)
		fatal("stdio forwarding failed");
}

static void
ssh_tun_confirm(struct ssh *ssh, 整数 id, 整数 success, void *arg)
{
	もし (!success) {
		error("Tunnel forwarding failed");
		もし (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

static void
ssh_init_stdio_forwarding(struct ssh *ssh)
{
	Channel *c;
	整数 in, out;

	もし (options.stdio_forward_host == NULL)
		戻る;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	もし ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	もし ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == NULL)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, NULL);
}

static void
ssh_init_forward_permissions(struct ssh *ssh, const char *what, char **opens,
    u_int num_opens)
{
	u_int i;
	整数 port;
	char *addr, *arg, *oarg;
	整数 where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	もし (num_opens == 0)
		戻る; /* permit any */

	/* handle keywords: "any" / "none" */
	もし (num_opens == 1 && strcmp(opens[0], "any") == 0)
		戻る;
	もし (num_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		戻る;
	}
	/* Otherwise treat it as a list of permitted host:port */
	ために (i = 0; i < num_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		もし (addr == NULL)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		もし (arg == NULL || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, addr, port);
		free(oarg);
	}
}

static void
ssh_init_forwarding(struct ssh *ssh, char **ifname)
{
	整数 success = 0;
	整数 i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.num_permitted_remote_opens);

	もし (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	ために (i = 0; i < options.num_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != NULL) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == NULL) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != NULL) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	もし (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	もし (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	ために (i = 0; i < options.num_remote_forwards; i++) {
		struct rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != NULL) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == NULL) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != NULL) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		もし ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, sizeof(*rctx));
			rctx->fid = i;
			client_register_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} 否则 もし (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		否则
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	もし (options.tun_open != SSH_TUNMODE_NO) {
		もし ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, NULL)) != NULL)
			forward_confirms_pending++;
		否则 もし (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		否则
			error("Could not request tunnel forwarding.");
	}
	もし (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

static void
check_agent_present(void)
{
	整数 r;

	もし (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		もし ((r = ssh_get_authentication_socket(NULL)) != 0) {
			options.forward_agent = 0;
			もし (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

static void
ssh_session2_setup(struct ssh *ssh, 整数 id, 整数 success, void *arg)
{
	extern char **environ;
	const char *display, *term;
	char *proto = NULL, *data = NULL;

	もし (!success)
		戻る; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	もし (display == NULL && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	もし (options.forward_x11 && client_x11_get_proto(ssh, display,
	    options.xauth_location, options.forward_x11_trusted,
	    options.forward_x11_timeout, &proto, &data) == 0) {
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(ssh, id, display, proto,
		    data, 1);
		client_expect_confirm(ssh, id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
	}

	check_agent_present();
	もし (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	もし ((term = lookup_env_in_list("TERM", options.setenv,
	    options.num_setenv)) == NULL || *term == '\0')
		term = getenv("TERM");
	client_session2_setup(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, term,
	    NULL, fileno(stdin), command, environ);
}

/* open new channel for a session */
static 整数
ssh_session2_open(struct ssh *ssh)
{
	Channel *c;
	整数 window, packetmax, in, out, err;

	もし (options.stdin_null) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} 否则 {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	もし (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	もし (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	もし (tty_flag)
		channel_set_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	もし (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, NULL);

	戻る c->self;
}

static 整数
ssh_session2(struct ssh *ssh, const struct ssh_conn_info *cinfo)
{
	整数 r, id = -1;
	char *cp, *tun_fwd_ifname = NULL;

	/* XXX should be pre-session */
	もし (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	もし (options.local_command != NULL) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "T", tun_fwd_ifname == NULL ? "NONE" : tun_fwd_ifname,
		    (char *)NULL);
		debug3("expanded LocalCommand: %s", options.local_command);
		free(cp);
	}

	/* Start listening for multiplex clients */
	もし (!ssh_packet_get_mux(ssh))
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
	もし (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		もし ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != NULL))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	もし (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	もし (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	もし (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		もし ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	もし (options.local_command != NULL &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	もし (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	もし (options.fork_after_authentication) {
		もし (options.exit_on_forward_failure &&
		    options.num_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} 否则
			fork_postauth();
	}

	戻る client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
static void
load_public_identity_files(const struct ssh_conn_info *cinfo)
{
	char *filename, *cp;
	struct sshkey *public;
	整数 i;
	u_int n_ids, n_certs;
	char *identity_files[SSH_MAX_IDENTITY_FILES];
	struct sshkey *identity_keys[SSH_MAX_IDENTITY_FILES];
	整数 identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	char *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	struct sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	整数 certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ifdef ENABLE_PKCS11
	struct sshkey **keys = NULL;
	char **comments = NULL;
	整数 nkeys;
#endif /* PKCS11 */

	n_ids = n_certs = 0;
	memset(identity_files, 0, sizeof(identity_files));
	memset(identity_keys, 0, sizeof(identity_keys));
	memset(identity_file_userprovided, 0,
	    sizeof(identity_file_userprovided));
	memset(certificate_files, 0, sizeof(certificate_files));
	memset(certificates, 0, sizeof(certificates));
	memset(certificate_file_userprovided, 0,
	    sizeof(certificate_file_userprovided));

#ifdef ENABLE_PKCS11
	もし (options.pkcs11_provider != NULL &&
	    options.num_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, NULL,
	    &keys, &comments)) > 0) {
		ために (i = 0; i < nkeys; i++) {
			もし (n_ids >= SSH_MAX_IDENTITY_FILES) {
				sshkey_free(keys[i]);
				free(comments[i]);
				continue;
			}
			identity_keys[n_ids] = keys[i];
			identity_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		free(keys);
		free(comments);
	}
#endif /* ENABLE_PKCS11 */
	ために (i = 0; i < options.num_identity_files; i++) {
		もし (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			free(options.identity_files[i]);
			options.identity_files[i] = NULL;
			continue;
		}
		cp = tilde_expand_filename(options.identity_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		free(cp);
		check_load(sshkey_load_public(filename, &public, NULL),
		    &public, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    public ? public->type : -1);
		free(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_keys[n_ids] = public;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		もし (++n_ids >= SSH_MAX_IDENTITY_FILES)
			continue;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		もし (options.num_certificate_files != 0)
			continue;
		xasprintf(&cp, "%s-cert", filename);
		check_load(sshkey_load_public(cp, &public, NULL),
		    &public, filename, "identity pubkey");
		もし (public == NULL) {
			free(cp);
			continue;
		}
		もし (!sshkey_is_cert(public)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(public));
			sshkey_free(public);
			free(cp);
			continue;
		}
		free(cp);
		/* NB. leave filename pointing to private key */
		identity_files[n_ids] = xstrdup(filename);
		identity_keys[n_ids] = public;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		n_ids++;
	}

	もし (options.num_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	ために (i = 0; i < options.num_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		free(cp);

		check_load(sshkey_load_public(filename, &public, NULL),
		    &public, filename, "identity cert");
		free(options.certificate_files[i]);
		options.certificate_files[i] = NULL;
		もし (public == NULL) {
			free(filename);
			continue;
		}
		もし (!sshkey_is_cert(public)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(public));
			sshkey_free(public);
			free(filename);
			continue;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = public;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.num_identity_files = n_ids;
	memcpy(options.identity_files, identity_files, sizeof(identity_files));
	memcpy(options.identity_keys, identity_keys, sizeof(identity_keys));
	memcpy(options.identity_file_userprovided,
	    identity_file_userprovided, sizeof(identity_file_userprovided));

	options.num_certificate_files = n_certs;
	memcpy(options.certificate_files,
	    certificate_files, sizeof(certificate_files));
	memcpy(options.certificates, certificates, sizeof(certificates));
	memcpy(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    sizeof(certificate_file_userprovided));
}

static void
main_sigchld_handler(整数 sig)
{
	整数 save_errno = errno;
	pid_t pid;
	整数 status;

	ながら ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
