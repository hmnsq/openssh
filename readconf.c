/* $OpenBSD: readconf.c,v 1.419 2026/10/05 06:03:40 dtucker Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for reading the configuration files.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <sys/socket.h>
#شامل <sys/wait.h>
#شامل <sys/un.h>

#شامل <net/if.h>
#شامل <netinet/in.h>
#شامل <netinet/ip.h>
#شامل <arpa/inet.h>

#شامل <ctype.h>
#شامل <errno.h>
#شامل <glob.h>
#شامل <ifaddrs.h>
#شامل <limits.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>
#شامل <util.h>
#اگر defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "cipher.h"
#شامل "pathnames.h"
#شامل "log.h"
#شامل "sshkey.h"
#شامل "misc.h"
#شامل "readconf.h"
#شامل "match.h"
#شامل "kex.h"
#شامل "mac.h"
#شامل "myproposal.h"
#شامل "digest.h"
#شامل "version.h"

/* Format of the configuration file:

   # Configuration data is parsed as follows:
   #  1. command line options
   #  2. user-specific file
   #  3. system-wide file
   # Any configuration value is only changed the first time it is set.
   # Thus, host-specific definitions should be at the beginning of the
   # configuration file, and defaults at the end.

   # Host-specific declarations.  These may override anything above.  A single
   # host may match multiple declarations; these are processed in the order
   # that they are given in.

   Host *.ngs.fi ngs.fi
     User foo

   Host fake.com
     Hostname another.host.name.real.org
     User blaah
     Port 34289
     ForwardX11 no
     ForwardAgent no

   Host books.com
     RemoteForward 9999 shadows.cs.hut.fi:9999
     Ciphers 3des-cbc

   Host fascist.blob.com
     Port 23123
     User tylonen
     PasswordAuthentication no

   Host puukko.hut.fi
     User t35124p
     ProxyCommand ssh-proxy %h %p

   Host *.fr
     PublicKeyAuthentication no

   Host *.su
     Ciphers aes128-ctr
     PasswordAuthentication no

   Host vpn.fake.com
     Tunnel yes
     TunnelDevice 3

   # Defaults for various options
   Host *
     ForwardAgent no
     ForwardX11 no
     PasswordAuthentication yes
     StrictHostKeyChecking yes
     TcpKeepAlive no
     IdentityFile ~/.ssh/identity
     Port 22
     EscapeChar ~

*/

ایستا صحیح read_config_file_depth(ثابت نویسه *filename, ساختار passwd *pw,
    ثابت نویسه *host, ثابت نویسه *original_host, ثابت نویسه *remote_command,
    Options *options, صحیح flags, صحیح *activep, صحیح *want_final_pass, صحیح depth);
ایستا صحیح process_config_سطر_depth(Options *options, ساختار passwd *pw,
    ثابت نویسه *host, ثابت نویسه *original_host, ثابت نویسه *remote_command,
    نویسه *سطر, ثابت نویسه *filename, صحیح linenum, صحیح *activep, صحیح flags,
    صحیح *want_final_pass, صحیح depth);

/* Keyword tokens. */

تعریفنوع شمارش {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_کلیدها_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_کلید_Checking, oCompression,
	oTCPKeepAlive, o_عدد_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_کلید_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_کلید_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_کلید_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_شمار_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_کلید,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_کلیدها,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_کلید_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

ایستا ساختار {
	ثابت نویسه *name;
	OpCodes opcode;
} keywords[] = {
	/* Deprecated options */
	{ "protocol", oIgnore }, /* NB. silently ignored */
	{ "cipher", oDeprecated },
	{ "fallbacktorsh", oDeprecated },
	{ "globalknownhostsfile2", oDeprecated },
	{ "rhostsauthentication", oDeprecated },
	{ "userknownhostsfile2", oDeprecated },
	{ "useroaming", oDeprecated },
	{ "usersh", oDeprecated },
	{ "useprivilegedport", oDeprecated },

	/* Unsupported options */
	{ "afstokenpassing", oUnsupported },
	{ "kerberosauthentication", oUnsupported },
	{ "kerberostgtpassing", oUnsupported },
	{ "rsaauthentication", oUnsupported },
	{ "rhostsrsaauthentication", oUnsupported },
	{ "compressionlevel", oUnsupported },

	/* Sometimes-unsupported options */
#اگر defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# وگرنه
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# وگرنه
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#endif

	{ "forwardagent", oForwardAgent },
	{ "forwardx11", oForwardX11 },
	{ "forwardx11trusted", oForwardX11Trusted },
	{ "forwardx11timeout", oForwardX11Timeout },
	{ "exitonforwardfailure", oExitOnForwardFailure },
	{ "xauthlocation", oXAuthLocation },
	{ "gatewayports", oGatewayPorts },
	{ "passwordauthentication", oPasswordAuthentication },
	{ "kbdinteractiveauthentication", oKbdInteractiveAuthentication },
	{ "kbdinteractivedevices", oKbdInteractiveDevices },
	{ "challengeresponseauthentication", oKbdInteractiveAuthentication }, /* alias */
	{ "skeyauthentication", oKbdInteractiveAuthentication }, /* alias */
	{ "tisauthentication", oKbdInteractiveAuthentication },  /* alias */
	{ "pubkeyauthentication", oPubkeyAuthentication },
	{ "dsaauthentication", oPubkeyAuthentication },		    /* alias */
	{ "hostbasedauthentication", oHostbasedAuthentication },
	{ "identityfile", oIdentityFile },
	{ "identityfile2", oIdentityFile },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_Add_کلیدها_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_کلید_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", oPort },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", oMatch },
	{ "tag", oTag },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", oGlobalKnownHostsFile },
	{ "userknownhostsfile", oUserKnownHostsFile },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", oBatchMode },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_کلید_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_عدد_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_کلید_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_کلید_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_شمار_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", oSetEnv },
	{ "controlpath", oControlPath },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", oHashKnownHosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", o_Visual_Host_کلید },
	{ "kexalgorithms", oKexAlgorithms },
	{ "ipqos", oIPQoS },
	{ "requesttty", oRequestTTY },
	{ "sessiontype", oSessionType },
	{ "stdinnull", oStdinNull },
	{ "forkafterauthentication", oForkAfterAuthentication },
	{ "proxyusefdpass", oProxyUseFdpass },
	{ "canonicaldomains", oCanonicalDomains },
	{ "canonicalizefallbacklocal", oCanonicalizeFallbackLocal },
	{ "canonicalizehostname", oCanonicalizeHostname },
	{ "canonicalizemaxdots", oCanonicalizeMaxDots },
	{ "canonicalizepermittedcnames", oCanonicalizePermittedCNAMEs },
	{ "streamlocalbindmask", oStreamLocalBindMask },
	{ "streamlocalbindunlink", oStreamLocalBindUnlink },
	{ "revokedhostkeys", o_Revoked_Host_کلیدها },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_کلید_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ پوچ, oBadOption }
};

ایستا ثابت نویسه *lookup_opcode_name(OpCodes code);

ثابت نویسه *
kex_default_pk_alg(تهی)
{
	ایستا نویسه *pkalgs;

	اگر (pkalgs == پوچ) {
		نویسه *all_کلید;

		all_کلید = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلید);
		آزاد(all_کلید);
	}
	بازگشت pkalgs;
}

نویسه *
ssh_connection_hash(ثابت نویسه *thishost, ثابت نویسه *host, ثابت نویسه *portstr,
    ثابت نویسه *user, ثابت نویسه *jumphost)
{
	ساختار ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	اگر ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == پوچ ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, اندازه(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	بازگشت tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

تهی
add_local_forward(Options *options, ثابت ساختار Forward *newfwd)
{
	ساختار Forward *fwd;
	صحیح i;

	/* Don't add duplicates */
	برای (i = 0; i < options->رقم_local_forwards; i++) {
		اگر (forward_equals(newfwd, options->local_forwards + i))
			بازگشت;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->رقم_local_forwards + 1,
	    اندازه(*options->local_forwards));
	fwd = &options->local_forwards[options->رقم_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

تهی
add_remote_forward(Options *options, ثابت ساختار Forward *newfwd)
{
	ساختار Forward *fwd;
	صحیح i;

	/* Don't add duplicates */
	برای (i = 0; i < options->رقم_remote_forwards; i++) {
		اگر (forward_equals(newfwd, options->remote_forwards + i))
			بازگشت;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->رقم_remote_forwards + 1,
	    اندازه(*options->remote_forwards));
	fwd = &options->remote_forwards[options->رقم_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

ایستا تهی
clear_forwardings(Options *options)
{
	صحیح i;

	برای (i = 0; i < options->رقم_local_forwards; i++) {
		آزاد(options->local_forwards[i].listen_host);
		آزاد(options->local_forwards[i].listen_path);
		آزاد(options->local_forwards[i].connect_host);
		آزاد(options->local_forwards[i].connect_path);
	}
	اگر (options->رقم_local_forwards > 0) {
		آزاد(options->local_forwards);
		options->local_forwards = پوچ;
	}
	options->رقم_local_forwards = 0;
	برای (i = 0; i < options->رقم_remote_forwards; i++) {
		آزاد(options->remote_forwards[i].listen_host);
		آزاد(options->remote_forwards[i].listen_path);
		آزاد(options->remote_forwards[i].connect_host);
		آزاد(options->remote_forwards[i].connect_path);
	}
	اگر (options->رقم_remote_forwards > 0) {
		آزاد(options->remote_forwards);
		options->remote_forwards = پوچ;
	}
	options->رقم_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

تهی
add_certificate_file(Options *options, ثابت نویسه *path, صحیح userprovided)
{
	صحیح i;

	اگر (options->رقم_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	برای (i = 0; i < options->رقم_certificate_files; i++) {
		اگر (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			بازگشت;
		}
	}

	options->certificate_file_userprovided[options->رقم_certificate_files] =
	    userprovided;
	options->certificate_files[options->رقم_certificate_files++] =
	    xstrdup(path);
}

تهی
add_identity_file(Options *options, ثابت نویسه *dir, ثابت نویسه *filename,
    صحیح userprovided)
{
	نویسه *path;
	صحیح i;

	اگر (options->رقم_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	اگر (dir == پوچ) /* no dir, filename is absolute */
		path = xstrdup(filename);
	وگرنه اگر (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	برای (i = 0; i < options->رقم_identity_files; i++) {
		اگر (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			آزاد(path);
			بازگشت;
		}
	}

	options->identity_file_userprovided[options->رقم_identity_files] =
	    userprovided;
	options->identity_files[options->رقم_identity_files++] = path;
}

صحیح
default_ssh_port(تهی)
{
	ایستا صحیح port;
	ساختار servent *sp;

	اگر (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	بازگشت port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
ایستا صحیح
execute_in_shell(ثابت نویسه *cmd)
{
	نویسه *shell;
	pid_t pid;
	صحیح status;

	اگر ((shell = getenv("SHELL")) == پوچ)
		shell = _PATH_BSHELL;

	اگر (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	اگر ((pid = fork()) == 0) {
		نویسه *argv[4];

		اگر (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = پوچ;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	اگر (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	وقتی (waitpid(pid, &status, 0) == -1) {
		اگر (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	اگر (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		بازگشت -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	بازگشت WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
ایستا صحیح
check_match_ifaddrs(ثابت نویسه *addrlist)
{
#ifdef HAVE_IFADDRS_H
	ساختار ifaddrs *ifa, *ifaddrs = پوچ;
	صحیح r, found = 0;
	نویسه addr[NI_MAXHOST];
	socklen_t salen;

	اگر (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		بازگشت 0;
	}
	برای (ifa = ifaddrs; ifa != پوچ; ifa = ifa->ifa_next) {
		اگر (ifa->ifa_addr == پوچ || ifa->ifa_name == پوچ ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			ادامه;
		انتخاب (ifa->ifa_addr->sa_family) {
		حالت AF_INET:
			salen = اندازه(ساختار sockaddr_in);
			بشکن;
		حالت AF_INET6:
			salen = اندازه(ساختار sockaddr_in6);
			بشکن;
#ifdef AF_LINK
		حالت AF_LINK:
			/* ignore */
			ادامه;
#endif /* AF_LINK */
		پیشفرض:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			ادامه;
		}
		اگر ((r = getnameinfo(ifa->ifa_addr, salen, addr, اندازه(addr),
		    پوچ, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			ادامه;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		اگر (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			بشکن;
		}
	}
	freeifaddrs(ifaddrs);
	بازگشت found;
#وگرنه /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	بازگشت 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
ایستا نویسه *
expand_match_exec_or_include_path(ثابت نویسه *path, Options *options,
    ساختار passwd *pw, ثابت نویسه *host_arg, ثابت نویسه *original_host,
    صحیح final_pass, صحیح is_include_path)
{
	نویسه thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	نویسه uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	نویسه *host, *ret;
	صحیح port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == پوچ ? pw->pw_name : options->user;
	اگر (final_pass) {
		host = xstrdup(options->hostname);
	} وگرنه اگر (options->hostname != پوچ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (نویسه *)پوچ);
	} وگرنه {
		host = xstrdup(host_arg);
	}
	اگر (gethostname(thishost, اندازه(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, اندازه(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, اندازه(portstr), "%d", port);
	snprintf(uidstr, اندازه(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_کلید_alias ?  options->host_کلید_alias : host;

	ret = (is_include_path ? percent_dollar_expand : percent_expand)(path,
	    "C", conn_hash_hex,
	    "L", shorthost,
	    "d", pw->pw_dir,
	    "h", host,
	    "k", keyalias,
	    "l", thishost,
	    "n", original_host,
	    "p", portstr,
	    "r", ruser,
	    "u", pw->pw_name,
	    "i", uidstr,
	    "j", jmphost,
	    (نویسه *)پوچ);
	آزاد(host);
	آزاد(conn_hash_hex);
	بازگشت ret;
}

/*
 * Parse and execute a Match directive.
 */
ایستا صحیح
match_cfg_سطر(Options *options, ثابت نویسه *full_سطر, صحیح *acp, نویسه ***avp,
    ساختار passwd *pw, ثابت نویسه *host_arg, ثابت نویسه *original_host,
    ثابت نویسه *remote_command, صحیح final_pass, صحیح *want_final_pass,
    ثابت نویسه *filename, صحیح linenum)
{
	نویسه *arg, *oattrib = پوچ, *attrib = پوچ, *cmd, *host, *criteria;
	ثابت نویسه *ruser;
	صحیح r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == پوچ ? pw->pw_name : options->user;
	اگر (final_pass) {
		host = xstrdup(options->hostname);
	} وگرنه اگر (options->hostname != پوچ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (نویسه *)پوچ);
	} وگرنه {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_سطر, host, original_host);
	وقتی ((attrib = argv_next(acp, avp)) != پوچ) {
		/* Terminate on comment */
		اگر (*attrib == '#') {
			argv_consume(acp);
			بشکن;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = پوچ;
		this_result = 1;
		اگر ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		اگر (strcasecmp(attrib, "all") == 0) {
			اگر (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != پوچ &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				برو out;
			}
			اگر (arg != پوچ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			اگر (result)
				result = negate ? 0 : 1;
			برو out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		اگر (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			اگر (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != پوچ)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			برو next;
		}

		/* Keep this list in sync with below */
		اگر (strprefix(attrib, "host=", 1)  != پوچ ||
		    strprefix(attrib, "originalhost=", 1) != پوچ ||
		    strprefix(attrib, "user=", 1) != پوچ ||
		    strprefix(attrib, "localuser=", 1) != پوچ ||
		    strprefix(attrib, "localnetwork=", 1) != پوچ ||
		    strprefix(attrib, "version=", 1) != پوچ ||
		    strprefix(attrib, "tagged=", 1) != پوچ ||
		    strprefix(attrib, "command=", 1) != پوچ ||
		    strprefix(attrib, "exec=", 1) != پوچ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} وگرنه اگر ((arg = argv_next(acp, avp)) == پوچ) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			برو out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		اگر (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = پوچ;
		اگر (arg == پوچ || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			برو out;
		}
		اگر (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه اگر (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه اگر (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه اگر (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه اگر (strcasecmp(attrib, "localnetwork") == 0) {
			اگر (addr_match_cidr_list(پوچ, arg) == -1) {
				/* Error already printed */
				result = -1;
				برو out;
			}
			r = check_match_ifaddrs(arg) == 1;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه اگر (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه اگر (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == پوچ ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه اگر (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == پوچ ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه اگر (strcasecmp(attrib, "sessiontype") == 0) {
			اگر (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			وگرنه اگر (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			وگرنه اگر (remote_command != پوچ &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			وگرنه
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه اگر (strcasecmp(attrib, "exec") == 0) {
			اگر ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == پوچ) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			اگر (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				آزاد(cmd);
				برو next;
			}
			r = execute_in_shell(cmd);
			اگر (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			آزاد(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			اگر (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وگرنه {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			برو out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == پوچ ? "" : " \"",
		    criteria == پوچ ? "" : criteria,
		    criteria == پوچ ? "" : "\"");
 next:
		آزاد(criteria);
		آزاد(oattrib);
		oattrib = attrib = پوچ;
	}
	اگر (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		برو out;
	}
 out:
	اگر (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	آزاد(oattrib);
	آزاد(host);
	بازگشت result;
}

/* Remove environment variable by pattern */
ایستا تهی
rm_env(Options *options, ثابت نویسه *arg, ثابت نویسه *filename, صحیح linenum)
{
	u_int i, j, onum_send_env = options->رقم_send_env;

	/* Remove an environment variable */
	برای (i = 0; i < options->رقم_send_env; ) {
		اگر (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			ادامه;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		آزاد(options->send_env[i]);
		options->send_env[i] = پوچ;
		برای (j = i; j < options->رقم_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = پوچ;
		}
		options->رقم_send_env--;
		/* NB. don't increment i */
	}
	اگر (onum_send_env != options->رقم_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->رقم_send_env,
		    اندازه(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
ایستا OpCodes
parse_token(ثابت نویسه *cp, ثابت نویسه *filename, صحیح linenum,
    ثابت نویسه *ignored_unknown)
{
	صحیح i;

	برای (i = 0; keywords[i].name; i++)
		اگر (strcmp(cp, keywords[i].name) == 0)
			بازگشت keywords[i].opcode;
	اگر (ignored_unknown != پوچ &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		بازگشت oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	بازگشت oBadOption;
}

ایستا تهی
free_canon_cnames(ساختار allowed_cname *cnames, u_int n)
{
	u_int i;

	اگر (cnames == پوچ || n == 0)
		بازگشت;
	برای (i = 0; i < n; i++) {
		آزاد(cnames[i].source_list);
		آزاد(cnames[i].target_list);
	}
	آزاد(cnames);
}

/* Multistate option parsing */
ساختار multistate {
	نویسه *کلید;
	صحیح مقدار;
};
ایستا ثابت ساختار multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ پوچ, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
ایستا ثابت ساختار multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ پوچ, -1 }
};

ایستا صحیح
parse_multistate_مقدار(ثابت نویسه *arg, ثابت نویسه *filename, صحیح linenum,
    ثابت ساختار multistate *multistate_ptr)
{
	صحیح i;

	اگر (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		بازگشت -1;
	}
	برای (i = 0; multistate_ptr[i].کلید != پوچ; i++) {
		اگر (strcasecmp(arg, multistate_ptr[i].کلید) == 0)
			بازگشت multistate_ptr[i].مقدار;
	}
	بازگشت -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
صحیح
process_config_سطر(Options *options, ساختار passwd *pw, ثابت نویسه *host,
    ثابت نویسه *original_host, ثابت نویسه *remote_command, نویسه *سطر,
    ثابت نویسه *filename, صحیح linenum, صحیح *activep, صحیح flags)
{
	بازگشت process_config_سطر_depth(options, pw, host, original_host,
	    remote_command, سطر, filename, linenum, activep, flags, پوچ, 0);
}

#define WHITESPACE " \t\r\n"
ایستا صحیح
process_config_سطر_depth(Options *options, ساختار passwd *pw, ثابت نویسه *host,
    ثابت نویسه *original_host, ثابت نویسه *remote_command, نویسه *سطر,
    ثابت نویسه *filename, صحیح linenum, صحیح *activep, صحیح flags,
    صحیح *want_final_pass, صحیح depth)
{
	نویسه *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	نویسه **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	صحیح r, oactive, negated, opcode, *intptr, مقدار, value2, cmdline = 0;
	صحیح remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	ساختار Forward fwd;
	ثابت ساختار multistate *multistate_ptr;
	glob_t gl;
	ثابت نویسه *errstr;
	نویسه **oav = پوچ, **av;
	صحیح oac = 0, ac;
	صحیح ret = -1;
	ساختار allowed_cname *cnames = پوچ;
	u_int ncnames = 0;
	نویسه **strs = پوچ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	اگر (activep == پوچ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	اگر ((len = strlen(سطر)) == 0)
		بازگشت 0;
	برای (len--; len > 0; len--) {
		اگر (strchr(WHITESPACE "\f", سطر[len]) == پوچ)
			بشکن;
		سطر[len] = '\0';
	}

	str = سطر;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	اگر ((keyword = strdelim(&str)) == پوچ)
		بازگشت 0;
	/* Ignore leading whitespace. */
	اگر (*keyword == '\0')
		keyword = strdelim(&str);
	اگر (keyword == پوچ || !*keyword || *keyword == '\n' || *keyword == '#')
		بازگشت 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	اگر (str != پوچ)
		str += strspn(str, WHITESPACE);
	اگر (str == پوچ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		بازگشت -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	اگر (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		بازگشت -1;
	}
	ac = oac;
	av = oav;

	انتخاب (opcode) {
	حالت oBadOption:
		/* don't panic, but count bad options */
		برو out;
	حالت oIgnore:
		argv_consume(&ac);
		بشکن;
	حالت oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		بشکن;
	حالت oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			برو out;
		}
		اگر (strcmp(arg, "none") == 0)
			مقدار = -1;
		وگرنه اگر ((مقدار = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			برو out;
		}
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			برو out;
		}

		مقدار = -1;
		multistate_ptr = multistate_flag;
		برای (i = 0; multistate_ptr[i].کلید != پوچ; i++) {
			اگر (strcasecmp(arg, multistate_ptr[i].کلید) == 0) {
				مقدار = multistate_ptr[i].مقدار;
				بشکن;
			}
		}
		اگر (مقدار != -1) {
			اگر (*activep && *intptr == -1)
				*intptr = مقدار;
			بشکن;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		اگر (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		برو parse_agent_path;

	حالت oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		اگر ((مقدار = parse_multistate_مقدار(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			برو out;
		}
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		برو parse_flag;

	حالت oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		برو parse_time;

	حالت oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		برو parse_flag;

	حالت oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		برو parse_flag;

	حالت oPasswordAuthentication:
		intptr = &options->password_authentication;
		برو parse_flag;

	حالت oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		برو parse_flag;

	حالت oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		برو parse_string;

	حالت oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		برو parse_multistate;

	حالت oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		برو parse_flag;

	حالت oGssAuthentication:
		intptr = &options->gss_authentication;
		برو parse_flag;

	حالت oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		برو parse_flag;

	حالت oBatchMode:
		intptr = &options->batch_mode;
		برو parse_flag;

	حالت oCheckHostIP:
		intptr = &options->check_host_ip;
		برو parse_flag;

	حالت o_Verify_Host_کلید_DNS:
		intptr = &options->verify_host_کلید_dns;
		multistate_ptr = multistate_yesnoask;
		برو parse_multistate;

	حالت o_Strict_Host_کلید_Checking:
		intptr = &options->strict_host_کلید_checking;
		multistate_ptr = multistate_strict_hostkey;
		برو parse_multistate;

	حالت oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		برو parse_multistate;

	حالت oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		برو parse_multistate;

	حالت oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		برو parse_flag;

	حالت o_عدد_Of_Password_Prompts:
		intptr = &options->عدد_of_password_prompts;
		برو parse_int;

	حالت oRekeyLimit:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			برو out;
		}
		اگر (strcmp(arg, "default") == 0) {
			val64 = 0;
		} وگرنه {
			اگر (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				برو out;
			}
			اگر (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				برو out;
			}
		}
		اگر (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		اگر (ac != 0) { /* optional rekey interval present */
			اگر (strcmp(av[0], "none") == 0) {
				(تهی)argv_next(&ac, &av);	/* discard */
				بشکن;
			}
			intptr = &options->rekey_interval;
			برو parse_time;
		}
		بشکن;

	حالت oIdentityFile:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر (*activep) {
			intptr = &options->رقم_identity_files;
			اگر (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				برو out;
			}
			add_identity_file(options, پوچ,
			    arg, flags & SSHCONF_USERCONF);
		}
		بشکن;

	حالت oCertificateFile:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر (*activep) {
			intptr = &options->رقم_certificate_files;
			اگر (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				برو out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		بشکن;

	حالت oXAuthLocation:
		charptr=&options->xauth_location;
		برو parse_string;

	حالت oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;

	حالت oGlobalKnownHostsFile:
		cpptr = (نویسه **)&options->system_hostfiles;
		uintptr = &options->رقم_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		مقدار = *uintptr == 0; /* was array empty when we started? */
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				برو out;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					برو out;
				}
			}
			i++;
			اگر (*activep && مقدار) {
				اگر ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					برو out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		بشکن;

	حالت oUserKnownHostsFile:
		cpptr = (نویسه **)&options->user_hostfiles;
		uintptr = &options->رقم_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		برو parse_char_array;

	حالت oHostname:
		charptr = &options->hostname;
		برو parse_string;

	حالت oTag:
		charptr = &options->tag;
		برو parse_string;

	حالت o_Host_کلید_Alias:
		charptr = &options->host_کلید_alias;
		برو parse_string;

	حالت oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		برو parse_string;

	حالت oBindAddress:
		charptr = &options->bind_address;
		برو parse_string;

	حالت oBindInterface:
		charptr = &options->bind_interface;
		برو parse_string;

	حالت oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		برو parse_string;

	حالت o_Security_کلید_Provider:
		charptr = &options->sk_provider;
		برو parse_string;

	حالت oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		برو parse_command;

	حالت oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		اگر (str == پوچ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		len = strspn(str, WHITESPACE "=");
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		بشکن;

	حالت oProxyJump:
		اگر (str == پوچ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		اگر (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			برو out;
		}
		argv_consume(&ac);
		بشکن;

	حالت oPort:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		مقدار = a2port(arg);
		اگر (مقدار <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			برو out;
		}
		اگر (*activep && options->port == -1)
			options->port = مقدار;
		بشکن;

	حالت oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		اگر ((errstr = atoi_err(arg, &مقدار)) != پوچ) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			برو out;
		}
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت oCiphers:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			برو out;
		}
		اگر (*activep && options->ciphers == پوچ)
			options->ciphers = xstrdup(arg);
		بشکن;

	حالت oMacs:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			برو out;
		}
		اگر (*activep && options->macs == پوچ)
			options->macs = xstrdup(arg);
		بشکن;

	حالت oKexAlgorithms:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			برو out;
		}
		اگر (*activep && options->kex_algorithms == پوچ)
			options->kex_algorithms = xstrdup(arg);
		بشکن;

	حالت o_Host_کلید_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			برو out;
		}
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;

	حالت oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		برو parse_pubkey_algos;

	حالت oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		مقدار = log_level_عدد(arg);
		اگر (مقدار == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			برو out;
		}
		اگر (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) مقدار;
		بشکن;

	حالت oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		مقدار = log_facility_عدد(arg);
		اگر (مقدار == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			برو out;
		}
		اگر (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) مقدار;
		بشکن;

	حالت oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->رقم_log_verbose;
		i = 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				برو out;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					برو out;
				}
			}
			i++;
			اگر (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, اندازه(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		بشکن;

	حالت oLocalForward:
	حالت oRemoteForward:
	حالت oDynamicForward:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		اگر (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			اگر (arg2 == پوچ || *arg2 == '\0') {
				اگر (remotefwd)
					dynamicfwd = 1;
				وگرنه {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					برو out;
				}
			} وگرنه {
				/* construct a string for parse_forward */
				snprintf(fwdarg, اندازه(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		اگر (dynamicfwd)
			strlcpy(fwdarg, arg, اندازه(fwdarg));

		اگر (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			برو out;
		}

		اگر (*activep) {
			اگر (remotefwd) {
				add_remote_forward(options, &fwd);
			} وگرنه {
				add_local_forward(options, &fwd);
			}
		}
		بشکن;

	حالت oPermitRemoteOpen:
		uintptr = &options->رقم_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			اگر (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					آزاد(arg2);
					برو out;
				}
			} وگرنه {
				p = hpdelim(&arg);
				اگر (p == پوچ) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				اگر (arg == پوچ || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			آزاد(arg2);
		}
		اگر (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		اگر (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت oClearAllForwardings:
		intptr = &options->clear_forwardings;
		برو parse_flag;

	حالت oHost:
		اگر (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			برو out;
		}
		*activep = 0;
		arg2 = پوچ;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				برو out;
			}
			اگر ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				بشکن;
			}
			negated = *arg == '!';
			اگر (negated)
				arg++;
			اگر (match_pattern(host, arg)) {
				اگر (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					بشکن;
				}
				اگر (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		اگر (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		بشکن;

	حالت oMatch:
		اگر (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			برو out;
		}
		مقدار = match_cfg_سطر(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		اگر (مقدار < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			برو out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : مقدار;
		بشکن;

	حالت oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر (strcmp(arg, "none") == 0)
			مقدار = SSH_ESCAPECHAR_NONE;
		وگرنه اگر (arg[1] == '\0')
			مقدار = (u_char) arg[0];
		وگرنه اگر (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			مقدار = (u_char) arg[1] & 31;
		وگرنه {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			برو out;
		}
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		برو parse_multistate;

	حالت oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		برو parse_flag;

	حالت oIdentitiesOnly:
		intptr = &options->identities_only;
		برو parse_flag;

	حالت oServerAliveInterval:
		intptr = &options->server_alive_interval;
		برو parse_time;

	حالت o_Server_Alive_شمار_Max:
		intptr = &options->server_alive_شمار_max;
		برو parse_int;

	حالت oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0' || strchr(arg, '=') != پوچ) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				برو out;
			}
			found = 1;
			اگر (!*activep)
				ادامه;
			اگر (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				ادامه;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->رقم_send_env, arg);
		}
		اگر (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		بشکن;

	حالت oSetEnv:
		found = options->رقم_setenv == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (strchr(arg, '=') == پوچ) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				برو out;
			}
			اگر (lookup_setenv_in_list(arg, strs, nstrs) != پوچ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ادامه;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			options->setenv = strs;
			options->رقم_setenv = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت oControlPath:
		charptr = &options->control_path;
		برو parse_string;

	حالت oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		برو parse_multistate;

	حالت oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			برو out;
		}
		مقدار = 0;
		value2 = 0;	/* timeout */
		اگر (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			مقدار = 0;
		وگرنه اگر (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			مقدار = 1;
		وگرنه اگر ((value2 = convtime(arg)) >= 0)
			مقدار = 1;
		وگرنه {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			برو out;
		}
		اگر (*activep && *intptr == -1) {
			*intptr = مقدار;
			options->control_persist_timeout = value2;
		}
		بشکن;

	حالت oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		برو parse_flag;

	حالت oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		برو parse_multistate;

	حالت oTunnelDevice:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		مقدار = a2tun(arg, &value2);
		اگر (مقدار == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			برو out;
		}
		اگر (*activep && options->tun_local == -1) {
			options->tun_local = مقدار;
			options->tun_remote = value2;
		}
		بشکن;

	حالت oLocalCommand:
		charptr = &options->local_command;
		برو parse_command;

	حالت oPermitLocalCommand:
		intptr = &options->permit_local_command;
		برو parse_flag;

	حالت oRemoteCommand:
		charptr = &options->remote_command;
		برو parse_command;

	حالت o_Visual_Host_کلید:
		intptr = &options->visual_host_کلید;
		برو parse_flag;

	حالت oInclude:
		اگر (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			برو out;
		}
		مقدار = 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				برو out;
			}
			/* Expand %tokens and environment variables */
			اگر ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == پوچ) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				ادامه;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			اگر (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				برو out;
			}
			اگر (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} وگرنه {
				arg2 = xstrdup(p);
			}
			آزاد(p);
			memset(&gl, 0, اندازه(gl));
			r = glob(arg2, GLOB_TILDE, پوچ, &gl);
			اگر (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				آزاد(arg2);
				ادامه;
			} وگرنه اگر (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				برو out;
			}
			آزاد(arg2);
			oactive = *activep;
			برای (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				اگر (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					برو out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				اگر (r != 1)
					مقدار = -1;
			}
			globfree(&gl);
		}
		اگر (مقدار != 0)
			ret = مقدار;
		بشکن;

	حالت oIPQoS:
		arg = argv_next(&ac, &av);
		اگر ((مقدار = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			برو out;
		}
		اگر (مقدار == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			مقدار = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		اگر (arg == پوچ)
			value2 = مقدار;
		وگرنه اگر ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			برو out;
		}
		اگر (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		اگر (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = مقدار;
			options->ip_qos_bulk = value2;
		}
		بشکن;

	حالت oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		برو parse_multistate;

	حالت oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		برو parse_multistate;

	حالت oStdinNull:
		intptr = &options->stdin_null;
		برو parse_flag;

	حالت oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		برو parse_flag;

	حالت oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		برو parse_string;

	حالت oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		برو parse_flag;

	حالت oCanonicalDomains:
		found = options->رقم_canonical_domains == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					برو out;
				}
			}
			اگر (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				برو out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			options->canonical_domains = strs;
			options->رقم_canonical_domains = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت oCanonicalizePermittedCNAMEs:
		found = options->رقم_permitted_cnames == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					برو out;
				}
				arg2 = "";
			} وگرنه اگر (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} وگرنه {
				lowercase(arg);
				اگر ((arg2 = strchr(arg, ':')) == پوچ ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					برو out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    اندازه(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		اگر (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			options->permitted_cnames = cnames;
			options->رقم_permitted_cnames = ncnames;
			cnames = پوچ; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		بشکن;

	حالت oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		برو parse_multistate;

	حالت oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		برو parse_int;

	حالت oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		برو parse_flag;

	حالت oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			برو out;
		}
		/* Parse mode in octal format */
		مقدار = strtol(arg, &endofnumber, 8);
		اگر (arg == endofnumber || مقدار < 0 || مقدار > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			برو out;
		}
		اگر (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)مقدار;
		بشکن;

	حالت oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		برو parse_flag;

	حالت o_Revoked_Host_کلیدها:
		uintptr = &options->رقم_revoked_host_کلیدها;
		cppptr = &options->revoked_host_کلیدها;
		found = *uintptr == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				برو out;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					برو out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر ((مقدار = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			برو out;
		}
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		برو parse_multistate;

	حالت oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		برو parse_pubkey_algos;

	حالت oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		برو parse_pubkey_algos;

	حالت o_Add_کلیدها_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		مقدار = parse_multistate_مقدار(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		اگر (مقدار == 3 && arg2 != پوچ) {
			/* allow "AddKeysToAgent confirm 5m" */
			اگر ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				برو out;
			}
		} وگرنه اگر (مقدار == -1 && arg2 == پوچ) {
			اگر ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				برو out;
			}
			مقدار = 1; /* yes */
		} وگرنه اگر (مقدار == -1 || arg2 != پوچ) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			برو out;
		}
		اگر (*activep && options->add_کلیدها_to_agent == -1) {
			options->add_کلیدها_to_agent = مقدار;
			options->add_کلیدها_to_agent_lifespan = value2;
		}
		بشکن;

	حالت oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		اگر ((arg2 = dollar_expand(&r, arg)) == پوچ || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			برو out;
		}
		آزاد(arg2);
		/* check for legacy environment format */
		اگر (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			برو out;
		}
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;

	حالت oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		برو parse_flag;

	حالت oRequiredRSASize:
		intptr = &options->required_rsa_size;
		برو parse_int;

	حالت oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		برو parse_multistate;

	حالت oObscureKeystrokeTiming:
		مقدار = -1;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (مقدار != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				برو out;
			}
			اگر (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				مقدار = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			وگرنه اگر (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				مقدار = 0;
			وگرنه اگر (strncmp(arg, "interval:", 9) == 0) {
				اگر ((errstr = atoi_err(arg + 9,
				    &مقدار)) != پوچ) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					برو out;
				}
				اگر (مقدار <= 0 || مقدار > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					برو out;
				}
			} وگرنه {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				برو out;
			}
		}
		اگر (مقدار == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			برو out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت oChannelTimeout:
		found = options->رقم_channel_timeouts == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					برو out;
				}
			} وگرنه اگر (parse_pattern_interval(arg,
			    پوچ, پوچ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			options->channel_timeouts = strs;
			options->رقم_channel_timeouts = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت oVersionAddendum:
		اگر (str == پوچ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		اگر (strchr(str + len, '\r') != پوچ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		اگر ((arg = strchr(سطر, '#')) != پوچ) {
			*arg = '\0';
			rtrim(سطر);
		}
		اگر (*activep && options->version_addendum == پوچ) {
			اگر (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			وگرنه
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		بشکن;

	حالت oRefuseConnection:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			برو out;
		}
		اگر (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		بشکن;

	حالت oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		بشکن;

	حالت oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		بشکن;

	پیشفرض:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		برو out;
	}

	/* Check that there is no garbage at end of line. */
	اگر (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		برو out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, پوچ, nstrs);
	argv_free(oav, oac);
	بازگشت ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
صحیح
read_config_file(ثابت نویسه *filename, ساختار passwd *pw, ثابت نویسه *host,
    ثابت نویسه *original_host, ثابت نویسه *remote_command, Options *options, صحیح flags,
    صحیح *want_final_pass)
{
	صحیح active = 1;

	بازگشت read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
ایستا صحیح
read_config_file_depth(ثابت نویسه *filename, ساختار passwd *pw,
    ثابت نویسه *host, ثابت نویسه *original_host, ثابت نویسه *remote_command,
    Options *options, صحیح flags, صحیح *activep, صحیح *want_final_pass, صحیح depth)
{
	FILE *f;
	نویسه *سطر = پوچ;
	size_t linesize = 0;
	صحیح linenum;
	صحیح bad_options = 0;

	اگر (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	اگر ((f = fopen(filename, "r")) == پوچ)
		بازگشت 0;

	اگر (flags & SSHCONF_CHECKPERM) {
		ساختار stat sb;

		اگر (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		اگر (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	وقتی (getline(&سطر, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		اگر (process_config_سطر_depth(options, pw, host, original_host,
		    remote_command, سطر, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	آزاد(سطر);
	fclose(f);
	اگر (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	بازگشت 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
صحیح
option_clear_or_none(ثابت نویسه *o)
{
	بازگشت o == پوچ || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
صحیح
config_has_permitted_cnames(Options *options)
{
	اگر (options->رقم_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		بازگشت 0;
	بازگشت options->رقم_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

تهی
initialize_options(Options * options)
{
	memset(options, 'X', اندازه(*options));
	options->host_arg = پوچ;
	options->forward_agent = -1;
	options->forward_agent_sock_path = پوچ;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = پوچ;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = پوچ;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = پوچ;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_کلید_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->عدد_of_password_prompts = -1;
	options->ciphers = پوچ;
	options->macs = پوچ;
	options->kex_algorithms = پوچ;
	options->hostkeyalgorithms = پوچ;
	options->ca_sign_algorithms = پوچ;
	options->رقم_identity_files = 0;
	memset(options->identity_کلیدها, 0, اندازه(options->identity_کلیدها));
	options->رقم_certificate_files = 0;
	memset(options->certificates, 0, اندازه(options->certificates));
	options->hostname = پوچ;
	options->host_کلید_alias = پوچ;
	options->proxy_command = پوچ;
	options->jump_user = پوچ;
	options->jump_host = پوچ;
	options->jump_port = -1;
	options->jump_extra = پوچ;
	options->user = پوچ;
	options->escape_char = -1;
	options->رقم_system_hostfiles = 0;
	options->رقم_user_hostfiles = 0;
	options->local_forwards = پوچ;
	options->رقم_local_forwards = 0;
	options->remote_forwards = پوچ;
	options->رقم_remote_forwards = 0;
	options->permitted_remote_opens = پوچ;
	options->رقم_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->رقم_log_verbose = 0;
	options->log_verbose = پوچ;
	options->preferred_authentications = پوچ;
	options->bind_address = پوچ;
	options->bind_interface = پوچ;
	options->pkcs11_provider = پوچ;
	options->sk_provider = پوچ;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_کلید_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_شمار_max = -1;
	options->send_env = پوچ;
	options->رقم_send_env = 0;
	options->setenv = پوچ;
	options->رقم_setenv = 0;
	options->control_path = پوچ;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = پوچ;
	options->permit_local_command = -1;
	options->remote_command = پوچ;
	options->add_کلیدها_to_agent = -1;
	options->add_کلیدها_to_agent_lifespan = -1;
	options->identity_agent = پوچ;
	options->visual_host_کلید = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = پوچ;
	options->رقم_canonical_domains = 0;
	options->رقم_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_کلیدها = پوچ;
	options->رقم_revoked_host_کلیدها = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = پوچ;
	options->pubkey_accepted_algos = پوچ;
	options->known_hosts_command = پوچ;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = پوچ;
	options->channel_timeouts = پوچ;
	options->رقم_channel_timeouts = 0;
	options->version_addendum = پوچ;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
تهی
fill_default_options_for_canonicalization(Options *options)
{
	اگر (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	اگر (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	اگر (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
صحیح
fill_default_options(Options * options)
{
	نویسه *all_cipher, *all_mac, *all_kex, *all_کلید, *all_sig;
	نویسه *def_cipher, *def_mac, *def_kex, *def_کلید, *def_sig;
	صحیح ret = -1, r;

	اگر (options->forward_agent == -1)
		options->forward_agent = 0;
	اگر (options->forward_x11 == -1)
		options->forward_x11 = 0;
	اگر (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	اگر (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	اگر (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != پوچ ? 1 : 0;
	اگر (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != پوچ ? 1 : 0;
	اگر (options->clear_forwardings == 1)
		clear_forwardings(options);

	اگر (options->xauth_location == پوچ)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	اگر (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	اگر (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	اگر (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	اگر (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	اگر (options->gss_authentication == -1)
		options->gss_authentication = 0;
	اگر (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	اگر (options->password_authentication == -1)
		options->password_authentication = 1;
	اگر (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	اگر (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	اگر (options->batch_mode == -1)
		options->batch_mode = 0;
	اگر (options->check_host_ip == -1)
		options->check_host_ip = 0;
	اگر (options->strict_host_کلید_checking == -1)
		options->strict_host_کلید_checking = SSH_STRICT_HOSTKEY_ASK;
	اگر (options->compression == -1)
		options->compression = 0;
	اگر (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	اگر (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	اگر (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	اگر (options->connection_attempts == -1)
		options->connection_attempts = 1;
	اگر (options->عدد_of_password_prompts == -1)
		options->عدد_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	اگر (options->add_کلیدها_to_agent == -1) {
		options->add_کلیدها_to_agent = 0;
		options->add_کلیدها_to_agent_lifespan = 0;
	}
	اگر (options->رقم_identity_files == 0) {
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_RSA, 0);
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_ECDSA, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ECDSA_SK, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ED25519, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ED25519_SK, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	اگر (options->escape_char == -1)
		options->escape_char = '~';
	اگر (options->رقم_system_hostfiles == 0) {
		options->system_hostfiles[options->رقم_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->رقم_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	اگر (options->update_hostkeys == -1) {
		اگر (options->verify_host_کلید_dns <= 0 &&
		    (options->رقم_user_hostfiles == 0 ||
		    (options->رقم_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		وگرنه
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	اگر (options->رقم_user_hostfiles == 0) {
		options->user_hostfiles[options->رقم_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->رقم_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	اگر (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	اگر (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	اگر (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	اگر (options->identities_only == -1)
		options->identities_only = 0;
	اگر (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	اگر (options->rekey_limit == -1)
		options->rekey_limit = 0;
	اگر (options->rekey_interval == -1)
		options->rekey_interval = 0;
	اگر (options->verify_host_کلید_dns == -1)
		options->verify_host_کلید_dns = 0;
	اگر (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	اگر (options->server_alive_شمار_max == -1)
		options->server_alive_شمار_max = 3;
	اگر (options->control_master == -1)
		options->control_master = 0;
	اگر (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	اگر (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	اگر (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	اگر (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	اگر (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	اگر (options->permit_local_command == -1)
		options->permit_local_command = 0;
	اگر (options->visual_host_کلید == -1)
		options->visual_host_کلید = 0;
	اگر (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	اگر (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	اگر (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	اگر (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	اگر (options->stdin_null == -1)
		options->stdin_null = 0;
	اگر (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	اگر (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	اگر (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	اگر (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	اگر (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	اگر (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	اگر (options->sk_provider == پوچ)
		options->sk_provider = xstrdup("internal");
#وگرنه
	اگر (options->sk_provider == پوچ)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	اگر (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	اگر (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	اگر (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	اگر (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_کلید = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلید);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	انجامبده { \
		اگر ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			برو fail; \
		} \
	} وقتی (0)
	options->kex_algorithms_set = options->kex_algorithms != پوچ;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(pubkey_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	انجامبده { \
		اگر (option_clear_or_none(v)) { \
			آزاد(v); \
			v = پوچ; \
		} \
	} وقتی(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	انجامبده { \
		اگر (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			آزاد(options->v[0]); \
			آزاد(options->v); \
			options->v = پوچ; \
			options->nv = 0; \
		} \
	} وقتی (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, رقم_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_کلیدها, رقم_revoked_host_کلیدها, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	اگر (options->jump_host != پوچ &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == پوچ) {
		آزاد(options->jump_host);
		options->jump_host = پوچ;
	}
	اگر (options->رقم_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		آزاد(options->permitted_cnames[0].source_list);
		آزاد(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    اندازه(*options->permitted_cnames));
		options->رقم_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	آزاد(all_cipher);
	آزاد(all_mac);
	آزاد(all_kex);
	آزاد(all_کلید);
	آزاد(all_sig);
	آزاد(def_cipher);
	آزاد(def_mac);
	آزاد(def_kex);
	آزاد(def_کلید);
	آزاد(def_sig);
	بازگشت ret;
}

تهی
free_options(Options *o)
{
	صحیح i;

	اگر (o == پوچ)
		بازگشت;

#define FREE_ARRAY(type, n, a) \
	انجامبده { \
		type _i; \
		برای (_i = 0; _i < (n); _i++) \
			آزاد((a)[_i]); \
	} وقتی (0)

	آزاد(o->forward_agent_sock_path);
	آزاد(o->xauth_location);
	FREE_ARRAY(u_int, o->رقم_log_verbose, o->log_verbose);
	آزاد(o->log_verbose);
	آزاد(o->ciphers);
	آزاد(o->macs);
	آزاد(o->hostkeyalgorithms);
	آزاد(o->kex_algorithms);
	آزاد(o->ca_sign_algorithms);
	آزاد(o->hostname);
	آزاد(o->host_کلید_alias);
	آزاد(o->proxy_command);
	آزاد(o->user);
	FREE_ARRAY(u_int, o->رقم_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->رقم_user_hostfiles, o->user_hostfiles);
	آزاد(o->preferred_authentications);
	آزاد(o->bind_address);
	آزاد(o->bind_interface);
	آزاد(o->pkcs11_provider);
	آزاد(o->sk_provider);
	برای (i = 0; i < o->رقم_identity_files; i++) {
		آزاد(o->identity_files[i]);
		sshkey_free(o->identity_کلیدها[i]);
	}
	برای (i = 0; i < o->رقم_certificate_files; i++) {
		آزاد(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	آزاد(o->identity_agent);
	برای (i = 0; i < o->رقم_local_forwards; i++) {
		آزاد(o->local_forwards[i].listen_host);
		آزاد(o->local_forwards[i].listen_path);
		آزاد(o->local_forwards[i].connect_host);
		آزاد(o->local_forwards[i].connect_path);
	}
	آزاد(o->local_forwards);
	برای (i = 0; i < o->رقم_remote_forwards; i++) {
		آزاد(o->remote_forwards[i].listen_host);
		آزاد(o->remote_forwards[i].listen_path);
		آزاد(o->remote_forwards[i].connect_host);
		آزاد(o->remote_forwards[i].connect_path);
	}
	آزاد(o->remote_forwards);
	آزاد(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->رقم_send_env, o->send_env);
	آزاد(o->send_env);
	FREE_ARRAY(u_int, o->رقم_setenv, o->setenv);
	آزاد(o->setenv);
	آزاد(o->control_path);
	آزاد(o->local_command);
	آزاد(o->remote_command);
	FREE_ARRAY(صحیح, o->رقم_canonical_domains, o->canonical_domains);
	برای (i = 0; i < o->رقم_permitted_cnames; i++) {
		آزاد(o->permitted_cnames[i].source_list);
		آزاد(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->رقم_revoked_host_کلیدها, o->revoked_host_کلیدها);
	آزاد(o->revoked_host_کلیدها);
	آزاد(o->hostbased_accepted_algos);
	آزاد(o->pubkey_accepted_algos);
	آزاد(o->jump_user);
	آزاد(o->jump_host);
	آزاد(o->jump_extra);
	آزاد(o->ignored_unknown);
	explicit_bzero(o, اندازه(*o));
#undef FREE_ARRAY
}

ساختار fwdarg {
	نویسه *arg;
	صحیح ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
ایستا صحیح
parse_fwd_field(نویسه **p, ساختار fwdarg *fwd)
{
	نویسه *ep, *cp = *p;
	صحیح ispath = 0;

	اگر (*cp == '\0') {
		*p = پوچ;
		بازگشت -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	اگر (*cp == '[') {
		/* find matching ']' */
		برای (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			اگر (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		اگر (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			بازگشت -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		اگر (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		بازگشت 0;
	}

	برای (cp = *p; *cp != '\0'; cp++) {
		انتخاب (*cp) {
		حالت '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			اگر (*cp == '\0')
				بازگشت -1;
			بشکن;
		حالت '/':
			ispath = 1;
			بشکن;
		حالت ':':
			*cp++ = '\0';
			برو done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	بازگشت 0;
}

/*
 * parse_forward
 * parses a string containing a port forwarding specification of the form:
 *   dynamicfwd == 0
 *	[listenhost:]listenport|listenpath:connecthost:connectport|connectpath
 *	listenpath:connectpath
 *   dynamicfwd == 1
 *	[listenhost:]listenport
 * returns number of arguments parsed or zero on error
 */
صحیح
parse_forward(ساختار Forward *fwd, ثابت نویسه *fwdspec, صحیح dynamicfwd, صحیح remotefwd)
{
	ساختار fwdarg fwdargs[4];
	نویسه *p, *cp;
	صحیح i, err;

	memset(fwd, 0, اندازه(*fwd));
	memset(fwdargs, 0, اندازه(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	اگر (p == پوچ || err)
		بازگشت 0;

	/* skip leading spaces */
	وقتی (isspace((u_char)*cp))
		cp++;

	برای (i = 0; i < 4; ++i) {
		اگر (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			بشکن;
	}

	/* Check for trailing garbage */
	اگر (cp != پوچ && *cp != '\0') {
		i = 0;	/* failure */
	}

	انتخاب (i) {
	حالت 1:
		اگر (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} وگرنه {
			fwd->listen_host = پوچ;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		بشکن;

	حالت 2:
		اگر (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} وگرنه اگر (fwdargs[1].ispath) {
			fwd->listen_host = پوچ;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} وگرنه {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		بشکن;

	حالت 3:
		اگر (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} وگرنه اگر (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} وگرنه {
			fwd->listen_host = پوچ;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		بشکن;

	حالت 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		بشکن;
	پیشفرض:
		i = 0; /* failure */
	}

	آزاد(p);

	اگر (dynamicfwd) {
		اگر (!(i == 1 || i == 2))
			برو fail_free;
	} وگرنه {
		اگر (!(i == 3 || i == 4)) {
			اگر (fwd->connect_path == پوچ &&
			    fwd->listen_path == پوچ)
				برو fail_free;
		}
		اگر (fwd->connect_port <= 0 && fwd->connect_path == پوچ)
			برو fail_free;
	}

	اگر ((fwd->listen_port < 0 && fwd->listen_path == پوچ) ||
	    (!remotefwd && fwd->listen_port == 0))
		برو fail_free;
	اگر (fwd->connect_host != پوچ &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		برو fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	اگر (fwd->connect_path != پوچ &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		برو fail_free;
	اگر (fwd->listen_host != پوچ &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		برو fail_free;
	اگر (fwd->listen_path != پوچ &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		برو fail_free;

	بازگشت (i);

 fail_free:
	آزاد(fwd->connect_host);
	fwd->connect_host = پوچ;
	آزاد(fwd->connect_path);
	fwd->connect_path = پوچ;
	آزاد(fwd->listen_host);
	fwd->listen_host = پوچ;
	آزاد(fwd->listen_path);
	fwd->listen_path = پوچ;
	بازگشت (0);
}

صحیح
ssh_valid_hostname(ثابت نویسه *s)
{
	size_t i;

	اگر (*s == '-')
		بازگشت 0;
	برای (i = 0; s[i] != 0; i++) {
		اگر (strchr("'`\"$\\;&<>|(){},", s[i]) != پوچ ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			بازگشت 0;
	}
	بازگشت 1;
}

صحیح
ssh_valid_ruser(ثابت نویسه *s)
{
	size_t i;

	اگر (*s == '-')
		بازگشت 0;
	برای (i = 0; s[i] != 0; i++) {
		اگر (iscntrl((u_char)s[i]))
			بازگشت 0;
		اگر (strchr("'`\";&<>|(){}$\\", s[i]) != پوچ)
			بازگشت 0;
		/* Disallow '-' after whitespace */
		اگر (isspace((u_char)s[i]) && s[i + 1] == '-')
			بازگشت 0;
	}
	بازگشت 1;
}

صحیح
parse_jump(ثابت نویسه *s, Options *o, صحیح strict, صحیح active)
{
	نویسه *orig = پوچ, *sdup = پوچ, *cp;
	نویسه *tmp_user = پوچ, *tmp_host = پوچ, *host = پوچ, *user = پوچ;
	صحیح r, ret = -1, tmp_port = -1, port = -1, first = 1;

	اگر (strcasecmp(s, "none") == 0) {
		اگر (active && o->jump_host == پوچ) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		بازگشت 0;
	}

	orig = xstrdup(s);
	اگر ((cp = strchr(orig, '#')) != پوچ)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == پوچ && o->jump_host == پوچ;
	sdup = xstrdup(orig);
	انجامبده {
		/* Work backwards through string */
		اگر ((cp = strrchr(sdup, ',')) == پوچ)
			cp = sdup; /* last */
		وگرنه
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		اگر (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			برو out; /* error already logged */
		اگر (strict) {
			اگر (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				برو out;
			}
			اگر (tmp_user != پوچ && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				برو out;
			}
		}
		اگر (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = پوچ; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		آزاد(tmp_user);
		آزاد(tmp_host);
		tmp_user = tmp_host = پوچ;
		tmp_port = -1;
	} وقتی (cp != sdup);

	/* success */
	اگر (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = پوچ; /* transferred */
		اگر (orig != پوچ && (cp = strrchr(orig, ',')) != پوچ) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	آزاد(orig);
	آزاد(sdup);
	آزاد(tmp_user);
	آزاد(tmp_host);
	آزاد(user);
	آزاد(host);
	بازگشت ret;
}

صحیح
parse_ssh_uri(ثابت نویسه *uri, نویسه **userp, نویسه **hostp, صحیح *portp)
{
	نویسه *user = پوچ, *host = پوچ, *path = پوچ;
	صحیح r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	اگر (r == 0 && path != پوچ)
		r = -1;		/* path not allowed */
	اگر (r == 0) {
		اگر (userp != پوچ) {
			*userp = user;
			user = پوچ;
		}
		اگر (hostp != پوچ) {
			*hostp = host;
			host = پوچ;
		}
		اگر (portp != پوچ)
			*portp = port;
	}
	آزاد(user);
	آزاد(host);
	آزاد(path);
	بازگشت r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
ایستا ثابت نویسه *
fmt_multistate_int(صحیح val, ثابت ساختار multistate *m)
{
	u_int i;

	برای (i = 0; m[i].کلید != پوچ; i++) {
		اگر (m[i].مقدار == val)
			بازگشت m[i].کلید;
	}
	بازگشت "UNKNOWN";
}

ایستا ثابت نویسه *
fmt_intarg(OpCodes code, صحیح val)
{
	اگر (val == -1)
		بازگشت "unset";
	انتخاب (code) {
	حالت oAddressFamily:
		بازگشت fmt_multistate_int(val, multistate_addressfamily);
	حالت oCompression:
		بازگشت fmt_multistate_int(val, multistate_compression);
	حالت o_Verify_Host_کلید_DNS:
	حالت oUpdateHostkeys:
		بازگشت fmt_multistate_int(val, multistate_yesnoask);
	حالت o_Strict_Host_کلید_Checking:
		بازگشت fmt_multistate_int(val, multistate_strict_hostkey);
	حالت oControlMaster:
		بازگشت fmt_multistate_int(val, multistate_controlmaster);
	حالت oTunnel:
		بازگشت fmt_multistate_int(val, multistate_tunnel);
	حالت oRequestTTY:
		بازگشت fmt_multistate_int(val, multistate_requesttty);
	حالت oSessionType:
		بازگشت fmt_multistate_int(val, multistate_sessiontype);
	حالت oCanonicalizeHostname:
		بازگشت fmt_multistate_int(val, multistate_canonicalizehostname);
	حالت o_Add_کلیدها_To_Agent:
		بازگشت fmt_multistate_int(val, multistate_yesnoaskconfirm);
	حالت oPubkeyAuthentication:
		بازگشت fmt_multistate_int(val, multistate_pubkey_auth);
	حالت oTCPKeepAlive:
		بازگشت fmt_multistate_int(val, multistate_keepalives);
	حالت oFingerprintHash:
		بازگشت ssh_digest_alg_name(val);
	پیشفرض:
		انتخاب (val) {
		حالت 0:
			بازگشت "no";
		حالت 1:
			بازگشت "yes";
		پیشفرض:
			بازگشت "UNKNOWN";
		}
	}
}

ایستا ثابت نویسه *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	برای (i = 0; keywords[i].name != پوچ; i++)
		اگر (keywords[i].opcode == code)
			بازگشت(keywords[i].name);
	بازگشت "UNKNOWN";
}

ایستا تهی
dump_cfg_int(OpCodes code, صحیح val)
{
	اگر (code == oObscureKeystrokeTiming) {
		اگر (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			بازگشت;
		} وگرنه اگر (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			بازگشت;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

ایستا تهی
dump_cfg_fmtint(OpCodes code, صحیح val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

ایستا تهی
dump_cfg_string(OpCodes code, ثابت نویسه *val)
{
	اگر (val == پوچ)
		بازگشت;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

ایستا تهی
dump_cfg_strarray(OpCodes code, u_int شمار, نویسه **vals)
{
	u_int i;

	برای (i = 0; i < شمار; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

ایستا تهی
dump_cfg_strarray_oneline(OpCodes code, u_int شمار, نویسه **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	اگر (شمار == 0)
		printf(" none");
	برای (i = 0; i < شمار; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

ایستا تهی
dump_cfg_forwards(OpCodes code, u_int شمار, ثابت ساختار Forward *fwds)
{
	ثابت ساختار Forward *fwd;
	u_int i;

	/* oDynamicForward */
	برای (i = 0; i < شمار; i++) {
		fwd = &fwds[i];
		اگر (code == oDynamicForward && fwd->connect_host != پوچ &&
		    strcmp(fwd->connect_host, "socks") != 0)
			ادامه;
		اگر (code == oLocalForward && fwd->connect_host != پوچ &&
		    strcmp(fwd->connect_host, "socks") == 0)
			ادامه;
		printf("%s", lookup_opcode_name(code));
		اگر (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		وگرنه اگر (fwd->listen_host == پوچ)
			printf(" %d", fwd->listen_port);
		وگرنه {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		اگر (code != oDynamicForward) {
			اگر (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			وگرنه اگر (fwd->connect_host == پوچ)
				printf(" %d", fwd->connect_port);
			وگرنه {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

تهی
dump_client_config(Options *o, ثابت نویسه *host)
{
	صحیح i, r;
	نویسه buf[8], *all_کلید;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	اگر ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_کلید)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	آزاد(all_کلید);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(oPort, o->port);

	/* Flag options */
	dump_cfg_fmtint(oAddressFamily, o->address_family);
	dump_cfg_fmtint(oBatchMode, o->batch_mode);
	dump_cfg_fmtint(oCanonicalizeFallbackLocal, o->canonicalize_fallback_local);
	dump_cfg_fmtint(oCanonicalizeHostname, o->canonicalize_hostname);
	dump_cfg_fmtint(oCheckHostIP, o->check_host_ip);
	dump_cfg_fmtint(oCompression, o->compression);
	dump_cfg_fmtint(oControlMaster, o->control_master);
	dump_cfg_fmtint(oEnableSSHKeysign, o->enable_ssh_keysign);
	dump_cfg_fmtint(oClearAllForwardings, o->clear_forwardings);
	dump_cfg_fmtint(oExitOnForwardFailure, o->exit_on_forward_failure);
	dump_cfg_fmtint(oFingerprintHash, o->fingerprint_hash);
	dump_cfg_fmtint(oForwardX11, o->forward_x11);
	dump_cfg_fmtint(oForwardX11Trusted, o->forward_x11_trusted);
	dump_cfg_fmtint(oGatewayPorts, o->fwd_opts.gateway_ports);
#ifdef GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#endif /* GSSAPI */
	dump_cfg_fmtint(oHashKnownHosts, o->hash_known_hosts);
	dump_cfg_fmtint(oHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(oIdentitiesOnly, o->identities_only);
	dump_cfg_fmtint(oKbdInteractiveAuthentication, o->kbd_interactive_authentication);
	dump_cfg_fmtint(oNoHostAuthenticationForLocalhost, o->no_host_authentication_for_localhost);
	dump_cfg_fmtint(oPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(oPermitLocalCommand, o->permit_local_command);
	dump_cfg_fmtint(oProxyUseFdpass, o->proxy_use_fdpass);
	dump_cfg_fmtint(oPubkeyAuthentication, o->pubkey_authentication);
	dump_cfg_fmtint(oRequestTTY, o->request_tty);
	dump_cfg_fmtint(oSessionType, o->session_type);
	dump_cfg_fmtint(oStdinNull, o->stdin_null);
	dump_cfg_fmtint(oForkAfterAuthentication, o->fork_after_authentication);
	dump_cfg_fmtint(oStreamLocalBindUnlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(o_Strict_Host_کلید_Checking, o->strict_host_کلید_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_کلید_DNS, o->verify_host_کلید_dns);
	dump_cfg_fmtint(o_Visual_Host_کلید, o->visual_host_کلید);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_عدد_Of_Password_Prompts, o->عدد_of_password_prompts);
	dump_cfg_int(o_Server_Alive_شمار_Max, o->server_alive_شمار_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_کلید_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_کلید_Alias, o->host_کلید_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(oIdentityAgent, o->identity_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#ifdef ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#endif
	dump_cfg_string(o_Security_کلید_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->رقم_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->رقم_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->رقم_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->رقم_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->رقم_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->رقم_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->رقم_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->رقم_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_کلیدها, o->رقم_revoked_host_کلیدها, o->revoked_host_کلیدها);
	dump_cfg_strarray(oSendEnv, o->رقم_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->رقم_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->رقم_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->رقم_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	اگر (o->رقم_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	وگرنه
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->رقم_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	اگر (o->add_کلیدها_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_کلیدها_To_Agent, o->add_کلیدها_to_agent);
	وگرنه {
		printf("addkeystoagent%s %d\n",
		    o->add_کلیدها_to_agent == 3 ? " confirm" : "",
		    o->add_کلیدها_to_agent_lifespan);
	}

	/* oForwardAgent */
	اگر (o->forward_agent_sock_path == پوچ)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	وگرنه
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	اگر (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	وگرنه
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	اگر (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	وگرنه
		printf(" %d", o->tun_local);
	اگر (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	وگرنه
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	اگر (o->رقم_permitted_cnames == 0)
		printf(" none");
	برای (i = 0; i < o->رقم_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	اگر (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	وگرنه
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	اگر (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	وگرنه {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		printf("escapechar %s\n", buf);
	}

	/* oIPQoS */
	printf("ipqos %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	printf("rekeylimit %llu %d\n",
	    (unsigned long long)o->rekey_limit, o->rekey_interval);

	/* oStreamLocalBindMask */
	printf("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_mask);

	/* oLogFacility */
	printf("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	اگر (o->jump_host == پوچ)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	وگرنه {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != پوچ ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, اندازه(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == پوچ ? "" : o->jump_extra,
		    o->jump_extra == پوچ ? "" : ",",
		    /* optional user */
		    o->jump_user == پوچ ? "" : o->jump_user,
		    o->jump_user == پوچ ? "" : "@",
		    /* opening [ if hostname is numeric */
		    i ? "[" : "",
		    /* mandatory hostname */
		    o->jump_host,
		    /* closing ] if hostname is numeric */
		    i ? "]" : "",
		    /* optional port number */
		    o->jump_port <= 0 ? "" : ":",
		    o->jump_port <= 0 ? "" : buf);
	}
}
