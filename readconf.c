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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <net/if.h>
#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <netinet/ip.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <glob.h>
#અન્તર્ભાવ <ifaddrs.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <util.h>
#જો defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "readconf.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "mac.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "version.h"

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

સ્થિર પૂર્ણાંક read_config_file_depth(અચલ અક્ષર *filename, સંરચના passwd *pw,
    અચલ અક્ષર *host, અચલ અક્ષર *original_host, અચલ અક્ષર *remote_command,
    Options *options, પૂર્ણાંક flags, પૂર્ણાંક *activep, પૂર્ણાંક *want_final_pass, પૂર્ણાંક depth);
સ્થિર પૂર્ણાંક process_config_લીટી_depth(Options *options, સંરચના passwd *pw,
    અચલ અક્ષર *host, અચલ અક્ષર *original_host, અચલ અક્ષર *remote_command,
    અક્ષર *લીટી, અચલ અક્ષર *filename, પૂર્ણાંક linenum, પૂર્ણાંક *activep, પૂર્ણાંક flags,
    પૂર્ણાંક *want_final_pass, પૂર્ણાંક depth);

/* Keyword tokens. */

પ્રકારવ્યાખ્યા ગણના {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_ચાવીઓ_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_ચાવી_Checking, oCompression,
	oTCPKeepAlive, o_સંખ્યા_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_ચાવી_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_ચાવી_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_ચાવી_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_ગણતરી_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_ચાવી,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_ચાવીઓ,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_ચાવી_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

સ્થિર સંરચના {
	અચલ અક્ષર *name;
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
#જો defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# નહીંતર
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# નહીંતર
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
	{ "addkeystoagent", o_Add_ચાવીઓ_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_ચાવી_Alias },
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
	{ "stricthostkeychecking", o_Strict_Host_ચાવી_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_સંખ્યા_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_ચાવી_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_ચાવી_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_ગણતરી_Max },
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
	{ "visualhostkey", o_Visual_Host_ચાવી },
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
	{ "revokedhostkeys", o_Revoked_Host_ચાવીઓ },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_ચાવી_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ ખાલી, oBadOption }
};

સ્થિર અચલ અક્ષર *lookup_opcode_name(OpCodes code);

અચલ અક્ષર *
kex_default_pk_alg(શૂન્ય)
{
	સ્થિર અક્ષર *pkalgs;

	જો (pkalgs == ખાલી) {
		અક્ષર *all_ચાવી;

		all_ચાવી = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ચાવી);
		મુક્ત(all_ચાવી);
	}
	પાછા pkalgs;
}

અક્ષર *
ssh_connection_hash(અચલ અક્ષર *thishost, અચલ અક્ષર *host, અચલ અક્ષર *portstr,
    અચલ અક્ષર *user, અચલ અક્ષર *jumphost)
{
	સંરચના ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	જો ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == ખાલી ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, કદ(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	પાછા tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

શૂન્ય
add_local_forward(Options *options, અચલ સંરચના Forward *newfwd)
{
	સંરચના Forward *fwd;
	પૂર્ણાંક i;

	/* Don't add duplicates */
	માટે (i = 0; i < options->અંક_local_forwards; i++) {
		જો (forward_equals(newfwd, options->local_forwards + i))
			પાછા;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->અંક_local_forwards + 1,
	    કદ(*options->local_forwards));
	fwd = &options->local_forwards[options->અંક_local_forwards++];

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

શૂન્ય
add_remote_forward(Options *options, અચલ સંરચના Forward *newfwd)
{
	સંરચના Forward *fwd;
	પૂર્ણાંક i;

	/* Don't add duplicates */
	માટે (i = 0; i < options->અંક_remote_forwards; i++) {
		જો (forward_equals(newfwd, options->remote_forwards + i))
			પાછા;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->અંક_remote_forwards + 1,
	    કદ(*options->remote_forwards));
	fwd = &options->remote_forwards[options->અંક_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

સ્થિર શૂન્ય
clear_forwardings(Options *options)
{
	પૂર્ણાંક i;

	માટે (i = 0; i < options->અંક_local_forwards; i++) {
		મુક્ત(options->local_forwards[i].listen_host);
		મુક્ત(options->local_forwards[i].listen_path);
		મુક્ત(options->local_forwards[i].connect_host);
		મુક્ત(options->local_forwards[i].connect_path);
	}
	જો (options->અંક_local_forwards > 0) {
		મુક્ત(options->local_forwards);
		options->local_forwards = ખાલી;
	}
	options->અંક_local_forwards = 0;
	માટે (i = 0; i < options->અંક_remote_forwards; i++) {
		મુક્ત(options->remote_forwards[i].listen_host);
		મુક્ત(options->remote_forwards[i].listen_path);
		મુક્ત(options->remote_forwards[i].connect_host);
		મુક્ત(options->remote_forwards[i].connect_path);
	}
	જો (options->અંક_remote_forwards > 0) {
		મુક્ત(options->remote_forwards);
		options->remote_forwards = ખાલી;
	}
	options->અંક_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

શૂન્ય
add_certificate_file(Options *options, અચલ અક્ષર *path, પૂર્ણાંક userprovided)
{
	પૂર્ણાંક i;

	જો (options->અંક_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	માટે (i = 0; i < options->અંક_certificate_files; i++) {
		જો (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			પાછા;
		}
	}

	options->certificate_file_userprovided[options->અંક_certificate_files] =
	    userprovided;
	options->certificate_files[options->અંક_certificate_files++] =
	    xstrdup(path);
}

શૂન્ય
add_identity_file(Options *options, અચલ અક્ષર *dir, અચલ અક્ષર *filename,
    પૂર્ણાંક userprovided)
{
	અક્ષર *path;
	પૂર્ણાંક i;

	જો (options->અંક_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	જો (dir == ખાલી) /* no dir, filename is absolute */
		path = xstrdup(filename);
	નહીંતર જો (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	માટે (i = 0; i < options->અંક_identity_files; i++) {
		જો (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			મુક્ત(path);
			પાછા;
		}
	}

	options->identity_file_userprovided[options->અંક_identity_files] =
	    userprovided;
	options->identity_files[options->અંક_identity_files++] = path;
}

પૂર્ણાંક
default_ssh_port(શૂન્ય)
{
	સ્થિર પૂર્ણાંક port;
	સંરચના servent *sp;

	જો (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	પાછા port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
સ્થિર પૂર્ણાંક
execute_in_shell(અચલ અક્ષર *cmd)
{
	અક્ષર *shell;
	pid_t pid;
	પૂર્ણાંક status;

	જો ((shell = getenv("SHELL")) == ખાલી)
		shell = _PATH_BSHELL;

	જો (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	જો ((pid = fork()) == 0) {
		અક્ષર *argv[4];

		જો (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = ખાલી;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	જો (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	જ્યારે (waitpid(pid, &status, 0) == -1) {
		જો (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	જો (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		પાછા -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	પાછા WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
સ્થિર પૂર્ણાંક
check_match_ifaddrs(અચલ અક્ષર *addrlist)
{
#ifdef HAVE_IFADDRS_H
	સંરચના ifaddrs *ifa, *ifaddrs = ખાલી;
	પૂર્ણાંક r, found = 0;
	અક્ષર addr[NI_MAXHOST];
	socklen_t salen;

	જો (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		પાછા 0;
	}
	માટે (ifa = ifaddrs; ifa != ખાલી; ifa = ifa->ifa_next) {
		જો (ifa->ifa_addr == ખાલી || ifa->ifa_name == ખાલી ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			ચાલુ;
		પસંદગી (ifa->ifa_addr->sa_family) {
		સ્થિતિ AF_INET:
			salen = કદ(સંરચના sockaddr_in);
			તોડો;
		સ્થિતિ AF_INET6:
			salen = કદ(સંરચના sockaddr_in6);
			તોડો;
#ifdef AF_LINK
		સ્થિતિ AF_LINK:
			/* ignore */
			ચાલુ;
#endif /* AF_LINK */
		મૂળભૂત:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			ચાલુ;
		}
		જો ((r = getnameinfo(ifa->ifa_addr, salen, addr, કદ(addr),
		    ખાલી, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			ચાલુ;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		જો (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			તોડો;
		}
	}
	freeifaddrs(ifaddrs);
	પાછા found;
#નહીંતર /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	પાછા 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
સ્થિર અક્ષર *
expand_match_exec_or_include_path(અચલ અક્ષર *path, Options *options,
    સંરચના passwd *pw, અચલ અક્ષર *host_arg, અચલ અક્ષર *original_host,
    પૂર્ણાંક final_pass, પૂર્ણાંક is_include_path)
{
	અક્ષર thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	અક્ષર uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	અક્ષર *host, *ret;
	પૂર્ણાંક port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == ખાલી ? pw->pw_name : options->user;
	જો (final_pass) {
		host = xstrdup(options->hostname);
	} નહીંતર જો (options->hostname != ખાલી) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (અક્ષર *)ખાલી);
	} નહીંતર {
		host = xstrdup(host_arg);
	}
	જો (gethostname(thishost, કદ(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, કદ(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, કદ(portstr), "%d", port);
	snprintf(uidstr, કદ(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_ચાવી_alias ?  options->host_ચાવી_alias : host;

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
	    (અક્ષર *)ખાલી);
	મુક્ત(host);
	મુક્ત(conn_hash_hex);
	પાછા ret;
}

/*
 * Parse and execute a Match directive.
 */
સ્થિર પૂર્ણાંક
match_cfg_લીટી(Options *options, અચલ અક્ષર *full_લીટી, પૂર્ણાંક *acp, અક્ષર ***avp,
    સંરચના passwd *pw, અચલ અક્ષર *host_arg, અચલ અક્ષર *original_host,
    અચલ અક્ષર *remote_command, પૂર્ણાંક final_pass, પૂર્ણાંક *want_final_pass,
    અચલ અક્ષર *filename, પૂર્ણાંક linenum)
{
	અક્ષર *arg, *oattrib = ખાલી, *attrib = ખાલી, *cmd, *host, *criteria;
	અચલ અક્ષર *ruser;
	પૂર્ણાંક r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == ખાલી ? pw->pw_name : options->user;
	જો (final_pass) {
		host = xstrdup(options->hostname);
	} નહીંતર જો (options->hostname != ખાલી) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (અક્ષર *)ખાલી);
	} નહીંતર {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_લીટી, host, original_host);
	જ્યારે ((attrib = argv_next(acp, avp)) != ખાલી) {
		/* Terminate on comment */
		જો (*attrib == '#') {
			argv_consume(acp);
			તોડો;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = ખાલી;
		this_result = 1;
		જો ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		જો (strcasecmp(attrib, "all") == 0) {
			જો (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != ખાલી &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				જાઓ out;
			}
			જો (arg != ખાલી && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			જો (result)
				result = negate ? 0 : 1;
			જાઓ out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		જો (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			જો (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != ખાલી)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			જાઓ next;
		}

		/* Keep this list in sync with below */
		જો (strprefix(attrib, "host=", 1)  != ખાલી ||
		    strprefix(attrib, "originalhost=", 1) != ખાલી ||
		    strprefix(attrib, "user=", 1) != ખાલી ||
		    strprefix(attrib, "localuser=", 1) != ખાલી ||
		    strprefix(attrib, "localnetwork=", 1) != ખાલી ||
		    strprefix(attrib, "version=", 1) != ખાલી ||
		    strprefix(attrib, "tagged=", 1) != ખાલી ||
		    strprefix(attrib, "command=", 1) != ખાલી ||
		    strprefix(attrib, "exec=", 1) != ખાલી) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} નહીંતર જો ((arg = argv_next(acp, avp)) == ખાલી) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			જાઓ out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		જો (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = ખાલી;
		જો (arg == ખાલી || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			જાઓ out;
		}
		જો (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર જો (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર જો (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર જો (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર જો (strcasecmp(attrib, "localnetwork") == 0) {
			જો (addr_match_cidr_list(ખાલી, arg) == -1) {
				/* Error already printed */
				result = -1;
				જાઓ out;
			}
			r = check_match_ifaddrs(arg) == 1;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર જો (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર જો (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == ખાલી ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર જો (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == ખાલી ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર જો (strcasecmp(attrib, "sessiontype") == 0) {
			જો (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			નહીંતર જો (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			નહીંતર જો (remote_command != ખાલી &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			નહીંતર
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર જો (strcasecmp(attrib, "exec") == 0) {
			જો ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == ખાલી) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			જો (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				મુક્ત(cmd);
				જાઓ next;
			}
			r = execute_in_shell(cmd);
			જો (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			મુક્ત(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			જો (r == (negate ? 1 : 0))
				this_result = result = 0;
		} નહીંતર {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			જાઓ out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == ખાલી ? "" : " \"",
		    criteria == ખાલી ? "" : criteria,
		    criteria == ખાલી ? "" : "\"");
 next:
		મુક્ત(criteria);
		મુક્ત(oattrib);
		oattrib = attrib = ખાલી;
	}
	જો (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		જાઓ out;
	}
 out:
	જો (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	મુક્ત(oattrib);
	મુક્ત(host);
	પાછા result;
}

/* Remove environment variable by pattern */
સ્થિર શૂન્ય
rm_env(Options *options, અચલ અક્ષર *arg, અચલ અક્ષર *filename, પૂર્ણાંક linenum)
{
	u_int i, j, onum_send_env = options->અંક_send_env;

	/* Remove an environment variable */
	માટે (i = 0; i < options->અંક_send_env; ) {
		જો (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			ચાલુ;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		મુક્ત(options->send_env[i]);
		options->send_env[i] = ખાલી;
		માટે (j = i; j < options->અંક_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = ખાલી;
		}
		options->અંક_send_env--;
		/* NB. don't increment i */
	}
	જો (onum_send_env != options->અંક_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->અંક_send_env,
		    કદ(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
સ્થિર OpCodes
parse_token(અચલ અક્ષર *cp, અચલ અક્ષર *filename, પૂર્ણાંક linenum,
    અચલ અક્ષર *ignored_unknown)
{
	પૂર્ણાંક i;

	માટે (i = 0; keywords[i].name; i++)
		જો (strcmp(cp, keywords[i].name) == 0)
			પાછા keywords[i].opcode;
	જો (ignored_unknown != ખાલી &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		પાછા oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	પાછા oBadOption;
}

સ્થિર શૂન્ય
free_canon_cnames(સંરચના allowed_cname *cnames, u_int n)
{
	u_int i;

	જો (cnames == ખાલી || n == 0)
		પાછા;
	માટે (i = 0; i < n; i++) {
		મુક્ત(cnames[i].source_list);
		મુક્ત(cnames[i].target_list);
	}
	મુક્ત(cnames);
}

/* Multistate option parsing */
સંરચના multistate {
	અક્ષર *ચાવી;
	પૂર્ણાંક કિંમત;
};
સ્થિર અચલ સંરચના multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ખાલી, -1 }
};
સ્થિર અચલ સંરચના multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ખાલી, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
સ્થિર અચલ સંરચના multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ખાલી, -1 }
};

સ્થિર પૂર્ણાંક
parse_multistate_કિંમત(અચલ અક્ષર *arg, અચલ અક્ષર *filename, પૂર્ણાંક linenum,
    અચલ સંરચના multistate *multistate_ptr)
{
	પૂર્ણાંક i;

	જો (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		પાછા -1;
	}
	માટે (i = 0; multistate_ptr[i].ચાવી != ખાલી; i++) {
		જો (strcasecmp(arg, multistate_ptr[i].ચાવી) == 0)
			પાછા multistate_ptr[i].કિંમત;
	}
	પાછા -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
પૂર્ણાંક
process_config_લીટી(Options *options, સંરચના passwd *pw, અચલ અક્ષર *host,
    અચલ અક્ષર *original_host, અચલ અક્ષર *remote_command, અક્ષર *લીટી,
    અચલ અક્ષર *filename, પૂર્ણાંક linenum, પૂર્ણાંક *activep, પૂર્ણાંક flags)
{
	પાછા process_config_લીટી_depth(options, pw, host, original_host,
	    remote_command, લીટી, filename, linenum, activep, flags, ખાલી, 0);
}

#define WHITESPACE " \t\r\n"
સ્થિર પૂર્ણાંક
process_config_લીટી_depth(Options *options, સંરચના passwd *pw, અચલ અક્ષર *host,
    અચલ અક્ષર *original_host, અચલ અક્ષર *remote_command, અક્ષર *લીટી,
    અચલ અક્ષર *filename, પૂર્ણાંક linenum, પૂર્ણાંક *activep, પૂર્ણાંક flags,
    પૂર્ણાંક *want_final_pass, પૂર્ણાંક depth)
{
	અક્ષર *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	અક્ષર **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	પૂર્ણાંક r, oactive, negated, opcode, *intptr, કિંમત, value2, cmdline = 0;
	પૂર્ણાંક remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	સંરચના Forward fwd;
	અચલ સંરચના multistate *multistate_ptr;
	glob_t gl;
	અચલ અક્ષર *errstr;
	અક્ષર **oav = ખાલી, **av;
	પૂર્ણાંક oac = 0, ac;
	પૂર્ણાંક ret = -1;
	સંરચના allowed_cname *cnames = ખાલી;
	u_int ncnames = 0;
	અક્ષર **strs = ખાલી; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	જો (activep == ખાલી) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	જો ((len = strlen(લીટી)) == 0)
		પાછા 0;
	માટે (len--; len > 0; len--) {
		જો (strchr(WHITESPACE "\f", લીટી[len]) == ખાલી)
			તોડો;
		લીટી[len] = '\0';
	}

	str = લીટી;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	જો ((keyword = strdelim(&str)) == ખાલી)
		પાછા 0;
	/* Ignore leading whitespace. */
	જો (*keyword == '\0')
		keyword = strdelim(&str);
	જો (keyword == ખાલી || !*keyword || *keyword == '\n' || *keyword == '#')
		પાછા 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	જો (str != ખાલી)
		str += strspn(str, WHITESPACE);
	જો (str == ખાલી || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		પાછા -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	જો (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		પાછા -1;
	}
	ac = oac;
	av = oav;

	પસંદગી (opcode) {
	સ્થિતિ oBadOption:
		/* don't panic, but count bad options */
		જાઓ out;
	સ્થિતિ oIgnore:
		argv_consume(&ac);
		તોડો;
	સ્થિતિ oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		તોડો;
	સ્થિતિ oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			જાઓ out;
		}
		જો (strcmp(arg, "none") == 0)
			કિંમત = -1;
		નહીંતર જો ((કિંમત = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			જાઓ out;
		}

		કિંમત = -1;
		multistate_ptr = multistate_flag;
		માટે (i = 0; multistate_ptr[i].ચાવી != ખાલી; i++) {
			જો (strcasecmp(arg, multistate_ptr[i].ચાવી) == 0) {
				કિંમત = multistate_ptr[i].કિંમત;
				તોડો;
			}
		}
		જો (કિંમત != -1) {
			જો (*activep && *intptr == -1)
				*intptr = કિંમત;
			તોડો;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		જો (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		જાઓ parse_agent_path;

	સ્થિતિ oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		જો ((કિંમત = parse_multistate_કિંમત(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			જાઓ out;
		}
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		જાઓ parse_flag;

	સ્થિતિ oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		જાઓ parse_time;

	સ્થિતિ oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		જાઓ parse_flag;

	સ્થિતિ oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		જાઓ parse_flag;

	સ્થિતિ oPasswordAuthentication:
		intptr = &options->password_authentication;
		જાઓ parse_flag;

	સ્થિતિ oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		જાઓ parse_flag;

	સ્થિતિ oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		જાઓ parse_string;

	સ્થિતિ oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		જાઓ parse_multistate;

	સ્થિતિ oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		જાઓ parse_flag;

	સ્થિતિ oGssAuthentication:
		intptr = &options->gss_authentication;
		જાઓ parse_flag;

	સ્થિતિ oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		જાઓ parse_flag;

	સ્થિતિ oBatchMode:
		intptr = &options->batch_mode;
		જાઓ parse_flag;

	સ્થિતિ oCheckHostIP:
		intptr = &options->check_host_ip;
		જાઓ parse_flag;

	સ્થિતિ o_Verify_Host_ચાવી_DNS:
		intptr = &options->verify_host_ચાવી_dns;
		multistate_ptr = multistate_yesnoask;
		જાઓ parse_multistate;

	સ્થિતિ o_Strict_Host_ચાવી_Checking:
		intptr = &options->strict_host_ચાવી_checking;
		multistate_ptr = multistate_strict_hostkey;
		જાઓ parse_multistate;

	સ્થિતિ oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		જાઓ parse_multistate;

	સ્થિતિ oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		જાઓ parse_multistate;

	સ્થિતિ oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		જાઓ parse_flag;

	સ્થિતિ o_સંખ્યા_Of_Password_Prompts:
		intptr = &options->સંખ્યા_of_password_prompts;
		જાઓ parse_int;

	સ્થિતિ oRekeyLimit:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			જાઓ out;
		}
		જો (strcmp(arg, "default") == 0) {
			val64 = 0;
		} નહીંતર {
			જો (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				જાઓ out;
			}
			જો (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				જાઓ out;
			}
		}
		જો (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		જો (ac != 0) { /* optional rekey interval present */
			જો (strcmp(av[0], "none") == 0) {
				(શૂન્ય)argv_next(&ac, &av);	/* discard */
				તોડો;
			}
			intptr = &options->rekey_interval;
			જાઓ parse_time;
		}
		તોડો;

	સ્થિતિ oIdentityFile:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*activep) {
			intptr = &options->અંક_identity_files;
			જો (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				જાઓ out;
			}
			add_identity_file(options, ખાલી,
			    arg, flags & SSHCONF_USERCONF);
		}
		તોડો;

	સ્થિતિ oCertificateFile:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*activep) {
			intptr = &options->અંક_certificate_files;
			જો (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				જાઓ out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		તોડો;

	સ્થિતિ oXAuthLocation:
		charptr=&options->xauth_location;
		જાઓ parse_string;

	સ્થિતિ oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;

	સ્થિતિ oGlobalKnownHostsFile:
		cpptr = (અક્ષર **)&options->system_hostfiles;
		uintptr = &options->અંક_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		કિંમત = *uintptr == 0; /* was array empty when we started? */
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				જાઓ out;
			}
			/* Allow "none" only in first position */
			જો (strcasecmp(arg, "none") == 0) {
				જો (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					જાઓ out;
				}
			}
			i++;
			જો (*activep && કિંમત) {
				જો ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					જાઓ out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		તોડો;

	સ્થિતિ oUserKnownHostsFile:
		cpptr = (અક્ષર **)&options->user_hostfiles;
		uintptr = &options->અંક_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		જાઓ parse_char_array;

	સ્થિતિ oHostname:
		charptr = &options->hostname;
		જાઓ parse_string;

	સ્થિતિ oTag:
		charptr = &options->tag;
		જાઓ parse_string;

	સ્થિતિ o_Host_ચાવી_Alias:
		charptr = &options->host_ચાવી_alias;
		જાઓ parse_string;

	સ્થિતિ oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		જાઓ parse_string;

	સ્થિતિ oBindAddress:
		charptr = &options->bind_address;
		જાઓ parse_string;

	સ્થિતિ oBindInterface:
		charptr = &options->bind_interface;
		જાઓ parse_string;

	સ્થિતિ oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		જાઓ parse_string;

	સ્થિતિ o_Security_ચાવી_Provider:
		charptr = &options->sk_provider;
		જાઓ parse_string;

	સ્થિતિ oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		જાઓ parse_command;

	સ્થિતિ oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		જો (str == ખાલી) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		len = strspn(str, WHITESPACE "=");
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		તોડો;

	સ્થિતિ oProxyJump:
		જો (str == ખાલી) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		જો (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			જાઓ out;
		}
		argv_consume(&ac);
		તોડો;

	સ્થિતિ oPort:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		કિંમત = a2port(arg);
		જો (કિંમત <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			જાઓ out;
		}
		જો (*activep && options->port == -1)
			options->port = કિંમત;
		તોડો;

	સ્થિતિ oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		જો ((errstr = atoi_err(arg, &કિંમત)) != ખાલી) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			જાઓ out;
		}
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ oCiphers:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			જાઓ out;
		}
		જો (*activep && options->ciphers == ખાલી)
			options->ciphers = xstrdup(arg);
		તોડો;

	સ્થિતિ oMacs:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			જાઓ out;
		}
		જો (*activep && options->macs == ખાલી)
			options->macs = xstrdup(arg);
		તોડો;

	સ્થિતિ oKexAlgorithms:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			જાઓ out;
		}
		જો (*activep && options->kex_algorithms == ખાલી)
			options->kex_algorithms = xstrdup(arg);
		તોડો;

	સ્થિતિ o_Host_ચાવી_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			જાઓ out;
		}
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;

	સ્થિતિ oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		જાઓ parse_pubkey_algos;

	સ્થિતિ oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		કિંમત = log_level_સંખ્યા(arg);
		જો (કિંમત == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			જાઓ out;
		}
		જો (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) કિંમત;
		તોડો;

	સ્થિતિ oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		કિંમત = log_facility_સંખ્યા(arg);
		જો (કિંમત == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			જાઓ out;
		}
		જો (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) કિંમત;
		તોડો;

	સ્થિતિ oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->અંક_log_verbose;
		i = 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				જાઓ out;
			}
			/* Allow "none" only in first position */
			જો (strcasecmp(arg, "none") == 0) {
				જો (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					જાઓ out;
				}
			}
			i++;
			જો (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, કદ(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		તોડો;

	સ્થિતિ oLocalForward:
	સ્થિતિ oRemoteForward:
	સ્થિતિ oDynamicForward:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		જો (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			જો (arg2 == ખાલી || *arg2 == '\0') {
				જો (remotefwd)
					dynamicfwd = 1;
				નહીંતર {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					જાઓ out;
				}
			} નહીંતર {
				/* construct a string for parse_forward */
				snprintf(fwdarg, કદ(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		જો (dynamicfwd)
			strlcpy(fwdarg, arg, કદ(fwdarg));

		જો (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			જાઓ out;
		}

		જો (*activep) {
			જો (remotefwd) {
				add_remote_forward(options, &fwd);
			} નહીંતર {
				add_local_forward(options, &fwd);
			}
		}
		તોડો;

	સ્થિતિ oPermitRemoteOpen:
		uintptr = &options->અંક_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			જો (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				જો (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					મુક્ત(arg2);
					જાઓ out;
				}
			} નહીંતર {
				p = hpdelim(&arg);
				જો (p == ખાલી) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				જો (arg == ખાલી || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			મુક્ત(arg2);
		}
		જો (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		જો (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ oClearAllForwardings:
		intptr = &options->clear_forwardings;
		જાઓ parse_flag;

	સ્થિતિ oHost:
		જો (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			જાઓ out;
		}
		*activep = 0;
		arg2 = ખાલી;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				જાઓ out;
			}
			જો ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				તોડો;
			}
			negated = *arg == '!';
			જો (negated)
				arg++;
			જો (match_pattern(host, arg)) {
				જો (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					તોડો;
				}
				જો (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		જો (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		તોડો;

	સ્થિતિ oMatch:
		જો (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			જાઓ out;
		}
		કિંમત = match_cfg_લીટી(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		જો (કિંમત < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			જાઓ out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : કિંમત;
		તોડો;

	સ્થિતિ oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (strcmp(arg, "none") == 0)
			કિંમત = SSH_ESCAPECHAR_NONE;
		નહીંતર જો (arg[1] == '\0')
			કિંમત = (u_char) arg[0];
		નહીંતર જો (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			કિંમત = (u_char) arg[1] & 31;
		નહીંતર {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		જાઓ parse_multistate;

	સ્થિતિ oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		જાઓ parse_flag;

	સ્થિતિ oIdentitiesOnly:
		intptr = &options->identities_only;
		જાઓ parse_flag;

	સ્થિતિ oServerAliveInterval:
		intptr = &options->server_alive_interval;
		જાઓ parse_time;

	સ્થિતિ o_Server_Alive_ગણતરી_Max:
		intptr = &options->server_alive_ગણતરી_max;
		જાઓ parse_int;

	સ્થિતિ oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0' || strchr(arg, '=') != ખાલી) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				જાઓ out;
			}
			found = 1;
			જો (!*activep)
				ચાલુ;
			જો (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				ચાલુ;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->અંક_send_env, arg);
		}
		જો (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		તોડો;

	સ્થિતિ oSetEnv:
		found = options->અંક_setenv == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (strchr(arg, '=') == ખાલી) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				જાઓ out;
			}
			જો (lookup_setenv_in_list(arg, strs, nstrs) != ખાલી) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ચાલુ;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			options->setenv = strs;
			options->અંક_setenv = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ oControlPath:
		charptr = &options->control_path;
		જાઓ parse_string;

	સ્થિતિ oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		જાઓ parse_multistate;

	સ્થિતિ oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			જાઓ out;
		}
		કિંમત = 0;
		value2 = 0;	/* timeout */
		જો (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			કિંમત = 0;
		નહીંતર જો (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			કિંમત = 1;
		નહીંતર જો ((value2 = convtime(arg)) >= 0)
			કિંમત = 1;
		નહીંતર {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*activep && *intptr == -1) {
			*intptr = કિંમત;
			options->control_persist_timeout = value2;
		}
		તોડો;

	સ્થિતિ oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		જાઓ parse_flag;

	સ્થિતિ oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		જાઓ parse_multistate;

	સ્થિતિ oTunnelDevice:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		કિંમત = a2tun(arg, &value2);
		જો (કિંમત == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*activep && options->tun_local == -1) {
			options->tun_local = કિંમત;
			options->tun_remote = value2;
		}
		તોડો;

	સ્થિતિ oLocalCommand:
		charptr = &options->local_command;
		જાઓ parse_command;

	સ્થિતિ oPermitLocalCommand:
		intptr = &options->permit_local_command;
		જાઓ parse_flag;

	સ્થિતિ oRemoteCommand:
		charptr = &options->remote_command;
		જાઓ parse_command;

	સ્થિતિ o_Visual_Host_ચાવી:
		intptr = &options->visual_host_ચાવી;
		જાઓ parse_flag;

	સ્થિતિ oInclude:
		જો (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			જાઓ out;
		}
		કિંમત = 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				જાઓ out;
			}
			/* Expand %tokens and environment variables */
			જો ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == ખાલી) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				ચાલુ;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			જો (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				જાઓ out;
			}
			જો (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} નહીંતર {
				arg2 = xstrdup(p);
			}
			મુક્ત(p);
			memset(&gl, 0, કદ(gl));
			r = glob(arg2, GLOB_TILDE, ખાલી, &gl);
			જો (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				મુક્ત(arg2);
				ચાલુ;
			} નહીંતર જો (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				જાઓ out;
			}
			મુક્ત(arg2);
			oactive = *activep;
			માટે (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				જો (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					જાઓ out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				જો (r != 1)
					કિંમત = -1;
			}
			globfree(&gl);
		}
		જો (કિંમત != 0)
			ret = કિંમત;
		તોડો;

	સ્થિતિ oIPQoS:
		arg = argv_next(&ac, &av);
		જો ((કિંમત = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			જાઓ out;
		}
		જો (કિંમત == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			કિંમત = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		જો (arg == ખાલી)
			value2 = કિંમત;
		નહીંતર જો ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			જાઓ out;
		}
		જો (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		જો (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = કિંમત;
			options->ip_qos_bulk = value2;
		}
		તોડો;

	સ્થિતિ oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		જાઓ parse_multistate;

	સ્થિતિ oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		જાઓ parse_multistate;

	સ્થિતિ oStdinNull:
		intptr = &options->stdin_null;
		જાઓ parse_flag;

	સ્થિતિ oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		જાઓ parse_flag;

	સ્થિતિ oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		જાઓ parse_string;

	સ્થિતિ oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		જાઓ parse_flag;

	સ્થિતિ oCanonicalDomains:
		found = options->અંક_canonical_domains == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			/* Allow "none" only in first position */
			જો (strcasecmp(arg, "none") == 0) {
				જો (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					જાઓ out;
				}
			}
			જો (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				જાઓ out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			options->canonical_domains = strs;
			options->અંક_canonical_domains = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ oCanonicalizePermittedCNAMEs:
		found = options->અંક_permitted_cnames == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			જો (strcasecmp(arg, "none") == 0) {
				જો (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					જાઓ out;
				}
				arg2 = "";
			} નહીંતર જો (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} નહીંતર {
				lowercase(arg);
				જો ((arg2 = strchr(arg, ':')) == ખાલી ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					જાઓ out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    કદ(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		જો (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			options->permitted_cnames = cnames;
			options->અંક_permitted_cnames = ncnames;
			cnames = ખાલી; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		તોડો;

	સ્થિતિ oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		જાઓ parse_multistate;

	સ્થિતિ oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		જાઓ parse_int;

	સ્થિતિ oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		જાઓ parse_flag;

	સ્થિતિ oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			જાઓ out;
		}
		/* Parse mode in octal format */
		કિંમત = strtol(arg, &endofnumber, 8);
		જો (arg == endofnumber || કિંમત < 0 || કિંમત > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			જાઓ out;
		}
		જો (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)કિંમત;
		તોડો;

	સ્થિતિ oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		જાઓ parse_flag;

	સ્થિતિ o_Revoked_Host_ચાવીઓ:
		uintptr = &options->અંક_revoked_host_ચાવીઓ;
		cppptr = &options->revoked_host_ચાવીઓ;
		found = *uintptr == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				જાઓ out;
			}
			/* Allow "none" only in first position */
			જો (strcasecmp(arg, "none") == 0) {
				જો (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					જાઓ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો ((કિંમત = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			જાઓ out;
		}
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		જાઓ parse_multistate;

	સ્થિતિ oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		જાઓ parse_pubkey_algos;

	સ્થિતિ oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		જાઓ parse_pubkey_algos;

	સ્થિતિ o_Add_ચાવીઓ_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		કિંમત = parse_multistate_કિંમત(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		જો (કિંમત == 3 && arg2 != ખાલી) {
			/* allow "AddKeysToAgent confirm 5m" */
			જો ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				જાઓ out;
			}
		} નહીંતર જો (કિંમત == -1 && arg2 == ખાલી) {
			જો ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				જાઓ out;
			}
			કિંમત = 1; /* yes */
		} નહીંતર જો (કિંમત == -1 || arg2 != ખાલી) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			જાઓ out;
		}
		જો (*activep && options->add_ચાવીઓ_to_agent == -1) {
			options->add_ચાવીઓ_to_agent = કિંમત;
			options->add_ચાવીઓ_to_agent_lifespan = value2;
		}
		તોડો;

	સ્થિતિ oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		જો ((arg2 = dollar_expand(&r, arg)) == ખાલી || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			જાઓ out;
		}
		મુક્ત(arg2);
		/* check for legacy environment format */
		જો (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			જાઓ out;
		}
		જો (*activep && *charptr == ખાલી)
			*charptr = xstrdup(arg);
		તોડો;

	સ્થિતિ oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		જાઓ parse_flag;

	સ્થિતિ oRequiredRSASize:
		intptr = &options->required_rsa_size;
		જાઓ parse_int;

	સ્થિતિ oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		જાઓ parse_multistate;

	સ્થિતિ oObscureKeystrokeTiming:
		કિંમત = -1;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			જો (કિંમત != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				જાઓ out;
			}
			જો (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				કિંમત = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			નહીંતર જો (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				કિંમત = 0;
			નહીંતર જો (strncmp(arg, "interval:", 9) == 0) {
				જો ((errstr = atoi_err(arg + 9,
				    &કિંમત)) != ખાલી) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					જાઓ out;
				}
				જો (કિંમત <= 0 || કિંમત > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					જાઓ out;
				}
			} નહીંતર {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				જાઓ out;
			}
		}
		જો (કિંમત == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			જાઓ out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		જો (*activep && *intptr == -1)
			*intptr = કિંમત;
		તોડો;

	સ્થિતિ oChannelTimeout:
		found = options->અંક_channel_timeouts == 0;
		જ્યારે ((arg = argv_next(&ac, &av)) != ખાલી) {
			/* Allow "none" only in first position */
			જો (strcasecmp(arg, "none") == 0) {
				જો (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					જાઓ out;
				}
			} નહીંતર જો (parse_pattern_interval(arg,
			    ખાલી, ખાલી) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		જો (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		જો (found && *activep) {
			options->channel_timeouts = strs;
			options->અંક_channel_timeouts = nstrs;
			strs = ખાલી; /* transferred */
			nstrs = 0;
		}
		તોડો;

	સ્થિતિ oVersionAddendum:
		જો (str == ખાલી || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		જો (strchr(str + len, '\r') != ખાલી) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		જો ((arg = strchr(લીટી, '#')) != ખાલી) {
			*arg = '\0';
			rtrim(લીટી);
		}
		જો (*activep && options->version_addendum == ખાલી) {
			જો (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			નહીંતર
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		તોડો;

	સ્થિતિ oRefuseConnection:
		arg = argv_next(&ac, &av);
		જો (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			જાઓ out;
		}
		જો (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		તોડો;

	સ્થિતિ oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		તોડો;

	સ્થિતિ oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		તોડો;

	મૂળભૂત:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		જાઓ out;
	}

	/* Check that there is no garbage at end of line. */
	જો (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		જાઓ out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, ખાલી, nstrs);
	argv_free(oav, oac);
	પાછા ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
પૂર્ણાંક
read_config_file(અચલ અક્ષર *filename, સંરચના passwd *pw, અચલ અક્ષર *host,
    અચલ અક્ષર *original_host, અચલ અક્ષર *remote_command, Options *options, પૂર્ણાંક flags,
    પૂર્ણાંક *want_final_pass)
{
	પૂર્ણાંક active = 1;

	પાછા read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
સ્થિર પૂર્ણાંક
read_config_file_depth(અચલ અક્ષર *filename, સંરચના passwd *pw,
    અચલ અક્ષર *host, અચલ અક્ષર *original_host, અચલ અક્ષર *remote_command,
    Options *options, પૂર્ણાંક flags, પૂર્ણાંક *activep, પૂર્ણાંક *want_final_pass, પૂર્ણાંક depth)
{
	FILE *f;
	અક્ષર *લીટી = ખાલી;
	size_t linesize = 0;
	પૂર્ણાંક linenum;
	પૂર્ણાંક bad_options = 0;

	જો (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	જો ((f = fopen(filename, "r")) == ખાલી)
		પાછા 0;

	જો (flags & SSHCONF_CHECKPERM) {
		સંરચના stat sb;

		જો (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		જો (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		જો (process_config_લીટી_depth(options, pw, host, original_host,
		    remote_command, લીટી, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	મુક્ત(લીટી);
	fclose(f);
	જો (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	પાછા 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
પૂર્ણાંક
option_clear_or_none(અચલ અક્ષર *o)
{
	પાછા o == ખાલી || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
પૂર્ણાંક
config_has_permitted_cnames(Options *options)
{
	જો (options->અંક_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		પાછા 0;
	પાછા options->અંક_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

શૂન્ય
initialize_options(Options * options)
{
	memset(options, 'X', કદ(*options));
	options->host_arg = ખાલી;
	options->forward_agent = -1;
	options->forward_agent_sock_path = ખાલી;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = ખાલી;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = ખાલી;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = ખાલી;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_ચાવી_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->સંખ્યા_of_password_prompts = -1;
	options->ciphers = ખાલી;
	options->macs = ખાલી;
	options->kex_algorithms = ખાલી;
	options->hostkeyalgorithms = ખાલી;
	options->ca_sign_algorithms = ખાલી;
	options->અંક_identity_files = 0;
	memset(options->identity_ચાવીઓ, 0, કદ(options->identity_ચાવીઓ));
	options->અંક_certificate_files = 0;
	memset(options->certificates, 0, કદ(options->certificates));
	options->hostname = ખાલી;
	options->host_ચાવી_alias = ખાલી;
	options->proxy_command = ખાલી;
	options->jump_user = ખાલી;
	options->jump_host = ખાલી;
	options->jump_port = -1;
	options->jump_extra = ખાલી;
	options->user = ખાલી;
	options->escape_char = -1;
	options->અંક_system_hostfiles = 0;
	options->અંક_user_hostfiles = 0;
	options->local_forwards = ખાલી;
	options->અંક_local_forwards = 0;
	options->remote_forwards = ખાલી;
	options->અંક_remote_forwards = 0;
	options->permitted_remote_opens = ખાલી;
	options->અંક_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->અંક_log_verbose = 0;
	options->log_verbose = ખાલી;
	options->preferred_authentications = ખાલી;
	options->bind_address = ખાલી;
	options->bind_interface = ખાલી;
	options->pkcs11_provider = ખાલી;
	options->sk_provider = ખાલી;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_ચાવી_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_ગણતરી_max = -1;
	options->send_env = ખાલી;
	options->અંક_send_env = 0;
	options->setenv = ખાલી;
	options->અંક_setenv = 0;
	options->control_path = ખાલી;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = ખાલી;
	options->permit_local_command = -1;
	options->remote_command = ખાલી;
	options->add_ચાવીઓ_to_agent = -1;
	options->add_ચાવીઓ_to_agent_lifespan = -1;
	options->identity_agent = ખાલી;
	options->visual_host_ચાવી = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = ખાલી;
	options->અંક_canonical_domains = 0;
	options->અંક_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_ચાવીઓ = ખાલી;
	options->અંક_revoked_host_ચાવીઓ = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = ખાલી;
	options->pubkey_accepted_algos = ખાલી;
	options->known_hosts_command = ખાલી;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = ખાલી;
	options->channel_timeouts = ખાલી;
	options->અંક_channel_timeouts = 0;
	options->version_addendum = ખાલી;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
શૂન્ય
fill_default_options_for_canonicalization(Options *options)
{
	જો (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	જો (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	જો (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
પૂર્ણાંક
fill_default_options(Options * options)
{
	અક્ષર *all_cipher, *all_mac, *all_kex, *all_ચાવી, *all_sig;
	અક્ષર *def_cipher, *def_mac, *def_kex, *def_ચાવી, *def_sig;
	પૂર્ણાંક ret = -1, r;

	જો (options->forward_agent == -1)
		options->forward_agent = 0;
	જો (options->forward_x11 == -1)
		options->forward_x11 = 0;
	જો (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	જો (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	જો (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != ખાલી ? 1 : 0;
	જો (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != ખાલી ? 1 : 0;
	જો (options->clear_forwardings == 1)
		clear_forwardings(options);

	જો (options->xauth_location == ખાલી)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	જો (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	જો (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	જો (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	જો (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	જો (options->gss_authentication == -1)
		options->gss_authentication = 0;
	જો (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	જો (options->password_authentication == -1)
		options->password_authentication = 1;
	જો (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	જો (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	જો (options->batch_mode == -1)
		options->batch_mode = 0;
	જો (options->check_host_ip == -1)
		options->check_host_ip = 0;
	જો (options->strict_host_ચાવી_checking == -1)
		options->strict_host_ચાવી_checking = SSH_STRICT_HOSTKEY_ASK;
	જો (options->compression == -1)
		options->compression = 0;
	જો (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	જો (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	જો (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	જો (options->connection_attempts == -1)
		options->connection_attempts = 1;
	જો (options->સંખ્યા_of_password_prompts == -1)
		options->સંખ્યા_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	જો (options->add_ચાવીઓ_to_agent == -1) {
		options->add_ચાવીઓ_to_agent = 0;
		options->add_ચાવીઓ_to_agent_lifespan = 0;
	}
	જો (options->અંક_identity_files == 0) {
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
	જો (options->escape_char == -1)
		options->escape_char = '~';
	જો (options->અંક_system_hostfiles == 0) {
		options->system_hostfiles[options->અંક_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->અંક_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	જો (options->update_hostkeys == -1) {
		જો (options->verify_host_ચાવી_dns <= 0 &&
		    (options->અંક_user_hostfiles == 0 ||
		    (options->અંક_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		નહીંતર
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	જો (options->અંક_user_hostfiles == 0) {
		options->user_hostfiles[options->અંક_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->અંક_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	જો (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	જો (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	જો (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	જો (options->identities_only == -1)
		options->identities_only = 0;
	જો (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	જો (options->rekey_limit == -1)
		options->rekey_limit = 0;
	જો (options->rekey_interval == -1)
		options->rekey_interval = 0;
	જો (options->verify_host_ચાવી_dns == -1)
		options->verify_host_ચાવી_dns = 0;
	જો (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	જો (options->server_alive_ગણતરી_max == -1)
		options->server_alive_ગણતરી_max = 3;
	જો (options->control_master == -1)
		options->control_master = 0;
	જો (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	જો (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	જો (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	જો (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	જો (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	જો (options->permit_local_command == -1)
		options->permit_local_command = 0;
	જો (options->visual_host_ચાવી == -1)
		options->visual_host_ચાવી = 0;
	જો (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	જો (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	જો (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	જો (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	જો (options->stdin_null == -1)
		options->stdin_null = 0;
	જો (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	જો (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	જો (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	જો (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	જો (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	જો (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	જો (options->sk_provider == ખાલી)
		options->sk_provider = xstrdup("internal");
#નહીંતર
	જો (options->sk_provider == ખાલી)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	જો (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	જો (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	જો (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	જો (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ચાવી = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_ચાવી = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ચાવી);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	કરો { \
		જો ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			જાઓ fail; \
		} \
	} જ્યારે (0)
	options->kex_algorithms_set = options->kex_algorithms != ખાલી;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_ચાવી, all_ચાવી);
	ASSEMBLE(pubkey_accepted_algos, def_ચાવી, all_ચાવી);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	કરો { \
		જો (option_clear_or_none(v)) { \
			મુક્ત(v); \
			v = ખાલી; \
		} \
	} જ્યારે(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	કરો { \
		જો (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			મુક્ત(options->v[0]); \
			મુક્ત(options->v); \
			options->v = ખાલી; \
			options->nv = 0; \
		} \
	} જ્યારે (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, અંક_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_ચાવીઓ, અંક_revoked_host_ચાવીઓ, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	જો (options->jump_host != ખાલી &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == ખાલી) {
		મુક્ત(options->jump_host);
		options->jump_host = ખાલી;
	}
	જો (options->અંક_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		મુક્ત(options->permitted_cnames[0].source_list);
		મુક્ત(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    કદ(*options->permitted_cnames));
		options->અંક_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	મુક્ત(all_cipher);
	મુક્ત(all_mac);
	મુક્ત(all_kex);
	મુક્ત(all_ચાવી);
	મુક્ત(all_sig);
	મુક્ત(def_cipher);
	મુક્ત(def_mac);
	મુક્ત(def_kex);
	મુક્ત(def_ચાવી);
	મુક્ત(def_sig);
	પાછા ret;
}

શૂન્ય
free_options(Options *o)
{
	પૂર્ણાંક i;

	જો (o == ખાલી)
		પાછા;

#define FREE_ARRAY(type, n, a) \
	કરો { \
		type _i; \
		માટે (_i = 0; _i < (n); _i++) \
			મુક્ત((a)[_i]); \
	} જ્યારે (0)

	મુક્ત(o->forward_agent_sock_path);
	મુક્ત(o->xauth_location);
	FREE_ARRAY(u_int, o->અંક_log_verbose, o->log_verbose);
	મુક્ત(o->log_verbose);
	મુક્ત(o->ciphers);
	મુક્ત(o->macs);
	મુક્ત(o->hostkeyalgorithms);
	મુક્ત(o->kex_algorithms);
	મુક્ત(o->ca_sign_algorithms);
	મુક્ત(o->hostname);
	મુક્ત(o->host_ચાવી_alias);
	મુક્ત(o->proxy_command);
	મુક્ત(o->user);
	FREE_ARRAY(u_int, o->અંક_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->અંક_user_hostfiles, o->user_hostfiles);
	મુક્ત(o->preferred_authentications);
	મુક્ત(o->bind_address);
	મુક્ત(o->bind_interface);
	મુક્ત(o->pkcs11_provider);
	મુક્ત(o->sk_provider);
	માટે (i = 0; i < o->અંક_identity_files; i++) {
		મુક્ત(o->identity_files[i]);
		sshkey_free(o->identity_ચાવીઓ[i]);
	}
	માટે (i = 0; i < o->અંક_certificate_files; i++) {
		મુક્ત(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	મુક્ત(o->identity_agent);
	માટે (i = 0; i < o->અંક_local_forwards; i++) {
		મુક્ત(o->local_forwards[i].listen_host);
		મુક્ત(o->local_forwards[i].listen_path);
		મુક્ત(o->local_forwards[i].connect_host);
		મુક્ત(o->local_forwards[i].connect_path);
	}
	મુક્ત(o->local_forwards);
	માટે (i = 0; i < o->અંક_remote_forwards; i++) {
		મુક્ત(o->remote_forwards[i].listen_host);
		મુક્ત(o->remote_forwards[i].listen_path);
		મુક્ત(o->remote_forwards[i].connect_host);
		મુક્ત(o->remote_forwards[i].connect_path);
	}
	મુક્ત(o->remote_forwards);
	મુક્ત(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->અંક_send_env, o->send_env);
	મુક્ત(o->send_env);
	FREE_ARRAY(u_int, o->અંક_setenv, o->setenv);
	મુક્ત(o->setenv);
	મુક્ત(o->control_path);
	મુક્ત(o->local_command);
	મુક્ત(o->remote_command);
	FREE_ARRAY(પૂર્ણાંક, o->અંક_canonical_domains, o->canonical_domains);
	માટે (i = 0; i < o->અંક_permitted_cnames; i++) {
		મુક્ત(o->permitted_cnames[i].source_list);
		મુક્ત(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->અંક_revoked_host_ચાવીઓ, o->revoked_host_ચાવીઓ);
	મુક્ત(o->revoked_host_ચાવીઓ);
	મુક્ત(o->hostbased_accepted_algos);
	મુક્ત(o->pubkey_accepted_algos);
	મુક્ત(o->jump_user);
	મુક્ત(o->jump_host);
	મુક્ત(o->jump_extra);
	મુક્ત(o->ignored_unknown);
	explicit_bzero(o, કદ(*o));
#undef FREE_ARRAY
}

સંરચના fwdarg {
	અક્ષર *arg;
	પૂર્ણાંક ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
સ્થિર પૂર્ણાંક
parse_fwd_field(અક્ષર **p, સંરચના fwdarg *fwd)
{
	અક્ષર *ep, *cp = *p;
	પૂર્ણાંક ispath = 0;

	જો (*cp == '\0') {
		*p = ખાલી;
		પાછા -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	જો (*cp == '[') {
		/* find matching ']' */
		માટે (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			જો (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		જો (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			પાછા -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		જો (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		પાછા 0;
	}

	માટે (cp = *p; *cp != '\0'; cp++) {
		પસંદગી (*cp) {
		સ્થિતિ '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			જો (*cp == '\0')
				પાછા -1;
			તોડો;
		સ્થિતિ '/':
			ispath = 1;
			તોડો;
		સ્થિતિ ':':
			*cp++ = '\0';
			જાઓ done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	પાછા 0;
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
પૂર્ણાંક
parse_forward(સંરચના Forward *fwd, અચલ અક્ષર *fwdspec, પૂર્ણાંક dynamicfwd, પૂર્ણાંક remotefwd)
{
	સંરચના fwdarg fwdargs[4];
	અક્ષર *p, *cp;
	પૂર્ણાંક i, err;

	memset(fwd, 0, કદ(*fwd));
	memset(fwdargs, 0, કદ(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	જો (p == ખાલી || err)
		પાછા 0;

	/* skip leading spaces */
	જ્યારે (isspace((u_char)*cp))
		cp++;

	માટે (i = 0; i < 4; ++i) {
		જો (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			તોડો;
	}

	/* Check for trailing garbage */
	જો (cp != ખાલી && *cp != '\0') {
		i = 0;	/* failure */
	}

	પસંદગી (i) {
	સ્થિતિ 1:
		જો (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} નહીંતર {
			fwd->listen_host = ખાલી;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		તોડો;

	સ્થિતિ 2:
		જો (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} નહીંતર જો (fwdargs[1].ispath) {
			fwd->listen_host = ખાલી;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} નહીંતર {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		તોડો;

	સ્થિતિ 3:
		જો (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} નહીંતર જો (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} નહીંતર {
			fwd->listen_host = ખાલી;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		તોડો;

	સ્થિતિ 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		તોડો;
	મૂળભૂત:
		i = 0; /* failure */
	}

	મુક્ત(p);

	જો (dynamicfwd) {
		જો (!(i == 1 || i == 2))
			જાઓ fail_free;
	} નહીંતર {
		જો (!(i == 3 || i == 4)) {
			જો (fwd->connect_path == ખાલી &&
			    fwd->listen_path == ખાલી)
				જાઓ fail_free;
		}
		જો (fwd->connect_port <= 0 && fwd->connect_path == ખાલી)
			જાઓ fail_free;
	}

	જો ((fwd->listen_port < 0 && fwd->listen_path == ખાલી) ||
	    (!remotefwd && fwd->listen_port == 0))
		જાઓ fail_free;
	જો (fwd->connect_host != ખાલી &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		જાઓ fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	જો (fwd->connect_path != ખાલી &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		જાઓ fail_free;
	જો (fwd->listen_host != ખાલી &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		જાઓ fail_free;
	જો (fwd->listen_path != ખાલી &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		જાઓ fail_free;

	પાછા (i);

 fail_free:
	મુક્ત(fwd->connect_host);
	fwd->connect_host = ખાલી;
	મુક્ત(fwd->connect_path);
	fwd->connect_path = ખાલી;
	મુક્ત(fwd->listen_host);
	fwd->listen_host = ખાલી;
	મુક્ત(fwd->listen_path);
	fwd->listen_path = ખાલી;
	પાછા (0);
}

પૂર્ણાંક
ssh_valid_hostname(અચલ અક્ષર *s)
{
	size_t i;

	જો (*s == '-')
		પાછા 0;
	માટે (i = 0; s[i] != 0; i++) {
		જો (strchr("'`\"$\\;&<>|(){},", s[i]) != ખાલી ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			પાછા 0;
	}
	પાછા 1;
}

પૂર્ણાંક
ssh_valid_ruser(અચલ અક્ષર *s)
{
	size_t i;

	જો (*s == '-')
		પાછા 0;
	માટે (i = 0; s[i] != 0; i++) {
		જો (iscntrl((u_char)s[i]))
			પાછા 0;
		જો (strchr("'`\";&<>|(){}$\\", s[i]) != ખાલી)
			પાછા 0;
		/* Disallow '-' after whitespace */
		જો (isspace((u_char)s[i]) && s[i + 1] == '-')
			પાછા 0;
	}
	પાછા 1;
}

પૂર્ણાંક
parse_jump(અચલ અક્ષર *s, Options *o, પૂર્ણાંક strict, પૂર્ણાંક active)
{
	અક્ષર *orig = ખાલી, *sdup = ખાલી, *cp;
	અક્ષર *tmp_user = ખાલી, *tmp_host = ખાલી, *host = ખાલી, *user = ખાલી;
	પૂર્ણાંક r, ret = -1, tmp_port = -1, port = -1, first = 1;

	જો (strcasecmp(s, "none") == 0) {
		જો (active && o->jump_host == ખાલી) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		પાછા 0;
	}

	orig = xstrdup(s);
	જો ((cp = strchr(orig, '#')) != ખાલી)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == ખાલી && o->jump_host == ખાલી;
	sdup = xstrdup(orig);
	કરો {
		/* Work backwards through string */
		જો ((cp = strrchr(sdup, ',')) == ખાલી)
			cp = sdup; /* last */
		નહીંતર
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		જો (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			જાઓ out; /* error already logged */
		જો (strict) {
			જો (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				જાઓ out;
			}
			જો (tmp_user != ખાલી && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				જાઓ out;
			}
		}
		જો (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = ખાલી; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		મુક્ત(tmp_user);
		મુક્ત(tmp_host);
		tmp_user = tmp_host = ખાલી;
		tmp_port = -1;
	} જ્યારે (cp != sdup);

	/* success */
	જો (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = ખાલી; /* transferred */
		જો (orig != ખાલી && (cp = strrchr(orig, ',')) != ખાલી) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	મુક્ત(orig);
	મુક્ત(sdup);
	મુક્ત(tmp_user);
	મુક્ત(tmp_host);
	મુક્ત(user);
	મુક્ત(host);
	પાછા ret;
}

પૂર્ણાંક
parse_ssh_uri(અચલ અક્ષર *uri, અક્ષર **userp, અક્ષર **hostp, પૂર્ણાંક *portp)
{
	અક્ષર *user = ખાલી, *host = ખાલી, *path = ખાલી;
	પૂર્ણાંક r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	જો (r == 0 && path != ખાલી)
		r = -1;		/* path not allowed */
	જો (r == 0) {
		જો (userp != ખાલી) {
			*userp = user;
			user = ખાલી;
		}
		જો (hostp != ખાલી) {
			*hostp = host;
			host = ખાલી;
		}
		જો (portp != ખાલી)
			*portp = port;
	}
	મુક્ત(user);
	મુક્ત(host);
	મુક્ત(path);
	પાછા r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
સ્થિર અચલ અક્ષર *
fmt_multistate_int(પૂર્ણાંક val, અચલ સંરચના multistate *m)
{
	u_int i;

	માટે (i = 0; m[i].ચાવી != ખાલી; i++) {
		જો (m[i].કિંમત == val)
			પાછા m[i].ચાવી;
	}
	પાછા "UNKNOWN";
}

સ્થિર અચલ અક્ષર *
fmt_intarg(OpCodes code, પૂર્ણાંક val)
{
	જો (val == -1)
		પાછા "unset";
	પસંદગી (code) {
	સ્થિતિ oAddressFamily:
		પાછા fmt_multistate_int(val, multistate_addressfamily);
	સ્થિતિ oCompression:
		પાછા fmt_multistate_int(val, multistate_compression);
	સ્થિતિ o_Verify_Host_ચાવી_DNS:
	સ્થિતિ oUpdateHostkeys:
		પાછા fmt_multistate_int(val, multistate_yesnoask);
	સ્થિતિ o_Strict_Host_ચાવી_Checking:
		પાછા fmt_multistate_int(val, multistate_strict_hostkey);
	સ્થિતિ oControlMaster:
		પાછા fmt_multistate_int(val, multistate_controlmaster);
	સ્થિતિ oTunnel:
		પાછા fmt_multistate_int(val, multistate_tunnel);
	સ્થિતિ oRequestTTY:
		પાછા fmt_multistate_int(val, multistate_requesttty);
	સ્થિતિ oSessionType:
		પાછા fmt_multistate_int(val, multistate_sessiontype);
	સ્થિતિ oCanonicalizeHostname:
		પાછા fmt_multistate_int(val, multistate_canonicalizehostname);
	સ્થિતિ o_Add_ચાવીઓ_To_Agent:
		પાછા fmt_multistate_int(val, multistate_yesnoaskconfirm);
	સ્થિતિ oPubkeyAuthentication:
		પાછા fmt_multistate_int(val, multistate_pubkey_auth);
	સ્થિતિ oTCPKeepAlive:
		પાછા fmt_multistate_int(val, multistate_keepalives);
	સ્થિતિ oFingerprintHash:
		પાછા ssh_digest_alg_name(val);
	મૂળભૂત:
		પસંદગી (val) {
		સ્થિતિ 0:
			પાછા "no";
		સ્થિતિ 1:
			પાછા "yes";
		મૂળભૂત:
			પાછા "UNKNOWN";
		}
	}
}

સ્થિર અચલ અક્ષર *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	માટે (i = 0; keywords[i].name != ખાલી; i++)
		જો (keywords[i].opcode == code)
			પાછા(keywords[i].name);
	પાછા "UNKNOWN";
}

સ્થિર શૂન્ય
dump_cfg_int(OpCodes code, પૂર્ણાંક val)
{
	જો (code == oObscureKeystrokeTiming) {
		જો (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			પાછા;
		} નહીંતર જો (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			પાછા;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

સ્થિર શૂન્ય
dump_cfg_fmtint(OpCodes code, પૂર્ણાંક val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

સ્થિર શૂન્ય
dump_cfg_string(OpCodes code, અચલ અક્ષર *val)
{
	જો (val == ખાલી)
		પાછા;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

સ્થિર શૂન્ય
dump_cfg_strarray(OpCodes code, u_int ગણતરી, અક્ષર **vals)
{
	u_int i;

	માટે (i = 0; i < ગણતરી; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

સ્થિર શૂન્ય
dump_cfg_strarray_oneline(OpCodes code, u_int ગણતરી, અક્ષર **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	જો (ગણતરી == 0)
		printf(" none");
	માટે (i = 0; i < ગણતરી; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

સ્થિર શૂન્ય
dump_cfg_forwards(OpCodes code, u_int ગણતરી, અચલ સંરચના Forward *fwds)
{
	અચલ સંરચના Forward *fwd;
	u_int i;

	/* oDynamicForward */
	માટે (i = 0; i < ગણતરી; i++) {
		fwd = &fwds[i];
		જો (code == oDynamicForward && fwd->connect_host != ખાલી &&
		    strcmp(fwd->connect_host, "socks") != 0)
			ચાલુ;
		જો (code == oLocalForward && fwd->connect_host != ખાલી &&
		    strcmp(fwd->connect_host, "socks") == 0)
			ચાલુ;
		printf("%s", lookup_opcode_name(code));
		જો (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		નહીંતર જો (fwd->listen_host == ખાલી)
			printf(" %d", fwd->listen_port);
		નહીંતર {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		જો (code != oDynamicForward) {
			જો (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			નહીંતર જો (fwd->connect_host == ખાલી)
				printf(" %d", fwd->connect_port);
			નહીંતર {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

શૂન્ય
dump_client_config(Options *o, અચલ અક્ષર *host)
{
	પૂર્ણાંક i, r;
	અક્ષર buf[8], *all_ચાવી;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_ચાવી = sshkey_alg_list(0, 0, 1, ',');
	જો ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_ચાવી)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	મુક્ત(all_ચાવી);

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
	dump_cfg_fmtint(o_Strict_Host_ચાવી_Checking, o->strict_host_ચાવી_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_ચાવી_DNS, o->verify_host_ચાવી_dns);
	dump_cfg_fmtint(o_Visual_Host_ચાવી, o->visual_host_ચાવી);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_સંખ્યા_Of_Password_Prompts, o->સંખ્યા_of_password_prompts);
	dump_cfg_int(o_Server_Alive_ગણતરી_Max, o->server_alive_ગણતરી_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_ચાવી_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_ચાવી_Alias, o->host_ચાવી_alias);
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
	dump_cfg_string(o_Security_ચાવી_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->અંક_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->અંક_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->અંક_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->અંક_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->અંક_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->અંક_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->અંક_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->અંક_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_ચાવીઓ, o->અંક_revoked_host_ચાવીઓ, o->revoked_host_ચાવીઓ);
	dump_cfg_strarray(oSendEnv, o->અંક_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->અંક_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->અંક_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->અંક_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	જો (o->અંક_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	નહીંતર
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->અંક_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	જો (o->add_ચાવીઓ_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_ચાવીઓ_To_Agent, o->add_ચાવીઓ_to_agent);
	નહીંતર {
		printf("addkeystoagent%s %d\n",
		    o->add_ચાવીઓ_to_agent == 3 ? " confirm" : "",
		    o->add_ચાવીઓ_to_agent_lifespan);
	}

	/* oForwardAgent */
	જો (o->forward_agent_sock_path == ખાલી)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	નહીંતર
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	જો (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	નહીંતર
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	જો (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	નહીંતર
		printf(" %d", o->tun_local);
	જો (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	નહીંતર
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	જો (o->અંક_permitted_cnames == 0)
		printf(" none");
	માટે (i = 0; i < o->અંક_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	જો (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	નહીંતર
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	જો (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	નહીંતર {
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
	જો (o->jump_host == ખાલી)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	નહીંતર {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != ખાલી ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, કદ(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == ખાલી ? "" : o->jump_extra,
		    o->jump_extra == ખાલી ? "" : ",",
		    /* optional user */
		    o->jump_user == ખાલી ? "" : o->jump_user,
		    o->jump_user == ખાલી ? "" : "@",
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
