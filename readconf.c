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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <net/if.h>
#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <netinet/ip.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <glob.h>
#అన్తర్భావ <ifaddrs.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <util.h>
#ఒకవేళ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#అయితే_ముగింపు

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "readconf.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "mac.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "version.h"

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

స్థిర పూర్ణాంకం read_config_file_లోతు(స్థిరరాశి అక్షరం *filename, నిర్మాణం passwd *pw,
    స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *original_host, స్థిరరాశి అక్షరం *remote_command,
    Options *options, పూర్ణాంకం flags, పూర్ణాంకం *activep, పూర్ణాంకం *want_final_pass, పూర్ణాంకం లోతు);
స్థిర పూర్ణాంకం process_config_పంక్తి_లోతు(Options *options, నిర్మాణం passwd *pw,
    స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *original_host, స్థిరరాశి అక్షరం *remote_command,
    అక్షరం *పంక్తి, స్థిరరాశి అక్షరం *filename, పూర్ణాంకం linenum, పూర్ణాంకం *activep, పూర్ణాంకం flags,
    పూర్ణాంకం *want_final_pass, పూర్ణాంకం లోతు);

/* Keyword tokens. */

రకనిర్వచనం గణన {
	oBadOption,
	oHost, o_సరిపోలిక, oInclude, o_ట్యాగ్,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	o_తటస్థం_File, oHostname, o_పోర్టు, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_కూడు_కీలకాలు_గమ్యం_Agent, o_తటస్థం_Agent,
	oUser, oEscapeChar, oProxyCommand,
	o_Global_తెలిసిన_Hosts_File, o_User_తెలిసిన_Hosts_File, oConnectionAttempts,
	o_Batch_బహుళకం, oCheckHostIP, o_Strict_Host_కీలకం_Checking, oCompression,
	oTCPKeepAlive, o_సంఖ్య_యొక్క_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_కీలకం_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_కీలకం_Algorithms, o_Bind_చిరునామా, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, o_Rekey_హద్దు, o_Verify_Host_కీలకం_DNS, oConnectTimeout,
	o_చిరునామా_Family, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_లెక్క_Max, oIdentitiesOnly,
	oSendEnv, o_సమితి_Env, o_Control_మార్గం, oControlMaster, oControlPersist,
	o_Hash_తెలిసిన_Hosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_కీలకం,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	o_ప్రవాహం_Local_Bind_ముసుగు, o_ప్రవాహం_Local_Bind_Unlink, o_Revoked_Host_కీలకాలు,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_కీలకం_Provider, o_తెలిసిన_Hosts_Command, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	o_సంస్కరణ_Addendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

స్థిర నిర్మాణం {
	స్థిరరాశి అక్షరం *name;
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
#ఒకవేళ defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# లేకపోతే
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#అయితే_ముగింపు
#నిర్వచితమైతే ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# లేకపోతే
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#అయితే_ముగింపు

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
	{ "identityfile", o_తటస్థం_File },
	{ "identityfile2", o_తటస్థం_File },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_కూడు_కీలకాలు_గమ్యం_Agent },
	{ "identityagent", o_తటస్థం_Agent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_కీలకం_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", o_పోర్టు },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", o_సరిపోలిక },
	{ "tag", o_ట్యాగ్ },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", o_Global_తెలిసిన_Hosts_File },
	{ "userknownhostsfile", o_User_తెలిసిన_Hosts_File },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", o_Batch_బహుళకం },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_కీలకం_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_సంఖ్య_యొక్క_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_కీలకం_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", o_Bind_చిరునామా },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_కీలకం_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", o_Rekey_హద్దు },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", o_చిరునామా_Family },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_లెక్క_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", o_సమితి_Env },
	{ "controlpath", o_Control_మార్గం },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", o_Hash_తెలిసిన_Hosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", o_Visual_Host_కీలకం },
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
	{ "streamlocalbindmask", o_ప్రవాహం_Local_Bind_ముసుగు },
	{ "streamlocalbindunlink", o_ప్రవాహం_Local_Bind_Unlink },
	{ "revokedhostkeys", o_Revoked_Host_కీలకాలు },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_కీలకం_Provider },
	{ "knownhostscommand", o_తెలిసిన_Hosts_Command },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", o_సంస్కరణ_Addendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ ఖాళీ, oBadOption }
};

స్థిర స్థిరరాశి అక్షరం *lookup_opcode_name(OpCodes సంకేతం_2);

స్థిరరాశి అక్షరం *
kex_default_pk_alg(శూన్య)
{
	స్థిర అక్షరం *pkalgs;

	ఒకవేళ (pkalgs == ఖాళీ) {
		అక్షరం *all_కీలకం;

		all_కీలకం = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = సరిపోలిక_filter_allowlist(KEX_DEFAULT_PK_ALG, all_కీలకం);
		విడుదల(all_కీలకం);
	}
	తిరిగి pkalgs;
}

అక్షరం *
ssh_connection_hash(స్థిరరాశి అక్షరం *thishost, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *portstr,
    స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *jumphost)
{
	నిర్మాణం ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_నిడివి];

	ఒకవేళ ((md = ssh_digest_ప్రారంభం(SSH_DIGEST_SHA1)) == ఖాళీ ||
	    ssh_digest_update(md, thishost, అక్షరశ్రేణి_పొడవు(thishost)) < 0 ||
	    ssh_digest_update(md, host, అక్షరశ్రేణి_పొడవు(host)) < 0 ||
	    ssh_digest_update(md, portstr, అక్షరశ్రేణి_పొడవు(portstr)) < 0 ||
	    ssh_digest_update(md, user, అక్షరశ్రేణి_పొడవు(user)) < 0 ||
	    ssh_digest_update(md, jumphost, అక్షరశ్రేణి_పొడవు(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, పరిమాణం(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	తిరిగి tohex(conn_hash, ssh_digest_బైట్లు(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

శూన్య
కూడు_local_forward(Options *options, స్థిరరాశి నిర్మాణం Forward *newfwd)
{
	నిర్మాణం Forward *fwd;
	పూర్ణాంకం i;

	/* Don't add duplicates */
	కొరకు (i = 0; i < options->అంకె_local_forwards; i++) {
		ఒకవేళ (forward_equals(newfwd, options->local_forwards + i))
			తిరిగి;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->అంకె_local_forwards + 1,
	    పరిమాణం(*options->local_forwards));
	fwd = &options->local_forwards[options->అంకె_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_పోర్టు = newfwd->listen_పోర్టు;
	fwd->listen_మార్గం = newfwd->listen_మార్గం;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_పోర్టు = newfwd->connect_పోర్టు;
	fwd->connect_మార్గం = newfwd->connect_మార్గం;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

శూన్య
కూడు_remote_forward(Options *options, స్థిరరాశి నిర్మాణం Forward *newfwd)
{
	నిర్మాణం Forward *fwd;
	పూర్ణాంకం i;

	/* Don't add duplicates */
	కొరకు (i = 0; i < options->అంకె_remote_forwards; i++) {
		ఒకవేళ (forward_equals(newfwd, options->remote_forwards + i))
			తిరిగి;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->అంకె_remote_forwards + 1,
	    పరిమాణం(*options->remote_forwards));
	fwd = &options->remote_forwards[options->అంకె_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_పోర్టు = newfwd->listen_పోర్టు;
	fwd->listen_మార్గం = newfwd->listen_మార్గం;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_పోర్టు = newfwd->connect_పోర్టు;
	fwd->connect_మార్గం = newfwd->connect_మార్గం;
	fwd->handle = newfwd->handle;
	fwd->allocated_పోర్టు = 0;
}

స్థిర శూన్య
clear_forwardings(Options *options)
{
	పూర్ణాంకం i;

	కొరకు (i = 0; i < options->అంకె_local_forwards; i++) {
		విడుదల(options->local_forwards[i].listen_host);
		విడుదల(options->local_forwards[i].listen_మార్గం);
		విడుదల(options->local_forwards[i].connect_host);
		విడుదల(options->local_forwards[i].connect_మార్గం);
	}
	ఒకవేళ (options->అంకె_local_forwards > 0) {
		విడుదల(options->local_forwards);
		options->local_forwards = ఖాళీ;
	}
	options->అంకె_local_forwards = 0;
	కొరకు (i = 0; i < options->అంకె_remote_forwards; i++) {
		విడుదల(options->remote_forwards[i].listen_host);
		విడుదల(options->remote_forwards[i].listen_మార్గం);
		విడుదల(options->remote_forwards[i].connect_host);
		విడుదల(options->remote_forwards[i].connect_మార్గం);
	}
	ఒకవేళ (options->అంకె_remote_forwards > 0) {
		విడుదల(options->remote_forwards);
		options->remote_forwards = ఖాళీ;
	}
	options->అంకె_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

శూన్య
కూడు_certificate_file(Options *options, స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం userprovided)
{
	పూర్ణాంకం i;

	ఒకవేళ (options->అంకె_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	కొరకు (i = 0; i < options->అంకె_certificate_files; i++) {
		ఒకవేళ (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], మార్గం) == 0) {
			debug2_f("ignoring duplicate key %s", మార్గం);
			తిరిగి;
		}
	}

	options->certificate_file_userprovided[options->అంకె_certificate_files] =
	    userprovided;
	options->certificate_files[options->అంకె_certificate_files++] =
	    xstrdup(మార్గం);
}

శూన్య
కూడు_తటస్థం_file(Options *options, స్థిరరాశి అక్షరం *dir, స్థిరరాశి అక్షరం *filename,
    పూర్ణాంకం userprovided)
{
	అక్షరం *మార్గం;
	పూర్ణాంకం i;

	ఒకవేళ (options->అంకె_తటస్థం_files >= SSH_MAX_తటస్థం_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_తటస్థం_FILES);

	ఒకవేళ (dir == ఖాళీ) /* no dir, filename is absolute */
		మార్గం = xstrdup(filename);
	లేకపోతే ఒకవేళ (xasprintf(&మార్గం, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", మార్గం);

	/* Avoid registering duplicates */
	కొరకు (i = 0; i < options->అంకె_తటస్థం_files; i++) {
		ఒకవేళ (options->తటస్థం_file_userprovided[i] == userprovided &&
		    strcmp(options->తటస్థం_files[i], మార్గం) == 0) {
			debug2_f("ignoring duplicate key %s", మార్గం);
			విడుదల(మార్గం);
			తిరిగి;
		}
	}

	options->తటస్థం_file_userprovided[options->అంకె_తటస్థం_files] =
	    userprovided;
	options->తటస్థం_files[options->అంకె_తటస్థం_files++] = మార్గం;
}

పూర్ణాంకం
default_ssh_పోర్టు(శూన్య)
{
	స్థిర పూర్ణాంకం పోర్టు;
	నిర్మాణం servent *sp;

	ఒకవేళ (పోర్టు == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		పోర్టు = sp ? ntohs(sp->s_port) : SSH_DEFAULT_పోర్టు;
	}
	తిరిగి పోర్టు;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
స్థిర పూర్ణాంకం
execute_లోపల_shell(స్థిరరాశి అక్షరం *cmd)
{
	అక్షరం *shell;
	pid_t pid;
	పూర్ణాంకం స్థితి_2;

	ఒకవేళ ((shell = getenv("SHELL")) == ఖాళీ)
		shell = _PATH_BSHELL;

	ఒకవేళ (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	ఒకవేళ ((pid = fork()) == 0) {
		అక్షరం *argv[4];

		ఒకవేళ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = ఖాళీ;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	ఒకవేళ (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	అయితే (waitpid(pid, &స్థితి_2, 0) == -1) {
		ఒకవేళ (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	ఒకవేళ (!WIFEXITED(స్థితి_2)) {
		error("command '%.100s' exited abnormally", cmd);
		తిరిగి -1;
	}
	debug3("command returned status %d", WEXITSTATUS(స్థితి_2));
	తిరిగి WEXITSTATUS(స్థితి_2);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
స్థిర పూర్ణాంకం
check_సరిపోలిక_ifaddrs(స్థిరరాశి అక్షరం *addrlist)
{
#నిర్వచితమైతే HAVE_IFADDRS_H
	నిర్మాణం ifaddrs *ifa, *ifaddrs = ఖాళీ;
	పూర్ణాంకం r, దొరికింది = 0;
	అక్షరం addr[NI_MAXHOST];
	socklen_t salen;

	ఒకవేళ (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		తిరిగి 0;
	}
	కొరకు (ifa = ifaddrs; ifa != ఖాళీ; ifa = ifa->ifa_తదుపరి) {
		ఒకవేళ (ifa->ifa_addr == ఖాళీ || ifa->ifa_name == ఖాళీ ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			కొనసాగు;
		ఎంపిక (ifa->ifa_addr->sa_family) {
		స్థితి AF_INET:
			salen = పరిమాణం(నిర్మాణం sockaddr_in);
			ఆపు;
		స్థితి AF_INET6:
			salen = పరిమాణం(నిర్మాణం sockaddr_in6);
			ఆపు;
#నిర్వచితమైతే AF_LINK
		స్థితి AF_LINK:
			/* ignore */
			కొనసాగు;
#అయితే_ముగింపు /* AF_LINK */
		అప్రమేయ:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			కొనసాగు;
		}
		ఒకవేళ ((r = getnameinfo(ifa->ifa_addr, salen, addr, పరిమాణం(addr),
		    ఖాళీ, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			కొనసాగు;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		ఒకవేళ (addr_సరిపోలిక_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			దొరికింది = 1;
			ఆపు;
		}
	}
	freeifaddrs(ifaddrs);
	తిరిగి దొరికింది;
#లేకపోతే /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	తిరిగి 0;
#అయితే_ముగింపు /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
స్థిర అక్షరం *
expand_సరిపోలిక_exec_or_include_మార్గం(స్థిరరాశి అక్షరం *మార్గం, Options *options,
    నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *host_arg, స్థిరరాశి అక్షరం *original_host,
    పూర్ణాంకం final_pass, పూర్ణాంకం is_include_మార్గం)
{
	అక్షరం thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	అక్షరం uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	అక్షరం *host, *ret;
	పూర్ణాంకం పోర్టు;

	పోర్టు = options->పోర్టు <= 0 ? default_ssh_పోర్టు() : options->పోర్టు;
	ruser = options->user == ఖాళీ ? pw->pw_name : options->user;
	ఒకవేళ (final_pass) {
		host = xstrdup(options->hostname);
	} లేకపోతే ఒకవేళ (options->hostname != ఖాళీ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (అక్షరం *)ఖాళీ);
	} లేకపోతే {
		host = xstrdup(host_arg);
	}
	ఒకవేళ (gethostname(thishost, పరిమాణం(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, పరిమాణం(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, పరిమాణం(portstr), "%d", పోర్టు);
	snprintf(uidstr, పరిమాణం(uidstr), "%llu",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_కీలకం_alias ?  options->host_కీలకం_alias : host;

	ret = (is_include_మార్గం ? percent_dollar_expand : percent_expand)(మార్గం,
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
	    (అక్షరం *)ఖాళీ);
	విడుదల(host);
	విడుదల(conn_hash_hex);
	తిరిగి ret;
}

/*
 * Parse and execute a Match directive.
 */
స్థిర పూర్ణాంకం
సరిపోలిక_cfg_పంక్తి(Options *options, స్థిరరాశి అక్షరం *నిండిన_పంక్తి, పూర్ణాంకం *acp, అక్షరం ***avp,
    నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *host_arg, స్థిరరాశి అక్షరం *original_host,
    స్థిరరాశి అక్షరం *remote_command, పూర్ణాంకం final_pass, పూర్ణాంకం *want_final_pass,
    స్థిరరాశి అక్షరం *filename, పూర్ణాంకం linenum)
{
	అక్షరం *arg, *oattrib = ఖాళీ, *attrib = ఖాళీ, *cmd, *host, *criteria;
	స్థిరరాశి అక్షరం *ruser;
	పూర్ణాంకం r, this_ఫలితం, ఫలితం = 1, లక్షణాలు = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == ఖాళీ ? pw->pw_name : options->user;
	ఒకవేళ (final_pass) {
		host = xstrdup(options->hostname);
	} లేకపోతే ఒకవేళ (options->hostname != ఖాళీ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (అక్షరం *)ఖాళీ);
	} లేకపోతే {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    నిండిన_పంక్తి, host, original_host);
	అయితే ((attrib = argv_తదుపరి(acp, avp)) != ఖాళీ) {
		/* Terminate on comment */
		ఒకవేళ (*attrib == '#') {
			argv_consume(acp);
			ఆపు;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = ఖాళీ;
		this_ఫలితం = 1;
		ఒకవేళ ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		ఒకవేళ (strcasecmp(attrib, "all") == 0) {
			ఒకవేళ (లక్షణాలు > 1 ||
			    ((arg = argv_తదుపరి(acp, avp)) != ఖాళీ &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				ఫలితం = -1;
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (arg != ఖాళీ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ఒకవేళ (ఫలితం)
				ఫలితం = negate ? 0 : 1;
			వెళ్ళు బహిర్గతం;
		}
		లక్షణాలు++;
		/* criteria "final" and "canonical" have no argument */
		ఒకవేళ (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			ఒకవేళ (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != ఖాళీ)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_ఫలితం ? "" : "not ", oattrib);
			వెళ్ళు తదుపరి;
		}

		/* Keep this list in sync with below */
		ఒకవేళ (strprefix(attrib, "host=", 1)  != ఖాళీ ||
		    strprefix(attrib, "originalhost=", 1) != ఖాళీ ||
		    strprefix(attrib, "user=", 1) != ఖాళీ ||
		    strprefix(attrib, "localuser=", 1) != ఖాళీ ||
		    strprefix(attrib, "localnetwork=", 1) != ఖాళీ ||
		    strprefix(attrib, "version=", 1) != ఖాళీ ||
		    strprefix(attrib, "tagged=", 1) != ఖాళీ ||
		    strprefix(attrib, "command=", 1) != ఖాళీ ||
		    strprefix(attrib, "exec=", 1) != ఖాళీ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} లేకపోతే ఒకవేళ ((arg = argv_తదుపరి(acp, avp)) == ఖాళీ) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			ఫలితం = -1;
			వెళ్ళు బహిర్గతం;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		ఒకవేళ (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = ఖాళీ;
		ఒకవేళ (arg == ఖాళీ || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			ఫలితం = -1;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = సరిపోలిక_hostname(host, arg) == 1;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = సరిపోలిక_hostname(original_host, arg) == 1;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = సరిపోలిక_నమూనా_list(ruser, arg, 0) == 1;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = సరిపోలిక_నమూనా_list(pw->pw_name, arg, 0) == 1;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "localnetwork") == 0) {
			ఒకవేళ (addr_సరిపోలిక_cidr_list(ఖాళీ, arg) == -1) {
				/* Error already printed */
				ఫలితం = -1;
				వెళ్ళు బహిర్గతం;
			}
			r = check_సరిపోలిక_ifaddrs(arg) == 1;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = సరిపోలిక_నమూనా_list(SSH_RELEASE, arg, 0) == 1;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->ట్యాగ్ == ఖాళీ ? "" :
			    options->ట్యాగ్);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    సరిపోలిక_నమూనా_list(criteria, arg, 0) == 1;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == ఖాళీ ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    సరిపోలిక_నమూనా_list(criteria, arg, 0) == 1;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "sessiontype") == 0) {
			ఒకవేళ (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			లేకపోతే ఒకవేళ (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			లేకపోతే ఒకవేళ (remote_command != ఖాళీ &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			లేకపోతే
				criteria = xstrdup("shell");
			r = సరిపోలిక_నమూనా_list(criteria, arg, 0) == 1;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "exec") == 0) {
			ఒకవేళ ((cmd = expand_సరిపోలిక_exec_or_include_మార్గం(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == ఖాళీ) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			ఒకవేళ (ఫలితం != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				విడుదల(cmd);
				వెళ్ళు తదుపరి;
			}
			r = execute_లోపల_shell(cmd);
			ఒకవేళ (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			విడుదల(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			ఒకవేళ (r == (negate ? 1 : 0))
				this_ఫలితం = ఫలితం = 0;
		} లేకపోతే {
			error("Unsupported Match attribute %s", attrib);
			ఫలితం = -1;
			వెళ్ళు బహిర్గతం;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_ఫలితం ? "": "not ", oattrib,
		    criteria == ఖాళీ ? "" : " \"",
		    criteria == ఖాళీ ? "" : criteria,
		    criteria == ఖాళీ ? "" : "\"");
 తదుపరి:
		విడుదల(criteria);
		విడుదల(oattrib);
		oattrib = attrib = ఖాళీ;
	}
	ఒకవేళ (లక్షణాలు == 0) {
		error("One or more attributes required for Match");
		ఫలితం = -1;
		వెళ్ళు బహిర్గతం;
	}
 బహిర్గతం:
	ఒకవేళ (ఫలితం != -1)
		debug2("match %sfound", ఫలితం ? "" : "not ");
	విడుదల(oattrib);
	విడుదల(host);
	తిరిగి ఫలితం;
}

/* Remove environment variable by pattern */
స్థిర శూన్య
rm_env(Options *options, స్థిరరాశి అక్షరం *arg, స్థిరరాశి అక్షరం *filename, పూర్ణాంకం linenum)
{
	u_int i, j, onum_send_env = options->అంకె_send_env;

	/* Remove an environment variable */
	కొరకు (i = 0; i < options->అంకె_send_env; ) {
		ఒకవేళ (!సరిపోలిక_నమూనా(options->send_env[i], arg + 1)) {
			i++;
			కొనసాగు;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		విడుదల(options->send_env[i]);
		options->send_env[i] = ఖాళీ;
		కొరకు (j = i; j < options->అంకె_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = ఖాళీ;
		}
		options->అంకె_send_env--;
		/* NB. don't increment i */
	}
	ఒకవేళ (onum_send_env != options->అంకె_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->అంకె_send_env,
		    పరిమాణం(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
స్థిర OpCodes
parse_token(స్థిరరాశి అక్షరం *cp, స్థిరరాశి అక్షరం *filename, పూర్ణాంకం linenum,
    స్థిరరాశి అక్షరం *ignored_unknown)
{
	పూర్ణాంకం i;

	కొరకు (i = 0; keywords[i].name; i++)
		ఒకవేళ (strcmp(cp, keywords[i].name) == 0)
			తిరిగి keywords[i].opcode;
	ఒకవేళ (ignored_unknown != ఖాళీ &&
	    సరిపోలిక_నమూనా_list(cp, ignored_unknown, 1) == 1)
		తిరిగి oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	తిరిగి oBadOption;
}

స్థిర శూన్య
free_canon_cnames(నిర్మాణం allowed_cname *cnames, u_int n)
{
	u_int i;

	ఒకవేళ (cnames == ఖాళీ || n == 0)
		తిరిగి;
	కొరకు (i = 0; i < n; i++) {
		విడుదల(cnames[i].ఆధారం_list);
		విడుదల(cnames[i].లక్ష్యం_list);
	}
	విడుదల(cnames);
}

/* Multistate option parsing */
నిర్మాణం multistate {
	అక్షరం *కీలకం;
	పూర్ణాంకం విలువ;
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_compression[] = {
#నిర్వచితమైతే WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#అయితే_ముగింపు
	{ "no",				COMP_NONE },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ఖాళీ, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ఖాళీ, -1 }
};

స్థిర పూర్ణాంకం
parse_multistate_విలువ(స్థిరరాశి అక్షరం *arg, స్థిరరాశి అక్షరం *filename, పూర్ణాంకం linenum,
    స్థిరరాశి నిర్మాణం multistate *multistate_ptr)
{
	పూర్ణాంకం i;

	ఒకవేళ (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		తిరిగి -1;
	}
	కొరకు (i = 0; multistate_ptr[i].కీలకం != ఖాళీ; i++) {
		ఒకవేళ (strcasecmp(arg, multistate_ptr[i].కీలకం) == 0)
			తిరిగి multistate_ptr[i].విలువ;
	}
	తిరిగి -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
పూర్ణాంకం
process_config_పంక్తి(Options *options, నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *host,
    స్థిరరాశి అక్షరం *original_host, స్థిరరాశి అక్షరం *remote_command, అక్షరం *పంక్తి,
    స్థిరరాశి అక్షరం *filename, పూర్ణాంకం linenum, పూర్ణాంకం *activep, పూర్ణాంకం flags)
{
	తిరిగి process_config_పంక్తి_లోతు(options, pw, host, original_host,
	    remote_command, పంక్తి, filename, linenum, activep, flags, ఖాళీ, 0);
}

#నిర్వచించు WHITESPACE " \t\r\n"
స్థిర పూర్ణాంకం
process_config_పంక్తి_లోతు(Options *options, నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *host,
    స్థిరరాశి అక్షరం *original_host, స్థిరరాశి అక్షరం *remote_command, అక్షరం *పంక్తి,
    స్థిరరాశి అక్షరం *filename, పూర్ణాంకం linenum, పూర్ణాంకం *activep, పూర్ణాంకం flags,
    పూర్ణాంకం *want_final_pass, పూర్ణాంకం లోతు)
{
	అక్షరం *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	అక్షరం **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	పూర్ణాంకం r, oactive, negated, opcode, *intptr, విలువ, value2, cmdline = 0;
	పూర్ణాంకం remotefwd, dynamicfwd, ca_only = 0, దొరికింది = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	దీర్ఘ దీర్ఘ val64;
	కొలత_t len;
	నిర్మాణం Forward fwd;
	స్థిరరాశి నిర్మాణం multistate *multistate_ptr;
	glob_t gl;
	స్థిరరాశి అక్షరం *errstr;
	అక్షరం **oav = ఖాళీ, **av;
	పూర్ణాంకం oac = 0, ac;
	పూర్ణాంకం ret = -1;
	నిర్మాణం allowed_cname *cnames = ఖాళీ;
	u_int ncnames = 0;
	అక్షరం **strs = ఖాళీ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	ఒకవేళ (activep == ఖాళీ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ఒకవేళ ((len = అక్షరశ్రేణి_పొడవు(పంక్తి)) == 0)
		తిరిగి 0;
	కొరకు (len--; len > 0; len--) {
		ఒకవేళ (strchr(WHITESPACE "\f", పంక్తి[len]) == ఖాళీ)
			ఆపు;
		పంక్తి[len] = '\0';
	}

	str = పంక్తి;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	ఒకవేళ ((keyword = strdelim(&str)) == ఖాళీ)
		తిరిగి 0;
	/* Ignore leading whitespace. */
	ఒకవేళ (*keyword == '\0')
		keyword = strdelim(&str);
	ఒకవేళ (keyword == ఖాళీ || !*keyword || *keyword == '\n' || *keyword == '#')
		తిరిగి 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	ఒకవేళ (str != ఖాళీ)
		str += strspn(str, WHITESPACE);
	ఒకవేళ (str == ఖాళీ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		తిరిగి -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	ఒకవేళ (argv_విభజించు(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		తిరిగి -1;
	}
	ac = oac;
	av = oav;

	ఎంపిక (opcode) {
	స్థితి oBadOption:
		/* don't panic, but count bad options */
		వెళ్ళు బహిర్గతం;
	స్థితి oIgnore:
		argv_consume(&ac);
		ఆపు;
	స్థితి oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ఆపు;
	స్థితి oConnectTimeout:
		intptr = &options->connection_timeout;
parse_సమయం:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (strcmp(arg, "none") == 0)
			విలువ = -1;
		లేకపోతే ఒకవేళ ((విలువ = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}

		విలువ = -1;
		multistate_ptr = multistate_flag;
		కొరకు (i = 0; multistate_ptr[i].కీలకం != ఖాళీ; i++) {
			ఒకవేళ (strcasecmp(arg, multistate_ptr[i].కీలకం) == 0) {
				విలువ = multistate_ptr[i].విలువ;
				ఆపు;
			}
		}
		ఒకవేళ (విలువ != -1) {
			ఒకవేళ (*activep && *intptr == -1)
				*intptr = విలువ;
			ఆపు;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_మార్గం;
		వెళ్ళు parse_agent_మార్గం;

	స్థితి oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ ((విలువ = parse_multistate_విలువ(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		వెళ్ళు parse_flag;

	స్థితి oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		వెళ్ళు parse_సమయం;

	స్థితి oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		వెళ్ళు parse_flag;

	స్థితి oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		వెళ్ళు parse_flag;

	స్థితి oPasswordAuthentication:
		intptr = &options->password_authentication;
		వెళ్ళు parse_flag;

	స్థితి oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		వెళ్ళు parse_flag;

	స్థితి oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		వెళ్ళు parse_string;

	స్థితి oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		వెళ్ళు parse_multistate;

	స్థితి oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		వెళ్ళు parse_flag;

	స్థితి oGssAuthentication:
		intptr = &options->gss_authentication;
		వెళ్ళు parse_flag;

	స్థితి oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		వెళ్ళు parse_flag;

	స్థితి o_Batch_బహుళకం:
		intptr = &options->batch_బహుళకం;
		వెళ్ళు parse_flag;

	స్థితి oCheckHostIP:
		intptr = &options->check_host_ip;
		వెళ్ళు parse_flag;

	స్థితి o_Verify_Host_కీలకం_DNS:
		intptr = &options->verify_host_కీలకం_dns;
		multistate_ptr = multistate_yesnoask;
		వెళ్ళు parse_multistate;

	స్థితి o_Strict_Host_కీలకం_Checking:
		intptr = &options->strict_host_కీలకం_checking;
		multistate_ptr = multistate_strict_hostkey;
		వెళ్ళు parse_multistate;

	స్థితి oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		వెళ్ళు parse_multistate;

	స్థితి oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		వెళ్ళు parse_multistate;

	స్థితి oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		వెళ్ళు parse_flag;

	స్థితి o_సంఖ్య_యొక్క_Password_Prompts:
		intptr = &options->సంఖ్య_యొక్క_password_prompts;
		వెళ్ళు parse_int;

	స్థితి o_Rekey_హద్దు:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} లేకపోతే {
			ఒకవేళ (పరిశీలన_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				వెళ్ళు బహిర్గతం;
			}
		}
		ఒకవేళ (*activep && options->rekey_హద్దు == -1)
			options->rekey_హద్దు = val64;
		ఒకవేళ (ac != 0) { /* optional rekey interval present */
			ఒకవేళ (strcmp(av[0], "none") == 0) {
				(శూన్య)argv_తదుపరి(&ac, &av);	/* discard */
				ఆపు;
			}
			intptr = &options->rekey_interval;
			వెళ్ళు parse_సమయం;
		}
		ఆపు;

	స్థితి o_తటస్థం_File:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep) {
			intptr = &options->అంకె_తటస్థం_files;
			ఒకవేళ (*intptr >= SSH_MAX_తటస్థం_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_తటస్థం_FILES);
				వెళ్ళు బహిర్గతం;
			}
			కూడు_తటస్థం_file(options, ఖాళీ,
			    arg, flags & SSHCONF_USERCONF);
		}
		ఆపు;

	స్థితి oCertificateFile:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep) {
			intptr = &options->అంకె_certificate_files;
			ఒకవేళ (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				వెళ్ళు బహిర్గతం;
			}
			కూడు_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		ఆపు;

	స్థితి oXAuthLocation:
		charptr=&options->xauth_location;
		వెళ్ళు parse_string;

	స్థితి oUser:
		charptr = &options->user;
parse_string:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;

	స్థితి o_Global_తెలిసిన_Hosts_File:
		cpptr = (అక్షరం **)&options->system_hostfiles;
		uintptr = &options->అంకె_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		విలువ = *uintptr == 0; /* was array empty when we started? */
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				వెళ్ళు బహిర్గతం;
			}
			/* Allow "none" only in first position */
			ఒకవేళ (strcasecmp(arg, "none") == 0) {
				ఒకవేళ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					వెళ్ళు బహిర్గతం;
				}
			}
			i++;
			ఒకవేళ (*activep && విలువ) {
				ఒకవేళ ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					వెళ్ళు బహిర్గతం;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		ఆపు;

	స్థితి o_User_తెలిసిన_Hosts_File:
		cpptr = (అక్షరం **)&options->user_hostfiles;
		uintptr = &options->అంకె_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		వెళ్ళు parse_char_array;

	స్థితి oHostname:
		charptr = &options->hostname;
		వెళ్ళు parse_string;

	స్థితి o_ట్యాగ్:
		charptr = &options->ట్యాగ్;
		వెళ్ళు parse_string;

	స్థితి o_Host_కీలకం_Alias:
		charptr = &options->host_కీలకం_alias;
		వెళ్ళు parse_string;

	స్థితి oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		వెళ్ళు parse_string;

	స్థితి o_Bind_చిరునామా:
		charptr = &options->bind_చిరునామా;
		వెళ్ళు parse_string;

	స్థితి oBindInterface:
		charptr = &options->bind_interface;
		వెళ్ళు parse_string;

	స్థితి oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		వెళ్ళు parse_string;

	స్థితి o_Security_కీలకం_Provider:
		charptr = &options->sk_provider;
		వెళ్ళు parse_string;

	స్థితి o_తెలిసిన_Hosts_Command:
		charptr = &options->తెలిసిన_hosts_command;
		వెళ్ళు parse_command;

	స్థితి oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		ఒకవేళ (str == ఖాళీ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		len = strspn(str, WHITESPACE "=");
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ఆపు;

	స్థితి oProxyJump:
		ఒకవేళ (str == ఖాళీ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		ఒకవేళ (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			వెళ్ళు బహిర్గతం;
		}
		argv_consume(&ac);
		ఆపు;

	స్థితి o_పోర్టు:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		విలువ = a2port(arg);
		ఒకవేళ (విలువ <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && options->పోర్టు == -1)
			options->పోర్టు = విలువ;
		ఆపు;

	స్థితి oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ ((errstr = atoi_err(arg, &విలువ)) != ఖాళీ) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి oCiphers:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && options->ciphers == ఖాళీ)
			options->ciphers = xstrdup(arg);
		ఆపు;

	స్థితి oMacs:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && options->macs == ఖాళీ)
			options->macs = xstrdup(arg);
		ఆపు;

	స్థితి oKexAlgorithms:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*arg != '-' &&
		    !kex_పేర్లు_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && options->kex_algorithms == ఖాళీ)
			options->kex_algorithms = xstrdup(arg);
		ఆపు;

	స్థితి o_Host_కీలకం_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*arg != '-' &&
		    !sshkey_పేర్లు_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;

	స్థితి oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		వెళ్ళు parse_pubkey_algos;

	స్థితి oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_తదుపరి(&ac, &av);
		విలువ = log_level_సంఖ్య(arg);
		ఒకవేళ (విలువ == SYSLOG_LEVEL_NOT_సమితి) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_సమితి)
			*log_level_ptr = (LogLevel) విలువ;
		ఆపు;

	స్థితి oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_తదుపరి(&ac, &av);
		విలువ = log_facility_సంఖ్య(arg);
		ఒకవేళ (విలువ == SYSLOG_FACILITY_NOT_సమితి) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) విలువ;
		ఆపు;

	స్థితి oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->అంకె_log_verbose;
		i = 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				వెళ్ళు బహిర్గతం;
			}
			/* Allow "none" only in first position */
			ఒకవేళ (strcasecmp(arg, "none") == 0) {
				ఒకవేళ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					వెళ్ళు బహిర్గతం;
				}
			}
			i++;
			ఒకవేళ (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, పరిమాణం(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		ఆపు;

	స్థితి oLocalForward:
	స్థితి oRemoteForward:
	స్థితి oDynamicForward:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		ఒకవేళ (!dynamicfwd) {
			arg2 = argv_తదుపరి(&ac, &av);
			ఒకవేళ (arg2 == ఖాళీ || *arg2 == '\0') {
				ఒకవేళ (remotefwd)
					dynamicfwd = 1;
				లేకపోతే {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					వెళ్ళు బహిర్గతం;
				}
			} లేకపోతే {
				/* construct a string for parse_forward */
				snprintf(fwdarg, పరిమాణం(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		ఒకవేళ (dynamicfwd)
			strlcpy(fwdarg, arg, పరిమాణం(fwdarg));

		ఒకవేళ (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}

		ఒకవేళ (*activep) {
			ఒకవేళ (remotefwd) {
				కూడు_remote_forward(options, &fwd);
			} లేకపోతే {
				కూడు_local_forward(options, &fwd);
			}
		}
		ఆపు;

	స్థితి oPermitRemoteOpen:
		uintptr = &options->అంకె_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		దొరికింది = *uintptr == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			ఒకవేళ (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				ఒకవేళ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					విడుదల(arg2);
					వెళ్ళు బహిర్గతం;
				}
			} లేకపోతే {
				p = hpdelim(&arg);
				ఒకవేళ (p == ఖాళీ) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				ఒకవేళ (arg == ఖాళీ || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			విడుదల(arg2);
		}
		ఒకవేళ (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		ఒకవేళ (దొరికింది && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి oClearAllForwardings:
		intptr = &options->clear_forwardings;
		వెళ్ళు parse_flag;

	స్థితి oHost:
		ఒకవేళ (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			వెళ్ళు బహిర్గతం;
		}
		*activep = 0;
		arg2 = ఖాళీ;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				ఆపు;
			}
			negated = *arg == '!';
			ఒకవేళ (negated)
				arg++;
			ఒకవేళ (సరిపోలిక_నమూనా(host, arg)) {
				ఒకవేళ (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					ఆపు;
				}
				ఒకవేళ (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		ఒకవేళ (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		ఆపు;

	స్థితి o_సరిపోలిక:
		ఒకవేళ (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			వెళ్ళు బహిర్గతం;
		}
		విలువ = సరిపోలిక_cfg_పంక్తి(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		ఒకవేళ (విలువ < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			వెళ్ళు బహిర్గతం;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : విలువ;
		ఆపు;

	స్థితి oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (strcmp(arg, "none") == 0)
			విలువ = SSH_ESCAPECHAR_NONE;
		లేకపోతే ఒకవేళ (arg[1] == '\0')
			విలువ = (u_char) arg[0];
		లేకపోతే ఒకవేళ (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			విలువ = (u_char) arg[1] & 31;
		లేకపోతే {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి o_చిరునామా_Family:
		intptr = &options->చిరునామా_family;
		multistate_ptr = multistate_addressfamily;
		వెళ్ళు parse_multistate;

	స్థితి oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		వెళ్ళు parse_flag;

	స్థితి oIdentitiesOnly:
		intptr = &options->identities_only;
		వెళ్ళు parse_flag;

	స్థితి oServerAliveInterval:
		intptr = &options->server_alive_interval;
		వెళ్ళు parse_సమయం;

	స్థితి o_Server_Alive_లెక్క_Max:
		intptr = &options->server_alive_లెక్క_max;
		వెళ్ళు parse_int;

	స్థితి oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0' || strchr(arg, '=') != ఖాళీ) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				వెళ్ళు బహిర్గతం;
			}
			దొరికింది = 1;
			ఒకవేళ (!*activep)
				కొనసాగు;
			ఒకవేళ (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				కొనసాగు;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->అంకె_send_env, arg);
		}
		ఒకవేళ (!దొరికింది) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఆపు;

	స్థితి o_సమితి_Env:
		దొరికింది = options->అంకె_setenv == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (strchr(arg, '=') == ఖాళీ) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (lookup_setenv_లోపల_list(arg, strs, nstrs) != ఖాళీ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				కొనసాగు;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			options->setenv = strs;
			options->అంకె_setenv = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి o_Control_మార్గం:
		charptr = &options->control_మార్గం;
		వెళ్ళు parse_string;

	స్థితి oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		వెళ్ళు parse_multistate;

	స్థితి oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		విలువ = 0;
		value2 = 0;	/* timeout */
		ఒకవేళ (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			విలువ = 0;
		లేకపోతే ఒకవేళ (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			విలువ = 1;
		లేకపోతే ఒకవేళ ((value2 = convtime(arg)) >= 0)
			విలువ = 1;
		లేకపోతే {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *intptr == -1) {
			*intptr = విలువ;
			options->control_persist_timeout = value2;
		}
		ఆపు;

	స్థితి o_Hash_తెలిసిన_Hosts:
		intptr = &options->hash_తెలిసిన_hosts;
		వెళ్ళు parse_flag;

	స్థితి oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		వెళ్ళు parse_multistate;

	స్థితి oTunnelDevice:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		విలువ = a2tun(arg, &value2);
		ఒకవేళ (విలువ == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && options->tun_local == -1) {
			options->tun_local = విలువ;
			options->tun_remote = value2;
		}
		ఆపు;

	స్థితి oLocalCommand:
		charptr = &options->local_command;
		వెళ్ళు parse_command;

	స్థితి oPermitLocalCommand:
		intptr = &options->permit_local_command;
		వెళ్ళు parse_flag;

	స్థితి oRemoteCommand:
		charptr = &options->remote_command;
		వెళ్ళు parse_command;

	స్థితి o_Visual_Host_కీలకం:
		intptr = &options->visual_host_కీలకం;
		వెళ్ళు parse_flag;

	స్థితి oInclude:
		ఒకవేళ (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			వెళ్ళు బహిర్గతం;
		}
		విలువ = 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				వెళ్ళు బహిర్గతం;
			}
			/* Expand %tokens and environment variables */
			ఒకవేళ ((p = expand_సరిపోలిక_exec_or_include_మార్గం(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == ఖాళీ) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				కొనసాగు;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			ఒకవేళ (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (!మార్గం_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" మార్గం_SSH_USER_DIR : SSHDIR, p);
			} లేకపోతే {
				arg2 = xstrdup(p);
			}
			విడుదల(p);
			memset(&gl, 0, పరిమాణం(gl));
			r = glob(arg2, GLOB_TILDE, ఖాళీ, &gl);
			ఒకవేళ (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				విడుదల(arg2);
				కొనసాగు;
			} లేకపోతే ఒకవేళ (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				వెళ్ళు బహిర్గతం;
			}
			విడుదల(arg2);
			oactive = *activep;
			కొరకు (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], లోతు,
				    oactive ? "" : " (parse only)");
				r = read_config_file_లోతు(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, లోతు + 1);
				ఒకవేళ (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					వెళ్ళు బహిర్గతం;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				ఒకవేళ (r != 1)
					విలువ = -1;
			}
			globfree(&gl);
		}
		ఒకవేళ (విలువ != 0)
			ret = విలువ;
		ఆపు;

	స్థితి oIPQoS:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ ((విలువ = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (విలువ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			విలువ = గరిష్ఠ_పూర్ణాంకం;
		}
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (arg == ఖాళీ)
			value2 = విలువ;
		లేకపోతే ఒకవేళ ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = గరిష్ఠ_పూర్ణాంకం;
		}
		ఒకవేళ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = విలువ;
			options->ip_qos_bulk = value2;
		}
		ఆపు;

	స్థితి oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		వెళ్ళు parse_multistate;

	స్థితి oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		వెళ్ళు parse_multistate;

	స్థితి oStdinNull:
		intptr = &options->stdin_null;
		వెళ్ళు parse_flag;

	స్థితి oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		వెళ్ళు parse_flag;

	స్థితి oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		వెళ్ళు parse_string;

	స్థితి oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		వెళ్ళు parse_flag;

	స్థితి oCanonicalDomains:
		దొరికింది = options->అంకె_canonical_domains == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			/* Allow "none" only in first position */
			ఒకవేళ (strcasecmp(arg, "none") == 0) {
				ఒకవేళ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					వెళ్ళు బహిర్గతం;
				}
			}
			ఒకవేళ (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				వెళ్ళు బహిర్గతం;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			options->canonical_domains = strs;
			options->అంకె_canonical_domains = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి oCanonicalizePermittedCNAMEs:
		దొరికింది = options->అంకె_permitted_cnames == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			ఒకవేళ (strcasecmp(arg, "none") == 0) {
				ఒకవేళ (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					వెళ్ళు బహిర్గతం;
				}
				arg2 = "";
			} లేకపోతే ఒకవేళ (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} లేకపోతే {
				lowercase(arg);
				ఒకవేళ ((arg2 = strchr(arg, ':')) == ఖాళీ ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					వెళ్ళు బహిర్గతం;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    పరిమాణం(*cnames));
			cnames[ncnames].ఆధారం_list = xstrdup(arg);
			cnames[ncnames].లక్ష్యం_list = xstrdup(arg2);
			ncnames++;
		}
		ఒకవేళ (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			options->permitted_cnames = cnames;
			options->అంకె_permitted_cnames = ncnames;
			cnames = ఖాళీ; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		ఆపు;

	స్థితి oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		వెళ్ళు parse_multistate;

	స్థితి oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		వెళ్ళు parse_int;

	స్థితి oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		వెళ్ళు parse_flag;

	స్థితి o_ప్రవాహం_Local_Bind_ముసుగు:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		/* Parse mode in octal format */
		విలువ = strtol(arg, &endofnumber, 8);
		ఒకవేళ (arg == endofnumber || విలువ < 0 || విలువ > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep &&
		    options->fwd_opts.streamlocal_bind_ముసుగు == (బహుళకం_t)-1)
			options->fwd_opts.streamlocal_bind_ముసుగు = (బహుళకం_t)విలువ;
		ఆపు;

	స్థితి o_ప్రవాహం_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		వెళ్ళు parse_flag;

	స్థితి o_Revoked_Host_కీలకాలు:
		uintptr = &options->అంకె_revoked_host_కీలకాలు;
		cppptr = &options->revoked_host_కీలకాలు;
		దొరికింది = *uintptr == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				వెళ్ళు బహిర్గతం;
			}
			/* Allow "none" only in first position */
			ఒకవేళ (strcasecmp(arg, "none") == 0) {
				ఒకవేళ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					వెళ్ళు బహిర్గతం;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((విలువ = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		వెళ్ళు parse_multistate;

	స్థితి oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		వెళ్ళు parse_pubkey_algos;

	స్థితి oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		వెళ్ళు parse_pubkey_algos;

	స్థితి o_కూడు_కీలకాలు_గమ్యం_Agent:
		arg = argv_తదుపరి(&ac, &av);
		arg2 = argv_తదుపరి(&ac, &av);
		విలువ = parse_multistate_విలువ(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		ఒకవేళ (విలువ == 3 && arg2 != ఖాళీ) {
			/* allow "AddKeysToAgent confirm 5m" */
			ఒకవేళ ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				వెళ్ళు బహిర్గతం;
			}
		} లేకపోతే ఒకవేళ (విలువ == -1 && arg2 == ఖాళీ) {
			ఒకవేళ ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				వెళ్ళు బహిర్గతం;
			}
			విలువ = 1; /* yes */
		} లేకపోతే ఒకవేళ (విలువ == -1 || arg2 != ఖాళీ) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && options->కూడు_కీలకాలు_గమ్యం_agent == -1) {
			options->కూడు_కీలకాలు_గమ్యం_agent = విలువ;
			options->కూడు_కీలకాలు_గమ్యం_agent_lifespan = value2;
		}
		ఆపు;

	స్థితి o_తటస్థం_Agent:
		charptr = &options->తటస్థం_agent;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
  parse_agent_మార్గం:
		/* Extra validation if the string represents an env var. */
		ఒకవేళ ((arg2 = dollar_expand(&r, arg)) == ఖాళీ || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			వెళ్ళు బహిర్గతం;
		}
		విడుదల(arg2);
		/* check for legacy environment format */
		ఒకవేళ (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;

	స్థితి oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		వెళ్ళు parse_flag;

	స్థితి oRequiredRSASize:
		intptr = &options->required_rsa_కొలత;
		వెళ్ళు parse_int;

	స్థితి oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		వెళ్ళు parse_multistate;

	స్థితి oObscureKeystrokeTiming:
		విలువ = -1;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (విలువ != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				విలువ = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			లేకపోతే ఒకవేళ (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				విలువ = 0;
			లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(arg, "interval:", 9) == 0) {
				ఒకవేళ ((errstr = atoi_err(arg + 9,
				    &విలువ)) != ఖాళీ) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					వెళ్ళు బహిర్గతం;
				}
				ఒకవేళ (విలువ <= 0 || విలువ > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					వెళ్ళు బహిర్గతం;
				}
			} లేకపోతే {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				వెళ్ళు బహిర్గతం;
			}
		}
		ఒకవేళ (విలువ == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి oChannelTimeout:
		దొరికింది = options->అంకె_channel_timeouts == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			/* Allow "none" only in first position */
			ఒకవేళ (strcasecmp(arg, "none") == 0) {
				ఒకవేళ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					వెళ్ళు బహిర్గతం;
				}
			} లేకపోతే ఒకవేళ (parse_నమూనా_interval(arg,
			    ఖాళీ, ఖాళీ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			options->channel_timeouts = strs;
			options->అంకె_channel_timeouts = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి o_సంస్కరణ_Addendum:
		ఒకవేళ (str == ఖాళీ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ఒకవేళ (strchr(str + len, '\r') != ఖాళీ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ఒకవేళ ((arg = strchr(పంక్తి, '#')) != ఖాళీ) {
			*arg = '\0';
			rtrim(పంక్తి);
		}
		ఒకవేళ (*activep && options->సంస్కరణ_addendum == ఖాళీ) {
			ఒకవేళ (strcasecmp(str + len, "none") == 0)
				options->సంస్కరణ_addendum = xstrdup("");
			లేకపోతే
				options->సంస్కరణ_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ఆపు;

	స్థితి oRefuseConnection:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		ఆపు;

	స్థితి oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ఆపు;

	స్థితి oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ఆపు;

	అప్రమేయ:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		వెళ్ళు బహిర్గతం;
	}

	/* Check that there is no garbage at end of line. */
	ఒకవేళ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		వెళ్ళు బహిర్గతం;
	}

	/* success */
	ret = 0;
 బహిర్గతం:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, ఖాళీ, nstrs);
	argv_free(oav, oac);
	తిరిగి ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
పూర్ణాంకం
read_config_file(స్థిరరాశి అక్షరం *filename, నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *host,
    స్థిరరాశి అక్షరం *original_host, స్థిరరాశి అక్షరం *remote_command, Options *options, పూర్ణాంకం flags,
    పూర్ణాంకం *want_final_pass)
{
	పూర్ణాంకం చురుకైన = 1;

	తిరిగి read_config_file_లోతు(filename, pw, host, original_host,
	    remote_command, options, flags, &చురుకైన, want_final_pass, 0);
}

#నిర్వచించు READCONF_MAX_లోతు	16
స్థిర పూర్ణాంకం
read_config_file_లోతు(స్థిరరాశి అక్షరం *filename, నిర్మాణం passwd *pw,
    స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *original_host, స్థిరరాశి అక్షరం *remote_command,
    Options *options, పూర్ణాంకం flags, పూర్ణాంకం *activep, పూర్ణాంకం *want_final_pass, పూర్ణాంకం లోతు)
{
	FILE *f;
	అక్షరం *పంక్తి = ఖాళీ;
	కొలత_t linesize = 0;
	పూర్ణాంకం linenum;
	పూర్ణాంకం bad_options = 0;

	ఒకవేళ (లోతు < 0 || లోతు > READCONF_MAX_లోతు)
		fatal("Too many recursive configuration includes");

	ఒకవేళ ((f = fopen(filename, "r")) == ఖాళీ)
		తిరిగి 0;

	ఒకవేళ (flags & SSHCONF_CHECKPERM) {
		నిర్మాణం stat sb;

		ఒకవేళ (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		ఒకవేళ (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		ఒకవేళ (process_config_పంక్తి_లోతు(options, pw, host, original_host,
		    remote_command, పంక్తి, filename, linenum, activep, flags,
		    want_final_pass, లోతు) != 0)
			bad_options++;
	}
	విడుదల(పంక్తి);
	fclose(f);
	ఒకవేళ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	తిరిగి 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
పూర్ణాంకం
option_clear_or_none(స్థిరరాశి అక్షరం *o)
{
	తిరిగి o == ఖాళీ || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
పూర్ణాంకం
config_has_permitted_cnames(Options *options)
{
	ఒకవేళ (options->అంకె_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].ఆధారం_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].లక్ష్యం_list, "") == 0)
		తిరిగి 0;
	తిరిగి options->అంకె_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

శూన్య
initialize_options(Options * options)
{
	memset(options, 'X', పరిమాణం(*options));
	options->host_arg = ఖాళీ;
	options->forward_agent = -1;
	options->forward_agent_sock_మార్గం = ఖాళీ;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = ఖాళీ;
	options->stdio_forward_పోర్టు = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = ఖాళీ;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_ముసుగు = (బహుళకం_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = ఖాళీ;
	options->hostbased_authentication = -1;
	options->batch_బహుళకం = -1;
	options->check_host_ip = -1;
	options->strict_host_కీలకం_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->పోర్టు = -1;
	options->చిరునామా_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->సంఖ్య_యొక్క_password_prompts = -1;
	options->ciphers = ఖాళీ;
	options->macs = ఖాళీ;
	options->kex_algorithms = ఖాళీ;
	options->hostkeyalgorithms = ఖాళీ;
	options->ca_sign_algorithms = ఖాళీ;
	options->అంకె_తటస్థం_files = 0;
	memset(options->తటస్థం_కీలకాలు, 0, పరిమాణం(options->తటస్థం_కీలకాలు));
	options->అంకె_certificate_files = 0;
	memset(options->certificates, 0, పరిమాణం(options->certificates));
	options->hostname = ఖాళీ;
	options->host_కీలకం_alias = ఖాళీ;
	options->proxy_command = ఖాళీ;
	options->jump_user = ఖాళీ;
	options->jump_host = ఖాళీ;
	options->jump_పోర్టు = -1;
	options->jump_extra = ఖాళీ;
	options->user = ఖాళీ;
	options->escape_char = -1;
	options->అంకె_system_hostfiles = 0;
	options->అంకె_user_hostfiles = 0;
	options->local_forwards = ఖాళీ;
	options->అంకె_local_forwards = 0;
	options->remote_forwards = ఖాళీ;
	options->అంకె_remote_forwards = 0;
	options->permitted_remote_opens = ఖాళీ;
	options->అంకె_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_సమితి;
	options->log_level = SYSLOG_LEVEL_NOT_సమితి;
	options->అంకె_log_verbose = 0;
	options->log_verbose = ఖాళీ;
	options->preferred_authentications = ఖాళీ;
	options->bind_చిరునామా = ఖాళీ;
	options->bind_interface = ఖాళీ;
	options->pkcs11_provider = ఖాళీ;
	options->sk_provider = ఖాళీ;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_హద్దు = -1;
	options->rekey_interval = -1;
	options->verify_host_కీలకం_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_లెక్క_max = -1;
	options->send_env = ఖాళీ;
	options->అంకె_send_env = 0;
	options->setenv = ఖాళీ;
	options->అంకె_setenv = 0;
	options->control_మార్గం = ఖాళీ;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_తెలిసిన_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = ఖాళీ;
	options->permit_local_command = -1;
	options->remote_command = ఖాళీ;
	options->కూడు_కీలకాలు_గమ్యం_agent = -1;
	options->కూడు_కీలకాలు_గమ్యం_agent_lifespan = -1;
	options->తటస్థం_agent = ఖాళీ;
	options->visual_host_కీలకం = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = ఖాళీ;
	options->అంకె_canonical_domains = 0;
	options->అంకె_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_కీలకాలు = ఖాళీ;
	options->అంకె_revoked_host_కీలకాలు = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = ఖాళీ;
	options->pubkey_accepted_algos = ఖాళీ;
	options->తెలిసిన_hosts_command = ఖాళీ;
	options->required_rsa_కొలత = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->ట్యాగ్ = ఖాళీ;
	options->channel_timeouts = ఖాళీ;
	options->అంకె_channel_timeouts = 0;
	options->సంస్కరణ_addendum = ఖాళీ;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
శూన్య
fill_default_options_for_canonicalization(Options *options)
{
	ఒకవేళ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ఒకవేళ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ఒకవేళ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
పూర్ణాంకం
fill_default_options(Options * options)
{
	అక్షరం *all_cipher, *all_mac, *all_kex, *all_కీలకం, *all_sig;
	అక్షరం *def_cipher, *def_mac, *def_kex, *def_కీలకం, *def_sig;
	పూర్ణాంకం ret = -1, r;

	ఒకవేళ (options->forward_agent == -1)
		options->forward_agent = 0;
	ఒకవేళ (options->forward_x11 == -1)
		options->forward_x11 = 0;
	ఒకవేళ (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	ఒకవేళ (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	ఒకవేళ (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != ఖాళీ ? 1 : 0;
	ఒకవేళ (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != ఖాళీ ? 1 : 0;
	ఒకవేళ (options->clear_forwardings == 1)
		clear_forwardings(options);

	ఒకవేళ (options->xauth_location == ఖాళీ)
		options->xauth_location = xstrdup(మార్గం_XAUTH);
	ఒకవేళ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ఒకవేళ (options->fwd_opts.streamlocal_bind_ముసుగు == (బహుళకం_t)-1)
		options->fwd_opts.streamlocal_bind_ముసుగు = 0177;
	ఒకవేళ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ఒకవేళ (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	ఒకవేళ (options->gss_authentication == -1)
		options->gss_authentication = 0;
	ఒకవేళ (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	ఒకవేళ (options->password_authentication == -1)
		options->password_authentication = 1;
	ఒకవేళ (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	ఒకవేళ (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	ఒకవేళ (options->batch_బహుళకం == -1)
		options->batch_బహుళకం = 0;
	ఒకవేళ (options->check_host_ip == -1)
		options->check_host_ip = 0;
	ఒకవేళ (options->strict_host_కీలకం_checking == -1)
		options->strict_host_కీలకం_checking = SSH_STRICT_HOSTKEY_ASK;
	ఒకవేళ (options->compression == -1)
		options->compression = 0;
	ఒకవేళ (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	ఒకవేళ (options->పోర్టు == -1)
		options->పోర్టు = 0;	/* Filled in ssh_connect. */
	ఒకవేళ (options->చిరునామా_family == -1)
		options->చిరునామా_family = AF_UNSPEC;
	ఒకవేళ (options->connection_attempts == -1)
		options->connection_attempts = 1;
	ఒకవేళ (options->సంఖ్య_యొక్క_password_prompts == -1)
		options->సంఖ్య_యొక్క_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	ఒకవేళ (options->కూడు_కీలకాలు_గమ్యం_agent == -1) {
		options->కూడు_కీలకాలు_గమ్యం_agent = 0;
		options->కూడు_కీలకాలు_గమ్యం_agent_lifespan = 0;
	}
	ఒకవేళ (options->అంకె_తటస్థం_files == 0) {
		కూడు_తటస్థం_file(options, "~/", మార్గం_SSH_CLIENT_ID_RSA, 0);
		కూడు_తటస్థం_file(options, "~/", మార్గం_SSH_CLIENT_ID_ECDSA, 0);
		కూడు_తటస్థం_file(options, "~/",
		    మార్గం_SSH_CLIENT_ID_ECDSA_SK, 0);
		కూడు_తటస్థం_file(options, "~/",
		    మార్గం_SSH_CLIENT_ID_ED25519, 0);
		కూడు_తటస్థం_file(options, "~/",
		    మార్గం_SSH_CLIENT_ID_ED25519_SK, 0);
		కూడు_తటస్థం_file(options, "~/",
		    మార్గం_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	ఒకవేళ (options->escape_char == -1)
		options->escape_char = '~';
	ఒకవేళ (options->అంకె_system_hostfiles == 0) {
		options->system_hostfiles[options->అంకె_system_hostfiles++] =
		    xstrdup(మార్గం_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->అంకె_system_hostfiles++] =
		    xstrdup(మార్గం_SSH_SYSTEM_HOSTFILE2);
	}
	ఒకవేళ (options->update_hostkeys == -1) {
		ఒకవేళ (options->verify_host_కీలకం_dns <= 0 &&
		    (options->అంకె_user_hostfiles == 0 ||
		    (options->అంకె_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], మార్గం_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		లేకపోతే
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	ఒకవేళ (options->అంకె_user_hostfiles == 0) {
		options->user_hostfiles[options->అంకె_user_hostfiles++] =
		    xstrdup(మార్గం_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->అంకె_user_hostfiles++] =
		    xstrdup(మార్గం_SSH_USER_HOSTFILE2);
	}
	ఒకవేళ (options->log_level == SYSLOG_LEVEL_NOT_సమితి)
		options->log_level = SYSLOG_LEVEL_INFO;
	ఒకవేళ (options->log_facility == SYSLOG_FACILITY_NOT_సమితి)
		options->log_facility = SYSLOG_FACILITY_USER;
	ఒకవేళ (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	ఒకవేళ (options->identities_only == -1)
		options->identities_only = 0;
	ఒకవేళ (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	ఒకవేళ (options->rekey_హద్దు == -1)
		options->rekey_హద్దు = 0;
	ఒకవేళ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ఒకవేళ (options->verify_host_కీలకం_dns == -1)
		options->verify_host_కీలకం_dns = 0;
	ఒకవేళ (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	ఒకవేళ (options->server_alive_లెక్క_max == -1)
		options->server_alive_లెక్క_max = 3;
	ఒకవేళ (options->control_master == -1)
		options->control_master = 0;
	ఒకవేళ (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	ఒకవేళ (options->hash_తెలిసిన_hosts == -1)
		options->hash_తెలిసిన_hosts = 0;
	ఒకవేళ (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	ఒకవేళ (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	ఒకవేళ (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	ఒకవేళ (options->permit_local_command == -1)
		options->permit_local_command = 0;
	ఒకవేళ (options->visual_host_కీలకం == -1)
		options->visual_host_కీలకం = 0;
	ఒకవేళ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ఒకవేళ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ఒకవేళ (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	ఒకవేళ (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	ఒకవేళ (options->stdin_null == -1)
		options->stdin_null = 0;
	ఒకవేళ (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	ఒకవేళ (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	ఒకవేళ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ఒకవేళ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ఒకవేళ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	ఒకవేళ (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#నిర్వచితమైతే ENABLE_SK_అంతర్గత
	ఒకవేళ (options->sk_provider == ఖాళీ)
		options->sk_provider = xstrdup("internal");
#లేకపోతే
	ఒకవేళ (options->sk_provider == ఖాళీ)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#అయితే_ముగింపు
	ఒకవేళ (options->required_rsa_కొలత == -1)
		options->required_rsa_కొలత = SSH_RSA_MINIMUM_MODULUS_కొలత;
	ఒకవేళ (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	ఒకవేళ (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	ఒకవేళ (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_కీలకం = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = సరిపోలిక_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = సరిపోలిక_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = సరిపోలిక_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_కీలకం = సరిపోలిక_filter_allowlist(KEX_DEFAULT_PK_ALG, all_కీలకం);
	def_sig = సరిపోలిక_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#నిర్వచించు ASSEMBLE(what, defaults, all) \
	చేయి { \
		ఒకవేళ ((r = kex_assemble_పేర్లు(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			వెళ్ళు fail; \
		} \
	} అయితే (0)
	options->kex_algorithms_సమితి = options->kex_algorithms != ఖాళీ;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_కీలకం, all_కీలకం);
	ASSEMBLE(pubkey_accepted_algos, def_కీలకం, all_కీలకం);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#నిర్వచనం_రద్దు ASSEMBLE

#నిర్వచించు CLEAR_ON_NONE(v) \
	చేయి { \
		ఒకవేళ (option_clear_or_none(v)) { \
			విడుదల(v); \
			v = ఖాళీ; \
		} \
	} అయితే(0)
#నిర్వచించు CLEAR_ON_NONE_ARRAY(v, nv, none) \
	చేయి { \
		ఒకవేళ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			విడుదల(options->v[0]); \
			విడుదల(options->v); \
			options->v = ఖాళీ; \
			options->nv = 0; \
		} \
	} అయితే (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_మార్గం);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->తెలిసిన_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, అంకె_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_కీలకాలు, అంకె_revoked_host_కీలకాలు, "none");
#నిర్వచనం_రద్దు CLEAR_ON_NONE
#నిర్వచనం_రద్దు CLEAR_ON_NONE_ARRAY
	ఒకవేళ (options->jump_host != ఖాళీ &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_పోర్టు == 0 && options->jump_user == ఖాళీ) {
		విడుదల(options->jump_host);
		options->jump_host = ఖాళీ;
	}
	ఒకవేళ (options->అంకె_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		విడుదల(options->permitted_cnames[0].ఆధారం_list);
		విడుదల(options->permitted_cnames[0].లక్ష్యం_list);
		memset(options->permitted_cnames, '\0',
		    పరిమాణం(*options->permitted_cnames));
		options->అంకె_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	విడుదల(all_cipher);
	విడుదల(all_mac);
	విడుదల(all_kex);
	విడుదల(all_కీలకం);
	విడుదల(all_sig);
	విడుదల(def_cipher);
	విడుదల(def_mac);
	విడుదల(def_kex);
	విడుదల(def_కీలకం);
	విడుదల(def_sig);
	తిరిగి ret;
}

శూన్య
free_options(Options *o)
{
	పూర్ణాంకం i;

	ఒకవేళ (o == ఖాళీ)
		తిరిగి;

#నిర్వచించు FREE_ARRAY(type, n, a) \
	చేయి { \
		type _i; \
		కొరకు (_i = 0; _i < (n); _i++) \
			విడుదల((a)[_i]); \
	} అయితే (0)

	విడుదల(o->forward_agent_sock_మార్గం);
	విడుదల(o->xauth_location);
	FREE_ARRAY(u_int, o->అంకె_log_verbose, o->log_verbose);
	విడుదల(o->log_verbose);
	విడుదల(o->ciphers);
	విడుదల(o->macs);
	విడుదల(o->hostkeyalgorithms);
	విడుదల(o->kex_algorithms);
	విడుదల(o->ca_sign_algorithms);
	విడుదల(o->hostname);
	విడుదల(o->host_కీలకం_alias);
	విడుదల(o->proxy_command);
	విడుదల(o->user);
	FREE_ARRAY(u_int, o->అంకె_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->అంకె_user_hostfiles, o->user_hostfiles);
	విడుదల(o->preferred_authentications);
	విడుదల(o->bind_చిరునామా);
	విడుదల(o->bind_interface);
	విడుదల(o->pkcs11_provider);
	విడుదల(o->sk_provider);
	కొరకు (i = 0; i < o->అంకె_తటస్థం_files; i++) {
		విడుదల(o->తటస్థం_files[i]);
		sshkey_free(o->తటస్థం_కీలకాలు[i]);
	}
	కొరకు (i = 0; i < o->అంకె_certificate_files; i++) {
		విడుదల(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	విడుదల(o->తటస్థం_agent);
	కొరకు (i = 0; i < o->అంకె_local_forwards; i++) {
		విడుదల(o->local_forwards[i].listen_host);
		విడుదల(o->local_forwards[i].listen_మార్గం);
		విడుదల(o->local_forwards[i].connect_host);
		విడుదల(o->local_forwards[i].connect_మార్గం);
	}
	విడుదల(o->local_forwards);
	కొరకు (i = 0; i < o->అంకె_remote_forwards; i++) {
		విడుదల(o->remote_forwards[i].listen_host);
		విడుదల(o->remote_forwards[i].listen_మార్గం);
		విడుదల(o->remote_forwards[i].connect_host);
		విడుదల(o->remote_forwards[i].connect_మార్గం);
	}
	విడుదల(o->remote_forwards);
	విడుదల(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->అంకె_send_env, o->send_env);
	విడుదల(o->send_env);
	FREE_ARRAY(u_int, o->అంకె_setenv, o->setenv);
	విడుదల(o->setenv);
	విడుదల(o->control_మార్గం);
	విడుదల(o->local_command);
	విడుదల(o->remote_command);
	FREE_ARRAY(పూర్ణాంకం, o->అంకె_canonical_domains, o->canonical_domains);
	కొరకు (i = 0; i < o->అంకె_permitted_cnames; i++) {
		విడుదల(o->permitted_cnames[i].ఆధారం_list);
		విడుదల(o->permitted_cnames[i].లక్ష్యం_list);
	}
	FREE_ARRAY(u_int, o->అంకె_revoked_host_కీలకాలు, o->revoked_host_కీలకాలు);
	విడుదల(o->revoked_host_కీలకాలు);
	విడుదల(o->hostbased_accepted_algos);
	విడుదల(o->pubkey_accepted_algos);
	విడుదల(o->jump_user);
	విడుదల(o->jump_host);
	విడుదల(o->jump_extra);
	విడుదల(o->ignored_unknown);
	explicit_bzero(o, పరిమాణం(*o));
#నిర్వచనం_రద్దు FREE_ARRAY
}

నిర్మాణం fwdarg {
	అక్షరం *arg;
	పూర్ణాంకం ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
స్థిర పూర్ణాంకం
parse_fwd_క్షేత్రం(అక్షరం **p, నిర్మాణం fwdarg *fwd)
{
	అక్షరం *ep, *cp = *p;
	పూర్ణాంకం ispath = 0;

	ఒకవేళ (*cp == '\0') {
		*p = ఖాళీ;
		తిరిగి -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	ఒకవేళ (*cp == '[') {
		/* find matching ']' */
		కొరకు (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			ఒకవేళ (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		ఒకవేళ (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			తిరిగి -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		ఒకవేళ (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		తిరిగి 0;
	}

	కొరకు (cp = *p; *cp != '\0'; cp++) {
		ఎంపిక (*cp) {
		స్థితి '\\':
			memmove(cp, cp + 1, అక్షరశ్రేణి_పొడవు(cp + 1) + 1);
			ఒకవేళ (*cp == '\0')
				తిరిగి -1;
			ఆపు;
		స్థితి '/':
			ispath = 1;
			ఆపు;
		స్థితి ':':
			*cp++ = '\0';
			వెళ్ళు పూర్తి;
		}
	}
పూర్తి:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	తిరిగి 0;
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
పూర్ణాంకం
parse_forward(నిర్మాణం Forward *fwd, స్థిరరాశి అక్షరం *fwdspec, పూర్ణాంకం dynamicfwd, పూర్ణాంకం remotefwd)
{
	నిర్మాణం fwdarg fwdargs[4];
	అక్షరం *p, *cp;
	పూర్ణాంకం i, err;

	memset(fwd, 0, పరిమాణం(*fwd));
	memset(fwdargs, 0, పరిమాణం(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	ఒకవేళ (p == ఖాళీ || err)
		తిరిగి 0;

	/* skip leading spaces */
	అయితే (ఖాళీనా((u_char)*cp))
		cp++;

	కొరకు (i = 0; i < 4; ++i) {
		ఒకవేళ (parse_fwd_క్షేత్రం(&cp, &fwdargs[i]) != 0)
			ఆపు;
	}

	/* Check for trailing garbage */
	ఒకవేళ (cp != ఖాళీ && *cp != '\0') {
		i = 0;	/* failure */
	}

	ఎంపిక (i) {
	స్థితి 1:
		ఒకవేళ (fwdargs[0].ispath) {
			fwd->listen_మార్గం = xstrdup(fwdargs[0].arg);
			fwd->listen_పోర్టు = పోర్టు_STREAMLOCAL;
		} లేకపోతే {
			fwd->listen_host = ఖాళీ;
			fwd->listen_పోర్టు = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		ఆపు;

	స్థితి 2:
		ఒకవేళ (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_మార్గం = xstrdup(fwdargs[0].arg);
			fwd->listen_పోర్టు = పోర్టు_STREAMLOCAL;
			fwd->connect_మార్గం = xstrdup(fwdargs[1].arg);
			fwd->connect_పోర్టు = పోర్టు_STREAMLOCAL;
		} లేకపోతే ఒకవేళ (fwdargs[1].ispath) {
			fwd->listen_host = ఖాళీ;
			fwd->listen_పోర్టు = a2port(fwdargs[0].arg);
			fwd->connect_మార్గం = xstrdup(fwdargs[1].arg);
			fwd->connect_పోర్టు = పోర్టు_STREAMLOCAL;
		} లేకపోతే {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_పోర్టు = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		ఆపు;

	స్థితి 3:
		ఒకవేళ (fwdargs[0].ispath) {
			fwd->listen_మార్గం = xstrdup(fwdargs[0].arg);
			fwd->listen_పోర్టు = పోర్టు_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_పోర్టు = a2port(fwdargs[2].arg);
		} లేకపోతే ఒకవేళ (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_పోర్టు = a2port(fwdargs[1].arg);
			fwd->connect_మార్గం = xstrdup(fwdargs[2].arg);
			fwd->connect_పోర్టు = పోర్టు_STREAMLOCAL;
		} లేకపోతే {
			fwd->listen_host = ఖాళీ;
			fwd->listen_పోర్టు = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_పోర్టు = a2port(fwdargs[2].arg);
		}
		ఆపు;

	స్థితి 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_పోర్టు = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_పోర్టు = a2port(fwdargs[3].arg);
		ఆపు;
	అప్రమేయ:
		i = 0; /* failure */
	}

	విడుదల(p);

	ఒకవేళ (dynamicfwd) {
		ఒకవేళ (!(i == 1 || i == 2))
			వెళ్ళు fail_free;
	} లేకపోతే {
		ఒకవేళ (!(i == 3 || i == 4)) {
			ఒకవేళ (fwd->connect_మార్గం == ఖాళీ &&
			    fwd->listen_మార్గం == ఖాళీ)
				వెళ్ళు fail_free;
		}
		ఒకవేళ (fwd->connect_పోర్టు <= 0 && fwd->connect_మార్గం == ఖాళీ)
			వెళ్ళు fail_free;
	}

	ఒకవేళ ((fwd->listen_పోర్టు < 0 && fwd->listen_మార్గం == ఖాళీ) ||
	    (!remotefwd && fwd->listen_పోర్టు == 0))
		వెళ్ళు fail_free;
	ఒకవేళ (fwd->connect_host != ఖాళీ &&
	    అక్షరశ్రేణి_పొడవు(fwd->connect_host) >= NI_MAXHOST)
		వెళ్ళు fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	ఒకవేళ (fwd->connect_మార్గం != ఖాళీ &&
	    అక్షరశ్రేణి_పొడవు(fwd->connect_మార్గం) >= మార్గం_MAX_SUN)
		వెళ్ళు fail_free;
	ఒకవేళ (fwd->listen_host != ఖాళీ &&
	    అక్షరశ్రేణి_పొడవు(fwd->listen_host) >= NI_MAXHOST)
		వెళ్ళు fail_free;
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ &&
	    అక్షరశ్రేణి_పొడవు(fwd->listen_మార్గం) >= మార్గం_MAX_SUN)
		వెళ్ళు fail_free;

	తిరిగి (i);

 fail_free:
	విడుదల(fwd->connect_host);
	fwd->connect_host = ఖాళీ;
	విడుదల(fwd->connect_మార్గం);
	fwd->connect_మార్గం = ఖాళీ;
	విడుదల(fwd->listen_host);
	fwd->listen_host = ఖాళీ;
	విడుదల(fwd->listen_మార్గం);
	fwd->listen_మార్గం = ఖాళీ;
	తిరిగి (0);
}

పూర్ణాంకం
ssh_valid_hostname(స్థిరరాశి అక్షరం *s)
{
	కొలత_t i;

	ఒకవేళ (*s == '-')
		తిరిగి 0;
	కొరకు (i = 0; s[i] != 0; i++) {
		ఒకవేళ (strchr("'`\"$\\;&<>|(){},", s[i]) != ఖాళీ ||
		    ఖాళీనా((u_char)s[i]) || iscntrl((u_char)s[i]))
			తిరిగి 0;
	}
	తిరిగి 1;
}

పూర్ణాంకం
ssh_valid_ruser(స్థిరరాశి అక్షరం *s)
{
	కొలత_t i;

	ఒకవేళ (*s == '-')
		తిరిగి 0;
	కొరకు (i = 0; s[i] != 0; i++) {
		ఒకవేళ (iscntrl((u_char)s[i]))
			తిరిగి 0;
		ఒకవేళ (strchr("'`\";&<>|(){}$\\", s[i]) != ఖాళీ)
			తిరిగి 0;
		/* Disallow '-' after whitespace */
		ఒకవేళ (ఖాళీనా((u_char)s[i]) && s[i + 1] == '-')
			తిరిగి 0;
	}
	తిరిగి 1;
}

పూర్ణాంకం
parse_jump(స్థిరరాశి అక్షరం *s, Options *o, పూర్ణాంకం strict, పూర్ణాంకం చురుకైన)
{
	అక్షరం *orig = ఖాళీ, *sdup = ఖాళీ, *cp;
	అక్షరం *tmp_user = ఖాళీ, *tmp_host = ఖాళీ, *host = ఖాళీ, *user = ఖాళీ;
	పూర్ణాంకం r, ret = -1, tmp_పోర్టు = -1, పోర్టు = -1, మొదటి = 1;

	ఒకవేళ (strcasecmp(s, "none") == 0) {
		ఒకవేళ (చురుకైన && o->jump_host == ఖాళీ) {
			o->jump_host = xstrdup("none");
			o->jump_పోర్టు = 0;
		}
		తిరిగి 0;
	}

	orig = xstrdup(s);
	ఒకవేళ ((cp = strchr(orig, '#')) != ఖాళీ)
		*cp = '\0';
	rtrim(orig);

	చురుకైన &= o->proxy_command == ఖాళీ && o->jump_host == ఖాళీ;
	sdup = xstrdup(orig);
	చేయి {
		/* Work backwards through string */
		ఒకవేళ ((cp = strrchr(sdup, ',')) == ఖాళీ)
			cp = sdup; /*చివరి*/
		లేకపోతే
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_పోర్టు);
		ఒకవేళ (r == -1 || (r == 1 && parse_user_host_పోర్టు(cp,
		    &tmp_user, &tmp_host, &tmp_పోర్టు) != 0))
			వెళ్ళు బహిర్గతం; /* error already logged */
		ఒకవేళ (strict) {
			ఒకవేళ (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (tmp_user != ఖాళీ && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				వెళ్ళు బహిర్గతం;
			}
		}
		ఒకవేళ (మొదటి) {
			user = tmp_user;
			host = tmp_host;
			పోర్టు = tmp_పోర్టు;
			tmp_user = tmp_host = ఖాళీ; /* transferred */
		}
		మొదటి = 0; /* only check syntax for subsequent hosts */
		విడుదల(tmp_user);
		విడుదల(tmp_host);
		tmp_user = tmp_host = ఖాళీ;
		tmp_పోర్టు = -1;
	} అయితే (cp != sdup);

	/* success */
	ఒకవేళ (చురుకైన) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_పోర్టు = పోర్టు;
		o->proxy_command = xstrdup("none");
		user = host = ఖాళీ; /* transferred */
		ఒకవేళ (orig != ఖాళీ && (cp = strrchr(orig, ',')) != ఖాళీ) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 బహిర్గతం:
	విడుదల(orig);
	విడుదల(sdup);
	విడుదల(tmp_user);
	విడుదల(tmp_host);
	విడుదల(user);
	విడుదల(host);
	తిరిగి ret;
}

పూర్ణాంకం
parse_ssh_uri(స్థిరరాశి అక్షరం *uri, అక్షరం **userp, అక్షరం **hostp, పూర్ణాంకం *portp)
{
	అక్షరం *user = ఖాళీ, *host = ఖాళీ, *మార్గం = ఖాళీ;
	పూర్ణాంకం r, పోర్టు;

	r = parse_uri("ssh", uri, &user, &host, &పోర్టు, &మార్గం);
	ఒకవేళ (r == 0 && మార్గం != ఖాళీ)
		r = -1;		/* path not allowed */
	ఒకవేళ (r == 0) {
		ఒకవేళ (userp != ఖాళీ) {
			*userp = user;
			user = ఖాళీ;
		}
		ఒకవేళ (hostp != ఖాళీ) {
			*hostp = host;
			host = ఖాళీ;
		}
		ఒకవేళ (portp != ఖాళీ)
			*portp = పోర్టు;
	}
	విడుదల(user);
	విడుదల(host);
	విడుదల(మార్గం);
	తిరిగి r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
స్థిర స్థిరరాశి అక్షరం *
fmt_multistate_int(పూర్ణాంకం val, స్థిరరాశి నిర్మాణం multistate *m)
{
	u_int i;

	కొరకు (i = 0; m[i].కీలకం != ఖాళీ; i++) {
		ఒకవేళ (m[i].విలువ == val)
			తిరిగి m[i].కీలకం;
	}
	తిరిగి "UNKNOWN";
}

స్థిర స్థిరరాశి అక్షరం *
fmt_intarg(OpCodes సంకేతం_2, పూర్ణాంకం val)
{
	ఒకవేళ (val == -1)
		తిరిగి "unset";
	ఎంపిక (సంకేతం_2) {
	స్థితి o_చిరునామా_Family:
		తిరిగి fmt_multistate_int(val, multistate_addressfamily);
	స్థితి oCompression:
		తిరిగి fmt_multistate_int(val, multistate_compression);
	స్థితి o_Verify_Host_కీలకం_DNS:
	స్థితి oUpdateHostkeys:
		తిరిగి fmt_multistate_int(val, multistate_yesnoask);
	స్థితి o_Strict_Host_కీలకం_Checking:
		తిరిగి fmt_multistate_int(val, multistate_strict_hostkey);
	స్థితి oControlMaster:
		తిరిగి fmt_multistate_int(val, multistate_controlmaster);
	స్థితి oTunnel:
		తిరిగి fmt_multistate_int(val, multistate_tunnel);
	స్థితి oRequestTTY:
		తిరిగి fmt_multistate_int(val, multistate_requesttty);
	స్థితి oSessionType:
		తిరిగి fmt_multistate_int(val, multistate_sessiontype);
	స్థితి oCanonicalizeHostname:
		తిరిగి fmt_multistate_int(val, multistate_canonicalizehostname);
	స్థితి o_కూడు_కీలకాలు_గమ్యం_Agent:
		తిరిగి fmt_multistate_int(val, multistate_yesnoaskconfirm);
	స్థితి oPubkeyAuthentication:
		తిరిగి fmt_multistate_int(val, multistate_pubkey_auth);
	స్థితి oTCPKeepAlive:
		తిరిగి fmt_multistate_int(val, multistate_keepalives);
	స్థితి oFingerprintHash:
		తిరిగి ssh_digest_alg_name(val);
	అప్రమేయ:
		ఎంపిక (val) {
		స్థితి 0:
			తిరిగి "no";
		స్థితి 1:
			తిరిగి "yes";
		అప్రమేయ:
			తిరిగి "UNKNOWN";
		}
	}
}

స్థిర స్థిరరాశి అక్షరం *
lookup_opcode_name(OpCodes సంకేతం_2)
{
	u_int i;

	కొరకు (i = 0; keywords[i].name != ఖాళీ; i++)
		ఒకవేళ (keywords[i].opcode == సంకేతం_2)
			తిరిగి(keywords[i].name);
	తిరిగి "UNKNOWN";
}

స్థిర శూన్య
dump_cfg_int(OpCodes సంకేతం_2, పూర్ణాంకం val)
{
	ఒకవేళ (సంకేతం_2 == oObscureKeystrokeTiming) {
		ఒకవేళ (val == 0) {
			రాయి("%s no\n", lookup_opcode_name(సంకేతం_2));
			తిరిగి;
		} లేకపోతే ఒకవేళ (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			రాయి("%s yes\n", lookup_opcode_name(సంకేతం_2));
			తిరిగి;
		}
		/* FALLTHROUGH */
	}
	రాయి("%s %d\n", lookup_opcode_name(సంకేతం_2), val);
}

స్థిర శూన్య
dump_cfg_fmtint(OpCodes సంకేతం_2, పూర్ణాంకం val)
{
	రాయి("%s %s\n", lookup_opcode_name(సంకేతం_2), fmt_intarg(సంకేతం_2, val));
}

స్థిర శూన్య
dump_cfg_string(OpCodes సంకేతం_2, స్థిరరాశి అక్షరం *val)
{
	ఒకవేళ (val == ఖాళీ)
		తిరిగి;
	రాయి("%s %s\n", lookup_opcode_name(సంకేతం_2), val);
}

స్థిర శూన్య
dump_cfg_strarray(OpCodes సంకేతం_2, u_int లెక్క, అక్షరం **vals)
{
	u_int i;

	కొరకు (i = 0; i < లెక్క; i++)
		రాయి("%s %s\n", lookup_opcode_name(సంకేతం_2), vals[i]);
}

స్థిర శూన్య
dump_cfg_strarray_oneline(OpCodes సంకేతం_2, u_int లెక్క, అక్షరం **vals)
{
	u_int i;

	రాయి("%s", lookup_opcode_name(సంకేతం_2));
	ఒకవేళ (లెక్క == 0)
		రాయి(" none");
	కొరకు (i = 0; i < లెక్క; i++)
		రాయి(" %s",  vals[i]);
	రాయి("\n");
}

స్థిర శూన్య
dump_cfg_forwards(OpCodes సంకేతం_2, u_int లెక్క, స్థిరరాశి నిర్మాణం Forward *fwds)
{
	స్థిరరాశి నిర్మాణం Forward *fwd;
	u_int i;

	/* oDynamicForward */
	కొరకు (i = 0; i < లెక్క; i++) {
		fwd = &fwds[i];
		ఒకవేళ (సంకేతం_2 == oDynamicForward && fwd->connect_host != ఖాళీ &&
		    strcmp(fwd->connect_host, "socks") != 0)
			కొనసాగు;
		ఒకవేళ (సంకేతం_2 == oLocalForward && fwd->connect_host != ఖాళీ &&
		    strcmp(fwd->connect_host, "socks") == 0)
			కొనసాగు;
		రాయి("%s", lookup_opcode_name(సంకేతం_2));
		ఒకవేళ (fwd->listen_పోర్టు == పోర్టు_STREAMLOCAL)
			రాయి(" %s", fwd->listen_మార్గం);
		లేకపోతే ఒకవేళ (fwd->listen_host == ఖాళీ)
			రాయి(" %d", fwd->listen_పోర్టు);
		లేకపోతే {
			రాయి(" [%s]:%d",
			    fwd->listen_host, fwd->listen_పోర్టు);
		}
		ఒకవేళ (సంకేతం_2 != oDynamicForward) {
			ఒకవేళ (fwd->connect_పోర్టు == పోర్టు_STREAMLOCAL)
				రాయి(" %s", fwd->connect_మార్గం);
			లేకపోతే ఒకవేళ (fwd->connect_host == ఖాళీ)
				రాయి(" %d", fwd->connect_పోర్టు);
			లేకపోతే {
				రాయి(" [%s]:%d",
				    fwd->connect_host, fwd->connect_పోర్టు);
			}
		}
		రాయి("\n");
	}
}

శూన్య
dump_client_config(Options *o, స్థిరరాశి అక్షరం *host)
{
	పూర్ణాంకం i, r;
	అక్షరం buf[8], *all_కీలకం;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_కీలకం = sshkey_alg_list(0, 0, 1, ',');
	ఒకవేళ ((r = kex_assemble_పేర్లు(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_కీలకం)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	విడుదల(all_కీలకం);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(o_పోర్టు, o->పోర్టు);

	/* Flag options */
	dump_cfg_fmtint(o_చిరునామా_Family, o->చిరునామా_family);
	dump_cfg_fmtint(o_Batch_బహుళకం, o->batch_బహుళకం);
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
#నిర్వచితమైతే GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#అయితే_ముగింపు /* GSSAPI */
	dump_cfg_fmtint(o_Hash_తెలిసిన_Hosts, o->hash_తెలిసిన_hosts);
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
	dump_cfg_fmtint(o_ప్రవాహం_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(o_Strict_Host_కీలకం_Checking, o->strict_host_కీలకం_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_కీలకం_DNS, o->verify_host_కీలకం_dns);
	dump_cfg_fmtint(o_Visual_Host_కీలకం, o->visual_host_కీలకం);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_సంఖ్య_యొక్క_Password_Prompts, o->సంఖ్య_యొక్క_password_prompts);
	dump_cfg_int(o_Server_Alive_లెక్క_Max, o->server_alive_లెక్క_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_కొలత);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(o_Bind_చిరునామా, o->bind_చిరునామా);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(o_Control_మార్గం, o->control_మార్గం);
	dump_cfg_string(o_Host_కీలకం_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_కీలకం_Alias, o->host_కీలకం_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(o_తటస్థం_Agent, o->తటస్థం_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#నిర్వచితమైతే ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#అయితే_ముగింపు
	dump_cfg_string(o_Security_కీలకం_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(o_తెలిసిన_Hosts_Command, o->తెలిసిన_hosts_command);
	dump_cfg_string(o_ట్యాగ్, o->ట్యాగ్);
	dump_cfg_string(o_సంస్కరణ_Addendum, o->సంస్కరణ_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->అంకె_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->అంకె_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->అంకె_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(o_తటస్థం_File, o->అంకె_తటస్థం_files, o->తటస్థం_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->అంకె_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->అంకె_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(o_Global_తెలిసిన_Hosts_File, o->అంకె_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(o_User_తెలిసిన_Hosts_File, o->అంకె_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_కీలకాలు, o->అంకె_revoked_host_కీలకాలు, o->revoked_host_కీలకాలు);
	dump_cfg_strarray(oSendEnv, o->అంకె_send_env, o->send_env);
	dump_cfg_strarray(o_సమితి_Env, o->అంకె_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->అంకె_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->అంకె_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	ఒకవేళ (o->అంకె_permitted_remote_opens == 0)
		రాయి("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	లేకపోతే
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->అంకె_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	ఒకవేళ (o->కూడు_కీలకాలు_గమ్యం_agent_lifespan <= 0)
		dump_cfg_fmtint(o_కూడు_కీలకాలు_గమ్యం_Agent, o->కూడు_కీలకాలు_గమ్యం_agent);
	లేకపోతే {
		రాయి("addkeystoagent%s %d\n",
		    o->కూడు_కీలకాలు_గమ్యం_agent == 3 ? " confirm" : "",
		    o->కూడు_కీలకాలు_గమ్యం_agent_lifespan);
	}

	/* oForwardAgent */
	ఒకవేళ (o->forward_agent_sock_మార్గం == ఖాళీ)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	లేకపోతే
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_మార్గం);

	/* oConnectTimeout */
	ఒకవేళ (o->connection_timeout == -1)
		రాయి("connecttimeout none\n");
	లేకపోతే
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	రాయి("tunneldevice");
	ఒకవేళ (o->tun_local == SSH_TUNID_ANY)
		రాయి(" any");
	లేకపోతే
		రాయి(" %d", o->tun_local);
	ఒకవేళ (o->tun_remote == SSH_TUNID_ANY)
		రాయి(":any");
	లేకపోతే
		రాయి(":%d", o->tun_remote);
	రాయి("\n");

	/* oCanonicalizePermittedCNAMEs */
	రాయి("canonicalizepermittedcnames");
	ఒకవేళ (o->అంకె_permitted_cnames == 0)
		రాయి(" none");
	కొరకు (i = 0; i < o->అంకె_permitted_cnames; i++) {
		రాయి(" %s:%s", o->permitted_cnames[i].ఆధారం_list,
		    o->permitted_cnames[i].లక్ష్యం_list);
	}
	రాయి("\n");

	/* oControlPersist */
	ఒకవేళ (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	లేకపోతే
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	ఒకవేళ (o->escape_char == SSH_ESCAPECHAR_NONE)
		రాయి("escapechar none\n");
	లేకపోతే {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		రాయి("escapechar %s\n", buf);
	}

	/* oIPQoS */
	రాయి("ipqos %s ", iptos2str(o->ip_qos_interactive));
	రాయి("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	రాయి("rekeylimit %llu %d\n",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)o->rekey_హద్దు, o->rekey_interval);

	/* oStreamLocalBindMask */
	రాయి("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_ముసుగు);

	/* oLogFacility */
	రాయి("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	ఒకవేళ (o->jump_host == ఖాళీ)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	లేకపోతే {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != ఖాళీ ||
		    strspn(o->jump_host, "1234567890.") == అక్షరశ్రేణి_పొడవు(o->jump_host);
		snprintf(buf, పరిమాణం(buf), "%d", o->jump_పోర్టు);
		రాయి("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == ఖాళీ ? "" : o->jump_extra,
		    o->jump_extra == ఖాళీ ? "" : ",",
		    /* optional user */
		    o->jump_user == ఖాళీ ? "" : o->jump_user,
		    o->jump_user == ఖాళీ ? "" : "@",
		    /* opening [ if hostname is numeric */
		    i ? "[" : "",
		    /* mandatory hostname */
		    o->jump_host,
		    /* closing ] if hostname is numeric */
		    i ? "]" : "",
		    /* optional port number */
		    o->jump_పోర్టు <= 0 ? "" : ":",
		    o->jump_పోర్టు <= 0 ? "" : buf);
	}
}
