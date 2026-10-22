/* $OpenBSD: pathnames.h,v 1.38 2026/09/16 00:25:50 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ETCDIR				"/etc"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SSHDIR
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHDIR				ETCDIR "/ssh"
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_SSH_PIDDIR
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_PIDDIR		"/var/run"
#ਜੇ_ਅੰਤ

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_HOST_ECDSA_ਕੁੰਜੀ_FILE	SSHDIR "/ssh_host_ecdsa_key"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_HOST_RSA_ਕੁੰਜੀ_FILE		SSHDIR "/ssh_host_rsa_key"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_HOST_ED25519_ਕੁੰਜੀ_FILE	SSHDIR "/ssh_host_ed25519_key"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_HOST_MLDSA44_ED25519_ਕੁੰਜੀ_FILE SSHDIR "/ssh_host_mldsa44_ed25519_key"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_DH_MODULI			SSHDIR "/moduli"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_SSH_ਪ੍ਰੋਗਰਾਮ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_ਪ੍ਰੋਗਰਾਮ		"/usr/bin/ssh"
#ਜੇ_ਅੰਤ

/* Binary paths for the sshd components */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_SSHD_SESSION
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSHD_SESSION		"/usr/libexec/sshd-session"
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_SSHD_AUTH
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSHD_AUTH			"/usr/libexec/sshd-auth"
#ਜੇ_ਅੰਤ

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_DAEMON_PID_FILE	ਰਸਤਾ_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_USER_DIR		".ssh"


/*
 * Directory spec for ssh-agent sockets and agent sockets forwarded by
 * sshd reside. This directory should not be world-readable.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_AGENT_SOCKET_DIR	"user:" ਰਸਤਾ_SSH_USER_DIR "/agent"

/* Directory spec for ssh-agent sockets in /tmp */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_AGENT_SOCKET_TMPDIR	"shared:/tmp"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_USER_HOSTFILE		"~/" ਰਸਤਾ_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_USER_HOSTFILE2	"~/" ਰਸਤਾ_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_CLIENT_ID_ECDSA	ਰਸਤਾ_SSH_USER_DIR "/id_ecdsa"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_CLIENT_ID_RSA		ਰਸਤਾ_SSH_USER_DIR "/id_rsa"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_CLIENT_ID_ED25519	ਰਸਤਾ_SSH_USER_DIR "/id_ed25519"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_CLIENT_ID_ECDSA_SK	ਰਸਤਾ_SSH_USER_DIR "/id_ecdsa_sk"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_CLIENT_ID_ED25519_SK	ਰਸਤਾ_SSH_USER_DIR "/id_ed25519_sk"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_CLIENT_ID_MLDSA44_ED25519 ਰਸਤਾ_SSH_USER_DIR "/id_mldsa44_ed25519"

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_USER_CONFFILE		ਰਸਤਾ_SSH_USER_DIR "/config"

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_USER_PERMITTED_ਕੁੰਜੀਆਂ	ਰਸਤਾ_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_USER_PERMITTED_KEYS2	ਰਸਤਾ_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_USER_RC		ਰਸਤਾ_SSH_USER_DIR "/rc"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_RHOSTS_EQUIV		"/etc/hosts.equiv"

/*
 * Default location of askpass
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_SSH_ASKPASS_DEFAULT
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"
#ਜੇ_ਅੰਤ

/* Location of ssh-keysign for hostbased authentication */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_SSH_ਕੁੰਜੀ_SIGN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_ਕੁੰਜੀ_SIGN		"/usr/libexec/ssh-keysign"
#ਜੇ_ਅੰਤ

/* Location of ssh-pkcs11-helper to support keys in tokens */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_SSH_PKCS11_HELPER
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_PKCS11_HELPER		"/usr/libexec/ssh-pkcs11-helper"
#ਜੇ_ਅੰਤ

/* Location of ssh-sk-helper to support keys in security keys */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_SSH_SK_HELPER
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SSH_SK_HELPER		"/usr/libexec/ssh-sk-helper"
#ਜੇ_ਅੰਤ

/* xauth for X11 forwarding */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_XAUTH
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_XAUTH			"/usr/X11R6/bin/xauth"
#ਜੇ_ਅੰਤ

/* UNIX domain socket for X11 server; displaynum will replace %u */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_UNIX_X
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_UNIX_X "/tmp/.X11-unix/X%u"
#ਜੇ_ਅੰਤ

/* for scp */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_CP
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_CP			"cp"
#ਜੇ_ਅੰਤ

/* for sftp */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_SFTP_SERVER
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_SFTP_SERVER		"/usr/libexec/sftp-server"
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_LS
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_LS			"ls"
#ਜੇ_ਅੰਤ

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_PRIVSEP_CHROOT_DIR
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_PRIVSEP_CHROOT_DIR	"/var/empty"
#ਜੇ_ਅੰਤ

/* for passwd change */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਰਸਤਾ_PASSWD_PROG
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਰਸਤਾ_PASSWD_PROG		"/usr/bin/passwd"
#ਜੇ_ਅੰਤ

/* Askpass program define */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ASKPASS_ਪ੍ਰੋਗਰਾਮ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASKPASS_ਪ੍ਰੋਗਰਾਮ         "/usr/lib/ssh/ssh-askpass"
#ਜੇ_ਅੰਤ /* ASKPASS_PROGRAM */
