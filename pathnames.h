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

#घोषणा ETCDIR				"/etc"

#अगर_अघोषित SSHDIR
#घोषणा SSHDIR				ETCDIR "/ssh"
#पूर्ण_अगर

#अगर_अघोषित _PATH_SSH_PIDDIR
#घोषणा _PATH_SSH_PIDDIR		"/var/run"
#पूर्ण_अगर

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#घोषणा _PATH_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#घोषणा _PATH_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#घोषणा _PATH_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#घोषणा _PATH_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#घोषणा PATH_HOST_ECDSA_कुंजी_FILE	SSHDIR "/ssh_host_ecdsa_key"
#घोषणा PATH_HOST_RSA_कुंजी_FILE		SSHDIR "/ssh_host_rsa_key"
#घोषणा PATH_HOST_ED25519_कुंजी_FILE	SSHDIR "/ssh_host_ed25519_key"
#घोषणा PATH_HOST_MLDSA44_ED25519_कुंजी_FILE SSHDIR "/ssh_host_mldsa44_ed25519_key"
#घोषणा _PATH_DH_MODULI			SSHDIR "/moduli"

#अगर_अघोषित _PATH_SSH_PROGRAM
#घोषणा _PATH_SSH_PROGRAM		"/usr/bin/ssh"
#पूर्ण_अगर

/* Binary paths for the sshd components */
#अगर_अघोषित _PATH_SSHD_SESSION
#घोषणा _PATH_SSHD_SESSION		"/usr/libexec/sshd-session"
#पूर्ण_अगर
#अगर_अघोषित _PATH_SSHD_AUTH
#घोषणा _PATH_SSHD_AUTH			"/usr/libexec/sshd-auth"
#पूर्ण_अगर

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#घोषणा _PATH_SSH_DAEMON_PID_FILE	_PATH_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#घोषणा _PATH_SSH_USER_DIR		".ssh"


/*
 * Directory spec for ssh-agent sockets and agent sockets forwarded by
 * sshd reside. This directory should not be world-readable.
 */
#घोषणा _PATH_SSH_AGENT_SOCKET_DIR	"user:" _PATH_SSH_USER_DIR "/agent"

/* Directory spec for ssh-agent sockets in /tmp */
#घोषणा _PATH_SSH_AGENT_SOCKET_TMPDIR	"shared:/tmp"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#घोषणा _PATH_SSH_USER_HOSTFILE		"~/" _PATH_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#घोषणा _PATH_SSH_USER_HOSTFILE2	"~/" _PATH_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#घोषणा _PATH_SSH_CLIENT_ID_ECDSA	_PATH_SSH_USER_DIR "/id_ecdsa"
#घोषणा _PATH_SSH_CLIENT_ID_RSA		_PATH_SSH_USER_DIR "/id_rsa"
#घोषणा _PATH_SSH_CLIENT_ID_ED25519	_PATH_SSH_USER_DIR "/id_ed25519"
#घोषणा _PATH_SSH_CLIENT_ID_ECDSA_SK	_PATH_SSH_USER_DIR "/id_ecdsa_sk"
#घोषणा _PATH_SSH_CLIENT_ID_ED25519_SK	_PATH_SSH_USER_DIR "/id_ed25519_sk"
#घोषणा _PATH_SSH_CLIENT_ID_MLDSA44_ED25519 _PATH_SSH_USER_DIR "/id_mldsa44_ed25519"

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#घोषणा _PATH_SSH_USER_CONFFILE		_PATH_SSH_USER_DIR "/config"

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#घोषणा PATH_SSH_USER_PERMITTED_कुंजियाँ	_PATH_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#घोषणा _PATH_SSH_USER_PERMITTED_KEYS2	_PATH_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#घोषणा _PATH_SSH_USER_RC		_PATH_SSH_USER_DIR "/rc"
#घोषणा _PATH_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#घोषणा _PATH_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#घोषणा _PATH_RHOSTS_EQUIV		"/etc/hosts.equiv"

/*
 * Default location of askpass
 */
#अगर_अघोषित _PATH_SSH_ASKPASS_DEFAULT
#घोषणा _PATH_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"
#पूर्ण_अगर

/* Location of ssh-keysign for hostbased authentication */
#अगर_अघोषित PATH_SSH_कुंजी_SIGN
#घोषणा PATH_SSH_कुंजी_SIGN		"/usr/libexec/ssh-keysign"
#पूर्ण_अगर

/* Location of ssh-pkcs11-helper to support keys in tokens */
#अगर_अघोषित _PATH_SSH_PKCS11_HELPER
#घोषणा _PATH_SSH_PKCS11_HELPER		"/usr/libexec/ssh-pkcs11-helper"
#पूर्ण_अगर

/* Location of ssh-sk-helper to support keys in security keys */
#अगर_अघोषित _PATH_SSH_SK_HELPER
#घोषणा _PATH_SSH_SK_HELPER		"/usr/libexec/ssh-sk-helper"
#पूर्ण_अगर

/* xauth for X11 forwarding */
#अगर_अघोषित _PATH_XAUTH
#घोषणा _PATH_XAUTH			"/usr/X11R6/bin/xauth"
#पूर्ण_अगर

/* UNIX domain socket for X11 server; displaynum will replace %u */
#अगर_अघोषित _PATH_UNIX_X
#घोषणा _PATH_UNIX_X "/tmp/.X11-unix/X%u"
#पूर्ण_अगर

/* for scp */
#अगर_अघोषित _PATH_CP
#घोषणा _PATH_CP			"cp"
#पूर्ण_अगर

/* for sftp */
#अगर_अघोषित _PATH_SFTP_SERVER
#घोषणा _PATH_SFTP_SERVER		"/usr/libexec/sftp-server"
#पूर्ण_अगर
#अगर_अघोषित _PATH_LS
#घोषणा _PATH_LS			"ls"
#पूर्ण_अगर

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#अगर_अघोषित _PATH_PRIVSEP_CHROOT_DIR
#घोषणा _PATH_PRIVSEP_CHROOT_DIR	"/var/empty"
#पूर्ण_अगर

/* for passwd change */
#अगर_अघोषित _PATH_PASSWD_PROG
#घोषणा _PATH_PASSWD_PROG		"/usr/bin/passwd"
#पूर्ण_अगर

/* Askpass program define */
#अगर_अघोषित ASKPASS_PROGRAM
#घोषणा ASKPASS_PROGRAM         "/usr/lib/ssh/ssh-askpass"
#पूर्ण_अगर /* ASKPASS_PROGRAM */
