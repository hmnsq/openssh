/* $OpenBSD: readconf.h,v 1.164 2026/09/16 00:13:58 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for reading the configuration file.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#اگر_غیر_تعریف_شدہ READCONF_H
#تعریف_کرو READCONF_H

/* Data structure for representing option data. */

#تعریف_کرو SSH_MAX_HOSTS_FILES	32
#تعریف_کرو راستہ_MAX_SUN		(حجم((ساخت sockaddr_un *)0)->sun_راستہ)

ساخت allowed_cname {
	حرف *ماخذ_list;
	حرف *ہدف_list;
};

قسمتعریف ساخت {
	حرف   *host_arg;	/* Host arg as specified on command line. */
	صحیح     forward_agent;	/* Forward authentication agent. */
	حرف   *forward_agent_sock_راستہ; /* Optional path of the agent. */
	صحیح     forward_x11;	/* Forward X11 display. */
	صحیح     forward_x11_timeout;	/* Expiration for Cookies */
	صحیح     forward_x11_trusted;	/* Trust Forward X11 display. */
	صحیح     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	حرف   *xauth_location;	/* Location for xauth program */
	ساخت ForwardOptions fwd_opts;	/* forwarding options */
	صحیح     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	صحیح     hostbased_authentication;	/* ssh2's rhosts_rsa */
	صحیح     gss_authentication;	/* Try GSS authentication */
	صحیح     gss_deleg_creds;	/* Delegate GSS credentials */
	صحیح     password_authentication;	/* Try password
						 * authentication. */
	صحیح     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	حرف	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	صحیح     batch_منوال;	/* Batch mode: do not ask for passwords. */
	صحیح     check_host_ip;	/* Also keep track of keys for IP address */
	صحیح     strict_host_کلید_checking;	/* Strict host key checking. */
	صحیح     compression;	/* Compress packets in both directions. */
	صحیح     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	صحیح	ip_qos_interactive;	/* DSCP value for interactive */
	صحیح	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	عدد_log_verbose;	/* Verbose log overrides */
	حرف   **log_verbose;
	صحیح     پورٹ;		/* Port to connect. */
	صحیح     پتہ_family;
	صحیح     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	صحیح     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	صحیح     نمبر_کا_password_prompts;	/* Max number of password
						 * prompts. */
	حرف   *ciphers;	/* SSH2 ciphers in order of preference. */
	حرف   *macs;		/* SSH2 macs in order of preference. */
	حرف   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	حرف   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	صحیح	kex_algorithms_سیٹ; /* KexAlgorithms was set by the user */
	حرف   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	حرف   *hostname;	/* Real host to connect. */
	حرف   *لیبل;		/* Configuration tag name. */
	حرف   *host_کلید_alias;	/* hostname alias for .ssh/known_hosts */
	حرف   *proxy_command;	/* Proxy command for connecting the host. */
	حرف   *user;		/* User to log in as. */
	صحیح     escape_char;	/* Escape character; -2 = none */

	u_int	عدد_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	حرف   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	عدد_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	حرف   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	حرف   *preferred_authentications;
	حرف   *bind_پتہ;	/* local socket address for connection to sshd */
	حرف   *bind_interface;	/* local interface for bind address */
	حرف   *pkcs11_provider; /* PKCS#11 provider */
	حرف   *sk_provider; /* Security key provider */
	صحیح	verify_host_کلید_dns;	/* Verify host key using DNS */

	صحیح     عدد_شناختی_عنصر_files;	/* Number of files for identities. */
	حرف   *شناختی_عنصر_files[SSH_MAX_شناختی_عنصر_FILES];
	صحیح    شناختی_عنصر_file_userprovided[SSH_MAX_شناختی_عنصر_FILES];
	ساخت sshkey *شناختی_عنصر_کلیدیں[SSH_MAX_شناختی_عنصر_FILES];

	صحیح	عدد_certificate_files; /* Number of extra certificates for ssh. */
	حرف	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	صحیح	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	ساخت sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	صحیح	جوڑو_کلیدیں_مقصد_agent;
	صحیح	جوڑو_کلیدیں_مقصد_agent_lifespan;
	حرف   *شناختی_عنصر_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	صحیح     عدد_local_forwards;
	ساخت Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	صحیح     عدد_remote_forwards;
	ساخت Forward *remote_forwards;
	صحیح	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	حرف  **permitted_remote_opens;
	u_int	عدد_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	حرف   *stdio_forward_host;
	صحیح	stdio_forward_پورٹ;

	صحیح	enable_ssh_keysign;
	int64_t rekey_حد_بندی;
	صحیح	rekey_interval;
	صحیح	no_host_authentication_for_localhost;
	صحیح	identities_only;
	صحیح	server_alive_interval;
	صحیح	server_alive_گنتی_max;

	u_int	عدد_send_env;
	حرف	**send_env;
	u_int	عدد_setenv;
	حرف	**setenv;

	حرف	*control_راستہ;
	صحیح	control_master;
	صحیح     control_persist; /* ControlPersist flag */
	صحیح     control_persist_timeout; /* ControlPersist timeout (seconds) */

	صحیح	hash_معلوم_hosts;

	صحیح	tun_open;	/* tun(4) */
	صحیح     tun_local;	/* force tun device (optional) */
	صحیح     tun_remote;	/* force tun device (optional) */

	حرف	*local_command;
	صحیح	permit_local_command;
	حرف	*remote_command;
	صحیح	visual_host_کلید;

	صحیح	request_tty;
	صحیح	session_type;
	صحیح	stdin_null;
	صحیح	fork_after_authentication;

	صحیح	proxy_use_fdpass;

	صحیح	عدد_canonical_domains;
	حرف	**canonical_domains;
	صحیح	canonicalize_hostname;
	صحیح	canonicalize_max_dots;
	صحیح	canonicalize_fallback_local;
	صحیح	عدد_permitted_cnames;
	ساخت allowed_cname *permitted_cnames;

	u_int	عدد_revoked_host_کلیدیں;
	حرف	**revoked_host_کلیدیں;

	صحیح	 fingerprint_hash;

	صحیح	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	حرف   *hostbased_accepted_algos;
	حرف   *pubkey_accepted_algos;

	حرف   *jump_user;
	حرف   *jump_host;
	صحیح	jump_پورٹ;
	حرف   *jump_extra;

	حرف   *معلوم_hosts_command;

	صحیح	required_rsa_سائز;	/* minimum size of RSA keys */
	صحیح	enable_escape_commandline;	/* ~C commandline */
	صحیح	obscure_keystroke_timing_interval;
	صحیح	warn_weak_crypto;

	حرف	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	عدد_channel_timeouts;

	حرف	*نسخہ_addendum;

	حرف	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
}       Options;

#تعریف_کرو SSH_PUBKEY_AUTH_NO	0x00
#تعریف_کرو SSH_PUBKEY_AUTH_UNBOUND	0x01
#تعریف_کرو SSH_PUBKEY_AUTH_HBOUND	0x02
#تعریف_کرو SSH_PUBKEY_AUTH_ALL	0x03

#تعریف_کرو SSH_CANONICALISE_NO	0
#تعریف_کرو SSH_CANONICALISE_YES	1
#تعریف_کرو SSH_CANONICALISE_ALWAYS	2

#تعریف_کرو SSHCTL_MASTER_NO	0
#تعریف_کرو SSHCTL_MASTER_YES	1
#تعریف_کرو SSHCTL_MASTER_AUTO	2
#تعریف_کرو SSHCTL_MASTER_ASK	3
#تعریف_کرو SSHCTL_MASTER_AUTO_ASK	4

#تعریف_کرو REQUEST_TTY_AUTO	0
#تعریف_کرو REQUEST_TTY_NO		1
#تعریف_کرو REQUEST_TTY_YES		2
#تعریف_کرو REQUEST_TTY_FORCE	3

#تعریف_کرو SESSION_TYPE_NONE	0
#تعریف_کرو SESSION_TYPE_SUBSYSTEM	1
#تعریف_کرو SESSION_TYPE_DEFAULT	2

#تعریف_کرو SSHCONF_CHECKPERM	1  /* check permissions on config file */
#تعریف_کرو SSHCONF_USERCONF	2  /* user provided config file not system */
#تعریف_کرو SSHCONF_FINAL		4  /* Final pass over config, after canon. */
#تعریف_کرو SSHCONF_NEVERMATCH	8  /* Match/Host never matches; internal only */

#تعریف_کرو SSH_UPDATE_HOSTKEYS_NO	0
#تعریف_کرو SSH_UPDATE_HOSTKEYS_YES	1
#تعریف_کرو SSH_UPDATE_HOSTKEYS_ASK	2

#تعریف_کرو SSH_STRICT_HOSTKEY_OFF	0
#تعریف_کرو SSH_STRICT_HOSTKEY_NEW	1
#تعریف_کرو SSH_STRICT_HOSTKEY_YES	2
#تعریف_کرو SSH_STRICT_HOSTKEY_ASK	3

/* ObscureKeystrokes parameters */
#تعریف_کرو SSH_KEYSTROKE_DEFAULT_INTERVAL_MS	20
#تعریف_کرو SSH_KEYSTROKE_CHAFF_MIN_MS		1024
#تعریف_کرو SSH_KEYSTROKE_CHAFF_RNG_MS		2048

#تعریف_کرو SSH_KEEPALIVES_OFF		0
#تعریف_کرو SSH_KEEPALIVES_TRANSPORT	1
#تعریف_کرو SSH_KEEPALIVES_ALL		2

ثابت حرف *kex_default_pk_alg(خالی);
حرف	*ssh_connection_hash(ثابت حرف *thishost, ثابت حرف *host,
    ثابت حرف *portstr, ثابت حرف *user, ثابت حرف *jump_host);
خالی     initialize_options(Options *);
صحیح      fill_default_options(Options *);
خالی	 fill_default_options_for_canonicalization(Options *);
خالی	 free_options(Options *o);
صحیح	 process_config_سطر(Options *, ساخت passwd *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, حرف *, ثابت حرف *, صحیح, صحیح *, صحیح);
صحیح	 read_config_file(ثابت حرف *, ساخت passwd *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, Options *, صحیح, صحیح *);
صحیح	 parse_forward(ساخت Forward *, ثابت حرف *, صحیح, صحیح);
صحیح	 ssh_valid_hostname(ثابت حرف *);
صحیح	 ssh_valid_ruser(ثابت حرف *);
صحیح	 parse_jump(ثابت حرف *, Options *, صحیح, صحیح);
صحیح	 parse_ssh_uri(ثابت حرف *, حرف **, حرف **, صحیح *);
صحیح	 default_ssh_پورٹ(خالی);
صحیح	 option_clear_or_none(ثابت حرف *);
صحیح	 config_has_permitted_cnames(Options *);
خالی	 dump_client_config(Options *o, ثابت حرف *host);

خالی	 جوڑو_local_forward(Options *, ثابت ساخت Forward *);
خالی	 جوڑو_remote_forward(Options *, ثابت ساخت Forward *);
خالی	 جوڑو_شناختی_عنصر_file(Options *, ثابت حرف *, ثابت حرف *, صحیح);
خالی	 جوڑو_certificate_file(Options *, ثابت حرف *, صحیح);

#اگر_ختم				/* READCONF_H */
