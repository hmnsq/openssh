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

#నిర్వచితం_కాకపోతే READCONF_H
#నిర్వచించు READCONF_H

/* Data structure for representing option data. */

#నిర్వచించు SSH_MAX_HOSTS_FILES	32
#నిర్వచించు మార్గం_MAX_SUN		(పరిమాణం((నిర్మాణం sockaddr_un *)0)->sun_మార్గం)

నిర్మాణం allowed_cname {
	అక్షరం *ఆధారం_list;
	అక్షరం *లక్ష్యం_list;
};

రకనిర్వచనం నిర్మాణం {
	అక్షరం   *host_arg;	/* Host arg as specified on command line. */
	పూర్ణాంకం     forward_agent;	/* Forward authentication agent. */
	అక్షరం   *forward_agent_sock_మార్గం; /* Optional path of the agent. */
	పూర్ణాంకం     forward_x11;	/* Forward X11 display. */
	పూర్ణాంకం     forward_x11_timeout;	/* Expiration for Cookies */
	పూర్ణాంకం     forward_x11_trusted;	/* Trust Forward X11 display. */
	పూర్ణాంకం     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	అక్షరం   *xauth_location;	/* Location for xauth program */
	నిర్మాణం ForwardOptions fwd_opts;	/* forwarding options */
	పూర్ణాంకం     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	పూర్ణాంకం     hostbased_authentication;	/* ssh2's rhosts_rsa */
	పూర్ణాంకం     gss_authentication;	/* Try GSS authentication */
	పూర్ణాంకం     gss_deleg_creds;	/* Delegate GSS credentials */
	పూర్ణాంకం     password_authentication;	/* Try password
						 * authentication. */
	పూర్ణాంకం     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	అక్షరం	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	పూర్ణాంకం     batch_బహుళకం;	/* Batch mode: do not ask for passwords. */
	పూర్ణాంకం     check_host_ip;	/* Also keep track of keys for IP address */
	పూర్ణాంకం     strict_host_కీలకం_checking;	/* Strict host key checking. */
	పూర్ణాంకం     compression;	/* Compress packets in both directions. */
	పూర్ణాంకం     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	పూర్ణాంకం	ip_qos_interactive;	/* DSCP value for interactive */
	పూర్ణాంకం	ip_qos_bulk;		/* DSCP value for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */
	u_int	అంకె_log_verbose;	/* Verbose log overrides */
	అక్షరం   **log_verbose;
	పూర్ణాంకం     పోర్టు;		/* Port to connect. */
	పూర్ణాంకం     చిరునామా_family;
	పూర్ణాంకం     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	పూర్ణాంకం     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	పూర్ణాంకం     సంఖ్య_యొక్క_password_prompts;	/* Max number of password
						 * prompts. */
	అక్షరం   *ciphers;	/* SSH2 ciphers in order of preference. */
	అక్షరం   *macs;		/* SSH2 macs in order of preference. */
	అక్షరం   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	అక్షరం   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	పూర్ణాంకం	kex_algorithms_సమితి; /* KexAlgorithms was set by the user */
	అక్షరం   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	అక్షరం   *hostname;	/* Real host to connect. */
	అక్షరం   *ట్యాగ్;		/* Configuration tag name. */
	అక్షరం   *host_కీలకం_alias;	/* hostname alias for .ssh/known_hosts */
	అక్షరం   *proxy_command;	/* Proxy command for connecting the host. */
	అక్షరం   *user;		/* User to log in as. */
	పూర్ణాంకం     escape_char;	/* Escape character; -2 = none */

	u_int	అంకె_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	అక్షరం   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	అంకె_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	అక్షరం   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	అక్షరం   *preferred_authentications;
	అక్షరం   *bind_చిరునామా;	/* local socket address for connection to sshd */
	అక్షరం   *bind_interface;	/* local interface for bind address */
	అక్షరం   *pkcs11_provider; /* PKCS#11 provider */
	అక్షరం   *sk_provider; /* Security key provider */
	పూర్ణాంకం	verify_host_కీలకం_dns;	/* Verify host key using DNS */

	పూర్ణాంకం     అంకె_తటస్థం_files;	/* Number of files for identities. */
	అక్షరం   *తటస్థం_files[SSH_MAX_తటస్థం_FILES];
	పూర్ణాంకం    తటస్థం_file_userprovided[SSH_MAX_తటస్థం_FILES];
	నిర్మాణం sshkey *తటస్థం_కీలకాలు[SSH_MAX_తటస్థం_FILES];

	పూర్ణాంకం	అంకె_certificate_files; /* Number of extra certificates for ssh. */
	అక్షరం	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	పూర్ణాంకం	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	నిర్మాణం sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	పూర్ణాంకం	కూడు_కీలకాలు_గమ్యం_agent;
	పూర్ణాంకం	కూడు_కీలకాలు_గమ్యం_agent_lifespan;
	అక్షరం   *తటస్థం_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	పూర్ణాంకం     అంకె_local_forwards;
	నిర్మాణం Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	పూర్ణాంకం     అంకె_remote_forwards;
	నిర్మాణం Forward *remote_forwards;
	పూర్ణాంకం	clear_forwardings;

	/* Restrict remote dynamic forwarding */
	అక్షరం  **permitted_remote_opens;
	u_int	అంకె_permitted_remote_opens;

	/* stdio forwarding (-W) host and port */
	అక్షరం   *stdio_forward_host;
	పూర్ణాంకం	stdio_forward_పోర్టు;

	పూర్ణాంకం	enable_ssh_keysign;
	int64_t rekey_హద్దు;
	పూర్ణాంకం	rekey_interval;
	పూర్ణాంకం	no_host_authentication_for_localhost;
	పూర్ణాంకం	identities_only;
	పూర్ణాంకం	server_alive_interval;
	పూర్ణాంకం	server_alive_లెక్క_max;

	u_int	అంకె_send_env;
	అక్షరం	**send_env;
	u_int	అంకె_setenv;
	అక్షరం	**setenv;

	అక్షరం	*control_మార్గం;
	పూర్ణాంకం	control_master;
	పూర్ణాంకం     control_persist; /* ControlPersist flag */
	పూర్ణాంకం     control_persist_timeout; /* ControlPersist timeout (seconds) */

	పూర్ణాంకం	hash_తెలిసిన_hosts;

	పూర్ణాంకం	tun_open;	/* tun(4) */
	పూర్ణాంకం     tun_local;	/* force tun device (optional) */
	పూర్ణాంకం     tun_remote;	/* force tun device (optional) */

	అక్షరం	*local_command;
	పూర్ణాంకం	permit_local_command;
	అక్షరం	*remote_command;
	పూర్ణాంకం	visual_host_కీలకం;

	పూర్ణాంకం	request_tty;
	పూర్ణాంకం	session_type;
	పూర్ణాంకం	stdin_null;
	పూర్ణాంకం	fork_after_authentication;

	పూర్ణాంకం	proxy_use_fdpass;

	పూర్ణాంకం	అంకె_canonical_domains;
	అక్షరం	**canonical_domains;
	పూర్ణాంకం	canonicalize_hostname;
	పూర్ణాంకం	canonicalize_max_dots;
	పూర్ణాంకం	canonicalize_fallback_local;
	పూర్ణాంకం	అంకె_permitted_cnames;
	నిర్మాణం allowed_cname *permitted_cnames;

	u_int	అంకె_revoked_host_కీలకాలు;
	అక్షరం	**revoked_host_కీలకాలు;

	పూర్ణాంకం	 fingerprint_hash;

	పూర్ణాంకం	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	అక్షరం   *hostbased_accepted_algos;
	అక్షరం   *pubkey_accepted_algos;

	అక్షరం   *jump_user;
	అక్షరం   *jump_host;
	పూర్ణాంకం	jump_పోర్టు;
	అక్షరం   *jump_extra;

	అక్షరం   *తెలిసిన_hosts_command;

	పూర్ణాంకం	required_rsa_కొలత;	/* minimum size of RSA keys */
	పూర్ణాంకం	enable_escape_commandline;	/* ~C commandline */
	పూర్ణాంకం	obscure_keystroke_timing_interval;
	పూర్ణాంకం	warn_weak_crypto;

	అక్షరం	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	అంకె_channel_timeouts;

	అక్షరం	*సంస్కరణ_addendum;

	అక్షరం	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
}       Options;

#నిర్వచించు SSH_PUBKEY_AUTH_NO	0x00
#నిర్వచించు SSH_PUBKEY_AUTH_UNBOUND	0x01
#నిర్వచించు SSH_PUBKEY_AUTH_HBOUND	0x02
#నిర్వచించు SSH_PUBKEY_AUTH_ALL	0x03

#నిర్వచించు SSH_CANONICALISE_NO	0
#నిర్వచించు SSH_CANONICALISE_YES	1
#నిర్వచించు SSH_CANONICALISE_ALWAYS	2

#నిర్వచించు SSHCTL_MASTER_NO	0
#నిర్వచించు SSHCTL_MASTER_YES	1
#నిర్వచించు SSHCTL_MASTER_AUTO	2
#నిర్వచించు SSHCTL_MASTER_ASK	3
#నిర్వచించు SSHCTL_MASTER_AUTO_ASK	4

#నిర్వచించు REQUEST_TTY_AUTO	0
#నిర్వచించు REQUEST_TTY_NO		1
#నిర్వచించు REQUEST_TTY_YES		2
#నిర్వచించు REQUEST_TTY_FORCE	3

#నిర్వచించు SESSION_TYPE_NONE	0
#నిర్వచించు SESSION_TYPE_SUBSYSTEM	1
#నిర్వచించు SESSION_TYPE_DEFAULT	2

#నిర్వచించు SSHCONF_CHECKPERM	1  /* check permissions on config file */
#నిర్వచించు SSHCONF_USERCONF	2  /* user provided config file not system */
#నిర్వచించు SSHCONF_FINAL		4  /* Final pass over config, after canon. */
#నిర్వచించు SSHCONF_NEVERMATCH	8  /* Match/Host never matches; internal only */

#నిర్వచించు SSH_UPDATE_HOSTKEYS_NO	0
#నిర్వచించు SSH_UPDATE_HOSTKEYS_YES	1
#నిర్వచించు SSH_UPDATE_HOSTKEYS_ASK	2

#నిర్వచించు SSH_STRICT_HOSTKEY_OFF	0
#నిర్వచించు SSH_STRICT_HOSTKEY_NEW	1
#నిర్వచించు SSH_STRICT_HOSTKEY_YES	2
#నిర్వచించు SSH_STRICT_HOSTKEY_ASK	3

/* ObscureKeystrokes parameters */
#నిర్వచించు SSH_KEYSTROKE_DEFAULT_INTERVAL_MS	20
#నిర్వచించు SSH_KEYSTROKE_CHAFF_MIN_MS		1024
#నిర్వచించు SSH_KEYSTROKE_CHAFF_RNG_MS		2048

#నిర్వచించు SSH_KEEPALIVES_OFF		0
#నిర్వచించు SSH_KEEPALIVES_TRANSPORT	1
#నిర్వచించు SSH_KEEPALIVES_ALL		2

స్థిరరాశి అక్షరం *kex_default_pk_alg(శూన్య);
అక్షరం	*ssh_connection_hash(స్థిరరాశి అక్షరం *thishost, స్థిరరాశి అక్షరం *host,
    స్థిరరాశి అక్షరం *portstr, స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *jump_host);
శూన్య     initialize_options(Options *);
పూర్ణాంకం      fill_default_options(Options *);
శూన్య	 fill_default_options_for_canonicalization(Options *);
శూన్య	 free_options(Options *o);
పూర్ణాంకం	 process_config_పంక్తి(Options *, నిర్మాణం passwd *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం *, పూర్ణాంకం);
పూర్ణాంకం	 read_config_file(స్థిరరాశి అక్షరం *, నిర్మాణం passwd *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, Options *, పూర్ణాంకం, పూర్ణాంకం *);
పూర్ణాంకం	 parse_forward(నిర్మాణం Forward *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం	 ssh_valid_hostname(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 ssh_valid_ruser(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 parse_jump(స్థిరరాశి అక్షరం *, Options *, పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం	 parse_ssh_uri(స్థిరరాశి అక్షరం *, అక్షరం **, అక్షరం **, పూర్ణాంకం *);
పూర్ణాంకం	 default_ssh_పోర్టు(శూన్య);
పూర్ణాంకం	 option_clear_or_none(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 config_has_permitted_cnames(Options *);
శూన్య	 dump_client_config(Options *o, స్థిరరాశి అక్షరం *host);

శూన్య	 కూడు_local_forward(Options *, స్థిరరాశి నిర్మాణం Forward *);
శూన్య	 కూడు_remote_forward(Options *, స్థిరరాశి నిర్మాణం Forward *);
శూన్య	 కూడు_తటస్థం_file(Options *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
శూన్య	 కూడు_certificate_file(Options *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);

#అయితే_ముగింపు				/* READCONF_H */
