/* $OpenBSD: packet.h,v 1.108 2026/09/22 00:24:47 dtucker Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Interface for the packet protocol functions.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef PACKET_H
#define PACKET_H

#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <termios.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/ecdsa.h>
#അന്തര്ഭാവ <openssl/evp.h>
#അല്ലെങ്കിൽ /* OPENSSL */
#define BIGNUM		ശൂന്യം
#define EC_GROUP	ശൂന്യം
#define EC_POINT	ശൂന്യം
#define EVP_PKEY	ശൂന്യം
#endif /* WITH_OPENSSL */

ഘടന kex;
ഘടന sshkey;
ഘടന sshbuf;
ഘടന session_state;	/* private session data */

#അന്തര്ഭാവ "dispatch.h"	/* typedef, DISPATCH_MAX */

ഘടന താക്കോൽ_entry {
	TAILQ_ENTRY(താക്കോൽ_entry) next;
	ഘടന sshkey *താക്കോൽ;
};

ഘടന ssh {
	/* Session state */
	ഘടന session_state *state;

	/* Key exchange */
	ഘടന kex *kex;

	/* cached local and remote ip addresses and ports */
	അക്ഷരം *remote_ipaddr;
	പൂർണ്ണസംഖ്യ remote_port;
	അക്ഷരം *local_ipaddr;
	പൂർണ്ണസംഖ്യ local_port;
	അക്ഷരം *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	അക്ഷരം *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	പൂർണ്ണസംഖ്യ dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	അക്ഷരം *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, താക്കോൽ_entry) private_താക്കോലുകൾ;
	TAILQ_HEAD(, താക്കോൽ_entry) public_താക്കോലുകൾ;

	/* Client/Server authentication context */
	ശൂന്യം *authctxt;

	/* Channels context */
	ഘടന ssh_channels *chanctxt;

	/* APP data */
	ശൂന്യം *app_data;
};

തരനിർവചനം പൂർണ്ണസംഖ്യ (ssh_packet_hook_fn)(ഘടന ssh *, ഘടന sshbuf *,
    u_char *, ശൂന്യം *);

ഘടന ssh *ssh_alloc_session_state(ശൂന്യം);
ഘടന ssh *ssh_packet_set_connection(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
ശൂന്യം     ssh_packet_set_timeout(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 ssh_packet_stop_discard(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_packet_connection_af(ഘടന ssh *);
ശൂന്യം     ssh_packet_set_nonblocking(ഘടന ssh *);
പൂർണ്ണസംഖ്യ      ssh_packet_get_connection_in(ഘടന ssh *);
പൂർണ്ണസംഖ്യ      ssh_packet_get_connection_out(ഘടന ssh *);
ശൂന്യം	 ssh_packet_free(ഘടന ssh *);
ശൂന്യം     ssh_packet_close(ഘടന ssh *);
ശൂന്യം	 ssh_packet_set_നിവേശം_hook(ഘടന ssh *, ssh_packet_hook_fn *, ശൂന്യം *);
ശൂന്യം	 ssh_packet_clear_താക്കോലുകൾ(ഘടന ssh *);
ശൂന്യം	 ssh_clear_newkeys(ഘടന ssh *, പൂർണ്ണസംഖ്യ);

പൂർണ്ണസംഖ്യ	 ssh_packet_is_rekeying(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_packet_check_rekey(ഘടന ssh *);
ശൂന്യം     ssh_packet_set_protocol_flags(ഘടന ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(ഘടന ssh *);
ശൂന്യം	 ssh_packet_set_interactive(ഘടന ssh *, പൂർണ്ണസംഖ്യ);
ശൂന്യം	 ssh_packet_set_qos(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
ശൂന്യം     ssh_packet_set_server(ഘടന ssh *);
ശൂന്യം     ssh_packet_set_authenticated(ഘടന ssh *);
ശൂന്യം     ssh_packet_set_mux(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_packet_get_mux(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_packet_set_log_preamble(ഘടന ssh *, സ്ഥിരം അക്ഷരം *, ...)
    __attribute__((format(printf, 2, 3)));

പൂർണ്ണസംഖ്യ	 ssh_packet_log_type(u_char);

പൂർണ്ണസംഖ്യ	 ssh_packet_send2_wrapped(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_packet_send2(ഘടന ssh *);

പൂർണ്ണസംഖ്യ      ssh_packet_read(ഘടന ssh *);
പൂർണ്ണസംഖ്യ ssh_packet_read_poll2(ഘടന ssh *, u_char *, uint32_t *seqnr_p);
പൂർണ്ണസംഖ്യ	 ssh_packet_process_incoming(ഘടന ssh *, സ്ഥിരം അക്ഷരം *buf, u_int len);
പൂർണ്ണസംഖ്യ	 ssh_packet_process_read(ഘടന ssh *, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ      ssh_packet_read_seqnr(ഘടന ssh *, u_char *, uint32_t *seqnr_p);
പൂർണ്ണസംഖ്യ      ssh_packet_read_poll_seqnr(ഘടന ssh *, u_char *, uint32_t *seqnr_p);

ശൂന്യം     ssh_packet_disconnect(ഘടന ssh *, സ്ഥിരം അക്ഷരം *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
ശൂന്യം     ssh_packet_send_debug(ഘടന ssh *, സ്ഥിരം അക്ഷരം *fmt, ...) __attribute__((format(printf, 2, 3)));

പൂർണ്ണസംഖ്യ	 ssh_set_newkeys(ഘടന ssh *, പൂർണ്ണസംഖ്യ mode);
ശൂന്യം	 ssh_packet_get_bytes(ഘടന ssh *, uint64_t *, uint64_t *);

പൂർണ്ണസംഖ്യ	 ssh_packet_write_poll(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_packet_write_wait(ഘടന ssh *);
പൂർണ്ണസംഖ്യ      ssh_packet_have_data_to_write(ഘടന ssh *);
പൂർണ്ണസംഖ്യ      ssh_packet_not_very_much_data_to_write(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_packet_interactive_data_to_write(ഘടന ssh *);

പൂർണ്ണസംഖ്യ	 ssh_packet_connection_is_on_socket(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_packet_remaining(ഘടന ssh *);

ശൂന്യം	 ssh_tty_make_modes(ഘടന ssh *, പൂർണ്ണസംഖ്യ, ഘടന termios *);
ശൂന്യം	 ssh_tty_parse_modes(ഘടന ssh *, പൂർണ്ണസംഖ്യ);

ശൂന്യം	 ssh_packet_set_alive_timeouts(ഘടന ssh *, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 ssh_packet_inc_alive_timeouts(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_packet_set_maxsize(ഘടന ssh *, u_int);
u_int	 ssh_packet_get_maxsize(ഘടന ssh *);

പൂർണ്ണസംഖ്യ	 ssh_packet_get_state(ഘടന ssh *, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ	 ssh_packet_set_state(ഘടന ssh *, ഘടന sshbuf *);

സ്ഥിരം അക്ഷരം *ssh_remote_ipaddr(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_remote_port(ഘടന ssh *);
സ്ഥിരം അക്ഷരം *ssh_local_ipaddr(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 ssh_local_port(ഘടന ssh *);
സ്ഥിരം അക്ഷരം *ssh_packet_rdomain_in(ഘടന ssh *);
അക്ഷരം	*ssh_remote_hostname(ഘടന ssh *);

ശൂന്യം	 ssh_packet_set_rekey_limits(ഘടന ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(ഘടന ssh *);

ശൂന്യം	*ssh_packet_get_നിവേശം(ഘടന ssh *);
ശൂന്യം	*ssh_packet_get_output(ഘടന ssh *);

/* new API */
പൂർണ്ണസംഖ്യ	sshpkt_start(ഘടന ssh *ssh, u_char type);
പൂർണ്ണസംഖ്യ	sshpkt_send(ഘടന ssh *ssh);
പൂർണ്ണസംഖ്യ     sshpkt_disconnect(ഘടന ssh *, സ്ഥിരം അക്ഷരം *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
പൂർണ്ണസംഖ്യ	sshpkt_add_padding(ഘടന ssh *, u_char);
ശൂന്യം	sshpkt_fatal(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ r, സ്ഥിരം അക്ഷരം *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
പൂർണ്ണസംഖ്യ	sshpkt_സന്ദേശം_ignore(ഘടന ssh *, u_int);

പൂർണ്ണസംഖ്യ	sshpkt_put(ഘടന ssh *ssh, സ്ഥിരം ശൂന്യം *v, size_t len);
പൂർണ്ണസംഖ്യ	sshpkt_putb(ഘടന ssh *ssh, സ്ഥിരം ഘടന sshbuf *b);
പൂർണ്ണസംഖ്യ	sshpkt_put_u8(ഘടന ssh *ssh, u_char val);
പൂർണ്ണസംഖ്യ	sshpkt_put_u32(ഘടന ssh *ssh, uint32_t val);
പൂർണ്ണസംഖ്യ	sshpkt_put_u64(ഘടന ssh *ssh, uint64_t val);
പൂർണ്ണസംഖ്യ	sshpkt_put_string(ഘടന ssh *ssh, സ്ഥിരം ശൂന്യം *v, size_t len);
പൂർണ്ണസംഖ്യ	sshpkt_put_cstring(ഘടന ssh *ssh, സ്ഥിരം ശൂന്യം *v);
പൂർണ്ണസംഖ്യ	sshpkt_put_stringb(ഘടന ssh *ssh, സ്ഥിരം ഘടന sshbuf *v);
പൂർണ്ണസംഖ്യ	sshpkt_put_ec(ഘടന ssh *ssh, സ്ഥിരം EC_POINT *v, സ്ഥിരം EC_GROUP *g);
പൂർണ്ണസംഖ്യ	sshpkt_put_ec_pkey(ഘടന ssh *ssh, EVP_PKEY *pkey);
പൂർണ്ണസംഖ്യ	sshpkt_put_bignum2(ഘടന ssh *ssh, സ്ഥിരം BIGNUM *v);

പൂർണ്ണസംഖ്യ	sshpkt_get(ഘടന ssh *ssh, ശൂന്യം *valp, size_t len);
പൂർണ്ണസംഖ്യ	sshpkt_get_u8(ഘടന ssh *ssh, u_char *valp);
പൂർണ്ണസംഖ്യ	sshpkt_get_u32(ഘടന ssh *ssh, uint32_t *valp);
പൂർണ്ണസംഖ്യ	sshpkt_get_u64(ഘടന ssh *ssh, uint64_t *valp);
പൂർണ്ണസംഖ്യ	sshpkt_get_string(ഘടന ssh *ssh, u_char **valp, size_t *lenp);
പൂർണ്ണസംഖ്യ	sshpkt_get_string_direct(ഘടന ssh *ssh, സ്ഥിരം u_char **valp, size_t *lenp);
പൂർണ്ണസംഖ്യ	sshpkt_peek_string_direct(ഘടന ssh *ssh, സ്ഥിരം u_char **valp, size_t *lenp);
പൂർണ്ണസംഖ്യ	sshpkt_get_cstring(ഘടന ssh *ssh, അക്ഷരം **valp, size_t *lenp);
പൂർണ്ണസംഖ്യ	sshpkt_getb_froms(ഘടന ssh *ssh, ഘടന sshbuf **valp);
പൂർണ്ണസംഖ്യ	sshpkt_get_ec(ഘടന ssh *ssh, EC_POINT *v, സ്ഥിരം EC_GROUP *g);
പൂർണ്ണസംഖ്യ	sshpkt_get_bignum2(ഘടന ssh *ssh, BIGNUM **valp);
പൂർണ്ണസംഖ്യ	sshpkt_get_end(ഘടന ssh *ssh);
ശൂന്യം	sshpkt_fmt_connection_id(ഘടന ssh *ssh, അക്ഷരം *s, size_t l);
സ്ഥിരം u_char	*sshpkt_ptr(ഘടന ssh *, size_t *lenp);
അക്ഷരം	*connection_info_message(ഘടന ssh *ssh);

#endif				/* PACKET_H */
