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

#include <sys/queue.h>

#include <stdint.h>
#include <signal.h>
#include <termios.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#မဟုတ်ပါက /* OPENSSL */
#define BIGNUM		void
#define EC_GROUP	void
#define EC_POINT	void
#define EVP_PKEY	void
#endif /* WITH_OPENSSL */

sa_nracanaa kex;
sa_nracanaa sshkey;
sa_nracanaa sshbuf;
sa_nracanaa session_state;	/* private session data */

#include "dispatch.h"	/* typedef, DISPATCH_MAX */

sa_nracanaa key_entry {
	TAILQ_ENTRY(key_entry) next;
	sa_nracanaa sshkey *key;
};

sa_nracanaa ssh {
	/* Session state */
	sa_nracanaa session_state *state;

	/* Key exchange */
	sa_nracanaa kex *kex;

	/* cached local and remote ip addresses and ports */
	var_na *remote_ipaddr;
	ကိန်းပြည့် remote_port;
	var_na *local_ipaddr;
	ကိန်းပြည့် local_port;
	var_na *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	var_na *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	ကိန်းပြည့် dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	var_na *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, key_entry) private_keys;
	TAILQ_HEAD(, key_entry) public_keys;

	/* Client/Server authentication context */
	void *authctxt;

	/* Channels context */
	sa_nracanaa ssh_channels *chanctxt;

	/* APP data */
	void *app_data;
};

typedef ကိန်းပြည့် (ssh_packet_hook_fn)(sa_nracanaa ssh *, sa_nracanaa sshbuf *,
    u_char *, void *);

sa_nracanaa ssh *ssh_alloc_session_state(void);
sa_nracanaa ssh *ssh_packet_set_connection(sa_nracanaa ssh *, ကိန်းပြည့်, ကိန်းပြည့်);
void     ssh_packet_set_timeout(sa_nracanaa ssh *, ကိန်းပြည့်, ကိန်းပြည့်);
ကိန်းပြည့်	 ssh_packet_stop_discard(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_packet_connection_af(sa_nracanaa ssh *);
void     ssh_packet_set_nonblocking(sa_nracanaa ssh *);
ကိန်းပြည့်      ssh_packet_get_connection_in(sa_nracanaa ssh *);
ကိန်းပြည့်      ssh_packet_get_connection_out(sa_nracanaa ssh *);
void	 ssh_packet_free(sa_nracanaa ssh *);
void     ssh_packet_close(sa_nracanaa ssh *);
void	 ssh_packet_set_input_hook(sa_nracanaa ssh *, ssh_packet_hook_fn *, void *);
void	 ssh_packet_clear_keys(sa_nracanaa ssh *);
void	 ssh_clear_newkeys(sa_nracanaa ssh *, ကိန်းပြည့်);

ကိန်းပြည့်	 ssh_packet_is_rekeying(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_packet_check_rekey(sa_nracanaa ssh *);
void     ssh_packet_set_protocol_flags(sa_nracanaa ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(sa_nracanaa ssh *);
void	 ssh_packet_set_interactive(sa_nracanaa ssh *, ကိန်းပြည့်);
void	 ssh_packet_set_qos(sa_nracanaa ssh *, ကိန်းပြည့်, ကိန်းပြည့်);
void     ssh_packet_set_server(sa_nracanaa ssh *);
void     ssh_packet_set_authenticated(sa_nracanaa ssh *);
void     ssh_packet_set_mux(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_packet_get_mux(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_packet_set_log_preamble(sa_nracanaa ssh *, const var_na *, ...)
    __attribute__((format(printf, 2, 3)));

ကိန်းပြည့်	 ssh_packet_log_type(u_char);

ကိန်းပြည့်	 ssh_packet_send2_wrapped(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_packet_send2(sa_nracanaa ssh *);

ကိန်းပြည့်      ssh_packet_read(sa_nracanaa ssh *);
ကိန်းပြည့် ssh_packet_read_poll2(sa_nracanaa ssh *, u_char *, uint32_t *seqnr_p);
ကိန်းပြည့်	 ssh_packet_process_incoming(sa_nracanaa ssh *, const var_na *buf, u_int len);
ကိန်းပြည့်	 ssh_packet_process_read(sa_nracanaa ssh *, ကိန်းပြည့်);
ကိန်းပြည့်      ssh_packet_read_seqnr(sa_nracanaa ssh *, u_char *, uint32_t *seqnr_p);
ကိန်းပြည့်      ssh_packet_read_poll_seqnr(sa_nracanaa ssh *, u_char *, uint32_t *seqnr_p);

void     ssh_packet_disconnect(sa_nracanaa ssh *, const var_na *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
void     ssh_packet_send_debug(sa_nracanaa ssh *, const var_na *fmt, ...) __attribute__((format(printf, 2, 3)));

ကိန်းပြည့်	 ssh_set_newkeys(sa_nracanaa ssh *, ကိန်းပြည့် mode);
void	 ssh_packet_get_bytes(sa_nracanaa ssh *, uint64_t *, uint64_t *);

ကိန်းပြည့်	 ssh_packet_write_poll(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_packet_write_wait(sa_nracanaa ssh *);
ကိန်းပြည့်      ssh_packet_have_data_to_write(sa_nracanaa ssh *);
ကိန်းပြည့်      ssh_packet_not_very_much_data_to_write(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_packet_interactive_data_to_write(sa_nracanaa ssh *);

ကိန်းပြည့်	 ssh_packet_connection_is_on_socket(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_packet_remaining(sa_nracanaa ssh *);

void	 ssh_tty_make_modes(sa_nracanaa ssh *, ကိန်းပြည့်, sa_nracanaa termios *);
void	 ssh_tty_parse_modes(sa_nracanaa ssh *, ကိန်းပြည့်);

void	 ssh_packet_set_alive_timeouts(sa_nracanaa ssh *, ကိန်းပြည့်);
ကိန်းပြည့်	 ssh_packet_inc_alive_timeouts(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_packet_set_maxsize(sa_nracanaa ssh *, u_int);
u_int	 ssh_packet_get_maxsize(sa_nracanaa ssh *);

ကိန်းပြည့်	 ssh_packet_get_state(sa_nracanaa ssh *, sa_nracanaa sshbuf *);
ကိန်းပြည့်	 ssh_packet_set_state(sa_nracanaa ssh *, sa_nracanaa sshbuf *);

const var_na *ssh_remote_ipaddr(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_remote_port(sa_nracanaa ssh *);
const var_na *ssh_local_ipaddr(sa_nracanaa ssh *);
ကိန်းပြည့်	 ssh_local_port(sa_nracanaa ssh *);
const var_na *ssh_packet_rdomain_in(sa_nracanaa ssh *);
var_na	*ssh_remote_hostname(sa_nracanaa ssh *);

void	 ssh_packet_set_rekey_limits(sa_nracanaa ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(sa_nracanaa ssh *);

void	*ssh_packet_get_input(sa_nracanaa ssh *);
void	*ssh_packet_get_output(sa_nracanaa ssh *);

/* new API */
ကိန်းပြည့်	sshpkt_start(sa_nracanaa ssh *ssh, u_char type);
ကိန်းပြည့်	sshpkt_send(sa_nracanaa ssh *ssh);
ကိန်းပြည့်     sshpkt_disconnect(sa_nracanaa ssh *, const var_na *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
ကိန်းပြည့်	sshpkt_add_padding(sa_nracanaa ssh *, u_char);
void	sshpkt_fatal(sa_nracanaa ssh *ssh, ကိန်းပြည့် r, const var_na *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
ကိန်းပြည့်	sshpkt_msg_ignore(sa_nracanaa ssh *, u_int);

ကိန်းပြည့်	sshpkt_put(sa_nracanaa ssh *ssh, const void *v, size_t len);
ကိန်းပြည့်	sshpkt_putb(sa_nracanaa ssh *ssh, const sa_nracanaa sshbuf *b);
ကိန်းပြည့်	sshpkt_put_u8(sa_nracanaa ssh *ssh, u_char val);
ကိန်းပြည့်	sshpkt_put_u32(sa_nracanaa ssh *ssh, uint32_t val);
ကိန်းပြည့်	sshpkt_put_u64(sa_nracanaa ssh *ssh, uint64_t val);
ကိန်းပြည့်	sshpkt_put_string(sa_nracanaa ssh *ssh, const void *v, size_t len);
ကိန်းပြည့်	sshpkt_put_cstring(sa_nracanaa ssh *ssh, const void *v);
ကိန်းပြည့်	sshpkt_put_stringb(sa_nracanaa ssh *ssh, const sa_nracanaa sshbuf *v);
ကိန်းပြည့်	sshpkt_put_ec(sa_nracanaa ssh *ssh, const EC_POINT *v, const EC_GROUP *g);
ကိန်းပြည့်	sshpkt_put_ec_pkey(sa_nracanaa ssh *ssh, EVP_PKEY *pkey);
ကိန်းပြည့်	sshpkt_put_bignum2(sa_nracanaa ssh *ssh, const BIGNUM *v);

ကိန်းပြည့်	sshpkt_get(sa_nracanaa ssh *ssh, void *valp, size_t len);
ကိန်းပြည့်	sshpkt_get_u8(sa_nracanaa ssh *ssh, u_char *valp);
ကိန်းပြည့်	sshpkt_get_u32(sa_nracanaa ssh *ssh, uint32_t *valp);
ကိန်းပြည့်	sshpkt_get_u64(sa_nracanaa ssh *ssh, uint64_t *valp);
ကိန်းပြည့်	sshpkt_get_string(sa_nracanaa ssh *ssh, u_char **valp, size_t *lenp);
ကိန်းပြည့်	sshpkt_get_string_direct(sa_nracanaa ssh *ssh, const u_char **valp, size_t *lenp);
ကိန်းပြည့်	sshpkt_peek_string_direct(sa_nracanaa ssh *ssh, const u_char **valp, size_t *lenp);
ကိန်းပြည့်	sshpkt_get_cstring(sa_nracanaa ssh *ssh, var_na **valp, size_t *lenp);
ကိန်းပြည့်	sshpkt_getb_froms(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf **valp);
ကိန်းပြည့်	sshpkt_get_ec(sa_nracanaa ssh *ssh, EC_POINT *v, const EC_GROUP *g);
ကိန်းပြည့်	sshpkt_get_bignum2(sa_nracanaa ssh *ssh, BIGNUM **valp);
ကိန်းပြည့်	sshpkt_get_end(sa_nracanaa ssh *ssh);
void	sshpkt_fmt_connection_id(sa_nracanaa ssh *ssh, var_na *s, size_t l);
const u_char	*sshpkt_ptr(sa_nracanaa ssh *, size_t *lenp);
var_na	*connection_info_message(sa_nracanaa ssh *ssh);

#endif				/* PACKET_H */
