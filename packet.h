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
#否则 /* OPENSSL */
#define BIGNUM		void
#define EC_GROUP	void
#define EC_POINT	void
#define EVP_PKEY	void
#endif /* WITH_OPENSSL */

struct kex;
struct sshkey;
struct sshbuf;
struct session_state;	/* private session data */

#include "dispatch.h"	/* typedef, DISPATCH_MAX */

struct key_entry {
	TAILQ_ENTRY(key_entry) next;
	struct sshkey *key;
};

struct ssh {
	/* Session state */
	struct session_state *state;

	/* Key exchange */
	struct kex *kex;

	/* cached local and remote ip addresses and ports */
	char *remote_ipaddr;
	整数 remote_port;
	char *local_ipaddr;
	整数 local_port;
	char *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	char *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	整数 dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	char *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, key_entry) private_keys;
	TAILQ_HEAD(, key_entry) public_keys;

	/* Client/Server authentication context */
	void *authctxt;

	/* Channels context */
	struct ssh_channels *chanctxt;

	/* APP data */
	void *app_data;
};

typedef 整数 (ssh_packet_hook_fn)(struct ssh *, struct sshbuf *,
    u_char *, void *);

struct ssh *ssh_alloc_session_state(void);
struct ssh *ssh_packet_set_connection(struct ssh *, 整数, 整数);
void     ssh_packet_set_timeout(struct ssh *, 整数, 整数);
整数	 ssh_packet_stop_discard(struct ssh *);
整数	 ssh_packet_connection_af(struct ssh *);
void     ssh_packet_set_nonblocking(struct ssh *);
整数      ssh_packet_get_connection_in(struct ssh *);
整数      ssh_packet_get_connection_out(struct ssh *);
void	 ssh_packet_free(struct ssh *);
void     ssh_packet_close(struct ssh *);
void	 ssh_packet_set_input_hook(struct ssh *, ssh_packet_hook_fn *, void *);
void	 ssh_packet_clear_keys(struct ssh *);
void	 ssh_clear_newkeys(struct ssh *, 整数);

整数	 ssh_packet_is_rekeying(struct ssh *);
整数	 ssh_packet_check_rekey(struct ssh *);
void     ssh_packet_set_protocol_flags(struct ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(struct ssh *);
void	 ssh_packet_set_interactive(struct ssh *, 整数);
void	 ssh_packet_set_qos(struct ssh *, 整数, 整数);
void     ssh_packet_set_server(struct ssh *);
void     ssh_packet_set_authenticated(struct ssh *);
void     ssh_packet_set_mux(struct ssh *);
整数	 ssh_packet_get_mux(struct ssh *);
整数	 ssh_packet_set_log_preamble(struct ssh *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

整数	 ssh_packet_log_type(u_char);

整数	 ssh_packet_send2_wrapped(struct ssh *);
整数	 ssh_packet_send2(struct ssh *);

整数      ssh_packet_read(struct ssh *);
整数 ssh_packet_read_poll2(struct ssh *, u_char *, uint32_t *seqnr_p);
整数	 ssh_packet_process_incoming(struct ssh *, const char *buf, u_int len);
整数	 ssh_packet_process_read(struct ssh *, 整数);
整数      ssh_packet_read_seqnr(struct ssh *, u_char *, uint32_t *seqnr_p);
整数      ssh_packet_read_poll_seqnr(struct ssh *, u_char *, uint32_t *seqnr_p);

void     ssh_packet_disconnect(struct ssh *, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
void     ssh_packet_send_debug(struct ssh *, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

整数	 ssh_set_newkeys(struct ssh *, 整数 mode);
void	 ssh_packet_get_bytes(struct ssh *, uint64_t *, uint64_t *);

整数	 ssh_packet_write_poll(struct ssh *);
整数	 ssh_packet_write_wait(struct ssh *);
整数      ssh_packet_have_data_to_write(struct ssh *);
整数      ssh_packet_not_very_much_data_to_write(struct ssh *);
整数	 ssh_packet_interactive_data_to_write(struct ssh *);

整数	 ssh_packet_connection_is_on_socket(struct ssh *);
整数	 ssh_packet_remaining(struct ssh *);

void	 ssh_tty_make_modes(struct ssh *, 整数, struct termios *);
void	 ssh_tty_parse_modes(struct ssh *, 整数);

void	 ssh_packet_set_alive_timeouts(struct ssh *, 整数);
整数	 ssh_packet_inc_alive_timeouts(struct ssh *);
整数	 ssh_packet_set_maxsize(struct ssh *, u_int);
u_int	 ssh_packet_get_maxsize(struct ssh *);

整数	 ssh_packet_get_state(struct ssh *, struct sshbuf *);
整数	 ssh_packet_set_state(struct ssh *, struct sshbuf *);

const char *ssh_remote_ipaddr(struct ssh *);
整数	 ssh_remote_port(struct ssh *);
const char *ssh_local_ipaddr(struct ssh *);
整数	 ssh_local_port(struct ssh *);
const char *ssh_packet_rdomain_in(struct ssh *);
char	*ssh_remote_hostname(struct ssh *);

void	 ssh_packet_set_rekey_limits(struct ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(struct ssh *);

void	*ssh_packet_get_input(struct ssh *);
void	*ssh_packet_get_output(struct ssh *);

/* new API */
整数	sshpkt_start(struct ssh *ssh, u_char type);
整数	sshpkt_send(struct ssh *ssh);
整数     sshpkt_disconnect(struct ssh *, const char *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
整数	sshpkt_add_padding(struct ssh *, u_char);
void	sshpkt_fatal(struct ssh *ssh, 整数 r, const char *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
整数	sshpkt_msg_ignore(struct ssh *, u_int);

整数	sshpkt_put(struct ssh *ssh, const void *v, size_t len);
整数	sshpkt_putb(struct ssh *ssh, const struct sshbuf *b);
整数	sshpkt_put_u8(struct ssh *ssh, u_char val);
整数	sshpkt_put_u32(struct ssh *ssh, uint32_t val);
整数	sshpkt_put_u64(struct ssh *ssh, uint64_t val);
整数	sshpkt_put_string(struct ssh *ssh, const void *v, size_t len);
整数	sshpkt_put_cstring(struct ssh *ssh, const void *v);
整数	sshpkt_put_stringb(struct ssh *ssh, const struct sshbuf *v);
整数	sshpkt_put_ec(struct ssh *ssh, const EC_POINT *v, const EC_GROUP *g);
整数	sshpkt_put_ec_pkey(struct ssh *ssh, EVP_PKEY *pkey);
整数	sshpkt_put_bignum2(struct ssh *ssh, const BIGNUM *v);

整数	sshpkt_get(struct ssh *ssh, void *valp, size_t len);
整数	sshpkt_get_u8(struct ssh *ssh, u_char *valp);
整数	sshpkt_get_u32(struct ssh *ssh, uint32_t *valp);
整数	sshpkt_get_u64(struct ssh *ssh, uint64_t *valp);
整数	sshpkt_get_string(struct ssh *ssh, u_char **valp, size_t *lenp);
整数	sshpkt_get_string_direct(struct ssh *ssh, const u_char **valp, size_t *lenp);
整数	sshpkt_peek_string_direct(struct ssh *ssh, const u_char **valp, size_t *lenp);
整数	sshpkt_get_cstring(struct ssh *ssh, char **valp, size_t *lenp);
整数	sshpkt_getb_froms(struct ssh *ssh, struct sshbuf **valp);
整数	sshpkt_get_ec(struct ssh *ssh, EC_POINT *v, const EC_GROUP *g);
整数	sshpkt_get_bignum2(struct ssh *ssh, BIGNUM **valp);
整数	sshpkt_get_end(struct ssh *ssh);
void	sshpkt_fmt_connection_id(struct ssh *ssh, char *s, size_t l);
const u_char	*sshpkt_ptr(struct ssh *, size_t *lenp);
char	*connection_info_message(struct ssh *ssh);

#endif				/* PACKET_H */
