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
#инако /* OPENSSL */
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
	цео remote_port;
	char *local_ipaddr;
	цео local_port;
	char *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	char *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	цео dispatch_skip_packets;

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

typedef цео (ssh_packet_hook_fn)(struct ssh *, struct sshbuf *,
    u_char *, void *);

struct ssh *ssh_alloc_session_state(void);
struct ssh *ssh_packet_set_connection(struct ssh *, цео, цео);
void     ssh_packet_set_timeout(struct ssh *, цео, цео);
цео	 ssh_packet_stop_discard(struct ssh *);
цео	 ssh_packet_connection_af(struct ssh *);
void     ssh_packet_set_nonblocking(struct ssh *);
цео      ssh_packet_get_connection_in(struct ssh *);
цео      ssh_packet_get_connection_out(struct ssh *);
void	 ssh_packet_free(struct ssh *);
void     ssh_packet_close(struct ssh *);
void	 ssh_packet_set_input_hook(struct ssh *, ssh_packet_hook_fn *, void *);
void	 ssh_packet_clear_keys(struct ssh *);
void	 ssh_clear_newkeys(struct ssh *, цео);

цео	 ssh_packet_is_rekeying(struct ssh *);
цео	 ssh_packet_check_rekey(struct ssh *);
void     ssh_packet_set_protocol_flags(struct ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(struct ssh *);
void	 ssh_packet_set_interactive(struct ssh *, цео);
void	 ssh_packet_set_qos(struct ssh *, цео, цео);
void     ssh_packet_set_server(struct ssh *);
void     ssh_packet_set_authenticated(struct ssh *);
void     ssh_packet_set_mux(struct ssh *);
цео	 ssh_packet_get_mux(struct ssh *);
цео	 ssh_packet_set_log_preamble(struct ssh *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

цео	 ssh_packet_log_type(u_char);

цео	 ssh_packet_send2_wrapped(struct ssh *);
цео	 ssh_packet_send2(struct ssh *);

цео      ssh_packet_read(struct ssh *);
цео ssh_packet_read_poll2(struct ssh *, u_char *, uint32_t *seqnr_p);
цео	 ssh_packet_process_incoming(struct ssh *, const char *buf, u_int len);
цео	 ssh_packet_process_read(struct ssh *, цео);
цео      ssh_packet_read_seqnr(struct ssh *, u_char *, uint32_t *seqnr_p);
цео      ssh_packet_read_poll_seqnr(struct ssh *, u_char *, uint32_t *seqnr_p);

void     ssh_packet_disconnect(struct ssh *, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
void     ssh_packet_send_debug(struct ssh *, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

цео	 ssh_set_newkeys(struct ssh *, цео mode);
void	 ssh_packet_get_bytes(struct ssh *, uint64_t *, uint64_t *);

цео	 ssh_packet_write_poll(struct ssh *);
цео	 ssh_packet_write_wait(struct ssh *);
цео      ssh_packet_have_data_to_write(struct ssh *);
цео      ssh_packet_not_very_much_data_to_write(struct ssh *);
цео	 ssh_packet_interactive_data_to_write(struct ssh *);

цео	 ssh_packet_connection_is_on_socket(struct ssh *);
цео	 ssh_packet_remaining(struct ssh *);

void	 ssh_tty_make_modes(struct ssh *, цео, struct termios *);
void	 ssh_tty_parse_modes(struct ssh *, цео);

void	 ssh_packet_set_alive_timeouts(struct ssh *, цео);
цео	 ssh_packet_inc_alive_timeouts(struct ssh *);
цео	 ssh_packet_set_maxsize(struct ssh *, u_int);
u_int	 ssh_packet_get_maxsize(struct ssh *);

цео	 ssh_packet_get_state(struct ssh *, struct sshbuf *);
цео	 ssh_packet_set_state(struct ssh *, struct sshbuf *);

const char *ssh_remote_ipaddr(struct ssh *);
цео	 ssh_remote_port(struct ssh *);
const char *ssh_local_ipaddr(struct ssh *);
цео	 ssh_local_port(struct ssh *);
const char *ssh_packet_rdomain_in(struct ssh *);
char	*ssh_remote_hostname(struct ssh *);

void	 ssh_packet_set_rekey_limits(struct ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(struct ssh *);

void	*ssh_packet_get_input(struct ssh *);
void	*ssh_packet_get_output(struct ssh *);

/* new API */
цео	sshpkt_start(struct ssh *ssh, u_char type);
цео	sshpkt_send(struct ssh *ssh);
цео     sshpkt_disconnect(struct ssh *, const char *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
цео	sshpkt_add_padding(struct ssh *, u_char);
void	sshpkt_fatal(struct ssh *ssh, цео r, const char *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
цео	sshpkt_msg_ignore(struct ssh *, u_int);

цео	sshpkt_put(struct ssh *ssh, const void *v, size_t len);
цео	sshpkt_putb(struct ssh *ssh, const struct sshbuf *b);
цео	sshpkt_put_u8(struct ssh *ssh, u_char val);
цео	sshpkt_put_u32(struct ssh *ssh, uint32_t val);
цео	sshpkt_put_u64(struct ssh *ssh, uint64_t val);
цео	sshpkt_put_string(struct ssh *ssh, const void *v, size_t len);
цео	sshpkt_put_cstring(struct ssh *ssh, const void *v);
цео	sshpkt_put_stringb(struct ssh *ssh, const struct sshbuf *v);
цео	sshpkt_put_ec(struct ssh *ssh, const EC_POINT *v, const EC_GROUP *g);
цео	sshpkt_put_ec_pkey(struct ssh *ssh, EVP_PKEY *pkey);
цео	sshpkt_put_bignum2(struct ssh *ssh, const BIGNUM *v);

цео	sshpkt_get(struct ssh *ssh, void *valp, size_t len);
цео	sshpkt_get_u8(struct ssh *ssh, u_char *valp);
цео	sshpkt_get_u32(struct ssh *ssh, uint32_t *valp);
цео	sshpkt_get_u64(struct ssh *ssh, uint64_t *valp);
цео	sshpkt_get_string(struct ssh *ssh, u_char **valp, size_t *lenp);
цео	sshpkt_get_string_direct(struct ssh *ssh, const u_char **valp, size_t *lenp);
цео	sshpkt_peek_string_direct(struct ssh *ssh, const u_char **valp, size_t *lenp);
цео	sshpkt_get_cstring(struct ssh *ssh, char **valp, size_t *lenp);
цео	sshpkt_getb_froms(struct ssh *ssh, struct sshbuf **valp);
цео	sshpkt_get_ec(struct ssh *ssh, EC_POINT *v, const EC_GROUP *g);
цео	sshpkt_get_bignum2(struct ssh *ssh, BIGNUM **valp);
цео	sshpkt_get_end(struct ssh *ssh);
void	sshpkt_fmt_connection_id(struct ssh *ssh, char *s, size_t l);
const u_char	*sshpkt_ptr(struct ssh *, size_t *lenp);
char	*connection_info_message(struct ssh *ssh);

#endif				/* PACKET_H */
