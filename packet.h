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

#અન્તર્ભાવ <sys/queue.h>

#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <termios.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/ecdsa.h>
#અન્તર્ભાવ <openssl/evp.h>
#નહીંતર /* OPENSSL */
#define BIGNUM		શૂન્ય
#define EC_GROUP	શૂન્ય
#define EC_POINT	શૂન્ય
#define EVP_PKEY	શૂન્ય
#endif /* WITH_OPENSSL */

સંરચના kex;
સંરચના sshkey;
સંરચના sshbuf;
સંરચના session_state;	/* private session data */

#અન્તર્ભાવ "dispatch.h"	/* typedef, DISPATCH_MAX */

સંરચના ચાવી_entry {
	TAILQ_ENTRY(ચાવી_entry) next;
	સંરચના sshkey *ચાવી;
};

સંરચના ssh {
	/* Session state */
	સંરચના session_state *state;

	/* Key exchange */
	સંરચના kex *kex;

	/* cached local and remote ip addresses and ports */
	અક્ષર *remote_ipaddr;
	પૂર્ણાંક remote_port;
	અક્ષર *local_ipaddr;
	પૂર્ણાંક local_port;
	અક્ષર *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	અક્ષર *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	પૂર્ણાંક dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	અક્ષર *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, ચાવી_entry) private_ચાવીઓ;
	TAILQ_HEAD(, ચાવી_entry) public_ચાવીઓ;

	/* Client/Server authentication context */
	શૂન્ય *authctxt;

	/* Channels context */
	સંરચના ssh_channels *chanctxt;

	/* APP data */
	શૂન્ય *app_data;
};

પ્રકારવ્યાખ્યા પૂર્ણાંક (ssh_packet_hook_fn)(સંરચના ssh *, સંરચના sshbuf *,
    u_char *, શૂન્ય *);

સંરચના ssh *ssh_alloc_session_state(શૂન્ય);
સંરચના ssh *ssh_packet_set_connection(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક);
શૂન્ય     ssh_packet_set_timeout(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક);
પૂર્ણાંક	 ssh_packet_stop_discard(સંરચના ssh *);
પૂર્ણાંક	 ssh_packet_connection_af(સંરચના ssh *);
શૂન્ય     ssh_packet_set_nonblocking(સંરચના ssh *);
પૂર્ણાંક      ssh_packet_get_connection_in(સંરચના ssh *);
પૂર્ણાંક      ssh_packet_get_connection_out(સંરચના ssh *);
શૂન્ય	 ssh_packet_free(સંરચના ssh *);
શૂન્ય     ssh_packet_close(સંરચના ssh *);
શૂન્ય	 ssh_packet_set_આગત_hook(સંરચના ssh *, ssh_packet_hook_fn *, શૂન્ય *);
શૂન્ય	 ssh_packet_clear_ચાવીઓ(સંરચના ssh *);
શૂન્ય	 ssh_clear_newkeys(સંરચના ssh *, પૂર્ણાંક);

પૂર્ણાંક	 ssh_packet_is_rekeying(સંરચના ssh *);
પૂર્ણાંક	 ssh_packet_check_rekey(સંરચના ssh *);
શૂન્ય     ssh_packet_set_protocol_flags(સંરચના ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(સંરચના ssh *);
શૂન્ય	 ssh_packet_set_interactive(સંરચના ssh *, પૂર્ણાંક);
શૂન્ય	 ssh_packet_set_qos(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક);
શૂન્ય     ssh_packet_set_server(સંરચના ssh *);
શૂન્ય     ssh_packet_set_authenticated(સંરચના ssh *);
શૂન્ય     ssh_packet_set_mux(સંરચના ssh *);
પૂર્ણાંક	 ssh_packet_get_mux(સંરચના ssh *);
પૂર્ણાંક	 ssh_packet_set_log_preamble(સંરચના ssh *, અચલ અક્ષર *, ...)
    __attribute__((format(printf, 2, 3)));

પૂર્ણાંક	 ssh_packet_log_type(u_char);

પૂર્ણાંક	 ssh_packet_send2_wrapped(સંરચના ssh *);
પૂર્ણાંક	 ssh_packet_send2(સંરચના ssh *);

પૂર્ણાંક      ssh_packet_read(સંરચના ssh *);
પૂર્ણાંક ssh_packet_read_poll2(સંરચના ssh *, u_char *, uint32_t *seqnr_p);
પૂર્ણાંક	 ssh_packet_process_incoming(સંરચના ssh *, અચલ અક્ષર *buf, u_int len);
પૂર્ણાંક	 ssh_packet_process_read(સંરચના ssh *, પૂર્ણાંક);
પૂર્ણાંક      ssh_packet_read_seqnr(સંરચના ssh *, u_char *, uint32_t *seqnr_p);
પૂર્ણાંક      ssh_packet_read_poll_seqnr(સંરચના ssh *, u_char *, uint32_t *seqnr_p);

શૂન્ય     ssh_packet_disconnect(સંરચના ssh *, અચલ અક્ષર *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
શૂન્ય     ssh_packet_send_debug(સંરચના ssh *, અચલ અક્ષર *fmt, ...) __attribute__((format(printf, 2, 3)));

પૂર્ણાંક	 ssh_set_newkeys(સંરચના ssh *, પૂર્ણાંક mode);
શૂન્ય	 ssh_packet_get_bytes(સંરચના ssh *, uint64_t *, uint64_t *);

પૂર્ણાંક	 ssh_packet_write_poll(સંરચના ssh *);
પૂર્ણાંક	 ssh_packet_write_wait(સંરચના ssh *);
પૂર્ણાંક      ssh_packet_have_data_to_write(સંરચના ssh *);
પૂર્ણાંક      ssh_packet_not_very_much_data_to_write(સંરચના ssh *);
પૂર્ણાંક	 ssh_packet_interactive_data_to_write(સંરચના ssh *);

પૂર્ણાંક	 ssh_packet_connection_is_on_socket(સંરચના ssh *);
પૂર્ણાંક	 ssh_packet_remaining(સંરચના ssh *);

શૂન્ય	 ssh_tty_make_modes(સંરચના ssh *, પૂર્ણાંક, સંરચના termios *);
શૂન્ય	 ssh_tty_parse_modes(સંરચના ssh *, પૂર્ણાંક);

શૂન્ય	 ssh_packet_set_alive_timeouts(સંરચના ssh *, પૂર્ણાંક);
પૂર્ણાંક	 ssh_packet_inc_alive_timeouts(સંરચના ssh *);
પૂર્ણાંક	 ssh_packet_set_maxsize(સંરચના ssh *, u_int);
u_int	 ssh_packet_get_maxsize(સંરચના ssh *);

પૂર્ણાંક	 ssh_packet_get_state(સંરચના ssh *, સંરચના sshbuf *);
પૂર્ણાંક	 ssh_packet_set_state(સંરચના ssh *, સંરચના sshbuf *);

અચલ અક્ષર *ssh_remote_ipaddr(સંરચના ssh *);
પૂર્ણાંક	 ssh_remote_port(સંરચના ssh *);
અચલ અક્ષર *ssh_local_ipaddr(સંરચના ssh *);
પૂર્ણાંક	 ssh_local_port(સંરચના ssh *);
અચલ અક્ષર *ssh_packet_rdomain_in(સંરચના ssh *);
અક્ષર	*ssh_remote_hostname(સંરચના ssh *);

શૂન્ય	 ssh_packet_set_rekey_limits(સંરચના ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(સંરચના ssh *);

શૂન્ય	*ssh_packet_get_આગત(સંરચના ssh *);
શૂન્ય	*ssh_packet_get_output(સંરચના ssh *);

/* new API */
પૂર્ણાંક	sshpkt_start(સંરચના ssh *ssh, u_char type);
પૂર્ણાંક	sshpkt_send(સંરચના ssh *ssh);
પૂર્ણાંક     sshpkt_disconnect(સંરચના ssh *, અચલ અક્ષર *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
પૂર્ણાંક	sshpkt_add_padding(સંરચના ssh *, u_char);
શૂન્ય	sshpkt_fatal(સંરચના ssh *ssh, પૂર્ણાંક r, અચલ અક્ષર *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
પૂર્ણાંક	sshpkt_સંદેશ_ignore(સંરચના ssh *, u_int);

પૂર્ણાંક	sshpkt_put(સંરચના ssh *ssh, અચલ શૂન્ય *v, size_t len);
પૂર્ણાંક	sshpkt_putb(સંરચના ssh *ssh, અચલ સંરચના sshbuf *b);
પૂર્ણાંક	sshpkt_put_u8(સંરચના ssh *ssh, u_char val);
પૂર્ણાંક	sshpkt_put_u32(સંરચના ssh *ssh, uint32_t val);
પૂર્ણાંક	sshpkt_put_u64(સંરચના ssh *ssh, uint64_t val);
પૂર્ણાંક	sshpkt_put_string(સંરચના ssh *ssh, અચલ શૂન્ય *v, size_t len);
પૂર્ણાંક	sshpkt_put_cstring(સંરચના ssh *ssh, અચલ શૂન્ય *v);
પૂર્ણાંક	sshpkt_put_stringb(સંરચના ssh *ssh, અચલ સંરચના sshbuf *v);
પૂર્ણાંક	sshpkt_put_ec(સંરચના ssh *ssh, અચલ EC_POINT *v, અચલ EC_GROUP *g);
પૂર્ણાંક	sshpkt_put_ec_pkey(સંરચના ssh *ssh, EVP_PKEY *pkey);
પૂર્ણાંક	sshpkt_put_bignum2(સંરચના ssh *ssh, અચલ BIGNUM *v);

પૂર્ણાંક	sshpkt_get(સંરચના ssh *ssh, શૂન્ય *valp, size_t len);
પૂર્ણાંક	sshpkt_get_u8(સંરચના ssh *ssh, u_char *valp);
પૂર્ણાંક	sshpkt_get_u32(સંરચના ssh *ssh, uint32_t *valp);
પૂર્ણાંક	sshpkt_get_u64(સંરચના ssh *ssh, uint64_t *valp);
પૂર્ણાંક	sshpkt_get_string(સંરચના ssh *ssh, u_char **valp, size_t *lenp);
પૂર્ણાંક	sshpkt_get_string_direct(સંરચના ssh *ssh, અચલ u_char **valp, size_t *lenp);
પૂર્ણાંક	sshpkt_peek_string_direct(સંરચના ssh *ssh, અચલ u_char **valp, size_t *lenp);
પૂર્ણાંક	sshpkt_get_cstring(સંરચના ssh *ssh, અક્ષર **valp, size_t *lenp);
પૂર્ણાંક	sshpkt_getb_froms(સંરચના ssh *ssh, સંરચના sshbuf **valp);
પૂર્ણાંક	sshpkt_get_ec(સંરચના ssh *ssh, EC_POINT *v, અચલ EC_GROUP *g);
પૂર્ણાંક	sshpkt_get_bignum2(સંરચના ssh *ssh, BIGNUM **valp);
પૂર્ણાંક	sshpkt_get_end(સંરચના ssh *ssh);
શૂન્ય	sshpkt_fmt_connection_id(સંરચના ssh *ssh, અક્ષર *s, size_t l);
અચલ u_char	*sshpkt_ptr(સંરચના ssh *, size_t *lenp);
અક્ષર	*connection_info_message(સંરચના ssh *ssh);

#endif				/* PACKET_H */
