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

#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <termios.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#அந்தர்பாவ <openssl/evp.h>
#இல்லையெனில் /* OPENSSL */
#define BIGNUM		வெறுமை
#define EC_GROUP	வெறுமை
#define EC_POINT	வெறுமை
#define EVP_PKEY	வெறுமை
#endif /* WITH_OPENSSL */

கட்டமைப்பு kex;
கட்டமைப்பு sshkey;
கட்டமைப்பு sshbuf;
கட்டமைப்பு session_state;	/* private session data */

#அந்தர்பாவ "dispatch.h"	/* typedef, DISPATCH_MAX */

கட்டமைப்பு சாவி_entry {
	TAILQ_ENTRY(சாவி_entry) next;
	கட்டமைப்பு sshkey *சாவி;
};

கட்டமைப்பு ssh {
	/* Session state */
	கட்டமைப்பு session_state *state;

	/* Key exchange */
	கட்டமைப்பு kex *kex;

	/* cached local and remote ip addresses and ports */
	எழுத்து *remote_ipaddr;
	முழு remote_port;
	எழுத்து *local_ipaddr;
	முழு local_port;
	எழுத்து *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	எழுத்து *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	முழு dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	எழுத்து *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, சாவி_entry) private_சாவிகள்;
	TAILQ_HEAD(, சாவி_entry) public_சாவிகள்;

	/* Client/Server authentication context */
	வெறுமை *authctxt;

	/* Channels context */
	கட்டமைப்பு ssh_channels *chanctxt;

	/* APP data */
	வெறுமை *app_data;
};

வகைவரை முழு (ssh_packet_hook_fn)(கட்டமைப்பு ssh *, கட்டமைப்பு sshbuf *,
    u_char *, வெறுமை *);

கட்டமைப்பு ssh *ssh_alloc_session_state(வெறுமை);
கட்டமைப்பு ssh *ssh_packet_set_connection(கட்டமைப்பு ssh *, முழு, முழு);
வெறுமை     ssh_packet_set_timeout(கட்டமைப்பு ssh *, முழு, முழு);
முழு	 ssh_packet_stop_discard(கட்டமைப்பு ssh *);
முழு	 ssh_packet_connection_af(கட்டமைப்பு ssh *);
வெறுமை     ssh_packet_set_nonblocking(கட்டமைப்பு ssh *);
முழு      ssh_packet_get_connection_in(கட்டமைப்பு ssh *);
முழு      ssh_packet_get_connection_out(கட்டமைப்பு ssh *);
வெறுமை	 ssh_packet_free(கட்டமைப்பு ssh *);
வெறுமை     ssh_packet_close(கட்டமைப்பு ssh *);
வெறுமை	 ssh_packet_set_உள்ளீடு_hook(கட்டமைப்பு ssh *, ssh_packet_hook_fn *, வெறுமை *);
வெறுமை	 ssh_packet_clear_சாவிகள்(கட்டமைப்பு ssh *);
வெறுமை	 ssh_clear_newkeys(கட்டமைப்பு ssh *, முழு);

முழு	 ssh_packet_is_rekeying(கட்டமைப்பு ssh *);
முழு	 ssh_packet_check_rekey(கட்டமைப்பு ssh *);
வெறுமை     ssh_packet_set_protocol_flags(கட்டமைப்பு ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(கட்டமைப்பு ssh *);
வெறுமை	 ssh_packet_set_interactive(கட்டமைப்பு ssh *, முழு);
வெறுமை	 ssh_packet_set_qos(கட்டமைப்பு ssh *, முழு, முழு);
வெறுமை     ssh_packet_set_server(கட்டமைப்பு ssh *);
வெறுமை     ssh_packet_set_authenticated(கட்டமைப்பு ssh *);
வெறுமை     ssh_packet_set_mux(கட்டமைப்பு ssh *);
முழு	 ssh_packet_get_mux(கட்டமைப்பு ssh *);
முழு	 ssh_packet_set_log_preamble(கட்டமைப்பு ssh *, மாறிலி எழுத்து *, ...)
    __attribute__((format(printf, 2, 3)));

முழு	 ssh_packet_log_type(u_char);

முழு	 ssh_packet_send2_wrapped(கட்டமைப்பு ssh *);
முழு	 ssh_packet_send2(கட்டமைப்பு ssh *);

முழு      ssh_packet_read(கட்டமைப்பு ssh *);
முழு ssh_packet_read_poll2(கட்டமைப்பு ssh *, u_char *, uint32_t *seqnr_p);
முழு	 ssh_packet_process_incoming(கட்டமைப்பு ssh *, மாறிலி எழுத்து *buf, u_int len);
முழு	 ssh_packet_process_read(கட்டமைப்பு ssh *, முழு);
முழு      ssh_packet_read_seqnr(கட்டமைப்பு ssh *, u_char *, uint32_t *seqnr_p);
முழு      ssh_packet_read_poll_seqnr(கட்டமைப்பு ssh *, u_char *, uint32_t *seqnr_p);

வெறுமை     ssh_packet_disconnect(கட்டமைப்பு ssh *, மாறிலி எழுத்து *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
வெறுமை     ssh_packet_send_debug(கட்டமைப்பு ssh *, மாறிலி எழுத்து *fmt, ...) __attribute__((format(printf, 2, 3)));

முழு	 ssh_set_newkeys(கட்டமைப்பு ssh *, முழு mode);
வெறுமை	 ssh_packet_get_bytes(கட்டமைப்பு ssh *, uint64_t *, uint64_t *);

முழு	 ssh_packet_write_poll(கட்டமைப்பு ssh *);
முழு	 ssh_packet_write_wait(கட்டமைப்பு ssh *);
முழு      ssh_packet_have_data_to_write(கட்டமைப்பு ssh *);
முழு      ssh_packet_not_very_much_data_to_write(கட்டமைப்பு ssh *);
முழு	 ssh_packet_interactive_data_to_write(கட்டமைப்பு ssh *);

முழு	 ssh_packet_connection_is_on_socket(கட்டமைப்பு ssh *);
முழு	 ssh_packet_remaining(கட்டமைப்பு ssh *);

வெறுமை	 ssh_tty_make_modes(கட்டமைப்பு ssh *, முழு, கட்டமைப்பு termios *);
வெறுமை	 ssh_tty_parse_modes(கட்டமைப்பு ssh *, முழு);

வெறுமை	 ssh_packet_set_alive_timeouts(கட்டமைப்பு ssh *, முழு);
முழு	 ssh_packet_inc_alive_timeouts(கட்டமைப்பு ssh *);
முழு	 ssh_packet_set_maxsize(கட்டமைப்பு ssh *, u_int);
u_int	 ssh_packet_get_maxsize(கட்டமைப்பு ssh *);

முழு	 ssh_packet_get_state(கட்டமைப்பு ssh *, கட்டமைப்பு sshbuf *);
முழு	 ssh_packet_set_state(கட்டமைப்பு ssh *, கட்டமைப்பு sshbuf *);

மாறிலி எழுத்து *ssh_remote_ipaddr(கட்டமைப்பு ssh *);
முழு	 ssh_remote_port(கட்டமைப்பு ssh *);
மாறிலி எழுத்து *ssh_local_ipaddr(கட்டமைப்பு ssh *);
முழு	 ssh_local_port(கட்டமைப்பு ssh *);
மாறிலி எழுத்து *ssh_packet_rdomain_in(கட்டமைப்பு ssh *);
எழுத்து	*ssh_remote_hostname(கட்டமைப்பு ssh *);

வெறுமை	 ssh_packet_set_rekey_limits(கட்டமைப்பு ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(கட்டமைப்பு ssh *);

வெறுமை	*ssh_packet_get_உள்ளீடு(கட்டமைப்பு ssh *);
வெறுமை	*ssh_packet_get_output(கட்டமைப்பு ssh *);

/* new API */
முழு	sshpkt_start(கட்டமைப்பு ssh *ssh, u_char type);
முழு	sshpkt_send(கட்டமைப்பு ssh *ssh);
முழு     sshpkt_disconnect(கட்டமைப்பு ssh *, மாறிலி எழுத்து *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
முழு	sshpkt_add_padding(கட்டமைப்பு ssh *, u_char);
வெறுமை	sshpkt_fatal(கட்டமைப்பு ssh *ssh, முழு r, மாறிலி எழுத்து *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
முழு	sshpkt_செய்தி_ignore(கட்டமைப்பு ssh *, u_int);

முழு	sshpkt_put(கட்டமைப்பு ssh *ssh, மாறிலி வெறுமை *v, size_t len);
முழு	sshpkt_putb(கட்டமைப்பு ssh *ssh, மாறிலி கட்டமைப்பு sshbuf *b);
முழு	sshpkt_put_u8(கட்டமைப்பு ssh *ssh, u_char val);
முழு	sshpkt_put_u32(கட்டமைப்பு ssh *ssh, uint32_t val);
முழு	sshpkt_put_u64(கட்டமைப்பு ssh *ssh, uint64_t val);
முழு	sshpkt_put_string(கட்டமைப்பு ssh *ssh, மாறிலி வெறுமை *v, size_t len);
முழு	sshpkt_put_cstring(கட்டமைப்பு ssh *ssh, மாறிலி வெறுமை *v);
முழு	sshpkt_put_stringb(கட்டமைப்பு ssh *ssh, மாறிலி கட்டமைப்பு sshbuf *v);
முழு	sshpkt_put_ec(கட்டமைப்பு ssh *ssh, மாறிலி EC_POINT *v, மாறிலி EC_GROUP *g);
முழு	sshpkt_put_ec_pkey(கட்டமைப்பு ssh *ssh, EVP_PKEY *pkey);
முழு	sshpkt_put_bignum2(கட்டமைப்பு ssh *ssh, மாறிலி BIGNUM *v);

முழு	sshpkt_get(கட்டமைப்பு ssh *ssh, வெறுமை *valp, size_t len);
முழு	sshpkt_get_u8(கட்டமைப்பு ssh *ssh, u_char *valp);
முழு	sshpkt_get_u32(கட்டமைப்பு ssh *ssh, uint32_t *valp);
முழு	sshpkt_get_u64(கட்டமைப்பு ssh *ssh, uint64_t *valp);
முழு	sshpkt_get_string(கட்டமைப்பு ssh *ssh, u_char **valp, size_t *lenp);
முழு	sshpkt_get_string_direct(கட்டமைப்பு ssh *ssh, மாறிலி u_char **valp, size_t *lenp);
முழு	sshpkt_peek_string_direct(கட்டமைப்பு ssh *ssh, மாறிலி u_char **valp, size_t *lenp);
முழு	sshpkt_get_cstring(கட்டமைப்பு ssh *ssh, எழுத்து **valp, size_t *lenp);
முழு	sshpkt_getb_froms(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshbuf **valp);
முழு	sshpkt_get_ec(கட்டமைப்பு ssh *ssh, EC_POINT *v, மாறிலி EC_GROUP *g);
முழு	sshpkt_get_bignum2(கட்டமைப்பு ssh *ssh, BIGNUM **valp);
முழு	sshpkt_get_end(கட்டமைப்பு ssh *ssh);
வெறுமை	sshpkt_fmt_connection_id(கட்டமைப்பு ssh *ssh, எழுத்து *s, size_t l);
மாறிலி u_char	*sshpkt_ptr(கட்டமைப்பு ssh *, size_t *lenp);
எழுத்து	*connection_info_message(கட்டமைப்பு ssh *ssh);

#endif				/* PACKET_H */
