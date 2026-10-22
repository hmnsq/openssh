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

#ضمن <sys/queue.h>

#ضمن <stdint.h>
#ضمن <signal.h>
#ضمن <termios.h>

#ifdef WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/evp.h>
#وإلا /* OPENSSL */
#define BIGNUM		فراغ
#define EC_GROUP	فراغ
#define EC_POINT	فراغ
#define EVP_PKEY	فراغ
#endif /* WITH_OPENSSL */

بنية kex;
بنية sshkey;
بنية sshbuf;
بنية session_state;	/* private session data */

#ضمن "dispatch.h"	/* typedef, DISPATCH_MAX */

بنية key_entry {
	TAILQ_ENTRY(key_entry) next;
	بنية sshkey *key;
};

بنية ssh {
	/* Session state */
	بنية session_state *state;

	/* Key exchange */
	بنية kex *kex;

	/* cached local and remote ip addresses and ports */
	حرف *remote_ipaddr;
	صحيح remote_port;
	حرف *local_ipaddr;
	صحيح local_port;
	حرف *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	حرف *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	صحيح dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	حرف *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, key_entry) private_keys;
	TAILQ_HEAD(, key_entry) public_keys;

	/* Client/Server authentication context */
	فراغ *authctxt;

	/* Channels context */
	بنية ssh_channels *chanctxt;

	/* APP data */
	فراغ *app_data;
};

تعريفنوع صحيح (ssh_packet_hook_fn)(بنية ssh *, بنية sshbuf *,
    u_char *, فراغ *);

بنية ssh *ssh_alloc_session_state(فراغ);
بنية ssh *ssh_packet_set_connection(بنية ssh *, صحيح, صحيح);
فراغ     ssh_packet_set_timeout(بنية ssh *, صحيح, صحيح);
صحيح	 ssh_packet_stop_discard(بنية ssh *);
صحيح	 ssh_packet_connection_af(بنية ssh *);
فراغ     ssh_packet_set_nonblocking(بنية ssh *);
صحيح      ssh_packet_get_connection_in(بنية ssh *);
صحيح      ssh_packet_get_connection_out(بنية ssh *);
فراغ	 ssh_packet_free(بنية ssh *);
فراغ     ssh_packet_close(بنية ssh *);
فراغ	 ssh_packet_set_input_hook(بنية ssh *, ssh_packet_hook_fn *, فراغ *);
فراغ	 ssh_packet_clear_keys(بنية ssh *);
فراغ	 ssh_clear_newkeys(بنية ssh *, صحيح);

صحيح	 ssh_packet_is_rekeying(بنية ssh *);
صحيح	 ssh_packet_check_rekey(بنية ssh *);
فراغ     ssh_packet_set_protocol_flags(بنية ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(بنية ssh *);
فراغ	 ssh_packet_set_interactive(بنية ssh *, صحيح);
فراغ	 ssh_packet_set_qos(بنية ssh *, صحيح, صحيح);
فراغ     ssh_packet_set_server(بنية ssh *);
فراغ     ssh_packet_set_authenticated(بنية ssh *);
فراغ     ssh_packet_set_mux(بنية ssh *);
صحيح	 ssh_packet_get_mux(بنية ssh *);
صحيح	 ssh_packet_set_log_preamble(بنية ssh *, ثابت حرف *, ...)
    __attribute__((format(printf, 2, 3)));

صحيح	 ssh_packet_log_type(u_char);

صحيح	 ssh_packet_send2_wrapped(بنية ssh *);
صحيح	 ssh_packet_send2(بنية ssh *);

صحيح      ssh_packet_read(بنية ssh *);
صحيح ssh_packet_read_poll2(بنية ssh *, u_char *, uint32_t *seqnr_p);
صحيح	 ssh_packet_process_incoming(بنية ssh *, ثابت حرف *buf, u_int len);
صحيح	 ssh_packet_process_read(بنية ssh *, صحيح);
صحيح      ssh_packet_read_seqnr(بنية ssh *, u_char *, uint32_t *seqnr_p);
صحيح      ssh_packet_read_poll_seqnr(بنية ssh *, u_char *, uint32_t *seqnr_p);

فراغ     ssh_packet_disconnect(بنية ssh *, ثابت حرف *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
فراغ     ssh_packet_send_debug(بنية ssh *, ثابت حرف *fmt, ...) __attribute__((format(printf, 2, 3)));

صحيح	 ssh_set_newkeys(بنية ssh *, صحيح mode);
فراغ	 ssh_packet_get_bytes(بنية ssh *, uint64_t *, uint64_t *);

صحيح	 ssh_packet_write_poll(بنية ssh *);
صحيح	 ssh_packet_write_wait(بنية ssh *);
صحيح      ssh_packet_have_data_to_write(بنية ssh *);
صحيح      ssh_packet_not_very_much_data_to_write(بنية ssh *);
صحيح	 ssh_packet_interactive_data_to_write(بنية ssh *);

صحيح	 ssh_packet_connection_is_on_socket(بنية ssh *);
صحيح	 ssh_packet_remaining(بنية ssh *);

فراغ	 ssh_tty_make_modes(بنية ssh *, صحيح, بنية termios *);
فراغ	 ssh_tty_parse_modes(بنية ssh *, صحيح);

فراغ	 ssh_packet_set_alive_timeouts(بنية ssh *, صحيح);
صحيح	 ssh_packet_inc_alive_timeouts(بنية ssh *);
صحيح	 ssh_packet_set_maxsize(بنية ssh *, u_int);
u_int	 ssh_packet_get_maxsize(بنية ssh *);

صحيح	 ssh_packet_get_state(بنية ssh *, بنية sshbuf *);
صحيح	 ssh_packet_set_state(بنية ssh *, بنية sshbuf *);

ثابت حرف *ssh_remote_ipaddr(بنية ssh *);
صحيح	 ssh_remote_port(بنية ssh *);
ثابت حرف *ssh_local_ipaddr(بنية ssh *);
صحيح	 ssh_local_port(بنية ssh *);
ثابت حرف *ssh_packet_rdomain_in(بنية ssh *);
حرف	*ssh_remote_hostname(بنية ssh *);

فراغ	 ssh_packet_set_rekey_limits(بنية ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(بنية ssh *);

فراغ	*ssh_packet_get_input(بنية ssh *);
فراغ	*ssh_packet_get_output(بنية ssh *);

/* new API */
صحيح	sshpkt_start(بنية ssh *ssh, u_char type);
صحيح	sshpkt_send(بنية ssh *ssh);
صحيح     sshpkt_disconnect(بنية ssh *, ثابت حرف *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
صحيح	sshpkt_add_padding(بنية ssh *, u_char);
فراغ	sshpkt_fatal(بنية ssh *ssh, صحيح r, ثابت حرف *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
صحيح	sshpkt_msg_ignore(بنية ssh *, u_int);

صحيح	sshpkt_put(بنية ssh *ssh, ثابت فراغ *v, size_t len);
صحيح	sshpkt_putb(بنية ssh *ssh, ثابت بنية sshbuf *b);
صحيح	sshpkt_put_u8(بنية ssh *ssh, u_char val);
صحيح	sshpkt_put_u32(بنية ssh *ssh, uint32_t val);
صحيح	sshpkt_put_u64(بنية ssh *ssh, uint64_t val);
صحيح	sshpkt_put_string(بنية ssh *ssh, ثابت فراغ *v, size_t len);
صحيح	sshpkt_put_cstring(بنية ssh *ssh, ثابت فراغ *v);
صحيح	sshpkt_put_stringb(بنية ssh *ssh, ثابت بنية sshbuf *v);
صحيح	sshpkt_put_ec(بنية ssh *ssh, ثابت EC_POINT *v, ثابت EC_GROUP *g);
صحيح	sshpkt_put_ec_pkey(بنية ssh *ssh, EVP_PKEY *pkey);
صحيح	sshpkt_put_bignum2(بنية ssh *ssh, ثابت BIGNUM *v);

صحيح	sshpkt_get(بنية ssh *ssh, فراغ *valp, size_t len);
صحيح	sshpkt_get_u8(بنية ssh *ssh, u_char *valp);
صحيح	sshpkt_get_u32(بنية ssh *ssh, uint32_t *valp);
صحيح	sshpkt_get_u64(بنية ssh *ssh, uint64_t *valp);
صحيح	sshpkt_get_string(بنية ssh *ssh, u_char **valp, size_t *lenp);
صحيح	sshpkt_get_string_direct(بنية ssh *ssh, ثابت u_char **valp, size_t *lenp);
صحيح	sshpkt_peek_string_direct(بنية ssh *ssh, ثابت u_char **valp, size_t *lenp);
صحيح	sshpkt_get_cstring(بنية ssh *ssh, حرف **valp, size_t *lenp);
صحيح	sshpkt_getb_froms(بنية ssh *ssh, بنية sshbuf **valp);
صحيح	sshpkt_get_ec(بنية ssh *ssh, EC_POINT *v, ثابت EC_GROUP *g);
صحيح	sshpkt_get_bignum2(بنية ssh *ssh, BIGNUM **valp);
صحيح	sshpkt_get_end(بنية ssh *ssh);
فراغ	sshpkt_fmt_connection_id(بنية ssh *ssh, حرف *s, size_t l);
ثابت u_char	*sshpkt_ptr(بنية ssh *, size_t *lenp);
حرف	*connection_info_message(بنية ssh *ssh);

#endif				/* PACKET_H */
