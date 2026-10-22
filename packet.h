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

#شامل <sys/queue.h>

#شامل <stdint.h>
#شامل <signal.h>
#شامل <termios.h>

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>
#وگرنه /* OPENSSL */
#define BIGNUM		تهی
#define EC_GROUP	تهی
#define EC_POINT	تهی
#define EVP_PKEY	تهی
#endif /* WITH_OPENSSL */

ساختار kex;
ساختار sshkey;
ساختار sshbuf;
ساختار session_state;	/* private session data */

#شامل "dispatch.h"	/* typedef, DISPATCH_MAX */

ساختار کلید_entry {
	TAILQ_ENTRY(کلید_entry) next;
	ساختار sshkey *کلید;
};

ساختار ssh {
	/* Session state */
	ساختار session_state *state;

	/* Key exchange */
	ساختار kex *kex;

	/* cached local and remote ip addresses and ports */
	نویسه *remote_ipaddr;
	صحیح remote_port;
	نویسه *local_ipaddr;
	صحیح local_port;
	نویسه *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	نویسه *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	صحیح dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	نویسه *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, کلید_entry) private_کلیدها;
	TAILQ_HEAD(, کلید_entry) public_کلیدها;

	/* Client/Server authentication context */
	تهی *authctxt;

	/* Channels context */
	ساختار ssh_channels *chanctxt;

	/* APP data */
	تهی *app_data;
};

تعریفنوع صحیح (ssh_packet_hook_fn)(ساختار ssh *, ساختار sshbuf *,
    u_char *, تهی *);

ساختار ssh *ssh_alloc_session_state(تهی);
ساختار ssh *ssh_packet_set_connection(ساختار ssh *, صحیح, صحیح);
تهی     ssh_packet_set_timeout(ساختار ssh *, صحیح, صحیح);
صحیح	 ssh_packet_stop_discard(ساختار ssh *);
صحیح	 ssh_packet_connection_af(ساختار ssh *);
تهی     ssh_packet_set_nonblocking(ساختار ssh *);
صحیح      ssh_packet_get_connection_in(ساختار ssh *);
صحیح      ssh_packet_get_connection_out(ساختار ssh *);
تهی	 ssh_packet_free(ساختار ssh *);
تهی     ssh_packet_close(ساختار ssh *);
تهی	 ssh_packet_set_درون_داد_hook(ساختار ssh *, ssh_packet_hook_fn *, تهی *);
تهی	 ssh_packet_clear_کلیدها(ساختار ssh *);
تهی	 ssh_clear_newkeys(ساختار ssh *, صحیح);

صحیح	 ssh_packet_is_rekeying(ساختار ssh *);
صحیح	 ssh_packet_check_rekey(ساختار ssh *);
تهی     ssh_packet_set_protocol_flags(ساختار ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(ساختار ssh *);
تهی	 ssh_packet_set_interactive(ساختار ssh *, صحیح);
تهی	 ssh_packet_set_qos(ساختار ssh *, صحیح, صحیح);
تهی     ssh_packet_set_server(ساختار ssh *);
تهی     ssh_packet_set_authenticated(ساختار ssh *);
تهی     ssh_packet_set_mux(ساختار ssh *);
صحیح	 ssh_packet_get_mux(ساختار ssh *);
صحیح	 ssh_packet_set_log_preamble(ساختار ssh *, ثابت نویسه *, ...)
    __attribute__((format(printf, 2, 3)));

صحیح	 ssh_packet_log_type(u_char);

صحیح	 ssh_packet_send2_wrapped(ساختار ssh *);
صحیح	 ssh_packet_send2(ساختار ssh *);

صحیح      ssh_packet_read(ساختار ssh *);
صحیح ssh_packet_read_poll2(ساختار ssh *, u_char *, uint32_t *seqnr_p);
صحیح	 ssh_packet_process_incoming(ساختار ssh *, ثابت نویسه *buf, u_int len);
صحیح	 ssh_packet_process_read(ساختار ssh *, صحیح);
صحیح      ssh_packet_read_seqnr(ساختار ssh *, u_char *, uint32_t *seqnr_p);
صحیح      ssh_packet_read_poll_seqnr(ساختار ssh *, u_char *, uint32_t *seqnr_p);

تهی     ssh_packet_disconnect(ساختار ssh *, ثابت نویسه *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
تهی     ssh_packet_send_debug(ساختار ssh *, ثابت نویسه *fmt, ...) __attribute__((format(printf, 2, 3)));

صحیح	 ssh_set_newkeys(ساختار ssh *, صحیح mode);
تهی	 ssh_packet_get_bytes(ساختار ssh *, uint64_t *, uint64_t *);

صحیح	 ssh_packet_write_poll(ساختار ssh *);
صحیح	 ssh_packet_write_wait(ساختار ssh *);
صحیح      ssh_packet_have_data_to_write(ساختار ssh *);
صحیح      ssh_packet_not_very_much_data_to_write(ساختار ssh *);
صحیح	 ssh_packet_interactive_data_to_write(ساختار ssh *);

صحیح	 ssh_packet_connection_is_on_socket(ساختار ssh *);
صحیح	 ssh_packet_remaining(ساختار ssh *);

تهی	 ssh_tty_make_modes(ساختار ssh *, صحیح, ساختار termios *);
تهی	 ssh_tty_parse_modes(ساختار ssh *, صحیح);

تهی	 ssh_packet_set_alive_timeouts(ساختار ssh *, صحیح);
صحیح	 ssh_packet_inc_alive_timeouts(ساختار ssh *);
صحیح	 ssh_packet_set_maxsize(ساختار ssh *, u_int);
u_int	 ssh_packet_get_maxsize(ساختار ssh *);

صحیح	 ssh_packet_get_state(ساختار ssh *, ساختار sshbuf *);
صحیح	 ssh_packet_set_state(ساختار ssh *, ساختار sshbuf *);

ثابت نویسه *ssh_remote_ipaddr(ساختار ssh *);
صحیح	 ssh_remote_port(ساختار ssh *);
ثابت نویسه *ssh_local_ipaddr(ساختار ssh *);
صحیح	 ssh_local_port(ساختار ssh *);
ثابت نویسه *ssh_packet_rdomain_in(ساختار ssh *);
نویسه	*ssh_remote_hostname(ساختار ssh *);

تهی	 ssh_packet_set_rekey_limits(ساختار ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(ساختار ssh *);

تهی	*ssh_packet_get_درون_داد(ساختار ssh *);
تهی	*ssh_packet_get_output(ساختار ssh *);

/* new API */
صحیح	sshpkt_start(ساختار ssh *ssh, u_char type);
صحیح	sshpkt_send(ساختار ssh *ssh);
صحیح     sshpkt_disconnect(ساختار ssh *, ثابت نویسه *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
صحیح	sshpkt_add_padding(ساختار ssh *, u_char);
تهی	sshpkt_fatal(ساختار ssh *ssh, صحیح r, ثابت نویسه *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
صحیح	sshpkt_پیام_ignore(ساختار ssh *, u_int);

صحیح	sshpkt_put(ساختار ssh *ssh, ثابت تهی *v, size_t len);
صحیح	sshpkt_putb(ساختار ssh *ssh, ثابت ساختار sshbuf *b);
صحیح	sshpkt_put_u8(ساختار ssh *ssh, u_char val);
صحیح	sshpkt_put_u32(ساختار ssh *ssh, uint32_t val);
صحیح	sshpkt_put_u64(ساختار ssh *ssh, uint64_t val);
صحیح	sshpkt_put_string(ساختار ssh *ssh, ثابت تهی *v, size_t len);
صحیح	sshpkt_put_cstring(ساختار ssh *ssh, ثابت تهی *v);
صحیح	sshpkt_put_stringb(ساختار ssh *ssh, ثابت ساختار sshbuf *v);
صحیح	sshpkt_put_ec(ساختار ssh *ssh, ثابت EC_POINT *v, ثابت EC_GROUP *g);
صحیح	sshpkt_put_ec_pkey(ساختار ssh *ssh, EVP_PKEY *pkey);
صحیح	sshpkt_put_bignum2(ساختار ssh *ssh, ثابت BIGNUM *v);

صحیح	sshpkt_get(ساختار ssh *ssh, تهی *valp, size_t len);
صحیح	sshpkt_get_u8(ساختار ssh *ssh, u_char *valp);
صحیح	sshpkt_get_u32(ساختار ssh *ssh, uint32_t *valp);
صحیح	sshpkt_get_u64(ساختار ssh *ssh, uint64_t *valp);
صحیح	sshpkt_get_string(ساختار ssh *ssh, u_char **valp, size_t *lenp);
صحیح	sshpkt_get_string_direct(ساختار ssh *ssh, ثابت u_char **valp, size_t *lenp);
صحیح	sshpkt_peek_string_direct(ساختار ssh *ssh, ثابت u_char **valp, size_t *lenp);
صحیح	sshpkt_get_cstring(ساختار ssh *ssh, نویسه **valp, size_t *lenp);
صحیح	sshpkt_getb_froms(ساختار ssh *ssh, ساختار sshbuf **valp);
صحیح	sshpkt_get_ec(ساختار ssh *ssh, EC_POINT *v, ثابت EC_GROUP *g);
صحیح	sshpkt_get_bignum2(ساختار ssh *ssh, BIGNUM **valp);
صحیح	sshpkt_get_end(ساختار ssh *ssh);
تهی	sshpkt_fmt_connection_id(ساختار ssh *ssh, نویسه *s, size_t l);
ثابت u_char	*sshpkt_ptr(ساختار ssh *, size_t *lenp);
نویسه	*connection_info_message(ساختار ssh *ssh);

#endif				/* PACKET_H */
