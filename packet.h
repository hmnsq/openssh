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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ PACKET_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PACKET_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <termios.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਨਹੀਂਤਾਂ /* OPENSSL */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BIGNUM		ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਸਮੂਹ	ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਬਿੰਦੂ	ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EVP_PKEY	ਖਾਲੀ
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਬਣਤਰ kex;
ਬਣਤਰ sshkey;
ਬਣਤਰ sshbuf;
ਬਣਤਰ session_state;	/* private session data */

#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"	/* typedef, DISPATCH_MAX */

ਬਣਤਰ ਕੁੰਜੀ_ਇੰਦਰਾਜ {
	TAILQ_ENTRY(ਕੁੰਜੀ_ਇੰਦਰਾਜ) ਅਗਲਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
};

ਬਣਤਰ ssh {
	/* Session state */
	ਬਣਤਰ session_state *state;

	/* Key exchange */
	ਬਣਤਰ kex *kex;

	/* cached local and remote ip addresses and ports */
	ਅੱਖਰ *remote_ipaddr;
	ਪੂਰਨ remote_ਪੋਰਟ;
	ਅੱਖਰ *local_ipaddr;
	ਪੂਰਨ local_ਪੋਰਟ;
	ਅੱਖਰ *rdomain_ਵਿੱਚ;

	/* Optional preamble for log messages (e.g. username) */
	ਅੱਖਰ *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	ਪੂਰਨ dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	ਅੱਖਰ *remote_ਸੰਸਕਰਣ;

	/* Lists for private and public keys */
	TAILQ_HEAD(, ਕੁੰਜੀ_ਇੰਦਰਾਜ) ਨਿੱਜੀ_ਕੁੰਜੀਆਂ;
	TAILQ_HEAD(, ਕੁੰਜੀ_ਇੰਦਰਾਜ) ਜਨਤਕ_ਕੁੰਜੀਆਂ;

	/* Client/Server authentication context */
	ਖਾਲੀ *authctxt;

	/* Channels context */
	ਬਣਤਰ ssh_channels *chanctxt;

	/* APP data */
	ਖਾਲੀ *app_ਅੰਕੜੇ;
};

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ (ssh_packet_hook_fn)(ਬਣਤਰ ssh *, ਬਣਤਰ sshbuf *,
    u_char *, ਖਾਲੀ *);

ਬਣਤਰ ssh *ssh_alloc_session_state(ਖਾਲੀ);
ਬਣਤਰ ssh *ssh_packet_ਸੈੱਟ_connection(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ);
ਖਾਲੀ     ssh_packet_ਸੈੱਟ_timeout(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ);
ਪੂਰਨ	 ssh_packet_stop_discard(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_packet_connection_af(ਬਣਤਰ ssh *);
ਖਾਲੀ     ssh_packet_ਸੈੱਟ_nonblocking(ਬਣਤਰ ssh *);
ਪੂਰਨ      ssh_packet_get_connection_ਵਿੱਚ(ਬਣਤਰ ssh *);
ਪੂਰਨ      ssh_packet_get_connection_ਬਾਹਰਲਾ(ਬਣਤਰ ssh *);
ਖਾਲੀ	 ssh_packet_free(ਬਣਤਰ ssh *);
ਖਾਲੀ     ssh_packet_close(ਬਣਤਰ ssh *);
ਖਾਲੀ	 ssh_packet_ਸੈੱਟ_ਨਿਵੇਸ਼_hook(ਬਣਤਰ ssh *, ssh_packet_hook_fn *, ਖਾਲੀ *);
ਖਾਲੀ	 ssh_packet_clear_ਕੁੰਜੀਆਂ(ਬਣਤਰ ssh *);
ਖਾਲੀ	 ssh_clear_newkeys(ਬਣਤਰ ssh *, ਪੂਰਨ);

ਪੂਰਨ	 ssh_packet_is_rekeying(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_packet_check_rekey(ਬਣਤਰ ssh *);
ਖਾਲੀ     ssh_packet_ਸੈੱਟ_protocol_flags(ਬਣਤਰ ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(ਬਣਤਰ ssh *);
ਖਾਲੀ	 ssh_packet_ਸੈੱਟ_interactive(ਬਣਤਰ ssh *, ਪੂਰਨ);
ਖਾਲੀ	 ssh_packet_ਸੈੱਟ_qos(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ);
ਖਾਲੀ     ssh_packet_ਸੈੱਟ_server(ਬਣਤਰ ssh *);
ਖਾਲੀ     ssh_packet_ਸੈੱਟ_authenticated(ਬਣਤਰ ssh *);
ਖਾਲੀ     ssh_packet_ਸੈੱਟ_mux(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_packet_get_mux(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_packet_ਸੈੱਟ_log_preamble(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *, ...)
    __attribute__((format(ਲਿਖੋ, 2, 3)));

ਪੂਰਨ	 ssh_packet_log_type(u_char);

ਪੂਰਨ	 ssh_packet_send2_wrapped(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_packet_send2(ਬਣਤਰ ssh *);

ਪੂਰਨ      ssh_packet_read(ਬਣਤਰ ssh *);
ਪੂਰਨ ssh_packet_read_poll2(ਬਣਤਰ ssh *, u_char *, uint32_t *seqnr_p);
ਪੂਰਨ	 ssh_packet_process_incoming(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *buf, u_int len);
ਪੂਰਨ	 ssh_packet_process_read(ਬਣਤਰ ssh *, ਪੂਰਨ);
ਪੂਰਨ      ssh_packet_read_seqnr(ਬਣਤਰ ssh *, u_char *, uint32_t *seqnr_p);
ਪੂਰਨ      ssh_packet_read_poll_seqnr(ਬਣਤਰ ssh *, u_char *, uint32_t *seqnr_p);

ਖਾਲੀ     ssh_packet_disconnect(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *fmt, ...)
	__attribute__((format(ਲਿਖੋ, 2, 3)))
	__attribute__((noreturn));
ਖਾਲੀ     ssh_packet_send_debug(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *fmt, ...) __attribute__((format(ਲਿਖੋ, 2, 3)));

ਪੂਰਨ	 ssh_ਸੈੱਟ_newkeys(ਬਣਤਰ ssh *, ਪੂਰਨ ਬਹੁਲਕ);
ਖਾਲੀ	 ssh_packet_get_ਬਾਈਟਾਂ(ਬਣਤਰ ssh *, uint64_t *, uint64_t *);

ਪੂਰਨ	 ssh_packet_write_poll(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_packet_write_wait(ਬਣਤਰ ssh *);
ਪੂਰਨ      ssh_packet_have_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ਬਣਤਰ ssh *);
ਪੂਰਨ      ssh_packet_not_very_much_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_packet_interactive_ਅੰਕੜੇ_ਮੰਜ਼ਿਲ_write(ਬਣਤਰ ssh *);

ਪੂਰਨ	 ssh_packet_connection_is_on_socket(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_packet_ਬਚਿਆ(ਬਣਤਰ ssh *);

ਖਾਲੀ	 ssh_tty_make_modes(ਬਣਤਰ ssh *, ਪੂਰਨ, ਬਣਤਰ termios *);
ਖਾਲੀ	 ssh_tty_parse_modes(ਬਣਤਰ ssh *, ਪੂਰਨ);

ਖਾਲੀ	 ssh_packet_ਸੈੱਟ_alive_timeouts(ਬਣਤਰ ssh *, ਪੂਰਨ);
ਪੂਰਨ	 ssh_packet_inc_alive_timeouts(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_packet_ਸੈੱਟ_maxsize(ਬਣਤਰ ssh *, u_int);
u_int	 ssh_packet_get_maxsize(ਬਣਤਰ ssh *);

ਪੂਰਨ	 ssh_packet_get_state(ਬਣਤਰ ssh *, ਬਣਤਰ sshbuf *);
ਪੂਰਨ	 ssh_packet_ਸੈੱਟ_state(ਬਣਤਰ ssh *, ਬਣਤਰ sshbuf *);

ਅਚਲ ਅੱਖਰ *ssh_remote_ipaddr(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_remote_ਪੋਰਟ(ਬਣਤਰ ssh *);
ਅਚਲ ਅੱਖਰ *ssh_local_ipaddr(ਬਣਤਰ ssh *);
ਪੂਰਨ	 ssh_local_ਪੋਰਟ(ਬਣਤਰ ssh *);
ਅਚਲ ਅੱਖਰ *ssh_packet_rdomain_ਵਿੱਚ(ਬਣਤਰ ssh *);
ਅੱਖਰ	*ssh_remote_hostname(ਬਣਤਰ ssh *);

ਖਾਲੀ	 ssh_packet_ਸੈੱਟ_rekey_limits(ਬਣਤਰ ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(ਬਣਤਰ ssh *);

ਖਾਲੀ	*ssh_packet_get_ਨਿਵੇਸ਼(ਬਣਤਰ ssh *);
ਖਾਲੀ	*ssh_packet_get_output(ਬਣਤਰ ssh *);

/* new API */
ਪੂਰਨ	sshpkt_ਸ਼ੁਰੂ(ਬਣਤਰ ssh *ssh, u_char type);
ਪੂਰਨ	sshpkt_send(ਬਣਤਰ ssh *ssh);
ਪੂਰਨ     sshpkt_disconnect(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *fmt, ...)
	    __attribute__((format(ਲਿਖੋ, 2, 3)));
ਪੂਰਨ	sshpkt_ਜੋੜੋ_padding(ਬਣਤਰ ssh *, u_char);
ਖਾਲੀ	sshpkt_fatal(ਬਣਤਰ ssh *ssh, ਪੂਰਨ r, ਅਚਲ ਅੱਖਰ *fmt, ...)
	    __attribute__((format(ਲਿਖੋ, 3, 4)))
	    __attribute__((noreturn));
ਪੂਰਨ	sshpkt_ਸੁਨੇਹਾ_ignore(ਬਣਤਰ ssh *, u_int);

ਪੂਰਨ	sshpkt_put(ਬਣਤਰ ssh *ssh, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len);
ਪੂਰਨ	sshpkt_putb(ਬਣਤਰ ssh *ssh, ਅਚਲ ਬਣਤਰ sshbuf *b);
ਪੂਰਨ	sshpkt_put_u8(ਬਣਤਰ ssh *ssh, u_char val);
ਪੂਰਨ	sshpkt_put_u32(ਬਣਤਰ ssh *ssh, uint32_t val);
ਪੂਰਨ	sshpkt_put_u64(ਬਣਤਰ ssh *ssh, uint64_t val);
ਪੂਰਨ	sshpkt_put_string(ਬਣਤਰ ssh *ssh, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len);
ਪੂਰਨ	sshpkt_put_cstring(ਬਣਤਰ ssh *ssh, ਅਚਲ ਖਾਲੀ *v);
ਪੂਰਨ	sshpkt_put_stringb(ਬਣਤਰ ssh *ssh, ਅਚਲ ਬਣਤਰ sshbuf *v);
ਪੂਰਨ	sshpkt_put_ec(ਬਣਤਰ ssh *ssh, ਅਚਲ EC_ਬਿੰਦੂ *v, ਅਚਲ EC_ਸਮੂਹ *g);
ਪੂਰਨ	sshpkt_put_ec_pkey(ਬਣਤਰ ssh *ssh, EVP_PKEY *pkey);
ਪੂਰਨ	sshpkt_put_bignum2(ਬਣਤਰ ssh *ssh, ਅਚਲ BIGNUM *v);

ਪੂਰਨ	sshpkt_get(ਬਣਤਰ ssh *ssh, ਖਾਲੀ *valp, ਮਾਪ_t len);
ਪੂਰਨ	sshpkt_get_u8(ਬਣਤਰ ssh *ssh, u_char *valp);
ਪੂਰਨ	sshpkt_get_u32(ਬਣਤਰ ssh *ssh, uint32_t *valp);
ਪੂਰਨ	sshpkt_get_u64(ਬਣਤਰ ssh *ssh, uint64_t *valp);
ਪੂਰਨ	sshpkt_get_string(ਬਣਤਰ ssh *ssh, u_char **valp, ਮਾਪ_t *lenp);
ਪੂਰਨ	sshpkt_get_string_ਸਿੱਧਾ(ਬਣਤਰ ssh *ssh, ਅਚਲ u_char **valp, ਮਾਪ_t *lenp);
ਪੂਰਨ	sshpkt_peek_string_ਸਿੱਧਾ(ਬਣਤਰ ssh *ssh, ਅਚਲ u_char **valp, ਮਾਪ_t *lenp);
ਪੂਰਨ	sshpkt_get_cstring(ਬਣਤਰ ssh *ssh, ਅੱਖਰ **valp, ਮਾਪ_t *lenp);
ਪੂਰਨ	sshpkt_getb_froms(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf **valp);
ਪੂਰਨ	sshpkt_get_ec(ਬਣਤਰ ssh *ssh, EC_ਬਿੰਦੂ *v, ਅਚਲ EC_ਸਮੂਹ *g);
ਪੂਰਨ	sshpkt_get_bignum2(ਬਣਤਰ ssh *ssh, BIGNUM **valp);
ਪੂਰਨ	sshpkt_get_ਸਿਰਾ(ਬਣਤਰ ssh *ssh);
ਖਾਲੀ	sshpkt_fmt_connection_id(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *s, ਮਾਪ_t l);
ਅਚਲ u_char	*sshpkt_ptr(ਬਣਤਰ ssh *, ਮਾਪ_t *lenp);
ਅੱਖਰ	*connection_info_ਸੁਨੇਹਾ(ਬਣਤਰ ssh *ssh);

#ਜੇ_ਅੰਤ				/* PACKET_H */
