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

#اگر_غیر_تعریف_شدہ PACKET_H
#تعریف_کرو PACKET_H

#شامل <sys/queue.h>

#شامل <stdint.h>
#شامل <signal.h>
#شامل <termios.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>
#ورنہ /* OPENSSL */
#تعریف_کرو BIGNUM		خالی
#تعریف_کرو EC_گروہ	خالی
#تعریف_کرو EC_نقطہ	خالی
#تعریف_کرو EVP_PKEY	خالی
#اگر_ختم /* WITH_OPENSSL */

ساخت kex;
ساخت sshkey;
ساخت sshbuf;
ساخت session_state;	/* private session data */

#شامل "dispatch.h"	/* typedef, DISPATCH_MAX */

ساخت کلید_اندراج {
	TAILQ_ENTRY(کلید_اندراج) اگلا;
	ساخت sshkey *کلید;
};

ساخت ssh {
	/* Session state */
	ساخت session_state *state;

	/* Key exchange */
	ساخت kex *kex;

	/* cached local and remote ip addresses and ports */
	حرف *remote_ipaddr;
	صحیح remote_پورٹ;
	حرف *local_ipaddr;
	صحیح local_پورٹ;
	حرف *rdomain_اندر;

	/* Optional preamble for log messages (e.g. username) */
	حرف *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	صحیح dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	حرف *remote_نسخہ;

	/* Lists for private and public keys */
	TAILQ_HEAD(, کلید_اندراج) نجی_کلیدیں;
	TAILQ_HEAD(, کلید_اندراج) عوامی_کلیدیں;

	/* Client/Server authentication context */
	خالی *authctxt;

	/* Channels context */
	ساخت ssh_channels *chanctxt;

	/* APP data */
	خالی *app_ڈیٹا;
};

قسمتعریف صحیح (ssh_packet_hook_fn)(ساخت ssh *, ساخت sshbuf *,
    u_char *, خالی *);

ساخت ssh *ssh_alloc_session_state(خالی);
ساخت ssh *ssh_packet_سیٹ_connection(ساخت ssh *, صحیح, صحیح);
خالی     ssh_packet_سیٹ_timeout(ساخت ssh *, صحیح, صحیح);
صحیح	 ssh_packet_stop_discard(ساخت ssh *);
صحیح	 ssh_packet_connection_af(ساخت ssh *);
خالی     ssh_packet_سیٹ_nonblocking(ساخت ssh *);
صحیح      ssh_packet_get_connection_اندر(ساخت ssh *);
صحیح      ssh_packet_get_connection_برآمد(ساخت ssh *);
خالی	 ssh_packet_free(ساخت ssh *);
خالی     ssh_packet_close(ساخت ssh *);
خالی	 ssh_packet_سیٹ_داخلہ_hook(ساخت ssh *, ssh_packet_hook_fn *, خالی *);
خالی	 ssh_packet_clear_کلیدیں(ساخت ssh *);
خالی	 ssh_clear_newkeys(ساخت ssh *, صحیح);

صحیح	 ssh_packet_is_rekeying(ساخت ssh *);
صحیح	 ssh_packet_check_rekey(ساخت ssh *);
خالی     ssh_packet_سیٹ_protocol_flags(ساخت ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(ساخت ssh *);
خالی	 ssh_packet_سیٹ_interactive(ساخت ssh *, صحیح);
خالی	 ssh_packet_سیٹ_qos(ساخت ssh *, صحیح, صحیح);
خالی     ssh_packet_سیٹ_server(ساخت ssh *);
خالی     ssh_packet_سیٹ_authenticated(ساخت ssh *);
خالی     ssh_packet_سیٹ_mux(ساخت ssh *);
صحیح	 ssh_packet_get_mux(ساخت ssh *);
صحیح	 ssh_packet_سیٹ_log_preamble(ساخت ssh *, ثابت حرف *, ...)
    __attribute__((format(لکھو, 2, 3)));

صحیح	 ssh_packet_log_type(u_char);

صحیح	 ssh_packet_send2_wrapped(ساخت ssh *);
صحیح	 ssh_packet_send2(ساخت ssh *);

صحیح      ssh_packet_read(ساخت ssh *);
صحیح ssh_packet_read_poll2(ساخت ssh *, u_char *, uint32_t *seqnr_p);
صحیح	 ssh_packet_process_incoming(ساخت ssh *, ثابت حرف *buf, u_int len);
صحیح	 ssh_packet_process_read(ساخت ssh *, صحیح);
صحیح      ssh_packet_read_seqnr(ساخت ssh *, u_char *, uint32_t *seqnr_p);
صحیح      ssh_packet_read_poll_seqnr(ساخت ssh *, u_char *, uint32_t *seqnr_p);

خالی     ssh_packet_disconnect(ساخت ssh *, ثابت حرف *fmt, ...)
	__attribute__((format(لکھو, 2, 3)))
	__attribute__((noreturn));
خالی     ssh_packet_send_debug(ساخت ssh *, ثابت حرف *fmt, ...) __attribute__((format(لکھو, 2, 3)));

صحیح	 ssh_سیٹ_newkeys(ساخت ssh *, صحیح منوال);
خالی	 ssh_packet_get_بائٹیں(ساخت ssh *, uint64_t *, uint64_t *);

صحیح	 ssh_packet_write_poll(ساخت ssh *);
صحیح	 ssh_packet_write_wait(ساخت ssh *);
صحیح      ssh_packet_have_ڈیٹا_مقصد_write(ساخت ssh *);
صحیح      ssh_packet_not_very_much_ڈیٹا_مقصد_write(ساخت ssh *);
صحیح	 ssh_packet_interactive_ڈیٹا_مقصد_write(ساخت ssh *);

صحیح	 ssh_packet_connection_is_on_socket(ساخت ssh *);
صحیح	 ssh_packet_بقایا(ساخت ssh *);

خالی	 ssh_tty_make_modes(ساخت ssh *, صحیح, ساخت termios *);
خالی	 ssh_tty_parse_modes(ساخت ssh *, صحیح);

خالی	 ssh_packet_سیٹ_alive_timeouts(ساخت ssh *, صحیح);
صحیح	 ssh_packet_inc_alive_timeouts(ساخت ssh *);
صحیح	 ssh_packet_سیٹ_maxsize(ساخت ssh *, u_int);
u_int	 ssh_packet_get_maxsize(ساخت ssh *);

صحیح	 ssh_packet_get_state(ساخت ssh *, ساخت sshbuf *);
صحیح	 ssh_packet_سیٹ_state(ساخت ssh *, ساخت sshbuf *);

ثابت حرف *ssh_remote_ipaddr(ساخت ssh *);
صحیح	 ssh_remote_پورٹ(ساخت ssh *);
ثابت حرف *ssh_local_ipaddr(ساخت ssh *);
صحیح	 ssh_local_پورٹ(ساخت ssh *);
ثابت حرف *ssh_packet_rdomain_اندر(ساخت ssh *);
حرف	*ssh_remote_hostname(ساخت ssh *);

خالی	 ssh_packet_سیٹ_rekey_limits(ساخت ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(ساخت ssh *);

خالی	*ssh_packet_get_داخلہ(ساخت ssh *);
خالی	*ssh_packet_get_output(ساخت ssh *);

/* new API */
صحیح	sshpkt_آغاز(ساخت ssh *ssh, u_char type);
صحیح	sshpkt_send(ساخت ssh *ssh);
صحیح     sshpkt_disconnect(ساخت ssh *, ثابت حرف *fmt, ...)
	    __attribute__((format(لکھو, 2, 3)));
صحیح	sshpkt_جوڑو_padding(ساخت ssh *, u_char);
خالی	sshpkt_fatal(ساخت ssh *ssh, صحیح r, ثابت حرف *fmt, ...)
	    __attribute__((format(لکھو, 3, 4)))
	    __attribute__((noreturn));
صحیح	sshpkt_پیغام_ignore(ساخت ssh *, u_int);

صحیح	sshpkt_put(ساخت ssh *ssh, ثابت خالی *v, سائز_t len);
صحیح	sshpkt_putb(ساخت ssh *ssh, ثابت ساخت sshbuf *b);
صحیح	sshpkt_put_u8(ساخت ssh *ssh, u_char val);
صحیح	sshpkt_put_u32(ساخت ssh *ssh, uint32_t val);
صحیح	sshpkt_put_u64(ساخت ssh *ssh, uint64_t val);
صحیح	sshpkt_put_string(ساخت ssh *ssh, ثابت خالی *v, سائز_t len);
صحیح	sshpkt_put_cstring(ساخت ssh *ssh, ثابت خالی *v);
صحیح	sshpkt_put_stringb(ساخت ssh *ssh, ثابت ساخت sshbuf *v);
صحیح	sshpkt_put_ec(ساخت ssh *ssh, ثابت EC_نقطہ *v, ثابت EC_گروہ *g);
صحیح	sshpkt_put_ec_pkey(ساخت ssh *ssh, EVP_PKEY *pkey);
صحیح	sshpkt_put_bignum2(ساخت ssh *ssh, ثابت BIGNUM *v);

صحیح	sshpkt_get(ساخت ssh *ssh, خالی *valp, سائز_t len);
صحیح	sshpkt_get_u8(ساخت ssh *ssh, u_char *valp);
صحیح	sshpkt_get_u32(ساخت ssh *ssh, uint32_t *valp);
صحیح	sshpkt_get_u64(ساخت ssh *ssh, uint64_t *valp);
صحیح	sshpkt_get_string(ساخت ssh *ssh, u_char **valp, سائز_t *lenp);
صحیح	sshpkt_get_string_براہ_راست(ساخت ssh *ssh, ثابت u_char **valp, سائز_t *lenp);
صحیح	sshpkt_peek_string_براہ_راست(ساخت ssh *ssh, ثابت u_char **valp, سائز_t *lenp);
صحیح	sshpkt_get_cstring(ساخت ssh *ssh, حرف **valp, سائز_t *lenp);
صحیح	sshpkt_getb_froms(ساخت ssh *ssh, ساخت sshbuf **valp);
صحیح	sshpkt_get_ec(ساخت ssh *ssh, EC_نقطہ *v, ثابت EC_گروہ *g);
صحیح	sshpkt_get_bignum2(ساخت ssh *ssh, BIGNUM **valp);
صحیح	sshpkt_get_انتہا(ساخت ssh *ssh);
خالی	sshpkt_fmt_connection_id(ساخت ssh *ssh, حرف *s, سائز_t l);
ثابت u_char	*sshpkt_ptr(ساخت ssh *, سائز_t *lenp);
حرف	*connection_info_پیغام(ساخت ssh *ssh);

#اگر_ختم				/* PACKET_H */
