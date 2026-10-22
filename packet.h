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

#నిర్వచితం_కాకపోతే PACKET_H
#నిర్వచించు PACKET_H

#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <stdint.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <termios.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/ecdsa.h>
#అన్తర్భావ <openssl/evp.h>
#లేకపోతే /* OPENSSL */
#నిర్వచించు BIGNUM		శూన్య
#నిర్వచించు EC_సమూహం	శూన్య
#నిర్వచించు EC_బిందువు	శూన్య
#నిర్వచించు EVP_PKEY	శూన్య
#అయితే_ముగింపు /* WITH_OPENSSL */

నిర్మాణం kex;
నిర్మాణం sshkey;
నిర్మాణం sshbuf;
నిర్మాణం session_state;	/* private session data */

#అన్తర్భావ "dispatch.h"	/* typedef, DISPATCH_MAX */

నిర్మాణం కీలకం_నమోదు {
	TAILQ_ENTRY(కీలకం_నమోదు) తదుపరి;
	నిర్మాణం sshkey *కీలకం;
};

నిర్మాణం ssh {
	/* Session state */
	నిర్మాణం session_state *state;

	/* Key exchange */
	నిర్మాణం kex *kex;

	/* cached local and remote ip addresses and ports */
	అక్షరం *remote_ipaddr;
	పూర్ణాంకం remote_పోర్టు;
	అక్షరం *local_ipaddr;
	పూర్ణాంకం local_పోర్టు;
	అక్షరం *rdomain_లోపల;

	/* Optional preamble for log messages (e.g. username) */
	అక్షరం *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	పూర్ణాంకం dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	అక్షరం *remote_సంస్కరణ;

	/* Lists for private and public keys */
	TAILQ_HEAD(, కీలకం_నమోదు) వ్యక్తిగత_కీలకాలు;
	TAILQ_HEAD(, కీలకం_నమోదు) ప్రజా_కీలకాలు;

	/* Client/Server authentication context */
	శూన్య *authctxt;

	/* Channels context */
	నిర్మాణం ssh_channels *chanctxt;

	/* APP data */
	శూన్య *app_దత్తాంశం;
};

రకనిర్వచనం పూర్ణాంకం (ssh_packet_hook_fn)(నిర్మాణం ssh *, నిర్మాణం sshbuf *,
    u_char *, శూన్య *);

నిర్మాణం ssh *ssh_alloc_session_state(శూన్య);
నిర్మాణం ssh *ssh_packet_సమితి_connection(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం);
శూన్య     ssh_packet_సమితి_timeout(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం	 ssh_packet_stop_discard(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_packet_connection_af(నిర్మాణం ssh *);
శూన్య     ssh_packet_సమితి_nonblocking(నిర్మాణం ssh *);
పూర్ణాంకం      ssh_packet_get_connection_లోపల(నిర్మాణం ssh *);
పూర్ణాంకం      ssh_packet_get_connection_బహిర్గతం(నిర్మాణం ssh *);
శూన్య	 ssh_packet_free(నిర్మాణం ssh *);
శూన్య     ssh_packet_close(నిర్మాణం ssh *);
శూన్య	 ssh_packet_సమితి_ఆదానం_hook(నిర్మాణం ssh *, ssh_packet_hook_fn *, శూన్య *);
శూన్య	 ssh_packet_clear_కీలకాలు(నిర్మాణం ssh *);
శూన్య	 ssh_clear_newkeys(నిర్మాణం ssh *, పూర్ణాంకం);

పూర్ణాంకం	 ssh_packet_is_rekeying(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_packet_check_rekey(నిర్మాణం ssh *);
శూన్య     ssh_packet_సమితి_protocol_flags(నిర్మాణం ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(నిర్మాణం ssh *);
శూన్య	 ssh_packet_సమితి_interactive(నిర్మాణం ssh *, పూర్ణాంకం);
శూన్య	 ssh_packet_సమితి_qos(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం);
శూన్య     ssh_packet_సమితి_server(నిర్మాణం ssh *);
శూన్య     ssh_packet_సమితి_authenticated(నిర్మాణం ssh *);
శూన్య     ssh_packet_సమితి_mux(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_packet_get_mux(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_packet_సమితి_log_preamble(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *, ...)
    __attribute__((format(రాయి, 2, 3)));

పూర్ణాంకం	 ssh_packet_log_type(u_char);

పూర్ణాంకం	 ssh_packet_send2_wrapped(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_packet_send2(నిర్మాణం ssh *);

పూర్ణాంకం      ssh_packet_read(నిర్మాణం ssh *);
పూర్ణాంకం ssh_packet_read_poll2(నిర్మాణం ssh *, u_char *, uint32_t *seqnr_p);
పూర్ణాంకం	 ssh_packet_process_incoming(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *buf, u_int len);
పూర్ణాంకం	 ssh_packet_process_read(నిర్మాణం ssh *, పూర్ణాంకం);
పూర్ణాంకం      ssh_packet_read_seqnr(నిర్మాణం ssh *, u_char *, uint32_t *seqnr_p);
పూర్ణాంకం      ssh_packet_read_poll_seqnr(నిర్మాణం ssh *, u_char *, uint32_t *seqnr_p);

శూన్య     ssh_packet_disconnect(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *fmt, ...)
	__attribute__((format(రాయి, 2, 3)))
	__attribute__((noreturn));
శూన్య     ssh_packet_send_debug(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *fmt, ...) __attribute__((format(రాయి, 2, 3)));

పూర్ణాంకం	 ssh_సమితి_newkeys(నిర్మాణం ssh *, పూర్ణాంకం బహుళకం);
శూన్య	 ssh_packet_get_బైట్లు(నిర్మాణం ssh *, uint64_t *, uint64_t *);

పూర్ణాంకం	 ssh_packet_write_poll(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_packet_write_wait(నిర్మాణం ssh *);
పూర్ణాంకం      ssh_packet_have_దత్తాంశం_గమ్యం_write(నిర్మాణం ssh *);
పూర్ణాంకం      ssh_packet_not_very_much_దత్తాంశం_గమ్యం_write(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_packet_interactive_దత్తాంశం_గమ్యం_write(నిర్మాణం ssh *);

పూర్ణాంకం	 ssh_packet_connection_is_on_socket(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_packet_మిగిలిన(నిర్మాణం ssh *);

శూన్య	 ssh_tty_make_modes(నిర్మాణం ssh *, పూర్ణాంకం, నిర్మాణం termios *);
శూన్య	 ssh_tty_parse_modes(నిర్మాణం ssh *, పూర్ణాంకం);

శూన్య	 ssh_packet_సమితి_alive_timeouts(నిర్మాణం ssh *, పూర్ణాంకం);
పూర్ణాంకం	 ssh_packet_inc_alive_timeouts(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_packet_సమితి_maxsize(నిర్మాణం ssh *, u_int);
u_int	 ssh_packet_get_maxsize(నిర్మాణం ssh *);

పూర్ణాంకం	 ssh_packet_get_state(నిర్మాణం ssh *, నిర్మాణం sshbuf *);
పూర్ణాంకం	 ssh_packet_సమితి_state(నిర్మాణం ssh *, నిర్మాణం sshbuf *);

స్థిరరాశి అక్షరం *ssh_remote_ipaddr(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_remote_పోర్టు(నిర్మాణం ssh *);
స్థిరరాశి అక్షరం *ssh_local_ipaddr(నిర్మాణం ssh *);
పూర్ణాంకం	 ssh_local_పోర్టు(నిర్మాణం ssh *);
స్థిరరాశి అక్షరం *ssh_packet_rdomain_లోపల(నిర్మాణం ssh *);
అక్షరం	*ssh_remote_hostname(నిర్మాణం ssh *);

శూన్య	 ssh_packet_సమితి_rekey_limits(నిర్మాణం ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(నిర్మాణం ssh *);

శూన్య	*ssh_packet_get_ఆదానం(నిర్మాణం ssh *);
శూన్య	*ssh_packet_get_output(నిర్మాణం ssh *);

/* new API */
పూర్ణాంకం	sshpkt_ప్రారంభం(నిర్మాణం ssh *ssh, u_char type);
పూర్ణాంకం	sshpkt_send(నిర్మాణం ssh *ssh);
పూర్ణాంకం     sshpkt_disconnect(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *fmt, ...)
	    __attribute__((format(రాయి, 2, 3)));
పూర్ణాంకం	sshpkt_కూడు_padding(నిర్మాణం ssh *, u_char);
శూన్య	sshpkt_fatal(నిర్మాణం ssh *ssh, పూర్ణాంకం r, స్థిరరాశి అక్షరం *fmt, ...)
	    __attribute__((format(రాయి, 3, 4)))
	    __attribute__((noreturn));
పూర్ణాంకం	sshpkt_సందేశం_ignore(నిర్మాణం ssh *, u_int);

పూర్ణాంకం	sshpkt_put(నిర్మాణం ssh *ssh, స్థిరరాశి శూన్య *v, కొలత_t len);
పూర్ణాంకం	sshpkt_putb(నిర్మాణం ssh *ssh, స్థిరరాశి నిర్మాణం sshbuf *b);
పూర్ణాంకం	sshpkt_put_u8(నిర్మాణం ssh *ssh, u_char val);
పూర్ణాంకం	sshpkt_put_u32(నిర్మాణం ssh *ssh, uint32_t val);
పూర్ణాంకం	sshpkt_put_u64(నిర్మాణం ssh *ssh, uint64_t val);
పూర్ణాంకం	sshpkt_put_string(నిర్మాణం ssh *ssh, స్థిరరాశి శూన్య *v, కొలత_t len);
పూర్ణాంకం	sshpkt_put_cstring(నిర్మాణం ssh *ssh, స్థిరరాశి శూన్య *v);
పూర్ణాంకం	sshpkt_put_stringb(నిర్మాణం ssh *ssh, స్థిరరాశి నిర్మాణం sshbuf *v);
పూర్ణాంకం	sshpkt_put_ec(నిర్మాణం ssh *ssh, స్థిరరాశి EC_బిందువు *v, స్థిరరాశి EC_సమూహం *g);
పూర్ణాంకం	sshpkt_put_ec_pkey(నిర్మాణం ssh *ssh, EVP_PKEY *pkey);
పూర్ణాంకం	sshpkt_put_bignum2(నిర్మాణం ssh *ssh, స్థిరరాశి BIGNUM *v);

పూర్ణాంకం	sshpkt_get(నిర్మాణం ssh *ssh, శూన్య *valp, కొలత_t len);
పూర్ణాంకం	sshpkt_get_u8(నిర్మాణం ssh *ssh, u_char *valp);
పూర్ణాంకం	sshpkt_get_u32(నిర్మాణం ssh *ssh, uint32_t *valp);
పూర్ణాంకం	sshpkt_get_u64(నిర్మాణం ssh *ssh, uint64_t *valp);
పూర్ణాంకం	sshpkt_get_string(నిర్మాణం ssh *ssh, u_char **valp, కొలత_t *lenp);
పూర్ణాంకం	sshpkt_get_string_ప్రత్యక్ష(నిర్మాణం ssh *ssh, స్థిరరాశి u_char **valp, కొలత_t *lenp);
పూర్ణాంకం	sshpkt_peek_string_ప్రత్యక్ష(నిర్మాణం ssh *ssh, స్థిరరాశి u_char **valp, కొలత_t *lenp);
పూర్ణాంకం	sshpkt_get_cstring(నిర్మాణం ssh *ssh, అక్షరం **valp, కొలత_t *lenp);
పూర్ణాంకం	sshpkt_getb_froms(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf **valp);
పూర్ణాంకం	sshpkt_get_ec(నిర్మాణం ssh *ssh, EC_బిందువు *v, స్థిరరాశి EC_సమూహం *g);
పూర్ణాంకం	sshpkt_get_bignum2(నిర్మాణం ssh *ssh, BIGNUM **valp);
పూర్ణాంకం	sshpkt_get_చివర(నిర్మాణం ssh *ssh);
శూన్య	sshpkt_fmt_connection_id(నిర్మాణం ssh *ssh, అక్షరం *s, కొలత_t l);
స్థిరరాశి u_char	*sshpkt_ptr(నిర్మాణం ssh *, కొలత_t *lenp);
అక్షరం	*connection_info_సందేశం(నిర్మాణం ssh *ssh);

#అయితే_ముగింపు				/* PACKET_H */
