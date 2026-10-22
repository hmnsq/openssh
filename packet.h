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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ PACKET_H
#ವ್ಯಾಖ್ಯಾನಿಸು PACKET_H

#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <termios.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಇಲ್ಲದಿದ್ದರೆ /* OPENSSL */
#ವ್ಯಾಖ್ಯಾನಿಸು BIGNUM		ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಗುಂಪು	ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಬಿಂದು	ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EVP_PKEY	ಶೂನ್ಯ
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ರಚನೆ kex;
ರಚನೆ sshkey;
ರಚನೆ sshbuf;
ರಚನೆ session_state;	/* private session data */

#ಅನ್ತರ್ಭಾವ "dispatch.h"	/* typedef, DISPATCH_MAX */

ರಚನೆ ಕೀಲಿ_ನಮೂದು {
	TAILQ_ENTRY(ಕೀಲಿ_ನಮೂದು) ಮುಂದಿನ;
	ರಚನೆ sshkey *ಕೀಲಿ;
};

ರಚನೆ ssh {
	/* Session state */
	ರಚನೆ session_state *state;

	/* Key exchange */
	ರಚನೆ kex *kex;

	/* cached local and remote ip addresses and ports */
	ಅಕ್ಷರ *remote_ipaddr;
	ಪೂರ್ಣಾಂಕ remote_ಪೋರ್ಟ್;
	ಅಕ್ಷರ *local_ipaddr;
	ಪೂರ್ಣಾಂಕ local_ಪೋರ್ಟ್;
	ಅಕ್ಷರ *rdomain_ಒಳ;

	/* Optional preamble for log messages (e.g. username) */
	ಅಕ್ಷರ *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	ಪೂರ್ಣಾಂಕ dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	ಅಕ್ಷರ *remote_ಆವೃತ್ತಿ;

	/* Lists for private and public keys */
	TAILQ_HEAD(, ಕೀಲಿ_ನಮೂದು) ಖಾಸಗಿ_ಕೀಲಿಗಳು;
	TAILQ_HEAD(, ಕೀಲಿ_ನಮೂದು) ಬಹಿರಂಗ_ಕೀಲಿಗಳು;

	/* Client/Server authentication context */
	ಶೂನ್ಯ *authctxt;

	/* Channels context */
	ರಚನೆ ssh_channels *chanctxt;

	/* APP data */
	ಶೂನ್ಯ *app_ದತ್ತಾಂಶ;
};

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ (ssh_packet_hook_fn)(ರಚನೆ ssh *, ರಚನೆ sshbuf *,
    u_char *, ಶೂನ್ಯ *);

ರಚನೆ ssh *ssh_alloc_session_state(ಶೂನ್ಯ);
ರಚನೆ ssh *ssh_packet_ಗಣ_connection(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ     ssh_packet_ಗಣ_timeout(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 ssh_packet_stop_discard(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_connection_af(ರಚನೆ ssh *);
ಶೂನ್ಯ     ssh_packet_ಗಣ_nonblocking(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ      ssh_packet_get_connection_ಒಳ(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ      ssh_packet_get_connection_ಹೊರಹೋಗು(ರಚನೆ ssh *);
ಶೂನ್ಯ	 ssh_packet_free(ರಚನೆ ssh *);
ಶೂನ್ಯ     ssh_packet_close(ರಚನೆ ssh *);
ಶೂನ್ಯ	 ssh_packet_ಗಣ_ಒಳಹರಿವು_hook(ರಚನೆ ssh *, ssh_packet_hook_fn *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 ssh_packet_clear_ಕೀಲಿಗಳು(ರಚನೆ ssh *);
ಶೂನ್ಯ	 ssh_clear_newkeys(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);

ಪೂರ್ಣಾಂಕ	 ssh_packet_is_rekeying(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_check_rekey(ರಚನೆ ssh *);
ಶೂನ್ಯ     ssh_packet_ಗಣ_protocol_flags(ರಚನೆ ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(ರಚನೆ ssh *);
ಶೂನ್ಯ	 ssh_packet_ಗಣ_interactive(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 ssh_packet_ಗಣ_qos(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ     ssh_packet_ಗಣ_server(ರಚನೆ ssh *);
ಶೂನ್ಯ     ssh_packet_ಗಣ_authenticated(ರಚನೆ ssh *);
ಶೂನ್ಯ     ssh_packet_ಗಣ_mux(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_get_mux(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_ಗಣ_log_preamble(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ...)
    __attribute__((format(ಬರೆ, 2, 3)));

ಪೂರ್ಣಾಂಕ	 ssh_packet_log_type(u_char);

ಪೂರ್ಣಾಂಕ	 ssh_packet_send2_wrapped(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_send2(ರಚನೆ ssh *);

ಪೂರ್ಣಾಂಕ      ssh_packet_read(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ ssh_packet_read_poll2(ರಚನೆ ssh *, u_char *, uint32_t *seqnr_p);
ಪೂರ್ಣಾಂಕ	 ssh_packet_process_incoming(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *buf, u_int len);
ಪೂರ್ಣಾಂಕ	 ssh_packet_process_read(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ      ssh_packet_read_seqnr(ರಚನೆ ssh *, u_char *, uint32_t *seqnr_p);
ಪೂರ್ಣಾಂಕ      ssh_packet_read_poll_seqnr(ರಚನೆ ssh *, u_char *, uint32_t *seqnr_p);

ಶೂನ್ಯ     ssh_packet_disconnect(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
	__attribute__((format(ಬರೆ, 2, 3)))
	__attribute__((noreturn));
ಶೂನ್ಯ     ssh_packet_send_debug(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...) __attribute__((format(ಬರೆ, 2, 3)));

ಪೂರ್ಣಾಂಕ	 ssh_ಗಣ_newkeys(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ);
ಶೂನ್ಯ	 ssh_packet_get_ಬೈಟುಗಳು(ರಚನೆ ssh *, uint64_t *, uint64_t *);

ಪೂರ್ಣಾಂಕ	 ssh_packet_write_poll(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_write_wait(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ      ssh_packet_have_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ      ssh_packet_not_very_much_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_interactive_ದತ್ತಾಂಶ_ಗಮ್ಯ_write(ರಚನೆ ssh *);

ಪೂರ್ಣಾಂಕ	 ssh_packet_connection_is_on_socket(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_ಉಳಿದ(ರಚನೆ ssh *);

ಶೂನ್ಯ	 ssh_tty_make_modes(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ರಚನೆ termios *);
ಶೂನ್ಯ	 ssh_tty_parse_modes(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);

ಶೂನ್ಯ	 ssh_packet_ಗಣ_alive_timeouts(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 ssh_packet_inc_alive_timeouts(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_ಗಣ_maxsize(ರಚನೆ ssh *, u_int);
u_int	 ssh_packet_get_maxsize(ರಚನೆ ssh *);

ಪೂರ್ಣಾಂಕ	 ssh_packet_get_state(ರಚನೆ ssh *, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ	 ssh_packet_ಗಣ_state(ರಚನೆ ssh *, ರಚನೆ sshbuf *);

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssh_remote_ipaddr(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_remote_ಪೋರ್ಟ್(ರಚನೆ ssh *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssh_local_ipaddr(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 ssh_local_ಪೋರ್ಟ್(ರಚನೆ ssh *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssh_packet_rdomain_ಒಳ(ರಚನೆ ssh *);
ಅಕ್ಷರ	*ssh_remote_hostname(ರಚನೆ ssh *);

ಶೂನ್ಯ	 ssh_packet_ಗಣ_rekey_limits(ರಚನೆ ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(ರಚನೆ ssh *);

ಶೂನ್ಯ	*ssh_packet_get_ಒಳಹರಿವು(ರಚನೆ ssh *);
ಶೂನ್ಯ	*ssh_packet_get_output(ರಚನೆ ssh *);

/* new API */
ಪೂರ್ಣಾಂಕ	sshpkt_ಆರಂಭ(ರಚನೆ ssh *ssh, u_char type);
ಪೂರ್ಣಾಂಕ	sshpkt_send(ರಚನೆ ssh *ssh);
ಪೂರ್ಣಾಂಕ     sshpkt_disconnect(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
	    __attribute__((format(ಬರೆ, 2, 3)));
ಪೂರ್ಣಾಂಕ	sshpkt_ಕೂಡಿಸು_padding(ರಚನೆ ssh *, u_char);
ಶೂನ್ಯ	sshpkt_fatal(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
	    __attribute__((format(ಬರೆ, 3, 4)))
	    __attribute__((noreturn));
ಪೂರ್ಣಾಂಕ	sshpkt_ಸಂದೇಶ_ignore(ರಚನೆ ssh *, u_int);

ಪೂರ್ಣಾಂಕ	sshpkt_put(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ	sshpkt_putb(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b);
ಪೂರ್ಣಾಂಕ	sshpkt_put_u8(ರಚನೆ ssh *ssh, u_char val);
ಪೂರ್ಣಾಂಕ	sshpkt_put_u32(ರಚನೆ ssh *ssh, uint32_t val);
ಪೂರ್ಣಾಂಕ	sshpkt_put_u64(ರಚನೆ ssh *ssh, uint64_t val);
ಪೂರ್ಣಾಂಕ	sshpkt_put_string(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ	sshpkt_put_cstring(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v);
ಪೂರ್ಣಾಂಕ	sshpkt_put_stringb(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *v);
ಪೂರ್ಣಾಂಕ	sshpkt_put_ec(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *v, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g);
ಪೂರ್ಣಾಂಕ	sshpkt_put_ec_pkey(ರಚನೆ ssh *ssh, EVP_PKEY *pkey);
ಪೂರ್ಣಾಂಕ	sshpkt_put_bignum2(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ BIGNUM *v);

ಪೂರ್ಣಾಂಕ	sshpkt_get(ರಚನೆ ssh *ssh, ಶೂನ್ಯ *valp, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ	sshpkt_get_u8(ರಚನೆ ssh *ssh, u_char *valp);
ಪೂರ್ಣಾಂಕ	sshpkt_get_u32(ರಚನೆ ssh *ssh, uint32_t *valp);
ಪೂರ್ಣಾಂಕ	sshpkt_get_u64(ರಚನೆ ssh *ssh, uint64_t *valp);
ಪೂರ್ಣಾಂಕ	sshpkt_get_string(ರಚನೆ ssh *ssh, u_char **valp, ಗಾತ್ರ_t *lenp);
ಪೂರ್ಣಾಂಕ	sshpkt_get_string_ನೇರ(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ u_char **valp, ಗಾತ್ರ_t *lenp);
ಪೂರ್ಣಾಂಕ	sshpkt_peek_string_ನೇರ(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ u_char **valp, ಗಾತ್ರ_t *lenp);
ಪೂರ್ಣಾಂಕ	sshpkt_get_cstring(ರಚನೆ ssh *ssh, ಅಕ್ಷರ **valp, ಗಾತ್ರ_t *lenp);
ಪೂರ್ಣಾಂಕ	sshpkt_getb_froms(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf **valp);
ಪೂರ್ಣಾಂಕ	sshpkt_get_ec(ರಚನೆ ssh *ssh, EC_ಬಿಂದು *v, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g);
ಪೂರ್ಣಾಂಕ	sshpkt_get_bignum2(ರಚನೆ ssh *ssh, BIGNUM **valp);
ಪೂರ್ಣಾಂಕ	sshpkt_get_ಕೊನೆ(ರಚನೆ ssh *ssh);
ಶೂನ್ಯ	sshpkt_fmt_connection_id(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *s, ಗಾತ್ರ_t l);
ಸ್ಥಿರಾಂಕ u_char	*sshpkt_ptr(ರಚನೆ ssh *, ಗಾತ್ರ_t *lenp);
ಅಕ್ಷರ	*connection_info_ಸಂದೇಶ(ರಚನೆ ssh *ssh);

#ಆದರೆ_ಅಂತ್ಯ				/* PACKET_H */
