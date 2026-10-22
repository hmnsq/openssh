/* 	$OpenBSD: tests.c,v 1.1 2026/05/31 11:39:44 djm Exp $ */
/*
 * Regress tests for servconf.h server configuration API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "xmalloc.h"

నిర్మాణం sshbuf *cfg;

/* stub */
పూర్ణాంకం auth2_methods_valid(స్థిరరాశి అక్షరం *methods, పూర్ణాంకం need_enable);
పూర్ణాంకం
auth2_methods_valid(స్థిరరాశి అక్షరం *methods, పూర్ణాంకం need_enable)
{
	తిరిగి 1;
}

స్థిర శూన్య
onerror(శూన్య *fuzz)
{
	fprintf(stderr, "Failed during fuzz:\n");
	fuzz_dump((నిర్మాణం fuzz *)fuzz);
}

స్థిర శూన్య
సమితి_string(అక్షరం **dst, స్థిరరాశి అక్షరం *s)
{
	*dst = s == ఖాళీ ? ఖాళీ : xstrdup(s);
}

స్థిర అక్షరం **
new_string_array(u_int n)
{
	తిరిగి xcalloc(n, పరిమాణం(అక్షరం *));
}

స్థిర శూన్య
సమితి_test_options(ServerOptions *o)
{
	initialize_server_options(o);

	o->అంకె_ports = 2;
	o->ports[0] = 22;
	o->ports[1] = 2022;
	o->ip_qos_interactive = 0x10;
	o->ip_qos_bulk = 0x08;
	o->log_facility = SYSLOG_FACILITY_AUTH;
	o->log_level = SYSLOG_LEVEL_DEBUG3;
	o->fwd_opts.gateway_ports = 1;
	o->fwd_opts.streamlocal_bind_ముసుగు = 0177;
	o->fwd_opts.streamlocal_bind_unlink = 1;
	o->permit_user_env = 1;
	సమితి_string(&o->permit_user_env_allowlist, "");
	o->rekey_హద్దు = 123456789;
	o->rekey_interval = 600;
	o->timing_secret = 0x0102030405060708ULL;

	సమితి_string(&o->routing_domain, "");
	సమితి_string(&o->banner, ఖాళీ);
	సమితి_string(&o->adm_forced_command, "internal-sftp");
	సమితి_string(&o->chroot_directory, "");
	సమితి_string(&o->host_కీలకం_agent, ఖాళీ);
	సమితి_string(&o->authorized_కీలకాలు_command, "/bin/echo");
	సమితి_string(&o->authorized_కీలకాలు_command_user, "");
	సమితి_string(&o->authorized_principals_file, ఖాళీ);

	o->అంకె_authkeys_files = 3;
	o->authorized_కీలకాలు_files = new_string_array(o->అంకె_authkeys_files);
	సమితి_string(&o->authorized_కీలకాలు_files[0], ఖాళీ);
	సమితి_string(&o->authorized_కీలకాలు_files[1], "");
	సమితి_string(&o->authorized_కీలకాలు_files[2], ".ssh/authorized_keys");

	o->అంకె_log_verbose = 2;
	o->log_verbose = new_string_array(o->అంకె_log_verbose);
	సమితి_string(&o->log_verbose[0], ఖాళీ);
	సమితి_string(&o->log_verbose[1], "kex.c:*");

	o->అంకె_host_కీలకం_files = 3;
	o->host_కీలకం_file_userprovided =
	    xcalloc(o->అంకె_host_కీలకం_files,
	    పరిమాణం(*o->host_కీలకం_file_userprovided));
	o->host_కీలకం_files = new_string_array(o->అంకె_host_కీలకం_files);
	o->host_కీలకం_file_userprovided[0] = 0;
	o->host_కీలకం_file_userprovided[1] = 1;
	o->host_కీలకం_file_userprovided[2] = -1;
	సమితి_string(&o->host_కీలకం_files[0], ఖాళీ);
	సమితి_string(&o->host_కీలకం_files[1], "");
	సమితి_string(&o->host_కీలకం_files[2], "/tmp/ssh_host_ed25519_key");

	o->అంకె_queued_listens = 2;
	o->queued_listen_addrs = xcalloc(o->అంకె_queued_listens,
	    పరిమాణం(*o->queued_listen_addrs));
	సమితి_string(&o->queued_listen_addrs[0].addr, "127.0.0.1");
	o->queued_listen_addrs[0].పోర్టు = 2222;
	సమితి_string(&o->queued_listen_addrs[0].rdomain, ఖాళీ);
	సమితి_string(&o->queued_listen_addrs[1].addr, "::1");
	o->queued_listen_addrs[1].పోర్టు = -1;
	సమితి_string(&o->queued_listen_addrs[1].rdomain, "");

	o->అంకె_subsystems = 2;
	o->subsystem_name = new_string_array(o->అంకె_subsystems);
	o->subsystem_command = new_string_array(o->అంకె_subsystems);
	o->subsystem_వాదనలు = new_string_array(o->అంకె_subsystems);
	సమితి_string(&o->subsystem_name[0], "sftp");
	సమితి_string(&o->subsystem_command[0], "internal-sftp");
	సమితి_string(&o->subsystem_వాదనలు[0], "internal-sftp -f AUTH");
	సమితి_string(&o->subsystem_name[1], "echo");
	సమితి_string(&o->subsystem_command[1], "/bin/echo");
	సమితి_string(&o->subsystem_వాదనలు[1], "/bin/echo hello");
}

స్థిర శూన్య
check_roundtrip(స్థిరరాశి ServerOptions *o)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	ServerOptions బహిర్గతం;

	initialize_server_options(&బహిర్గతం);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ఖాళీ);
	ASSERT_INT_EQ(deserialise_server_options(buf, &బహిర్గతం), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(buf), 0);

	ASSERT_U_INT_EQ(బహిర్గతం.అంకె_ports, 2);
	ASSERT_INT_EQ(బహిర్గతం.ports[0], 22);
	ASSERT_INT_EQ(బహిర్గతం.ports[1], 2022);
	ASSERT_INT_EQ(బహిర్గతం.ip_qos_interactive, 0x10);
	ASSERT_INT_EQ(బహిర్గతం.ip_qos_bulk, 0x08);
	ASSERT_INT_EQ(బహిర్గతం.log_facility, SYSLOG_FACILITY_AUTH);
	ASSERT_INT_EQ(బహిర్గతం.log_level, SYSLOG_LEVEL_DEBUG3);
	ASSERT_INT_EQ(బహిర్గతం.fwd_opts.gateway_ports, 1);
	ASSERT_INT_EQ(బహిర్గతం.fwd_opts.streamlocal_bind_ముసుగు, 0177);
	ASSERT_INT_EQ(బహిర్గతం.fwd_opts.streamlocal_bind_unlink, 1);
	ASSERT_INT_EQ(బహిర్గతం.permit_user_env, 1);
	ASSERT_STRING_EQ(బహిర్గతం.permit_user_env_allowlist, "");
	ASSERT_LONG_LONG_EQ(బహిర్గతం.rekey_హద్దు, 123456789);
	ASSERT_INT_EQ(బహిర్గతం.rekey_interval, 600);
	ASSERT_U64_EQ(బహిర్గతం.timing_secret, 0x0102030405060708ULL);

	ASSERT_STRING_EQ(బహిర్గతం.routing_domain, "");
	ASSERT_PTR_EQ(బహిర్గతం.banner, ఖాళీ);
	ASSERT_STRING_EQ(బహిర్గతం.adm_forced_command, "internal-sftp");
	ASSERT_STRING_EQ(బహిర్గతం.chroot_directory, "");
	ASSERT_PTR_EQ(బహిర్గతం.host_కీలకం_agent, ఖాళీ);
	ASSERT_STRING_EQ(బహిర్గతం.authorized_కీలకాలు_command, "/bin/echo");
	ASSERT_STRING_EQ(బహిర్గతం.authorized_కీలకాలు_command_user, "");
	ASSERT_PTR_EQ(బహిర్గతం.authorized_principals_file, ఖాళీ);

	ASSERT_U_INT_EQ(బహిర్గతం.అంకె_authkeys_files, 3);
	ASSERT_PTR_EQ(బహిర్గతం.authorized_కీలకాలు_files[0], ఖాళీ);
	ASSERT_STRING_EQ(బహిర్గతం.authorized_కీలకాలు_files[1], "");
	ASSERT_STRING_EQ(బహిర్గతం.authorized_కీలకాలు_files[2], ".ssh/authorized_keys");

	ASSERT_U_INT_EQ(బహిర్గతం.అంకె_log_verbose, 2);
	ASSERT_PTR_EQ(బహిర్గతం.log_verbose[0], ఖాళీ);
	ASSERT_STRING_EQ(బహిర్గతం.log_verbose[1], "kex.c:*");

	ASSERT_U_INT_EQ(బహిర్గతం.అంకె_host_కీలకం_files, 3);
	ASSERT_INT_EQ(బహిర్గతం.host_కీలకం_file_userprovided[0], 0);
	ASSERT_INT_EQ(బహిర్గతం.host_కీలకం_file_userprovided[1], 1);
	ASSERT_INT_EQ(బహిర్గతం.host_కీలకం_file_userprovided[2], -1);
	ASSERT_PTR_EQ(బహిర్గతం.host_కీలకం_files[0], ఖాళీ);
	ASSERT_STRING_EQ(బహిర్గతం.host_కీలకం_files[1], "");
	ASSERT_STRING_EQ(బహిర్గతం.host_కీలకం_files[2], "/tmp/ssh_host_ed25519_key");

	ASSERT_U_INT_EQ(బహిర్గతం.అంకె_queued_listens, 2);
	ASSERT_STRING_EQ(బహిర్గతం.queued_listen_addrs[0].addr, "127.0.0.1");
	ASSERT_INT_EQ(బహిర్గతం.queued_listen_addrs[0].పోర్టు, 2222);
	ASSERT_PTR_EQ(బహిర్గతం.queued_listen_addrs[0].rdomain, ఖాళీ);
	ASSERT_STRING_EQ(బహిర్గతం.queued_listen_addrs[1].addr, "::1");
	ASSERT_INT_EQ(బహిర్గతం.queued_listen_addrs[1].పోర్టు, -1);
	ASSERT_STRING_EQ(బహిర్గతం.queued_listen_addrs[1].rdomain, "");

	ASSERT_U_INT_EQ(బహిర్గతం.అంకె_subsystems, 2);
	ASSERT_STRING_EQ(బహిర్గతం.subsystem_name[0], "sftp");
	ASSERT_STRING_EQ(బహిర్గతం.subsystem_command[0], "internal-sftp");
	ASSERT_STRING_EQ(బహిర్గతం.subsystem_వాదనలు[0], "internal-sftp -f AUTH");
	ASSERT_STRING_EQ(బహిర్గతం.subsystem_name[1], "echo");
	ASSERT_STRING_EQ(బహిర్గతం.subsystem_command[1], "/bin/echo");
	ASSERT_STRING_EQ(బహిర్గతం.subsystem_వాదనలు[1], "/bin/echo hello");

	free_server_options(&బహిర్గతం);
	sshbuf_free(buf);
}

స్థిర శూన్య
check_rejects_trailing_దత్తాంశం(స్థిరరాశి ServerOptions *o)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	ServerOptions బహిర్గతం;
	పూర్ణాంకం r;

	initialize_server_options(&బహిర్గతం);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put_u8(buf, 0), 0);
	r = deserialise_server_options(buf, &బహిర్గతం);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&బహిర్గతం);
	sshbuf_free(buf);
}

స్థిర శూన్య
check_rejects_bad_సంస్కరణ(స్థిరరాశి ServerOptions *o)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	ServerOptions బహిర్గతం;
	పూర్ణాంకం r;

	initialize_server_options(&బహిర్గతం);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ఖాళీ);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ఖాళీ);
	POKE_U32(sshbuf_mutable_ptr(buf), 2);
	r = deserialise_server_options(buf, &బహిర్గతం);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&బహిర్గతం);
	sshbuf_free(buf);
}

స్థిర శూన్య
check_rejects_bad_పోర్టు_లెక్క(స్థిరరాశి ServerOptions *o)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	ServerOptions బహిర్గతం;
	పూర్ణాంకం r;

	initialize_server_options(&బహిర్గతం);
	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ఖాళీ);
	ASSERT_కొలత_T_GT(sshbuf_len(buf), 8);
	ASSERT_PTR_NE(sshbuf_mutable_ptr(buf), ఖాళీ);
	POKE_U32(sshbuf_mutable_ptr(buf) + 4, MAX_PORTS + 1);
	r = deserialise_server_options(buf, &బహిర్గతం);
	ASSERT_INT_EQ(r, SSH_ERR_INVALID_FORMAT);
	free_server_options(&బహిర్గతం);
	sshbuf_free(buf);
}

స్థిర శూన్య
check_roundtrip_signed_limits(స్థిరరాశి ServerOptions *o)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	ServerOptions బహిర్గతం, లోపల;

	initialize_server_options(&బహిర్గతం);
	లోపల = *o;
	లోపల.fwd_opts.streamlocal_bind_ముసుగు = (బహుళకం_t)-1;
	లోపల.ip_qos_bulk = INT_MIN;
	లోపల.rekey_హద్దు = INT64_MIN;
	ASSERT_INT_EQ(serialise_server_options(&లోపల, &buf), 0);
	ASSERT_PTR_NE(buf, ఖాళీ);
	ASSERT_INT_EQ(deserialise_server_options(buf, &బహిర్గతం), 0);
	ASSERT_INT_EQ(బహిర్గతం.fwd_opts.streamlocal_bind_ముసుగు == (బహుళకం_t)-1, 1);
	ASSERT_INT_EQ(బహిర్గతం.ip_qos_bulk, INT_MIN);
	ASSERT_LONG_LONG_EQ(బహిర్గతం.rekey_హద్దు, INT64_MIN);
	free_server_options(&బహిర్గతం);
	sshbuf_free(buf);
}

స్థిర శూన్య
attempt_deserialise_blob(స్థిరరాశి u_char *p, కొలత_t len)
{
	నిర్మాణం sshbuf *buf;
	ServerOptions బహిర్గతం;

	initialize_server_options(&బహిర్గతం);
	ASSERT_PTR_NE(buf = sshbuf_from(p, len), ఖాళీ);
	(శూన్య)deserialise_server_options(buf, &బహిర్గతం);
	free_server_options(&బహిర్గతం);
	sshbuf_free(buf);
}

స్థిర శూన్య
check_fuzz_deserialise(స్థిరరాశి ServerOptions *o)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	నిర్మాణం fuzz *fuzz;
	u_int fuzzers = FUZZ_1_బిట్టు_FLIP | FUZZ_1_BYTE_FLIP |
	    FUZZ_TRUNCATE_ప్రారంభం | FUZZ_TRUNCATE_చివర;

	ఒకవేళ (test_is_fast())
		fuzzers &= ~FUZZ_1_బిట్టు_FLIP;
	ఒకవేళ (test_is_slow())
		fuzzers |= FUZZ_2_BYTE_FLIP;

	ASSERT_INT_EQ(serialise_server_options(o, &buf), 0);
	ASSERT_PTR_NE(buf, ఖాళీ);
	fuzz = fuzz_begin(fuzzers, sshbuf_ptr(buf), sshbuf_len(buf));
	TEST_ONERROR(onerror, fuzz);
	కొరకు (; !fuzz_పూర్తి(fuzz); fuzz_తదుపరి(fuzz))
		attempt_deserialise_blob(fuzz_ptr(fuzz), fuzz_len(fuzz));
	TEST_ONERROR(ఖాళీ, ఖాళీ);
	fuzz_cleanup(fuzz);
	sshbuf_free(buf);
}

శూన్య
tests(శూన్య)
{
	ServerOptions o;

	log_init("test_servconf", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);

	TEST_ప్రారంభం("server options round trip preserves nullable state");
	సమితి_test_options(&o);
	check_roundtrip(&o);
	free_server_options(&o);
	TEST_పూర్తి();

	TEST_ప్రారంభం("server options reject trailing data");
	సమితి_test_options(&o);
	check_rejects_trailing_దత్తాంశం(&o);
	free_server_options(&o);
	TEST_పూర్తి();

	TEST_ప్రారంభం("server options reject unsupported version");
	సమితి_test_options(&o);
	check_rejects_bad_సంస్కరణ(&o);
	free_server_options(&o);
	TEST_పూర్తి();

	TEST_ప్రారంభం("server options reject bad port count");
	సమితి_test_options(&o);
	check_rejects_bad_పోర్టు_లెక్క(&o);
	free_server_options(&o);
	TEST_పూర్తి();

	TEST_ప్రారంభం("server options round trip signed limits");
	సమితి_test_options(&o);
	check_roundtrip_signed_limits(&o);
	free_server_options(&o);
	TEST_పూర్తి();

	TEST_ప్రారంభం("server options deserialise fuzz");
	సమితి_test_options(&o);
	check_fuzz_deserialise(&o);
	free_server_options(&o);
	TEST_పూర్తి();
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
