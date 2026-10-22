// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <pwd.h>
#شامل <unistd.h>

خارجی "C" {

#شامل "includes.h"
#شامل "ssh.h"
#شامل "misc.h"
#شامل "log.h"
#شامل "readconf.h"
#شامل "xmalloc.h"

// Stub out log output to reduce noise
خالی sshsig_free(ساخت sshsig_ctx *ctx) {}

}  // extern "C"

ساکن ساخت passwd fuzz_pw;
ساکن حرف fuzz_username[] = "fuzzer";
ساکن حرف fuzz_home[] = "/tmp";
ساکن حرف fuzz_shell[] = "/bin/sh";

ساکن خالی init_pw(خالی) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

خارجی "C" صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t *ڈیٹا, سائز_t سائز) {
    ساکن صحیح initialized = 0;
    اگر (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    حرف tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    صحیح fd = mkstemp(tmpfile);
    اگر (fd < 0)
        واپس 0;

    اگر (اكتب(fd, ڈیٹا, سائز) != (ssize_t)سائز) {
        close(fd);
        unlink(tmpfile);
        واپس 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     تہی, &options, 0, تہی);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    واپس 0;
}
