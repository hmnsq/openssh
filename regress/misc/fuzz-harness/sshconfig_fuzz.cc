// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <pwd.h>
#ضمن <unistd.h>

خارجي "C" {

#ضمن "includes.h"
#ضمن "ssh.h"
#ضمن "misc.h"
#ضمن "log.h"
#ضمن "readconf.h"
#ضمن "xmalloc.h"

// Stub out log output to reduce noise
فراغ sshsig_free(بنية sshsig_ctx *ctx) {}

}  // extern "C"

ساكن بنية passwd fuzz_pw;
ساكن حرف fuzz_username[] = "fuzzer";
ساكن حرف fuzz_home[] = "/tmp";
ساكن حرف fuzz_shell[] = "/bin/sh";

ساكن فراغ init_pw(فراغ) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

خارجي "C" صحيح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t *data, size_t size) {
    ساكن صحيح initialized = 0;
    إذا (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    حرف tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    صحيح fd = mkstemp(tmpfile);
    إذا (fd < 0)
        أرجع 0;

    إذا (اكتب(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        أرجع 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     عدم, &options, 0, عدم);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    أرجع 0;
}
