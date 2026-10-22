// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <unistd.h>

బాహ్య "C" {

#అన్తర్భావ "includes.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "readconf.h"
#అన్తర్భావ "xmalloc.h"

// Stub out log output to reduce noise
శూన్య sshsig_free(నిర్మాణం sshsig_ctx *ctx) {}

}  // extern "C"

స్థిర నిర్మాణం passwd fuzz_pw;
స్థిర అక్షరం fuzz_username[] = "fuzzer";
స్థిర అక్షరం fuzz_home[] = "/tmp";
స్థిర అక్షరం fuzz_shell[] = "/bin/sh";

స్థిర శూన్య init_pw(శూన్య) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

బాహ్య "C" పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత) {
    స్థిర పూర్ణాంకం initialized = 0;
    ఒకవేళ (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    అక్షరం tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    పూర్ణాంకం fd = mkstemp(tmpfile);
    ఒకవేళ (fd < 0)
        తిరిగి 0;

    ఒకవేళ (లిఖ(fd, దత్తాంశం, కొలత) != (ssize_t)కొలత) {
        close(fd);
        unlink(tmpfile);
        తిరిగి 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     ఖాళీ, &options, 0, ఖాళీ);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    తిరిగి 0;
}
