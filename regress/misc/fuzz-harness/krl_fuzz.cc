// libfuzzer driver for krl parse fuzzing.

#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>

خارجي "C" {
#ضمن "includes.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "krl.h"
#ضمن "log.h"
#ضمن "authfile.h"
}

ساكن صحيح initialised = 0;
ساكن FILE *null_file;
ساكن بنية sshkey *ڪنجي = عدم;

خارجي "C" صحيح LLVMFuzzer_Test_One_داخلا(ثابت uint8_t *معلومات, سائيز_t سائيز) {
    // single initialisation
    إذا (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        إذا ((null_file = fopen("/dev/null", "w")) == عدم) أرجع 0;

        إذا (sshkey_generate(ڪنجي_ED25519, 0, &ڪنجي) != 0) أرجع 0;

        initialised = 1;
    }

    // Reject empty corpus
    إذا (سائيز < 4) أرجع 0;

    // Convert fuzzer data to ssh buffer
    بنية sshbuf *buf = sshbuf_from(معلومات, سائيز);
    إذا (!buf) أرجع 0;

    // Parse the ssh buffer as krl, early exit if failed
    بنية ssh_krl *krl = عدم;
    صحيح ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    إذا (ret != 0) أرجع 0;

    // Fuzz serailisation roundtrip
    بنية sshbuf *output = sshbuf_new();
    بنية ssh_krl *krl2 = عدم;
    ssh_krl_منزل_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_ڪنجي(krl, ڪنجي);

    ssh_krl_free(krl);
    أرجع 0;
}
