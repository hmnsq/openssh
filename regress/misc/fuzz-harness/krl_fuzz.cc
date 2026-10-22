// libfuzzer driver for krl parse fuzzing.

#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>

வெளி "C" {
#அந்தர்பாவ "includes.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "krl.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "authfile.h"
}

நிலையான முழு initialised = 0;
நிலையான FILE *null_file;
நிலையான கட்டமைப்பு sshkey *சாவி = வெற்று;

வெளி "C" முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t *data, size_t size) {
    // single initialisation
    எனில் (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        எனில் ((null_file = fopen("/dev/null", "w")) == வெற்று) திரும்பு 0;

        எனில் (sshkey_generate(சாவி_ED25519, 0, &சாவி) != 0) திரும்பு 0;

        initialised = 1;
    }

    // Reject empty corpus
    எனில் (size < 4) திரும்பு 0;

    // Convert fuzzer data to ssh buffer
    கட்டமைப்பு sshbuf *buf = sshbuf_from(data, size);
    எனில் (!buf) திரும்பு 0;

    // Parse the ssh buffer as krl, early exit if failed
    கட்டமைப்பு ssh_krl *krl = வெற்று;
    முழு ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    எனில் (ret != 0) திரும்பு 0;

    // Fuzz serailisation roundtrip
    கட்டமைப்பு sshbuf *output = sshbuf_new();
    கட்டமைப்பு ssh_krl *krl2 = வெற்று;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_சாவி(krl, சாவி);

    ssh_krl_free(krl);
    திரும்பு 0;
}
