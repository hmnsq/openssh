/* $OpenBSD: pkcs11.h,v 1.4 2025/07/25 13:06:07 djm Exp $ */
/* pkcs11.h
   Copyright 2006, 2007 g10 Code GmbH
   Copyright 2006 Andreas Jellinghaus

   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even
   the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
   PURPOSE.  */

/* Please submit changes back to the Scute project at
   http://www.scute.org/ (or send them to marcus@g10code.com), so that
   they can be picked up by other projects from there as well.  */

/* This file is a modified implementation of the PKCS #11 standard by
   RSA Security Inc.  It is mostly a drop-in replacement, with the
   following change:

   This header file does not require any macro definitions by the user
   (like CK_DEFINE_FUNCTION etc).  In fact, it defines those macros
   for you (if useful, some are missing, let me know if you need
   more).

   There is an additional API available that does comply better to the
   GNU coding standard.  It can be switched on by defining
   CRYPTOKI_GNU before including this header file.  For this, the
   following changes are made to the specification:

   All structure types are changed to a "struct ck_foo" where CK_FOO
   is the type name in PKCS #11.

   All non-structure types are changed to ck_foo_t where CK_FOO is the
   lowercase version of the type name in PKCS #11.  The basic types
   (CK_ULONG et al.) are removed without substitute.

   All members of structures are modified in the following way: Type
   indication prefixes are removed, and underscore characters are
   inserted before words.  Then the result is lowercased.

   Note that function names are still in the original case, as they
   need for ABI compatibility.

   CK_FALSE, CK_TRUE and NULL_PTR are removed without substitute.  Use
   <stdbool.h>.

   If CRYPTOKI_COMPAT is defined before including this header file,
   then none of the API changes above take place, and the API is the
   one defined by the PKCS #11 standard.  */

#यदि_अपरिभाषितम् PKCS11_H
#परिभाषय PKCS11_H 1

#यदि defined(__cplusplus)
बाह्य "C" {
#यदि_अन्तः


/* The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  */
#परिभाषय CRYPTOKI_संस्करणम्_MAJOR		3
#परिभाषय CRYPTOKI_संस्करणम्_MINOR		0
#परिभाषय CRYPTOKI_संस्करणम्_REVISION	0


/* Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  */
#यदि_अपरिभाषितम् CRYPTOKI_GNU
#यदि_अपरिभाषितम् CRYPTOKI_COMPAT
#परिभाषय CRYPTOKI_COMPAT 1
#यदि_अन्तः
#यदि_अन्तः

/* System dependencies.  */

#यदि defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#निर्देशः pack(प्रक्षिप, cryptoki, 1)

#यदि_परिभाषितम् CRYPTOKI_EXPORTS
#परिभाषय CK_SPEC __declspec(dllexport)
#अन्यथा
#परिभाषय CK_SPEC __declspec(dllimport)
#यदि_अन्तः

#अन्यथा

#परिभाषय CK_SPEC

#यदि_अन्तः

#यदि_परिभाषितम् CRYPTOKI_COMPAT
  /* If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  */

#परिभाषय ck_flags_t CK_FLAGS
#परिभाषय ck_संस्करणम् CK_संस्करणम्

#परिभाषय ck_info _CK_INFO
#परिभाषय cryptoki_संस्करणम् cryptoki_संस्करणम्_2
#परिभाषय manufacturer_id manufacturerID
#परिभाषय library_description libraryDescription
#परिभाषय library_संस्करणम् library_संस्करणम्_2

#परिभाषय ck_notification_t CK_NOTIFICATION
#परिभाषय ck_slot_id_t CK_SLOT_ID

#परिभाषय ck_slot_info _CK_SLOT_INFO
#परिभाषय slot_description slotDescription
#परिभाषय hardware_संस्करणम् hardware_संस्करणम्_2
#परिभाषय firmware_संस्करणम् firmware_संस्करणम्_2

#परिभाषय ck_token_info _CK_TOKEN_INFO
#परिभाषय serial_सङ्ख्या serial_सङ्ख्या_2
#परिभाषय max_session_गणनम् ul_Max_Session_गणनम्
#परिभाषय session_गणनम् ul_Session_गणनम्
#परिभाषय max_rw_session_गणनम् ul_Max_Rw_Session_गणनम्
#परिभाषय rw_session_गणनम् ul_Rw_Session_गणनम्
#परिभाषय max_pin_len ulMaxPinLen
#परिभाषय min_pin_len ulMinPinLen
#परिभाषय योग_लौकिकम्_स्मृतिः ul_योग_लौकिकम्_स्मृतिः
#परिभाषय free_लौकिकम्_स्मृतिः ul_Free_लौकिकम्_स्मृतिः
#परिभाषय योग_वैयक्तिकम्_स्मृतिः ul_योग_वैयक्तिकम्_स्मृतिः
#परिभाषय free_वैयक्तिकम्_स्मृतिः ul_Free_वैयक्तिकम्_स्मृतिः
#परिभाषय utc_time utcTime

#परिभाषय ck_session_handle_t CK_SESSION_HANDLE
#परिभाषय ck_user_type_t CK_USER_TYPE
#परिभाषय ck_state_t CK_STATE

#परिभाषय ck_session_info _CK_SESSION_INFO
#परिभाषय slot_id slotID
#परिभाषय device_error ulDeviceError

#परिभाषय ck_object_handle_t CK_OBJECT_HANDLE
#परिभाषय ck_object_class_t CK_OBJECT_CLASS
#परिभाषय ck_hw_feature_type_t CK_HW_FEATURE_TYPE
#परिभाषय ck_कुञ्चिका_type_t CK_कुञ्चिका_TYPE
#परिभाषय ck_certificate_type_t CK_CERTIFICATE_TYPE
#परिभाषय ck_attribute_type_t CK_ATTRIBUTE_TYPE

#परिभाषय ck_attribute _CK_ATTRIBUTE
#परिभाषय मानम् p_मानम्
#परिभाषय मानम्_len ul_मानम्_Len

#परिभाषय ck_date _CK_DATE

#परिभाषय ck_mechanism_type_t CK_MECHANISM_TYPE

#परिभाषय ck_rsa_pkcs_mgf_type_t CK_RSA_PKCS_MGF_TYPE

#परिभाषय ck_mechanism _CK_MECHANISM
#परिभाषय parameter pParameter
#परिभाषय parameter_len ulParameterLen

#परिभाषय ck_mechanism_info _CK_MECHANISM_INFO
#परिभाषय min_कुञ्चिका_आकार ul_Min_कुञ्चिका_आकार
#परिभाषय max_कुञ्चिका_आकार ul_Max_कुञ्चिका_आकार

#परिभाषय ck_rv_t CK_RV
#परिभाषय ck_notify_t CK_NOTIFY

#परिभाषय ck_interface CK_INTERFACE

#परिभाषय ck_function_list _CK_FUNCTION_LIST
#परिभाषय ck_function_list_3_0 _CK_FUNCTION_LIST_3_0

#परिभाषय ck_createmutex_t CK_CREATEMUTEX
#परिभाषय ck_destroymutex_t CK_DESTROYMUTEX
#परिभाषय ck_lockmutex_t CK_LOCKMUTEX
#परिभाषय ck_unlockmutex_t CK_UNLOCKMUTEX

#परिभाषय ck_c_initialize_तर्काः CK_C_INITIALIZE_तर्काः
#परिभाषय create_mutex CreateMutex
#परिभाषय destroy_mutex DestroyMutex
#परिभाषय तालकम्_mutex तालकम्_Mutex
#परिभाषय unlock_mutex UnlockMutex
#परिभाषय reserved pReserved

#यदि_अन्तः	/* CRYPTOKI_COMPAT */


प्रकारनिर्देश अचिह्नित दीर्घ ck_flags_t;

संरचना ck_संस्करणम्
{
  अचिह्नित वर्ण major;
  अचिह्नित वर्ण minor;
};


संरचना ck_info
{
  संरचना ck_संस्करणम् cryptoki_संस्करणम्;
  अचिह्नित वर्ण manufacturer_id[32];
  ck_flags_t flags;
  अचिह्नित वर्ण library_description[32];
  संरचना ck_संस्करणम् library_संस्करणम्;
};


प्रकारनिर्देश अचिह्नित दीर्घ ck_notification_t;

#परिभाषय CKN_SURRENDER	(0UL)


प्रकारनिर्देश अचिह्नित दीर्घ ck_slot_id_t;


संरचना ck_slot_info
{
  अचिह्नित वर्ण slot_description[64];
  अचिह्नित वर्ण manufacturer_id[32];
  ck_flags_t flags;
  संरचना ck_संस्करणम् hardware_संस्करणम्;
  संरचना ck_संस्करणम् firmware_संस्करणम्;
};


#परिभाषय CKF_TOKEN_PRESENT	(1UL << 0)
#परिभाषय CKF_REMOVABLE_DEVICE	(1UL << 1)
#परिभाषय CKF_HW_SLOT		(1UL << 2)
#परिभाषय CKF_ARRAY_ATTRIBUTE	(1UL << 30)


संरचना ck_token_info
{
  अचिह्नित वर्ण label[32];
  अचिह्नित वर्ण manufacturer_id[32];
  अचिह्नित वर्ण model[16];
  अचिह्नित वर्ण serial_सङ्ख्या[16];
  ck_flags_t flags;
  अचिह्नित दीर्घ max_session_गणनम्;
  अचिह्नित दीर्घ session_गणनम्;
  अचिह्नित दीर्घ max_rw_session_गणनम्;
  अचिह्नित दीर्घ rw_session_गणनम्;
  अचिह्नित दीर्घ max_pin_len;
  अचिह्नित दीर्घ min_pin_len;
  अचिह्नित दीर्घ योग_लौकिकम्_स्मृतिः;
  अचिह्नित दीर्घ free_लौकिकम्_स्मृतिः;
  अचिह्नित दीर्घ योग_वैयक्तिकम्_स्मृतिः;
  अचिह्नित दीर्घ free_वैयक्तिकम्_स्मृतिः;
  संरचना ck_संस्करणम् hardware_संस्करणम्;
  संरचना ck_संस्करणम् firmware_संस्करणम्;
  अचिह्नित वर्ण utc_time[16];
};


#परिभाषय CKF_RNG					(1UL << 0)
#परिभाषय CKF_WRITE_PROTECTED			(1UL << 1)
#परिभाषय CKF_LOGIN_REQUIRED			(1UL << 2)
#परिभाषय CKF_USER_PIN_INITIALIZED		(1UL << 3)
#परिभाषय CKF_RESTORE_कुञ्चिका_NOT_NEEDED		(1UL << 5)
#परिभाषय CKF_CLOCK_ON_TOKEN			(1UL << 6)
#परिभाषय CKF_PROTECTED_AUTHENTICATION_मार्गः	(1UL << 8)
#परिभाषय CKF_DUAL_CRYPTO_OPERATIONS		(1UL << 9)
#परिभाषय CKF_TOKEN_INITIALIZED			(1UL << 10)
#परिभाषय CKF_SECONDARY_AUTHENTICATION		(1UL << 11)
#परिभाषय CKF_USER_PIN_गणनम्_नीचः			(1UL << 16)
#परिभाषय CKF_USER_PIN_FINAL_TRY			(1UL << 17)
#परिभाषय CKF_USER_PIN_LOCKED			(1UL << 18)
#परिभाषय CKF_USER_PIN_गन्तव्यम्_BE_परिवर्तितम्		(1UL << 19)
#परिभाषय CKF_SO_PIN_गणनम्_नीचः			(1UL << 20)
#परिभाषय CKF_SO_PIN_FINAL_TRY			(1UL << 21)
#परिभाषय CKF_SO_PIN_LOCKED			(1UL << 22)
#परिभाषय CKF_SO_PIN_गन्तव्यम्_BE_परिवर्तितम्		(1UL << 23)

#परिभाषय CK_UNAVAILABLE_INFORMATION	((अचिह्नित दीर्घ) -1)
#परिभाषय CK_EFFECTIVELY_INFINITE		(0UL)


प्रकारनिर्देश अचिह्नित दीर्घ ck_session_handle_t;

#परिभाषय CK_INVALID_HANDLE	(0UL)


प्रकारनिर्देश अचिह्नित दीर्घ ck_user_type_t;

#परिभाषय CKU_SO			(0UL)
#परिभाषय CKU_USER		(1UL)
#परिभाषय CKU_CONTEXT_SPECIFIC	(2UL)


प्रकारनिर्देश अचिह्नित दीर्घ ck_state_t;

#परिभाषय CKS_RO_लौकिकम्_SESSION	(0UL)
#परिभाषय CKS_RO_USER_FUNCTIONS	(1UL)
#परिभाषय CKS_RW_लौकिकम्_SESSION	(2UL)
#परिभाषय CKS_RW_USER_FUNCTIONS	(3UL)
#परिभाषय CKS_RW_SO_FUNCTIONS	(4UL)


संरचना ck_session_info
{
  ck_slot_id_t slot_id;
  ck_state_t state;
  ck_flags_t flags;
  अचिह्नित दीर्घ device_error;
};

#परिभाषय CKF_RW_SESSION		(1UL << 1)
#परिभाषय CKF_SERIAL_SESSION	(1UL << 2)


प्रकारनिर्देश अचिह्नित दीर्घ ck_object_handle_t;


प्रकारनिर्देश अचिह्नित दीर्घ ck_object_class_t;

#परिभाषय CKO_दत्त		(0UL)
#परिभाषय CKO_CERTIFICATE		(1UL)
#परिभाषय CKO_लौकिकम्_कुञ्चिका		(2UL)
#परिभाषय CKO_वैयक्तिकम्_कुञ्चिका		(3UL)
#परिभाषय CKO_SECRET_कुञ्चिका		(4UL)
#परिभाषय CKO_HW_FEATURE		(5UL)
#परिभाषय CKO_DOMAIN_PARAMETERS	(6UL)
#परिभाषय CKO_MECHANISM		(7UL)
#परिभाषय CKO_OTP_कुञ्चिका		(8UL)
#परिभाषय CKO_PROFILE		(9UL)
#परिभाषय CKO_VENDOR_DEFINED	(1UL << 31)

#परिभाषय CKP_INVALID_ID                (0UL)
#परिभाषय CKP_BASELINE_PROVIDER         (1UL)
#परिभाषय CKP_EXTENDED_PROVIDER         (2UL)
#परिभाषय CKP_AUTHENTICATION_TOKEN      (3UL)
#परिभाषय CKP_लौकिकम्_CERTIFICATES_TOKEN (4UL)
#परिभाषय CKP_VENDOR_DEFINED            (1UL << 31)

प्रकारनिर्देश अचिह्नित दीर्घ ck_hw_feature_type_t;

#परिभाषय CKH_MONOTONIC_गणक	(1UL)
#परिभाषय CKH_CLOCK		(2UL)
#परिभाषय CKH_USER_INTERFACE	(3UL)
#परिभाषय CKH_VENDOR_DEFINED	(1UL << 31)


प्रकारनिर्देश अचिह्नित दीर्घ ck_कुञ्चिका_type_t;

#परिभाषय CKK_RSA			(0UL)
#परिभाषय CKK_DSA			(1UL)
#परिभाषय CKK_DH			(2UL)
#परिभाषय CKK_ECDSA		(3UL)
#परिभाषय CKK_EC			(3UL)
#परिभाषय CKK_X9_42_DH		(4UL)
#परिभाषय CKK_KEA			(5UL)
#परिभाषय CKK_GENERIC_SECRET	(0x10UL)
#परिभाषय CKK_RC2			(0x11UL)
#परिभाषय CKK_RC4			(0x12UL)
#परिभाषय CKK_DES			(0x13UL)
#परिभाषय CKK_DES2		(0x14UL)
#परिभाषय CKK_DES3		(0x15UL)
#परिभाषय CKK_CAST		(0x16UL)
#परिभाषय CKK_CAST3		(0x17UL)
#परिभाषय CKK_CAST128		(0x18UL)
#परिभाषय CKK_RC5			(0x19UL)
#परिभाषय CKK_IDEA		(0x1aUL)
#परिभाषय CKK_SKIPJACK		(0x1bUL)
#परिभाषय CKK_BATON		(0x1cUL)
#परिभाषय CKK_JUNIPER		(0x1dUL)
#परिभाषय CKK_CDMF		(0x1eUL)
#परिभाषय CKK_AES			(0x1fUL)
#परिभाषय CKK_BLOWFISH		(0x20UL)
#परिभाषय CKK_TWOFISH		(0x21UL)
#परिभाषय CKK_GOSTR3410		(0x30UL)
#परिभाषय CKK_GOSTR3411		(0x31UL)
#परिभाषय CKK_GOST28147		(0x32UL)
#परिभाषय CKK_EC_EDWARDS		(0x40UL)
#परिभाषय CKK_EC_MONTGOMERY	(0x41UL)
#परिभाषय CKK_HKDF		(0x42UL)
#परिभाषय CKK_VENDOR_DEFINED	(1UL << 31)

/*
 * A mask for new GOST algorithms.
 * For details visit https://tc26.ru/standarts/perevody/guidelines-the-pkcs-11-extensions-for-implementing-the-gost-r-34-10-2012-and-gost-r-34-11-2012-russian-standards-.html
 */
#परिभाषय NSSCK_VENDOR_PKCS11_RU_TEAM     (CKK_VENDOR_DEFINED | 0x54321000)
#परिभाषय CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

#परिभाषय CKK_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

प्रकारनिर्देश अचिह्नित दीर्घ ck_certificate_type_t;

#परिभाषय CKC_X_509		(0UL)
#परिभाषय CKC_X_509_ATTR_CERT	(1UL)
#परिभाषय CKC_WTLS		(2UL)
#परिभाषय CKC_VENDOR_DEFINED	(1UL << 31)


प्रकारनिर्देश अचिह्नित दीर्घ ck_attribute_type_t;

#परिभाषय CKA_CLASS			(0UL)
#परिभाषय CKA_TOKEN			(1UL)
#परिभाषय CKA_वैयक्तिकम्			(2UL)
#परिभाषय CKA_LABEL			(3UL)
#परिभाषय CKA_UNIQUE_ID		(4UL)
#परिभाषय CKA_APPLICATION			(0x10UL)
#परिभाषय CKA_मानम्			(0x11UL)
#परिभाषय CKA_OBJECT_ID			(0x12UL)
#परिभाषय CKA_CERTIFICATE_TYPE		(0x80UL)
#परिभाषय CKA_ISSUER			(0x81UL)
#परिभाषय CKA_SERIAL_सङ्ख्या		(0x82UL)
#परिभाषय CKA_AC_ISSUER			(0x83UL)
#परिभाषय CKA_OWNER			(0x84UL)
#परिभाषय CKA_ATTR_TYPES			(0x85UL)
#परिभाषय CKA_TRUSTED			(0x86UL)
#परिभाषय CKA_CERTIFICATE_CATEGORY	(0x87UL)
#परिभाषय CKA_JAVA_MIDP_SECURITY_DOMAIN	(0x88UL)
#परिभाषय CKA_URL				(0x89UL)
#परिभाषय CKA_HASH_सम्बन्धि_SUBJECT_लौकिकम्_कुञ्चिका	(0x8aUL)
#परिभाषय CKA_HASH_सम्बन्धि_ISSUER_लौकिकम्_कुञ्चिका	(0x8bUL)
#परिभाषय CKA_CHECK_मानम्			(0x90UL)
#परिभाषय CKA_कुञ्चिका_TYPE			(0x100UL)
#परिभाषय CKA_SUBJECT			(0x101UL)
#परिभाषय CKA_ID				(0x102UL)
#परिभाषय CKA_SENSITIVE			(0x103UL)
#परिभाषय CKA_ENCRYPT			(0x104UL)
#परिभाषय CKA_DECRYPT			(0x105UL)
#परिभाषय CKA_WRAP			(0x106UL)
#परिभाषय CKA_UNWRAP			(0x107UL)
#परिभाषय CKA_SIGN			(0x108UL)
#परिभाषय CKA_SIGN_RECOVER		(0x109UL)
#परिभाषय CKA_VERIFY			(0x10aUL)
#परिभाषय CKA_VERIFY_RECOVER		(0x10bUL)
#परिभाषय CKA_DERIVE			(0x10cUL)
#परिभाषय CKA_START_DATE			(0x110UL)
#परिभाषय CKA_अन्तः_DATE			(0x111UL)
#परिभाषय CKA_MODULUS			(0x120UL)
#परिभाषय CKA_MODULUS_द्वयङ्काः		(0x121UL)
#परिभाषय CKA_लौकिकम्_EXPONENT		(0x122UL)
#परिभाषय CKA_वैयक्तिकम्_EXPONENT		(0x123UL)
#परिभाषय CKA_अविभाज्यः_1			(0x124UL)
#परिभाषय CKA_अविभाज्यः_2			(0x125UL)
#परिभाषय CKA_EXPONENT_1			(0x126UL)
#परिभाषय CKA_EXPONENT_2			(0x127UL)
#परिभाषय CKA_COEFFICIENT			(0x128UL)
#परिभाषय CKA_लौकिकम्_कुञ्चिका_INFO		(0x129UL)
#परिभाषय CKA_अविभाज्यः			(0x130UL)
#परिभाषय CKA_SUBPRIME			(0x131UL)
#परिभाषय CKA_आधारः			(0x132UL)
#परिभाषय CKA_अविभाज्यः_द्वयङ्काः			(0x133UL)
#परिभाषय CKA_SUB_अविभाज्यः_द्वयङ्काः		(0x134UL)
#परिभाषय CKA_मानम्_द्वयङ्काः			(0x160UL)
#परिभाषय CKA_मानम्_LEN			(0x161UL)
#परिभाषय CKA_EXTRACTABLE			(0x162UL)
#परिभाषय CKA_LOCAL			(0x163UL)
#परिभाषय CKA_NEVER_EXTRACTABLE		(0x164UL)
#परिभाषय CKA_ALWAYS_SENSITIVE		(0x165UL)
#परिभाषय CKA_कुञ्चिका_GEN_MECHANISM		(0x166UL)
#परिभाषय CKA_MODIFIABLE			(0x170UL)
#परिभाषय CKA_COPYABLE			(0x171UL)
#परिभाषय CKA_DESTROYABLE			(0x172UL)
#परिभाषय CKA_ECDSA_PARAMS		(0x180UL)
#परिभाषय CKA_EC_PARAMS			(0x180UL)
#परिभाषय CKA_EC_POINT			(0x181UL)
#परिभाषय CKA_SECONDARY_AUTH		(0x200UL)
#परिभाषय CKA_AUTH_PIN_FLAGS		(0x201UL)
#परिभाषय CKA_ALWAYS_AUTHENTICATE		(0x202UL)
#परिभाषय CKA_WRAP_WITH_TRUSTED		(0x210UL)
#परिभाषय CKA_GOSTR3410_PARAMS		(0x250UL)
#परिभाषय CKA_GOSTR3411_PARAMS		(0x251UL)
#परिभाषय CKA_GOST28147_PARAMS		(0x252UL)
#परिभाषय CKA_HW_FEATURE_TYPE		(0x300UL)
#परिभाषय CKA_RESET_ON_INIT		(0x301UL)
#परिभाषय CKA_HAS_RESET			(0x302UL)
#परिभाषय CKA_PIXEL_X			(0x400UL)
#परिभाषय CKA_PIXEL_Y			(0x401UL)
#परिभाषय CKA_RESOLUTION			(0x402UL)
#परिभाषय CKA_CHAR_पङ्क्तिकाः			(0x403UL)
#परिभाषय CKA_CHAR_COLUMNS		(0x404UL)
#परिभाषय CKA_COLOR			(0x405UL)
#परिभाषय CKA_द्वयङ्काः_प्रत्येकम्_PIXEL		(0x406UL)
#परिभाषय CKA_CHAR_SETS			(0x480UL)
#परिभाषय CKA_ENCODING_METHODS		(0x481UL)
#परिभाषय CKA_MIME_TYPES			(0x482UL)
#परिभाषय CKA_MECHANISM_TYPE		(0x500UL)
#परिभाषय CKA_REQUIRED_CMS_गुणाः	(0x501UL)
#परिभाषय CKA_DEFAULT_CMS_गुणाः	(0x502UL)
#परिभाषय CKA_SUPPORTED_CMS_गुणाः	(0x503UL)
#परिभाषय CKA_WRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x211UL)
#परिभाषय CKA_UNWRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x212UL)
#परिभाषय CKA_OTP_FORMAT			(0x220UL)
#परिभाषय CKA_OTP_दीर्घता			(0x221UL)
#परिभाषय CKA_OTP_TIME_INTERVAL		(0x222UL)
#परिभाषय CKA_OTP_USER_FRIENDLY_बहुलकम्	(0x223UL)
#परिभाषय CKA_OTP_CHALLENGE_REQUIREMENT	(0x224UL)
#परिभाषय CKA_OTP_TIME_REQUIREMENT	(0x225UL)
#परिभाषय CKA_OTP_गणक_REQUIREMENT	(0x226UL)
#परिभाषय CKA_OTP_PIN_REQUIREMENT		(0x227UL)
#परिभाषय CKA_OTP_USER_IDENTIFIER		(0x22AUL)
#परिभाषय CKA_OTP_SERVICE_IDENTIFIER	(0x22BUL)
#परिभाषय CKA_OTP_SERVICE_LOGO		(0x22CUL)
#परिभाषय CKA_OTP_SERVICE_LOGO_TYPE	(0x22DUL)
#परिभाषय CKA_OTP_गणक			(0x22EUL)
#परिभाषय CKA_OTP_TIME			(0x22FUL)
#परिभाषय CKA_ALLOWED_MECHANISMS		(CKF_ARRAY_ATTRIBUTE | 0x600UL)
#परिभाषय CKA_PROFILE_ID			(0x601UL)
#परिभाषय CKA_VENDOR_DEFINED		(1UL << 31)


संरचना ck_attribute
{
  ck_attribute_type_t type;
  शून्य *मानम्;
  अचिह्नित दीर्घ मानम्_len;
};


संरचना ck_date
{
  अचिह्नित वर्ण year[4];
  अचिह्नित वर्ण month[2];
  अचिह्नित वर्ण day[2];
};


प्रकारनिर्देश अचिह्नित दीर्घ ck_mechanism_type_t;

#परिभाषय CKM_RSA_PKCS_कुञ्चिका_PAIR_GEN	(0UL)
#परिभाषय CKM_RSA_PKCS			(1UL)
#परिभाषय CKM_RSA_9796			(2UL)
#परिभाषय CKM_RSA_X_509			(3UL)
#परिभाषय CKM_MD2_RSA_PKCS		(4UL)
#परिभाषय CKM_MD5_RSA_PKCS		(5UL)
#परिभाषय CKM_SHA1_RSA_PKCS		(6UL)
#परिभाषय CKM_RIPEMD128_RSA_PKCS		(7UL)
#परिभाषय CKM_RIPEMD160_RSA_PKCS		(8UL)
#परिभाषय CKM_RSA_PKCS_OAEP		(9UL)
#परिभाषय CKM_RSA_X9_31_कुञ्चिका_PAIR_GEN	(0xaUL)
#परिभाषय CKM_RSA_X9_31			(0xbUL)
#परिभाषय CKM_SHA1_RSA_X9_31		(0xcUL)
#परिभाषय CKM_RSA_PKCS_PSS		(0xdUL)
#परिभाषय CKM_SHA1_RSA_PKCS_PSS		(0xeUL)
#परिभाषय CKM_DSA_कुञ्चिका_PAIR_GEN		(0x10UL)
#परिभाषय	CKM_DSA				(0x11UL)
#परिभाषय CKM_DSA_SHA1			(0x12UL)
#परिभाषय CKM_DSA_SHA224			(0x13UL)
#परिभाषय CKM_DSA_SHA256			(0x14UL)
#परिभाषय CKM_DSA_SHA384			(0x15UL)
#परिभाषय CKM_DSA_SHA512			(0x16UL)
#परिभाषय CKM_DH_PKCS_कुञ्चिका_PAIR_GEN	(0x20UL)
#परिभाषय CKM_DH_PKCS_DERIVE		(0x21UL)
#परिभाषय	CKM_X9_42_DH_कुञ्चिका_PAIR_GEN	(0x30UL)
#परिभाषय CKM_X9_42_DH_DERIVE		(0x31UL)
#परिभाषय CKM_X9_42_DH_HYBRID_DERIVE	(0x32UL)
#परिभाषय CKM_X9_42_MQV_DERIVE		(0x33UL)
#परिभाषय CKM_SHA256_RSA_PKCS		(0x40UL)
#परिभाषय CKM_SHA384_RSA_PKCS		(0x41UL)
#परिभाषय CKM_SHA512_RSA_PKCS		(0x42UL)
#परिभाषय CKM_SHA256_RSA_PKCS_PSS		(0x43UL)
#परिभाषय CKM_SHA384_RSA_PKCS_PSS		(0x44UL)
#परिभाषय CKM_SHA512_RSA_PKCS_PSS		(0x45UL)
#परिभाषय CKM_SHA224_RSA_PKCS		(0x46UL)
#परिभाषय CKM_SHA224_RSA_PKCS_PSS		(0x47UL)
#परिभाषय CKM_SHA3_256_RSA_PKCS		(0x60UL)
#परिभाषय CKM_SHA3_384_RSA_PKCS		(0x61UL)
#परिभाषय CKM_SHA3_512_RSA_PKCS		(0x62UL)
#परिभाषय CKM_SHA3_256_RSA_PKCS_PSS	(0x63UL)
#परिभाषय CKM_SHA3_384_RSA_PKCS_PSS	(0x64UL)
#परिभाषय CKM_SHA3_512_RSA_PKCS_PSS	(0x65UL)
#परिभाषय CKM_SHA3_224_RSA_PKCS		(0x66UL)
#परिभाषय CKM_SHA3_224_RSA_PKCS_PSS	(0x67UL)
#परिभाषय CKM_RC2_कुञ्चिका_GEN			(0x100UL)
#परिभाषय CKM_RC2_ECB			(0x101UL)
#परिभाषय	CKM_RC2_CBC			(0x102UL)
#परिभाषय	CKM_RC2_MAC			(0x103UL)
#परिभाषय CKM_RC2_MAC_GENERAL		(0x104UL)
#परिभाषय CKM_RC2_CBC_PAD			(0x105UL)
#परिभाषय CKM_RC4_कुञ्चिका_GEN			(0x110UL)
#परिभाषय CKM_RC4				(0x111UL)
#परिभाषय CKM_DES_कुञ्चिका_GEN			(0x120UL)
#परिभाषय CKM_DES_ECB			(0x121UL)
#परिभाषय CKM_DES_CBC			(0x122UL)
#परिभाषय CKM_DES_MAC			(0x123UL)
#परिभाषय CKM_DES_MAC_GENERAL		(0x124UL)
#परिभाषय CKM_DES_CBC_PAD			(0x125UL)
#परिभाषय CKM_DES2_कुञ्चिका_GEN		(0x130UL)
#परिभाषय CKM_DES3_कुञ्चिका_GEN		(0x131UL)
#परिभाषय CKM_DES3_ECB			(0x132UL)
#परिभाषय CKM_DES3_CBC			(0x133UL)
#परिभाषय CKM_DES3_MAC			(0x134UL)
#परिभाषय CKM_DES3_MAC_GENERAL		(0x135UL)
#परिभाषय CKM_DES3_CBC_PAD		(0x136UL)
#परिभाषय CKM_DES3_CMAC_GENERAL		(0x137UL)
#परिभाषय CKM_DES3_CMAC			(0x138UL)
#परिभाषय CKM_CDMF_कुञ्चिका_GEN		(0x140UL)
#परिभाषय CKM_CDMF_ECB			(0x141UL)
#परिभाषय CKM_CDMF_CBC			(0x142UL)
#परिभाषय CKM_CDMF_MAC			(0x143UL)
#परिभाषय CKM_CDMF_MAC_GENERAL		(0x144UL)
#परिभाषय CKM_CDMF_CBC_PAD		(0x145UL)
#परिभाषय CKM_MD2				(0x200UL)
#परिभाषय CKM_MD2_HMAC			(0x201UL)
#परिभाषय CKM_MD2_HMAC_GENERAL		(0x202UL)
#परिभाषय CKM_MD5				(0x210UL)
#परिभाषय CKM_MD5_HMAC			(0x211UL)
#परिभाषय CKM_MD5_HMAC_GENERAL		(0x212UL)
#परिभाषय CKM_SHA_1			(0x220UL)
#परिभाषय CKM_SHA_1_HMAC			(0x221UL)
#परिभाषय CKM_SHA_1_HMAC_GENERAL		(0x222UL)
#परिभाषय CKM_RIPEMD128			(0x230UL)
#परिभाषय CKM_RIPEMD128_HMAC		(0x231UL)
#परिभाषय CKM_RIPEMD128_HMAC_GENERAL	(0x232UL)
#परिभाषय CKM_RIPEMD160			(0x240UL)
#परिभाषय CKM_RIPEMD160_HMAC		(0x241UL)
#परिभाषय CKM_RIPEMD160_HMAC_GENERAL	(0x242UL)
#परिभाषय CKM_SHA256			(0x250UL)
#परिभाषय CKM_SHA256_HMAC			(0x251UL)
#परिभाषय CKM_SHA256_HMAC_GENERAL		(0x252UL)
#परिभाषय CKM_SHA224			(0x255UL)
#परिभाषय CKM_SHA224_HMAC			(0x256UL)
#परिभाषय CKM_SHA224_HMAC_GENERAL		(0x257UL)
#परिभाषय CKM_SHA384			(0x260UL)
#परिभाषय CKM_SHA384_HMAC			(0x261UL)
#परिभाषय CKM_SHA384_HMAC_GENERAL		(0x262UL)
#परिभाषय CKM_SHA512			(0x270UL)
#परिभाषय CKM_SHA512_HMAC			(0x271UL)
#परिभाषय CKM_SHA512_HMAC_GENERAL		(0x272UL)
#परिभाषय CKM_SHA3_256			(0x2B0UL)
#परिभाषय CKM_SHA3_256_HMAC		(0x2B1UL)
#परिभाषय CKM_SHA3_256_HMAC_GENERAL	(0x2B2UL)
#परिभाषय CKM_SHA3_256_कुञ्चिका_GEN		(0x2B3UL)
#परिभाषय CKM_SHA3_224			(0x2B5UL)
#परिभाषय CKM_SHA3_224_HMAC		(0x2B6UL)
#परिभाषय CKM_SHA3_224_HMAC_GENERAL	(0x2B7UL)
#परिभाषय CKM_SHA3_224_कुञ्चिका_GEN		(0x2B8UL)
#परिभाषय CKM_SHA3_384			(0x2C0UL)
#परिभाषय CKM_SHA3_384_HMAC		(0x2C1UL)
#परिभाषय CKM_SHA3_384_HMAC_GENERAL	(0x2C2UL)
#परिभाषय CKM_SHA3_384_कुञ्चिका_GEN		(0x2C3UL)
#परिभाषय CKM_SHA3_512			(0x2D0UL)
#परिभाषय CKM_SHA3_512_HMAC		(0x2D1UL)
#परिभाषय CKM_SHA3_512_HMAC_GENERAL	(0x2D2UL)
#परिभाषय CKM_SHA3_512_कुञ्चिका_GEN		(0x2D3UL)
#परिभाषय CKM_CAST_कुञ्चिका_GEN		(0x300UL)
#परिभाषय CKM_CAST_ECB			(0x301UL)
#परिभाषय CKM_CAST_CBC			(0x302UL)
#परिभाषय CKM_CAST_MAC			(0x303UL)
#परिभाषय CKM_CAST_MAC_GENERAL		(0x304UL)
#परिभाषय CKM_CAST_CBC_PAD		(0x305UL)
#परिभाषय CKM_CAST3_कुञ्चिका_GEN		(0x310UL)
#परिभाषय CKM_CAST3_ECB			(0x311UL)
#परिभाषय CKM_CAST3_CBC			(0x312UL)
#परिभाषय CKM_CAST3_MAC			(0x313UL)
#परिभाषय CKM_CAST3_MAC_GENERAL		(0x314UL)
#परिभाषय CKM_CAST3_CBC_PAD		(0x315UL)
#परिभाषय CKM_CAST5_कुञ्चिका_GEN		(0x320UL)
#परिभाषय CKM_CAST128_कुञ्चिका_GEN		(0x320UL)
#परिभाषय CKM_CAST5_ECB			(0x321UL)
#परिभाषय CKM_CAST128_ECB			(0x321UL)
#परिभाषय CKM_CAST5_CBC			(0x322UL)
#परिभाषय CKM_CAST128_CBC			(0x322UL)
#परिभाषय CKM_CAST5_MAC			(0x323UL)
#परिभाषय	CKM_CAST128_MAC			(0x323UL)
#परिभाषय CKM_CAST5_MAC_GENERAL		(0x324UL)
#परिभाषय CKM_CAST128_MAC_GENERAL		(0x324UL)
#परिभाषय CKM_CAST5_CBC_PAD		(0x325UL)
#परिभाषय CKM_CAST128_CBC_PAD		(0x325UL)
#परिभाषय CKM_RC5_कुञ्चिका_GEN			(0x330UL)
#परिभाषय CKM_RC5_ECB			(0x331UL)
#परिभाषय CKM_RC5_CBC			(0x332UL)
#परिभाषय CKM_RC5_MAC			(0x333UL)
#परिभाषय CKM_RC5_MAC_GENERAL		(0x334UL)
#परिभाषय CKM_RC5_CBC_PAD			(0x335UL)
#परिभाषय CKM_IDEA_कुञ्चिका_GEN		(0x340UL)
#परिभाषय CKM_IDEA_ECB			(0x341UL)
#परिभाषय	CKM_IDEA_CBC			(0x342UL)
#परिभाषय CKM_IDEA_MAC			(0x343UL)
#परिभाषय CKM_IDEA_MAC_GENERAL		(0x344UL)
#परिभाषय CKM_IDEA_CBC_PAD		(0x345UL)
#परिभाषय CKM_GENERIC_SECRET_कुञ्चिका_GEN	(0x350UL)
#परिभाषय CKM_CONCATENATE_आधारः_AND_कुञ्चिका	(0x360UL)
#परिभाषय CKM_CONCATENATE_आधारः_AND_दत्त	(0x362UL)
#परिभाषय CKM_CONCATENATE_दत्त_AND_आधारः	(0x363UL)
#परिभाषय CKM_XOR_आधारः_AND_दत्त		(0x364UL)
#परिभाषय CKM_EXTRACT_कुञ्चिका_FROM_कुञ्चिका	(0x365UL)
#परिभाषय CKM_SSL3_PRE_MASTER_कुञ्चिका_GEN	(0x370UL)
#परिभाषय CKM_SSL3_MASTER_कुञ्चिका_DERIVE	(0x371UL)
#परिभाषय CKM_SSL3_कुञ्चिका_AND_MAC_DERIVE	(0x372UL)
#परिभाषय CKM_SSL3_MASTER_कुञ्चिका_DERIVE_DH	(0x373UL)
#परिभाषय CKM_TLS_PRE_MASTER_कुञ्चिका_GEN	(0x374UL)
#परिभाषय CKM_TLS_MASTER_कुञ्चिका_DERIVE	(0x375UL)
#परिभाषय CKM_TLS_कुञ्चिका_AND_MAC_DERIVE	(0x376UL)
#परिभाषय CKM_TLS_MASTER_कुञ्चिका_DERIVE_DH	(0x377UL)
#परिभाषय CKM_SSL3_MD5_MAC		(0x380UL)
#परिभाषय CKM_SSL3_SHA1_MAC		(0x381UL)
#परिभाषय CKM_MD5_कुञ्चिका_DERIVATION		(0x390UL)
#परिभाषय CKM_MD2_कुञ्चिका_DERIVATION		(0x391UL)
#परिभाषय CKM_SHA1_कुञ्चिका_DERIVATION		(0x392UL)
#परिभाषय CKM_PBE_MD2_DES_CBC		(0x3a0UL)
#परिभाषय CKM_PBE_MD5_DES_CBC		(0x3a1UL)
#परिभाषय CKM_PBE_MD5_CAST_CBC		(0x3a2UL)
#परिभाषय CKM_PBE_MD5_CAST3_CBC		(0x3a3UL)
#परिभाषय CKM_PBE_MD5_CAST5_CBC		(0x3a4UL)
#परिभाषय CKM_PBE_MD5_CAST128_CBC		(0x3a4UL)
#परिभाषय CKM_PBE_SHA1_CAST5_CBC		(0x3a5UL)
#परिभाषय CKM_PBE_SHA1_CAST128_CBC	(0x3a5UL)
#परिभाषय CKM_PBE_SHA1_RC4_128		(0x3a6UL)
#परिभाषय CKM_PBE_SHA1_RC4_40		(0x3a7UL)
#परिभाषय CKM_PBE_SHA1_DES3_EDE_CBC	(0x3a8UL)
#परिभाषय CKM_PBE_SHA1_DES2_EDE_CBC	(0x3a9UL)
#परिभाषय CKM_PBE_SHA1_RC2_128_CBC	(0x3aaUL)
#परिभाषय CKM_PBE_SHA1_RC2_40_CBC		(0x3abUL)
#परिभाषय CKM_PKCS5_PBKD2			(0x3b0UL)
#परिभाषय CKM_PBA_SHA1_WITH_SHA1_HMAC	(0x3c0UL)
#परिभाषय CKM_कुञ्चिका_WRAP_LYNKS		(0x400UL)
#परिभाषय CKM_कुञ्चिका_WRAP_समुच्चयः_OAEP		(0x401UL)
#परिभाषय CKM_SKIPJACK_कुञ्चिका_GEN		(0x1000UL)
#परिभाषय CKM_SKIPJACK_ECB64		(0x1001UL)
#परिभाषय CKM_SKIPJACK_CBC64		(0x1002UL)
#परिभाषय CKM_SKIPJACK_OFB64		(0x1003UL)
#परिभाषय CKM_SKIPJACK_CFB64		(0x1004UL)
#परिभाषय CKM_SKIPJACK_CFB32		(0x1005UL)
#परिभाषय CKM_SKIPJACK_CFB16		(0x1006UL)
#परिभाषय CKM_SKIPJACK_CFB8		(0x1007UL)
#परिभाषय CKM_SKIPJACK_WRAP		(0x1008UL)
#परिभाषय CKM_SKIPJACK_वैयक्तिकम्_WRAP	(0x1009UL)
#परिभाषय CKM_SKIPJACK_RELAYX		(0x100aUL)
#परिभाषय CKM_KEA_कुञ्चिका_PAIR_GEN		(0x1010UL)
#परिभाषय CKM_KEA_कुञ्चिका_DERIVE		(0x1011UL)
#परिभाषय CKM_FORTEZZA_TIMESTAMP		(0x1020UL)
#परिभाषय CKM_BATON_कुञ्चिका_GEN		(0x1030UL)
#परिभाषय CKM_BATON_ECB128		(0x1031UL)
#परिभाषय CKM_BATON_ECB96			(0x1032UL)
#परिभाषय CKM_BATON_CBC128		(0x1033UL)
#परिभाषय CKM_BATON_गणक		(0x1034UL)
#परिभाषय CKM_BATON_SHUFFLE		(0x1035UL)
#परिभाषय CKM_BATON_WRAP			(0x1036UL)
#परिभाषय CKM_ECDSA_कुञ्चिका_PAIR_GEN		(0x1040UL)
#परिभाषय CKM_EC_कुञ्चिका_PAIR_GEN		(0x1040UL)
#परिभाषय CKM_ECDSA			(0x1041UL)
#परिभाषय CKM_ECDSA_SHA1			(0x1042UL)
#परिभाषय CKM_ECDSA_SHA224		(0x1043UL)
#परिभाषय CKM_ECDSA_SHA256		(0x1044UL)
#परिभाषय CKM_ECDSA_SHA384		(0x1045UL)
#परिभाषय CKM_ECDSA_SHA512		(0x1046UL)
#परिभाषय CKM_ECDSA_SHA3_224		(0x1047UL)
#परिभाषय CKM_ECDSA_SHA3_256		(0x1048UL)
#परिभाषय CKM_ECDSA_SHA3_384		(0x1049UL)
#परिभाषय CKM_ECDSA_SHA3_512		(0x104AUL)
#परिभाषय CKM_ECDH1_DERIVE		(0x1050UL)
#परिभाषय CKM_ECDH1_COFACTOR_DERIVE	(0x1051UL)
#परिभाषय CKM_ECMQV_DERIVE		(0x1052UL)
#परिभाषय CKM_EC_EDWARDS_कुञ्चिका_PAIR_GEN     (0x1055UL)
#परिभाषय CKM_EC_MONTGOMERY_कुञ्चिका_PAIR_GEN  (0x1056UL)
#परिभाषय CKM_EDDSA			(0x1057UL)
#परिभाषय CKM_JUNIPER_कुञ्चिका_GEN		(0x1060UL)
#परिभाषय CKM_JUNIPER_ECB128		(0x1061UL)
#परिभाषय CKM_JUNIPER_CBC128		(0x1062UL)
#परिभाषय CKM_JUNIPER_गणक		(0x1063UL)
#परिभाषय CKM_JUNIPER_SHUFFLE		(0x1064UL)
#परिभाषय CKM_JUNIPER_WRAP		(0x1065UL)
#परिभाषय CKM_FASTHASH			(0x1070UL)
#परिभाषय CKM_AES_कुञ्चिका_GEN			(0x1080UL)
#परिभाषय CKM_AES_ECB			(0x1081UL)
#परिभाषय CKM_AES_CBC			(0x1082UL)
#परिभाषय CKM_AES_MAC			(0x1083UL)
#परिभाषय CKM_AES_MAC_GENERAL		(0x1084UL)
#परिभाषय CKM_AES_CBC_PAD			(0x1085UL)
#परिभाषय CKM_AES_CTR				(0x1086UL)
#परिभाषय CKM_AES_GCM				(0x1087UL)
#परिभाषय CKM_AES_CCM				(0x1088UL)
#परिभाषय CKM_AES_CTS				(0x1089UL)
#परिभाषय CKM_AES_CMAC			(0x108AUL)
#परिभाषय CKM_AES_CMAC_GENERAL		(0x108BUL)
#परिभाषय CKM_AES_XCBC_MAC		(0x108CUL)
#परिभाषय CKM_AES_XCBC_MAC_96		(0x108DUL)
#परिभाषय CKM_AES_GMAC			(0x108EUL)
#परिभाषय CKM_BLOWFISH_कुञ्चिका_GEN    (0x1090UL)
#परिभाषय CKM_BLOWFISH_CBC        (0x1091UL)
#परिभाषय CKM_TWOFISH_कुञ्चिका_GEN     (0x1092UL)
#परिभाषय CKM_TWOFISH_CBC         (0x1093UL)
#परिभाषय CKM_DES_ECB_ENCRYPT_दत्त	(0x1100UL)
#परिभाषय CKM_DES_CBC_ENCRYPT_दत्त	(0x1101UL)
#परिभाषय CKM_DES3_ECB_ENCRYPT_दत्त	(0x1102UL)
#परिभाषय CKM_DES3_CBC_ENCRYPT_दत्त	(0x1103UL)
#परिभाषय CKM_AES_ECB_ENCRYPT_दत्त	(0x1104UL)
#परिभाषय CKM_AES_CBC_ENCRYPT_दत्त	(0x1105UL)
#परिभाषय CKM_GOSTR3410_कुञ्चिका_PAIR_GEN	(0x1200UL)
#परिभाषय CKM_GOSTR3410			(0x1201UL)
#परिभाषय CKM_GOSTR3410_WITH_GOSTR3411	(0x1202UL)
#परिभाषय CKM_GOSTR3410_कुञ्चिका_WRAP  (0x1203UL)
#परिभाषय CKM_GOSTR3410_DERIVE    (0x1204UL)
#परिभाषय CKM_GOSTR3410_512_कुञ्चिका_PAIR_GEN	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#परिभाषय CKM_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#परिभाषय CKM_GOSTR3410_12_DERIVE	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#परिभाषय CKM_GOSTR3410_WITH_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#परिभाषय CKM_GOSTR3410_WITH_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#परिभाषय CKM_GOSTR3411			(0x1210UL)
#परिभाषय CKM_GOSTR3411_HMAC      (0x1211UL)
#परिभाषय CKM_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#परिभाषय CKM_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#परिभाषय CKM_GOSTR3411_12_256_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#परिभाषय CKM_GOSTR3411_12_512_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#परिभाषय CKM_GOST28147_कुञ्चिका_GEN   (0x1220UL)
#परिभाषय CKM_GOST28147_ECB       (0x1221UL)
#परिभाषय CKM_GOST28147           (0x1222UL)
#परिभाषय CKM_GOST28147_MAC       (0x1223UL)
#परिभाषय CKM_GOST28147_कुञ्चिका_WRAP  (0x1224UL)

#परिभाषय CKM_DSA_PARAMETER_GEN		(0x2000UL)
#परिभाषय CKM_DH_PKCS_PARAMETER_GEN	(0x2001UL)
#परिभाषय CKM_X9_42_DH_PARAMETER_GEN	(0x2002UL)
#परिभाषय CKM_AES_OFB			(0x2104UL)
#परिभाषय CKM_AES_CFB64			(0x2105UL)
#परिभाषय CKM_AES_CFB8			(0x2106UL)
#परिभाषय CKM_AES_CFB128			(0x2107UL)
#परिभाषय CKM_AES_CFB1			(0x2108UL)
#परिभाषय CKM_AES_कुञ्चिका_WRAP		(0x2109UL)
#परिभाषय CKM_AES_कुञ्चिका_WRAP_PAD		(0x210AUL)
#परिभाषय CKM_XEDDSA			(0x4029UL)
#परिभाषय CKM_HKDF_DERIVE			(0x402AUL)
#परिभाषय CKM_HKDF_दत्त			(0x402BUL)
#परिभाषय CKM_HKDF_कुञ्चिका_GEN		(0x402CUL)

#परिभाषय CKM_VENDOR_DEFINED		(1UL << 31)

संरचना ck_mechanism
{
  ck_mechanism_type_t mechanism;
  शून्य *parameter;
  अचिह्नित दीर्घ parameter_len;
};


संरचना ck_mechanism_info
{
  अचिह्नित दीर्घ min_कुञ्चिका_आकार;
  अचिह्नित दीर्घ max_कुञ्चिका_आकार;
  ck_flags_t flags;
};

#परिभाषय CKF_HW			(1UL << 0)

#परिभाषय CKF_सन्देशः_ENCRYPT	(1UL << 1)
#परिभाषय CKF_सन्देशः_DECRYPT	(1UL << 2)
#परिभाषय CKF_सन्देशः_SIGN	(1UL << 3)
#परिभाषय CKF_सन्देशः_VERIFY	(1UL << 4)
#परिभाषय CKF_MULTI_सन्देशः	(1UL << 5)
#परिभाषय CKF_FIND_OBJECTS	(1UL << 6)

#परिभाषय CKF_ENCRYPT		(1UL << 8)
#परिभाषय CKF_DECRYPT		(1UL << 9)
#परिभाषय CKF_DIGEST		(1UL << 10)
#परिभाषय CKF_SIGN		(1UL << 11)
#परिभाषय CKF_SIGN_RECOVER	(1UL << 12)
#परिभाषय CKF_VERIFY		(1UL << 13)
#परिभाषय CKF_VERIFY_RECOVER	(1UL << 14)
#परिभाषय CKF_GENERATE		(1UL << 15)
#परिभाषय CKF_GENERATE_कुञ्चिका_PAIR	(1UL << 16)
#परिभाषय CKF_WRAP		(1UL << 17)
#परिभाषय CKF_UNWRAP		(1UL << 18)
#परिभाषय CKF_DERIVE		(1UL << 19)
#परिभाषय CKF_EXTENSION		(1UL << 31)

#परिभाषय CKF_EC_F_P			(1UL << 20)
#परिभाषय CKF_EC_F_2M			(1UL << 21)
#परिभाषय CKF_EC_ECPARAMETERS	(1UL << 22)
#परिभाषय CKF_EC_OID		(1UL << 23)
#परिभाषय CKF_EC_NAMEDCURVE	CKF_EC_OID
#परिभाषय CKF_EC_UNCOMPRESS	(1UL << 24)
#परिभाषय CKF_EC_COMPRESS		(1UL << 25)
#परिभाषय CKF_EC_CURVENAME	(1UL << 26)

/* Flags for C_WaitForSlotEvent.  */
#परिभाषय CKF_DONT_खण्डम्				(1UL)

/* Flags for Key derivation */
#परिभाषय CKD_NULL			(0x1UL)
#परिभाषय CKD_SHA1_KDF			(0x2UL)
#परिभाषय CKD_SHA224_KDF			(0x5UL)
#परिभाषय CKD_SHA256_KDF			(0x6UL)
#परिभाषय CKD_SHA384_KDF			(0x7UL)
#परिभाषय CKD_SHA512_KDF			(0x8UL)

प्रकारनिर्देश संरचना CK_ECDH1_DERIVE_PARAMS {
	अचिह्नित दीर्घ  kdf;
	अचिह्नित दीर्घ  ul_Shared_दत्त_Len;
	अचिह्नित वर्ण *  p_Shared_दत्त;
	अचिह्नित दीर्घ  ul_लौकिकम्_दत्त_Len;
	अचिह्नित वर्ण *  p_लौकिकम्_दत्त;
} CK_ECDH1_DERIVE_PARAMS;

प्रकारनिर्देश संरचना CK_ECMQV_DERIVE_PARAMS {
	अचिह्नित दीर्घ kdf;
	अचिह्नित दीर्घ ul_Shared_दत्त_Len;
	अचिह्नित वर्ण * p_Shared_दत्त;
	अचिह्नित दीर्घ ul_लौकिकम्_दत्त_Len;
	अचिह्नित वर्ण * p_लौकिकम्_दत्त;
	अचिह्नित दीर्घ ul_वैयक्तिकम्_दत्त_Len;
	CK_OBJECT_HANDLE h_वैयक्तिकम्_दत्त;
	अचिह्नित दीर्घ ul_लौकिकम्_दत्त_Len2;
	अचिह्नित वर्ण * p_लौकिकम्_Data2;
	CK_OBJECT_HANDLE लौकिकम्_कुञ्चिका_2;
} CK_ECMQV_DERIVE_PARAMS;

प्रकारनिर्देश अचिह्नित दीर्घ ck_rsa_pkcs_mgf_type_t;
प्रकारनिर्देश अचिह्नित दीर्घ CK_RSA_PKCS_OAEP_SOURCE_TYPE;

प्रकारनिर्देश संरचना CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
	शून्य *p_Source_दत्त;
	अचिह्नित दीर्घ ul_Source_दत्त_Len;
} CK_RSA_PKCS_OAEP_PARAMS;

प्रकारनिर्देश संरचना CK_RSA_PKCS_PSS_PARAMS {
	ck_mechanism_type_t hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	अचिह्नित दीर्घ sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#परिभाषय CKG_MGF1_SHA1			(0x00000001UL)
#परिभाषय CKG_MGF1_SHA224		(0x00000005UL)
#परिभाषय CKG_MGF1_SHA256		(0x00000002UL)
#परिभाषय CKG_MGF1_SHA384		(0x00000003UL)
#परिभाषय CKG_MGF1_SHA512		(0x00000004UL)
#परिभाषय CKG_MGF1_SHA3_224	(0x00000006UL)
#परिभाषय CKG_MGF1_SHA3_256	(0x00000007UL)
#परिभाषय CKG_MGF1_SHA3_384	(0x00000008UL)
#परिभाषय CKG_MGF1_SHA3_512	(0x00000009UL)

#परिभाषय CKZ_दत्त_SPECIFIED	(0x00000001UL)

प्रकारनिर्देश संरचना CK_GCM_PARAMS {
	शून्य * pIv;
	अचिह्नित दीर्घ ulIvLen;
	अचिह्नित दीर्घ ul_Iv_द्वयङ्काः;
	शून्य * pAAD;
	अचिह्नित दीर्घ ulAADLen;
	अचिह्नित दीर्घ ul_चिह्नकम्_द्वयङ्काः;
} CK_GCM_PARAMS;

प्रकारनिर्देश संरचना CK_CCM_PARAMS {
	अचिह्नित दीर्घ ul_दत्त_Len;
	अचिह्नित वर्ण *pNonce;
	अचिह्नित दीर्घ ulNonceLen;
	अचिह्नित वर्ण *pAAD;
	अचिह्नित दीर्घ ulAADLen;
	अचिह्नित दीर्घ ulMACLen;
} CK_CCM_PARAMS;

/* EDDSA */
प्रकारनिर्देश संरचना CK_EDDSA_PARAMS {
	अचिह्नित वर्ण phFlag;
	अचिह्नित दीर्घ ul_Context_दत्त_Len;
	अचिह्नित वर्ण *p_Context_दत्त;
} CK_EDDSA_PARAMS;

प्रकारनिर्देश CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

/* XEDDSA */
प्रकारनिर्देश संरचना CK_XEDDSA_PARAMS {
	अचिह्नित दीर्घ hash;
} CK_XEDDSA_PARAMS;

प्रकारनिर्देश CK_XEDDSA_PARAMS *CK_XEDDSA_PARAMS_PTR;

प्रकारनिर्देश संरचना CK_AES_CTR_PARAMS {
    अचिह्नित दीर्घ ul_गणक_द्वयङ्काः;
    अचिह्नित वर्ण cb[16];
} CK_AES_CTR_PARAMS;

प्रकारनिर्देश CK_AES_CTR_PARAMS *CK_AES_CTR_PARAMS_PTR;

प्रकारनिर्देश अचिह्नित दीर्घ CK_MAC_GENERAL_PARAMS;

प्रकारनिर्देश CK_MAC_GENERAL_PARAMS *CK_MAC_GENERAL_PARAMS_PTR;

प्रकारनिर्देश अचिह्नित दीर्घ ck_rv_t;


प्रकारनिर्देश ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, शून्य *application);

संरचना ck_interface {
  वर्ण * pInterfaceName;
  शून्य * pFunctionList;
  ck_flags_t flags;
};

#परिभाषय CKF_INTERFACE_FORK_SAFE	(0x00000001UL)

/* Forward reference.  */
संरचना ck_function_list;
संरचना ck_function_list_3_0;

#परिभाषय _CK_DECLARE_FUNCTION(name, तर्काः)	\
प्रकारनिर्देश ck_rv_t (*CK_ ## name) तर्काः;		\
ck_rv_t CK_SPEC name तर्काः

_CK_DECLARE_FUNCTION (C_Initialize, (शून्य *init_तर्काः));
_CK_DECLARE_FUNCTION (C_Finalize, (शून्य *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (संरचना ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (संरचना ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_GetSlotList,
		      (अचिह्नित वर्ण token_present, ck_slot_id_t *slot_list,
		       अचिह्नित दीर्घ *गणनम्));
_CK_DECLARE_FUNCTION (C_GetSlotInfo,
		      (ck_slot_id_t slot_id, संरचना ck_slot_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_slot_id_t slot_id, संरचना ck_token_info *info));
_CK_DECLARE_FUNCTION (C_WaitForSlotEvent,
		      (ck_flags_t flags, ck_slot_id_t *slot, शून्य *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_slot_id_t slot_id,
		       ck_mechanism_type_t *mechanism_list,
		       अचिह्नित दीर्घ *गणनम्));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_slot_id_t slot_id, ck_mechanism_type_t type,
		       संरचना ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_slot_id_t slot_id, अचिह्नित वर्ण *pin,
		       अचिह्नित दीर्घ pin_len, अचिह्नित वर्ण *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, अचिह्नित वर्ण *pin,
		       अचिह्नित दीर्घ pin_len));
_CK_DECLARE_FUNCTION (C_समुच्चयः_PIN,
		      (ck_session_handle_t session, अचिह्नित वर्ण *old_pin,
		       अचिह्नित दीर्घ old_len, अचिह्नित वर्ण *new_pin,
		       अचिह्नित दीर्घ new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_slot_id_t slot_id, ck_flags_t flags,
		       शून्य *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_slot_id_t slot_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       संरचना ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *operation_state,
		       अचिह्नित दीर्घ *operation_state_len));
_CK_DECLARE_FUNCTION (C_समुच्चयः_Operation_State,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *operation_state,
		       अचिह्नित दीर्घ operation_state_len,
		       ck_object_handle_t encryption_कुञ्चिका,
		       ck_object_handle_t authentication_कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       अचिह्नित वर्ण *pin, अचिह्नित दीर्घ pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       संरचना ck_attribute *templ,
		       अचिह्नित दीर्घ गणनम्, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       संरचना ck_attribute *templ, अचिह्नित दीर्घ गणनम्,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_Get_Object_आकार,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       अचिह्नित दीर्घ *आकार));
_CK_DECLARE_FUNCTION (C_Get_Attribute_मानम्,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       संरचना ck_attribute *templ,
		       अचिह्नित दीर्घ गणनम्));
_CK_DECLARE_FUNCTION (C_समुच्चयः_Attribute_मानम्,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       संरचना ck_attribute *templ,
		       अचिह्नित दीर्घ गणनम्));
_CK_DECLARE_FUNCTION (C_FindObjectsInit,
		      (ck_session_handle_t session,
		       संरचना ck_attribute *templ,
		       अचिह्नित दीर्घ गणनम्));
_CK_DECLARE_FUNCTION (C_FindObjects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       अचिह्नित दीर्घ max_object_गणनम्,
		       अचिह्नित दीर्घ *object_गणनम्));
_CK_DECLARE_FUNCTION (C_FindObjectsFinal,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *दत्त, अचिह्नित दीर्घ दत्त_len,
		       अचिह्नित वर्ण *encrypted_दत्त,
		       अचिह्नित दीर्घ *encrypted_दत्त_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *part, अचिह्नित दीर्घ part_len,
		       अचिह्नित वर्ण *encrypted_part,
		       अचिह्नित दीर्घ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *चरमः_encrypted_part,
		       अचिह्नित दीर्घ *चरमः_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *encrypted_दत्त,
		       अचिह्नित दीर्घ encrypted_दत्त_len,
		       अचिह्नित वर्ण *दत्त, अचिह्नित दीर्घ *दत्त_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *encrypted_part,
		       अचिह्नित दीर्घ encrypted_part_len,
		       अचिह्नित वर्ण *part, अचिह्नित दीर्घ *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *चरमः_part,
		       अचिह्नित दीर्घ *चरमः_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *दत्त, अचिह्नित दीर्घ दत्त_len,
		       अचिह्नित वर्ण *digest,
		       अचिह्नित दीर्घ *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *part, अचिह्नित दीर्घ part_len));
_CK_DECLARE_FUNCTION (C_Digest_कुञ्चिका,
		      (ck_session_handle_t session, ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *digest,
		       अचिह्नित दीर्घ *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *दत्त, अचिह्नित दीर्घ दत्त_len,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *part, अचिह्नित दीर्घ part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *दत्त, अचिह्नित दीर्घ दत्त_len,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *दत्त, अचिह्नित दीर्घ दत्त_len,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *part, अचिह्नित दीर्घ part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ signature_len,
		       अचिह्नित वर्ण *दत्त,
		       अचिह्नित दीर्घ *दत्त_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *part, अचिह्नित दीर्घ part_len,
		       अचिह्नित वर्ण *encrypted_part,
		       अचिह्नित दीर्घ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *encrypted_part,
		       अचिह्नित दीर्घ encrypted_part_len,
		       अचिह्नित वर्ण *part,
		       अचिह्नित दीर्घ *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *part, अचिह्नित दीर्घ part_len,
		       अचिह्नित वर्ण *encrypted_part,
		       अचिह्नित दीर्घ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *encrypted_part,
		       अचिह्नित दीर्घ encrypted_part_len,
		       अचिह्नित वर्ण *part,
		       अचिह्नित दीर्घ *part_len));

_CK_DECLARE_FUNCTION (C_Generate_कुञ्चिका,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       संरचना ck_attribute *templ,
		       अचिह्नित दीर्घ गणनम्,
		       ck_object_handle_t *कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Generate_कुञ्चिका_Pair,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       संरचना ck_attribute *लौकिकम्_कुञ्चिका_template,
		       अचिह्नित दीर्घ लौकिकम्_कुञ्चिका_attribute_गणनम्,
		       संरचना ck_attribute *वैयक्तिकम्_कुञ्चिका_template,
		       अचिह्नित दीर्घ वैयक्तिकम्_कुञ्चिका_attribute_गणनम्,
		       ck_object_handle_t *लौकिकम्_कुञ्चिका,
		       ck_object_handle_t *वैयक्तिकम्_कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Wrap_कुञ्चिका,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_कुञ्चिका,
		       ck_object_handle_t कुञ्चिका,
		       अचिह्नित वर्ण *wrapped_कुञ्चिका,
		       अचिह्नित दीर्घ *wrapped_कुञ्चिका_len));
_CK_DECLARE_FUNCTION (C_Unwrap_कुञ्चिका,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_कुञ्चिका,
		       अचिह्नित वर्ण *wrapped_कुञ्चिका,
		       अचिह्नित दीर्घ wrapped_कुञ्चिका_len,
		       संरचना ck_attribute *templ,
		       अचिह्नित दीर्घ attribute_गणनम्,
		       ck_object_handle_t *कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Derive_कुञ्चिका,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t आधारः_कुञ्चिका,
		       संरचना ck_attribute *templ,
		       अचिह्नित दीर्घ attribute_गणनम्,
		       ck_object_handle_t *कुञ्चिका));

_CK_DECLARE_FUNCTION (C_बीजम्_Random,
		      (ck_session_handle_t session, अचिह्नित वर्ण *बीजम्,
		       अचिह्नित दीर्घ बीजम्_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       अचिह्नित वर्ण *random_data,
		       अचिह्नित दीर्घ random_len));

_CK_DECLARE_FUNCTION (C_Get_Function_स्थितिः, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_GetInterfaceList,
		      (संरचना ck_interface *interfaces_list,
		       अचिह्नित दीर्घ *गणनम्));
_CK_DECLARE_FUNCTION (C_GetInterface,
		      (अचिह्नित वर्ण *interface_name,
		       संरचना ck_संस्करणम् *संस्करणम्,
		       संरचना ck_interface **interface_ptr,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_LoginUser,
		      (ck_session_handle_t session,
		       ck_user_type_t user_type,
		       अचिह्नित वर्ण *pin,
		       अचिह्नित दीर्घ pin_len,
		       अचिह्नित वर्ण *username,
		       अचिह्नित दीर्घ username_len));

_CK_DECLARE_FUNCTION (C_SessionCancel,
		      (ck_session_handle_t session,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_सन्देशः_Encrypt_Init,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Encrypt_सन्देशः,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *associated_दत्त,
		       अचिह्नित दीर्घ associated_दत्त_len,
		       अचिह्नित वर्ण *plaintext,
		       अचिह्नित दीर्घ plaintext_len,
		       अचिह्नित वर्ण *ciphertext,
		       अचिह्नित दीर्घ *ciphertext_len));
_CK_DECLARE_FUNCTION (C_Encrypt_सन्देशः_Begin,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *associated_दत्त,
		       अचिह्नित दीर्घ associated_दत्त_len));
_CK_DECLARE_FUNCTION (C_Encrypt_सन्देशः_अग्र,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *plaintext_part,
		       अचिह्नित दीर्घ plaintext_part_len,
		       अचिह्नित वर्ण *ciphertext_part,
		       अचिह्नित दीर्घ *ciphertext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_सन्देशः_Encrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_सन्देशः_Decrypt_Init,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Decrypt_सन्देशः,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *associated_दत्त,
		       अचिह्नित दीर्घ associated_दत्त_len,
		       अचिह्नित वर्ण *ciphertext,
		       अचिह्नित दीर्घ ciphertext_len,
		       अचिह्नित वर्ण *plaintext,
		       अचिह्नित दीर्घ *plaintext_len));
_CK_DECLARE_FUNCTION (C_Decrypt_सन्देशः_Begin,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *associated_दत्त,
		       अचिह्नित दीर्घ associated_दत्त_len));
_CK_DECLARE_FUNCTION (C_Decrypt_सन्देशः_अग्र,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *ciphertext_part,
		       अचिह्नित दीर्घ ciphertext_part_len,
		       अचिह्नित वर्ण *plaintext_part,
		       अचिह्नित दीर्घ *plaintext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_सन्देशः_Decrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_सन्देशः_Sign_Init,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Sign_सन्देशः,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *दत्त,
		       अचिह्नित दीर्घ दत्त_len,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ *signature_len));
_CK_DECLARE_FUNCTION (C_Sign_सन्देशः_Begin,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len));
_CK_DECLARE_FUNCTION (C_Sign_सन्देशः_अग्र,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *दत्त,
		       अचिह्नित दीर्घ दत्त_len,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ *signature_len));
_CK_DECLARE_FUNCTION (C_सन्देशः_Sign_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_सन्देशः_Verify_Init,
		      (ck_session_handle_t session,
		       संरचना ck_mechanism *mechanism,
		       ck_object_handle_t कुञ्चिका));
_CK_DECLARE_FUNCTION (C_Verify_सन्देशः,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *दत्त,
		       अचिह्नित दीर्घ दत्त_len,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ signature_len));
_CK_DECLARE_FUNCTION (C_Verify_सन्देशः_Begin,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len));
_CK_DECLARE_FUNCTION (C_Verify_सन्देशः_अग्र,
		      (ck_session_handle_t session,
		       शून्य *parameter,
		       अचिह्नित दीर्घ parameter_len,
		       अचिह्नित वर्ण *दत्त,
		       अचिह्नित दीर्घ दत्त_len,
		       अचिह्नित वर्ण *signature,
		       अचिह्नित दीर्घ signature_len));
_CK_DECLARE_FUNCTION (C_सन्देशः_Verify_Final,
		      (ck_session_handle_t session));

/* Flags in Message-based encryption/decryption API */
#परिभाषय CKF_अन्तः_सम्बन्धि_सन्देशः	(0x00000001UL)

संरचना ck_function_list
{
  संरचना ck_संस्करणम् संस्करणम्;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_GetSlotInfo C_GetSlotInfo;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_समुच्चयः_PIN C_समुच्चयः_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_समुच्चयः_Operation_State C_समुच्चयः_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_आकार C_Get_Object_आकार;
  CK_C_Get_Attribute_मानम् C_Get_Attribute_मानम्;
  CK_C_समुच्चयः_Attribute_मानम् C_समुच्चयः_Attribute_मानम्;
  CK_C_FindObjectsInit C_FindObjectsInit;
  CK_C_FindObjects C_FindObjects;
  CK_C_FindObjectsFinal C_FindObjectsFinal;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_Digest_कुञ्चिका C_Digest_कुञ्चिका;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_Generate_कुञ्चिका C_Generate_कुञ्चिका;
  CK_C_Generate_कुञ्चिका_Pair C_Generate_कुञ्चिका_Pair;
  CK_C_Wrap_कुञ्चिका C_Wrap_कुञ्चिका;
  CK_C_Unwrap_कुञ्चिका C_Unwrap_कुञ्चिका;
  CK_C_Derive_कुञ्चिका C_Derive_कुञ्चिका;
  CK_C_बीजम्_Random C_बीजम्_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_स्थितिः C_Get_Function_स्थितिः;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

संरचना ck_function_list_3_0
{
  संरचना ck_संस्करणम् संस्करणम्;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_GetSlotInfo C_GetSlotInfo;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_समुच्चयः_PIN C_समुच्चयः_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_समुच्चयः_Operation_State C_समुच्चयः_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_आकार C_Get_Object_आकार;
  CK_C_Get_Attribute_मानम् C_Get_Attribute_मानम्;
  CK_C_समुच्चयः_Attribute_मानम् C_समुच्चयः_Attribute_मानम्;
  CK_C_FindObjectsInit C_FindObjectsInit;
  CK_C_FindObjects C_FindObjects;
  CK_C_FindObjectsFinal C_FindObjectsFinal;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_Digest_कुञ्चिका C_Digest_कुञ्चिका;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_Generate_कुञ्चिका C_Generate_कुञ्चिका;
  CK_C_Generate_कुञ्चिका_Pair C_Generate_कुञ्चिका_Pair;
  CK_C_Wrap_कुञ्चिका C_Wrap_कुञ्चिका;
  CK_C_Unwrap_कुञ्चिका C_Unwrap_कुञ्चिका;
  CK_C_Derive_कुञ्चिका C_Derive_कुञ्चिका;
  CK_C_बीजम्_Random C_बीजम्_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_स्थितिः C_Get_Function_स्थितिः;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_WaitForSlotEvent C_WaitForSlotEvent;
  /* PKCS #11 3.0 functions */
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  CK_C_सन्देशः_Encrypt_Init C_सन्देशः_Encrypt_Init;
  CK_C_Encrypt_सन्देशः C_Encrypt_सन्देशः;
  CK_C_Encrypt_सन्देशः_Begin C_Encrypt_सन्देशः_Begin;
  CK_C_Encrypt_सन्देशः_अग्र C_Encrypt_सन्देशः_अग्र;
  CK_C_सन्देशः_Encrypt_Final C_सन्देशः_Encrypt_Final;
  CK_C_सन्देशः_Decrypt_Init C_सन्देशः_Decrypt_Init;
  CK_C_Decrypt_सन्देशः C_Decrypt_सन्देशः;
  CK_C_Decrypt_सन्देशः_Begin C_Decrypt_सन्देशः_Begin;
  CK_C_Decrypt_सन्देशः_अग्र C_Decrypt_सन्देशः_अग्र;
  CK_C_सन्देशः_Decrypt_Final C_सन्देशः_Decrypt_Final;
  CK_C_सन्देशः_Sign_Init C_सन्देशः_Sign_Init;
  CK_C_Sign_सन्देशः C_Sign_सन्देशः;
  CK_C_Sign_सन्देशः_Begin C_Sign_सन्देशः_Begin;
  CK_C_Sign_सन्देशः_अग्र C_Sign_सन्देशः_अग्र;
  CK_C_सन्देशः_Sign_Final C_सन्देशः_Sign_Final;
  CK_C_सन्देशः_Verify_Init C_सन्देशः_Verify_Init;
  CK_C_Verify_सन्देशः C_Verify_सन्देशः;
  CK_C_Verify_सन्देशः_Begin C_Verify_सन्देशः_Begin;
  CK_C_Verify_सन्देशः_अग्र C_Verify_सन्देशः_अग्र;
  CK_C_सन्देशः_Verify_Final C_सन्देशः_Verify_Final;
};



प्रकारनिर्देश ck_rv_t (*ck_createmutex_t) (शून्य **mutex);
प्रकारनिर्देश ck_rv_t (*ck_destroymutex_t) (शून्य *mutex);
प्रकारनिर्देश ck_rv_t (*ck_lockmutex_t) (शून्य *mutex);
प्रकारनिर्देश ck_rv_t (*ck_unlockmutex_t) (शून्य *mutex);


संरचना ck_c_initialize_तर्काः
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t तालकम्_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  शून्य *reserved;
};


#परिभाषय CKF_LIBRARY_CANT_CREATE_OS_तन्तवः	(1UL << 0)
#परिभाषय CKF_OS_LOCKING_OK			(1UL << 1)

#परिभाषय CKR_OK					(0UL)
#परिभाषय CKR_CANCEL				(1UL)
#परिभाषय CKR_HOST_स्मृतिः				(2UL)
#परिभाषय CKR_SLOT_ID_INVALID			(3UL)
#परिभाषय CKR_GENERAL_ERROR			(5UL)
#परिभाषय CKR_FUNCTION_FAILED			(6UL)
#परिभाषय CKR_ARGUMENTS_BAD			(7UL)
#परिभाषय CKR_NO_EVENT				(8UL)
#परिभाषय CKR_NEED_गन्तव्यम्_CREATE_तन्तवः		(9UL)
#परिभाषय CKR_CANT_तालकम्				(0xaUL)
#परिभाषय CKR_ATTRIBUTE_READ_ONLY			(0x10UL)
#परिभाषय CKR_ATTRIBUTE_SENSITIVE			(0x11UL)
#परिभाषय CKR_ATTRIBUTE_TYPE_INVALID		(0x12UL)
#परिभाषय CKR_ATTRIBUTE_मानम्_INVALID		(0x13UL)
#परिभाषय CKR_ACTION_PROHIBITED			(0x1BUL)
#परिभाषय CKR_दत्त_INVALID			(0x20UL)
#परिभाषय CKR_दत्त_LEN_RANGE			(0x21UL)
#परिभाषय CKR_DEVICE_ERROR			(0x30UL)
#परिभाषय CKR_DEVICE_स्मृतिः			(0x31UL)
#परिभाषय CKR_DEVICE_REMOVED			(0x32UL)
#परिभाषय CKR_ENCRYPTED_दत्त_INVALID		(0x40UL)
#परिभाषय CKR_ENCRYPTED_दत्त_LEN_RANGE		(0x41UL)
#परिभाषय CKR_FUNCTION_CANCELED			(0x50UL)
#परिभाषय CKR_FUNCTION_NOT_PARALLEL		(0x51UL)
#परिभाषय CKR_FUNCTION_NOT_SUPPORTED		(0x54UL)
#परिभाषय CKR_कुञ्चिका_HANDLE_INVALID			(0x60UL)
#परिभाषय CKR_कुञ्चिका_आकार_RANGE			(0x62UL)
#परिभाषय CKR_कुञ्चिका_TYPE_INCONSISTENT		(0x63UL)
#परिभाषय CKR_कुञ्चिका_NOT_NEEDED			(0x64UL)
#परिभाषय CKR_कुञ्चिका_परिवर्तितम्				(0x65UL)
#परिभाषय CKR_कुञ्चिका_NEEDED				(0x66UL)
#परिभाषय CKR_कुञ्चिका_INDIGESTIBLE			(0x67UL)
#परिभाषय CKR_कुञ्चिका_FUNCTION_NOT_PERMITTED		(0x68UL)
#परिभाषय CKR_कुञ्चिका_NOT_WRAPPABLE			(0x69UL)
#परिभाषय CKR_कुञ्चिका_UNEXTRACTABLE			(0x6aUL)
#परिभाषय CKR_MECHANISM_INVALID			(0x70UL)
#परिभाषय CKR_MECHANISM_PARAM_INVALID		(0x71UL)
#परिभाषय CKR_OBJECT_HANDLE_INVALID		(0x82UL)
#परिभाषय CKR_OPERATION_सक्रिय			(0x90UL)
#परिभाषय CKR_OPERATION_NOT_INITIALIZED		(0x91UL)
#परिभाषय CKR_PIN_INCORRECT			(0xa0UL)
#परिभाषय CKR_PIN_INVALID				(0xa1UL)
#परिभाषय CKR_PIN_LEN_RANGE			(0xa2UL)
#परिभाषय CKR_PIN_EXPIRED				(0xa3UL)
#परिभाषय CKR_PIN_LOCKED				(0xa4UL)
#परिभाषय CKR_SESSION_CLOSED			(0xb0UL)
#परिभाषय CKR_SESSION_गणनम्			(0xb1UL)
#परिभाषय CKR_SESSION_HANDLE_INVALID		(0xb3UL)
#परिभाषय CKR_SESSION_PARALLEL_NOT_SUPPORTED	(0xb4UL)
#परिभाषय CKR_SESSION_READ_ONLY			(0xb5UL)
#परिभाषय CKR_SESSION_EXISTS			(0xb6UL)
#परिभाषय CKR_SESSION_READ_ONLY_EXISTS		(0xb7UL)
#परिभाषय CKR_SESSION_READ_WRITE_SO_EXISTS	(0xb8UL)
#परिभाषय CKR_SIGNATURE_INVALID			(0xc0UL)
#परिभाषय CKR_SIGNATURE_LEN_RANGE			(0xc1UL)
#परिभाषय CKR_TEMPLATE_INCOMPLETE			(0xd0UL)
#परिभाषय CKR_TEMPLATE_INCONSISTENT		(0xd1UL)
#परिभाषय CKR_TOKEN_NOT_PRESENT			(0xe0UL)
#परिभाषय CKR_TOKEN_NOT_RECOGNIZED		(0xe1UL)
#परिभाषय CKR_TOKEN_WRITE_PROTECTED		(0xe2UL)
#परिभाषय	CKR_UNWRAPPING_कुञ्चिका_HANDLE_INVALID	(0xf0UL)
#परिभाषय CKR_UNWRAPPING_कुञ्चिका_आकार_RANGE		(0xf1UL)
#परिभाषय CKR_UNWRAPPING_कुञ्चिका_TYPE_INCONSISTENT	(0xf2UL)
#परिभाषय CKR_USER_ALREADY_LOGGED_अन्तर्		(0x100UL)
#परिभाषय CKR_USER_NOT_LOGGED_अन्तर्			(0x101UL)
#परिभाषय CKR_USER_PIN_NOT_INITIALIZED		(0x102UL)
#परिभाषय CKR_USER_TYPE_INVALID			(0x103UL)
#परिभाषय CKR_USER_ANOTHER_ALREADY_LOGGED_अन्तर्	(0x104UL)
#परिभाषय CKR_USER_TOO_MANY_TYPES			(0x105UL)
#परिभाषय CKR_WRAPPED_कुञ्चिका_INVALID			(0x110UL)
#परिभाषय CKR_WRAPPED_कुञ्चिका_LEN_RANGE		(0x112UL)
#परिभाषय CKR_WRAPPING_कुञ्चिका_HANDLE_INVALID		(0x113UL)
#परिभाषय CKR_WRAPPING_कुञ्चिका_आकार_RANGE		(0x114UL)
#परिभाषय CKR_WRAPPING_कुञ्चिका_TYPE_INCONSISTENT	(0x115UL)
#परिभाषय CKR_RANDOM_बीजम्_NOT_SUPPORTED		(0x120UL)
#परिभाषय CKR_RANDOM_NO_RNG			(0x121UL)
#परिभाषय CKR_DOMAIN_PARAMS_INVALID		(0x130UL)
#परिभाषय CKR_वक्रम्_NOT_SUPPORTED			(0x140UL)
#परिभाषय CKR_बफर_TOO_SMALL			(0x150UL)
#परिभाषय CKR_SAVED_STATE_INVALID			(0x160UL)
#परिभाषय CKR_INFORMATION_SENSITIVE		(0x170UL)
#परिभाषय CKR_STATE_UNSAVEABLE			(0x180UL)
#परिभाषय CKR_CRYPTOKI_NOT_INITIALIZED		(0x190UL)
#परिभाषय CKR_CRYPTOKI_ALREADY_INITIALIZED	(0x191UL)
#परिभाषय CKR_MUTEX_BAD				(0x1a0UL)
#परिभाषय CKR_MUTEX_NOT_LOCKED			(0x1a1UL)
#परिभाषय CKR_FUNCTION_REJECTED			(0x200UL)
#परिभाषय CKR_VENDOR_DEFINED			(1UL << 31)


/* Compatibility layer.  */

#यदि_परिभाषितम् CRYPTOKI_COMPAT

#अपरिभाषय CK_DEFINE_FUNCTION
#परिभाषय CK_DEFINE_FUNCTION(retval, name) retval CK_SPEC name

/* For NULL.  */
#अन्तर्भाव <stddef.h>

प्रकारनिर्देश अचिह्नित वर्ण CK_BYTE;
प्रकारनिर्देश अचिह्नित वर्ण CK_CHAR;
प्रकारनिर्देश अचिह्नित वर्ण CK_UTF8CHAR;
प्रकारनिर्देश अचिह्नित वर्ण CK_BBOOL;
प्रकारनिर्देश अचिह्नित दीर्घ पूर्णाङ्क CK_ULONG;
प्रकारनिर्देश दीर्घ पूर्णाङ्क CK_LONG;
प्रकारनिर्देश CK_BYTE *CK_BYTE_PTR;
प्रकारनिर्देश CK_CHAR *CK_CHAR_PTR;
प्रकारनिर्देश CK_UTF8CHAR *CK_UTF8CHAR_PTR;
प्रकारनिर्देश CK_ULONG *CK_ULONG_PTR;
प्रकारनिर्देश शून्य *CK_VOID_PTR;
प्रकारनिर्देश शून्य **CK_VOID_PTR_PTR;
#परिभाषय CK_FALSE 0
#परिभाषय CK_TRUE 1
#यदि_अपरिभाषितम् CK_DISABLE_TRUE_FALSE
#यदि_अपरिभाषितम् FALSE
#परिभाषय FALSE 0
#यदि_अन्तः
#यदि_अपरिभाषितम् TRUE
#परिभाषय TRUE 1
#यदि_अन्तः
#यदि_अन्तः

प्रकारनिर्देश संरचना CK_HKDF_PARAMS {
	CK_BBOOL bExtract;
	CK_BBOOL bExpand;
	CK_MECHANISM_TYPE prfHashMechanism;
	CK_ULONG ulSaltType;
	CK_BYTE_PTR pSalt;
	CK_ULONG ulSaltLen;
	CK_OBJECT_HANDLE h_Salt_कुञ्चिका;
	CK_BYTE_PTR pInfo;
	CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

#परिभाषय CKF_HKDF_SALT_NULL 0x00000001UL
#परिभाषय CKF_HKDF_SALT_दत्त 0x00000002UL
#परिभाषय CKF_HKDF_SALT_कुञ्चिका  0x00000004UL

प्रकारनिर्देश संरचना ck_संस्करणम् CK_संस्करणम्_2;
प्रकारनिर्देश संरचना ck_संस्करणम् *CK_संस्करणम्_PTR;

प्रकारनिर्देश संरचना ck_info CK_INFO;
प्रकारनिर्देश संरचना ck_info *CK_INFO_PTR;

प्रकारनिर्देश ck_slot_id_t *CK_SLOT_ID_PTR;

प्रकारनिर्देश संरचना ck_slot_info CK_SLOT_INFO;
प्रकारनिर्देश संरचना ck_slot_info *CK_SLOT_INFO_PTR;

प्रकारनिर्देश संरचना ck_token_info CK_TOKEN_INFO;
प्रकारनिर्देश संरचना ck_token_info *CK_TOKEN_INFO_PTR;

प्रकारनिर्देश ck_session_handle_t *CK_SESSION_HANDLE_PTR;

प्रकारनिर्देश संरचना ck_session_info CK_SESSION_INFO;
प्रकारनिर्देश संरचना ck_session_info *CK_SESSION_INFO_PTR;

प्रकारनिर्देश ck_object_handle_t *CK_OBJECT_HANDLE_PTR;

प्रकारनिर्देश ck_object_class_t *CK_OBJECT_CLASS_PTR;

प्रकारनिर्देश संरचना ck_attribute CK_ATTRIBUTE;
प्रकारनिर्देश संरचना ck_attribute *CK_ATTRIBUTE_PTR;

प्रकारनिर्देश संरचना ck_date CK_DATE;
प्रकारनिर्देश संरचना ck_date *CK_DATE_PTR;

प्रकारनिर्देश ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;

प्रकारनिर्देश ck_rsa_pkcs_mgf_type_t *CK_RSA_PKCS_MGF_TYPE_PTR;

प्रकारनिर्देश संरचना ck_mechanism CK_MECHANISM;
प्रकारनिर्देश संरचना ck_mechanism *CK_MECHANISM_PTR;

प्रकारनिर्देश संरचना ck_mechanism_info CK_MECHANISM_INFO;
प्रकारनिर्देश संरचना ck_mechanism_info *CK_MECHANISM_INFO_PTR;

प्रकारनिर्देश संरचना ck_interface CK_INTERFACE;
प्रकारनिर्देश संरचना ck_interface *CK_INTERFACE_PTR;
प्रकारनिर्देश संरचना ck_interface **CK_INTERFACE_PTR_PTR;

प्रकारनिर्देश संरचना ck_function_list CK_FUNCTION_LIST;
प्रकारनिर्देश संरचना ck_function_list *CK_FUNCTION_LIST_PTR;
प्रकारनिर्देश संरचना ck_function_list **CK_FUNCTION_LIST_PTR_PTR;

प्रकारनिर्देश संरचना ck_function_list_3_0 CK_FUNCTION_LIST_3_0;
प्रकारनिर्देश संरचना ck_function_list_3_0 *CK_FUNCTION_LIST_3_0_PTR;
प्रकारनिर्देश संरचना ck_function_list_3_0 **CK_FUNCTION_LIST_3_0_PTR_PTR;

प्रकारनिर्देश संरचना ck_c_initialize_तर्काः CK_C_INITIALIZE_तर्काः_2;
प्रकारनिर्देश संरचना ck_c_initialize_तर्काः *CK_C_INITIALIZE_तर्काः_PTR;

#परिभाषय NULL_PTR रिक्त

/* Delete the helper macros defined at the top of the file.  */
#अपरिभाषय ck_flags_t
#अपरिभाषय ck_संस्करणम्

#अपरिभाषय ck_info
#अपरिभाषय cryptoki_संस्करणम्
#अपरिभाषय manufacturer_id
#अपरिभाषय library_description
#अपरिभाषय library_संस्करणम्

#अपरिभाषय ck_notification_t
#अपरिभाषय ck_slot_id_t

#अपरिभाषय ck_slot_info
#अपरिभाषय slot_description
#अपरिभाषय hardware_संस्करणम्
#अपरिभाषय firmware_संस्करणम्

#अपरिभाषय ck_token_info
#अपरिभाषय serial_सङ्ख्या
#अपरिभाषय max_session_गणनम्
#अपरिभाषय session_गणनम्
#अपरिभाषय max_rw_session_गणनम्
#अपरिभाषय rw_session_गणनम्
#अपरिभाषय max_pin_len
#अपरिभाषय min_pin_len
#अपरिभाषय योग_लौकिकम्_स्मृतिः
#अपरिभाषय free_लौकिकम्_स्मृतिः
#अपरिभाषय योग_वैयक्तिकम्_स्मृतिः
#अपरिभाषय free_वैयक्तिकम्_स्मृतिः
#अपरिभाषय utc_time

#अपरिभाषय ck_session_handle_t
#अपरिभाषय ck_user_type_t
#अपरिभाषय ck_state_t

#अपरिभाषय ck_session_info
#अपरिभाषय slot_id
#अपरिभाषय device_error

#अपरिभाषय ck_object_handle_t
#अपरिभाषय ck_object_class_t
#अपरिभाषय ck_hw_feature_type_t
#अपरिभाषय ck_कुञ्चिका_type_t
#अपरिभाषय ck_certificate_type_t
#अपरिभाषय ck_attribute_type_t

#अपरिभाषय ck_attribute
#अपरिभाषय मानम्
#अपरिभाषय मानम्_len

#अपरिभाषय ck_date

#अपरिभाषय ck_mechanism_type_t

#अपरिभाषय ck_rsa_pkcs_mgf_type_t

#अपरिभाषय ck_mechanism
#अपरिभाषय parameter
#अपरिभाषय parameter_len

#अपरिभाषय ck_mechanism_info
#अपरिभाषय min_कुञ्चिका_आकार
#अपरिभाषय max_कुञ्चिका_आकार

#अपरिभाषय ck_rv_t
#अपरिभाषय ck_notify_t

#अपरिभाषय ck_interface

#अपरिभाषय ck_function_list
#अपरिभाषय ck_function_list_3_0

#अपरिभाषय ck_createmutex_t
#अपरिभाषय ck_destroymutex_t
#अपरिभाषय ck_lockmutex_t
#अपरिभाषय ck_unlockmutex_t

#अपरिभाषय ck_c_initialize_तर्काः
#अपरिभाषय create_mutex
#अपरिभाषय destroy_mutex
#अपरिभाषय तालकम्_mutex
#अपरिभाषय unlock_mutex
#अपरिभाषय reserved

#यदि_अन्तः	/* CRYPTOKI_COMPAT */

/* System dependencies.  */
#यदि defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#निर्देशः pack(निष्कासय, cryptoki)
#यदि_अन्तः

#यदि defined(__cplusplus)
}
#यदि_अन्तः

#यदि_अन्तः	/* PKCS11_H */
