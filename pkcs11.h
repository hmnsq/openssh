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

#اگر_غیر_تعریف_شدہ PKCS11_H
#تعریف_کرو PKCS11_H 1

#اگر defined(__cplusplus)
خارجی "C" {
#اگر_ختم


/* The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  */
#تعریف_کرو CRYPTOKI_نسخہ_MAJOR		3
#تعریف_کرو CRYPTOKI_نسخہ_MINOR		0
#تعریف_کرو CRYPTOKI_نسخہ_REVISION	0


/* Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  */
#اگر_غیر_تعریف_شدہ CRYPTOKI_GNU
#اگر_غیر_تعریف_شدہ CRYPTOKI_COMPAT
#تعریف_کرو CRYPTOKI_COMPAT 1
#اگر_ختم
#اگر_ختم

/* System dependencies.  */

#اگر defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#ہدایت pack(ڈالو, cryptoki, 1)

#اگر_تعریف_شدہ CRYPTOKI_EXPORTS
#تعریف_کرو CK_SPEC __declspec(dllexport)
#ورنہ
#تعریف_کرو CK_SPEC __declspec(dllimport)
#اگر_ختم

#ورنہ

#تعریف_کرو CK_SPEC

#اگر_ختم

#اگر_تعریف_شدہ CRYPTOKI_COMPAT
  /* If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  */

#تعریف_کرو ck_flags_t CK_FLAGS
#تعریف_کرو ck_نسخہ CK_نسخہ

#تعریف_کرو ck_info _CK_INFO
#تعریف_کرو cryptoki_نسخہ cryptoki_نسخہ_2
#تعریف_کرو manufacturer_id manufacturerID
#تعریف_کرو library_description libraryDescription
#تعریف_کرو library_نسخہ library_نسخہ_2

#تعریف_کرو ck_notification_t CK_NOTIFICATION
#تعریف_کرو ck_خانہ_id_t CK_خانہ_ID

#تعریف_کرو ck_خانہ_info CK_خانہ_INFO
#تعریف_کرو خانہ_description خانہ_Description
#تعریف_کرو hardware_نسخہ hardware_نسخہ_2
#تعریف_کرو firmware_نسخہ firmware_نسخہ_2

#تعریف_کرو ck_token_info _CK_TOKEN_INFO
#تعریف_کرو serial_نمبر serial_نمبر_2
#تعریف_کرو max_session_گنتی ul_Max_Session_گنتی
#تعریف_کرو session_گنتی ul_Session_گنتی
#تعریف_کرو max_rw_session_گنتی ul_Max_Rw_Session_گنتی
#تعریف_کرو rw_session_گنتی ul_Rw_Session_گنتی
#تعریف_کرو max_pin_len ulMaxPinLen
#تعریف_کرو min_pin_len ulMinPinLen
#تعریف_کرو کل_عوامی_حافظہ ul_کل_عوامی_حافظہ
#تعریف_کرو free_عوامی_حافظہ ul_Free_عوامی_حافظہ
#تعریف_کرو کل_نجی_حافظہ ul_کل_نجی_حافظہ
#تعریف_کرو free_نجی_حافظہ ul_Free_نجی_حافظہ
#تعریف_کرو utc_وقت utc_وقت_2

#تعریف_کرو ck_session_handle_t CK_SESSION_HANDLE
#تعریف_کرو ck_user_type_t CK_USER_TYPE
#تعریف_کرو ck_state_t CK_STATE

#تعریف_کرو ck_session_info _CK_SESSION_INFO
#تعریف_کرو خانہ_id خانہ_ID
#تعریف_کرو device_error ulDeviceError

#تعریف_کرو ck_object_handle_t CK_OBJECT_HANDLE
#تعریف_کرو ck_object_class_t CK_OBJECT_CLASS
#تعریف_کرو ck_hw_feature_type_t CK_HW_FEATURE_TYPE
#تعریف_کرو ck_کلید_type_t CK_کلید_TYPE
#تعریف_کرو ck_certificate_type_t CK_CERTIFICATE_TYPE
#تعریف_کرو ck_attribute_type_t CK_ATTRIBUTE_TYPE

#تعریف_کرو ck_attribute _CK_ATTRIBUTE
#تعریف_کرو قدر p_قدر
#تعریف_کرو قدر_len ul_قدر_Len

#تعریف_کرو ck_date _CK_DATE

#تعریف_کرو ck_mechanism_type_t CK_MECHANISM_TYPE

#تعریف_کرو ck_rsa_pkcs_mgf_type_t CK_RSA_PKCS_MGF_TYPE

#تعریف_کرو ck_mechanism _CK_MECHANISM
#تعریف_کرو parameter pParameter
#تعریف_کرو parameter_len ulParameterLen

#تعریف_کرو ck_mechanism_info _CK_MECHANISM_INFO
#تعریف_کرو min_کلید_سائز ul_Min_کلید_سائز
#تعریف_کرو max_کلید_سائز ul_Max_کلید_سائز

#تعریف_کرو ck_rv_t CK_RV
#تعریف_کرو ck_notify_t CK_NOTIFY

#تعریف_کرو ck_interface CK_INTERFACE

#تعریف_کرو ck_function_list _CK_FUNCTION_LIST
#تعریف_کرو ck_function_list_3_0 _CK_FUNCTION_LIST_3_0

#تعریف_کرو ck_createmutex_t CK_CREATEMUTEX
#تعریف_کرو ck_destroymutex_t CK_DESTROYMUTEX
#تعریف_کرو ck_lockmutex_t CK_LOCKMUTEX
#تعریف_کرو ck_unlockmutex_t CK_UNLOCKMUTEX

#تعریف_کرو ck_c_initialize_دلائل CK_C_INITIALIZE_دلائل
#تعریف_کرو create_mutex CreateMutex
#تعریف_کرو destroy_mutex DestroyMutex
#تعریف_کرو تالا_mutex تالا_Mutex
#تعریف_کرو unlock_mutex UnlockMutex
#تعریف_کرو reserved pReserved

#اگر_ختم	/* CRYPTOKI_COMPAT */


قسمتعریف غیرعلامتی طویل ck_flags_t;

ساخت ck_نسخہ
{
  غیرعلامتی حرف major;
  غیرعلامتی حرف minor;
};


ساخت ck_info
{
  ساخت ck_نسخہ cryptoki_نسخہ;
  غیرعلامتی حرف manufacturer_id[32];
  ck_flags_t flags;
  غیرعلامتی حرف library_description[32];
  ساخت ck_نسخہ library_نسخہ;
};


قسمتعریف غیرعلامتی طویل ck_notification_t;

#تعریف_کرو CKN_SURRENDER	(0UL)


قسمتعریف غیرعلامتی طویل ck_خانہ_id_t;


ساخت ck_خانہ_info
{
  غیرعلامتی حرف خانہ_description[64];
  غیرعلامتی حرف manufacturer_id[32];
  ck_flags_t flags;
  ساخت ck_نسخہ hardware_نسخہ;
  ساخت ck_نسخہ firmware_نسخہ;
};


#تعریف_کرو CKF_TOKEN_PRESENT	(1UL << 0)
#تعریف_کرو CKF_REMOVABLE_DEVICE	(1UL << 1)
#تعریف_کرو CKF_HW_خانہ		(1UL << 2)
#تعریف_کرو CKF_ARRAY_ATTRIBUTE	(1UL << 30)


ساخت ck_token_info
{
  غیرعلامتی حرف label[32];
  غیرعلامتی حرف manufacturer_id[32];
  غیرعلامتی حرف model[16];
  غیرعلامتی حرف serial_نمبر[16];
  ck_flags_t flags;
  غیرعلامتی طویل max_session_گنتی;
  غیرعلامتی طویل session_گنتی;
  غیرعلامتی طویل max_rw_session_گنتی;
  غیرعلامتی طویل rw_session_گنتی;
  غیرعلامتی طویل max_pin_len;
  غیرعلامتی طویل min_pin_len;
  غیرعلامتی طویل کل_عوامی_حافظہ;
  غیرعلامتی طویل free_عوامی_حافظہ;
  غیرعلامتی طویل کل_نجی_حافظہ;
  غیرعلامتی طویل free_نجی_حافظہ;
  ساخت ck_نسخہ hardware_نسخہ;
  ساخت ck_نسخہ firmware_نسخہ;
  غیرعلامتی حرف utc_وقت[16];
};


#تعریف_کرو CKF_RNG					(1UL << 0)
#تعریف_کرو CKF_WRITE_PROTECTED			(1UL << 1)
#تعریف_کرو CKF_LOGIN_REQUIRED			(1UL << 2)
#تعریف_کرو CKF_USER_PIN_INITIALIZED		(1UL << 3)
#تعریف_کرو CKF_RESTORE_کلید_NOT_NEEDED		(1UL << 5)
#تعریف_کرو CKF_CLOCK_ON_TOKEN			(1UL << 6)
#تعریف_کرو CKF_PROTECTED_AUTHENTICATION_راستہ	(1UL << 8)
#تعریف_کرو CKF_DUAL_CRYPTO_OPERATIONS		(1UL << 9)
#تعریف_کرو CKF_TOKEN_INITIALIZED			(1UL << 10)
#تعریف_کرو CKF_SECONDARY_AUTHENTICATION		(1UL << 11)
#تعریف_کرو CKF_USER_PIN_گنتی_کم			(1UL << 16)
#تعریف_کرو CKF_USER_PIN_FINAL_TRY			(1UL << 17)
#تعریف_کرو CKF_USER_PIN_LOCKED			(1UL << 18)
#تعریف_کرو CKF_USER_PIN_مقصد_BE_بدلا		(1UL << 19)
#تعریف_کرو CKF_SO_PIN_گنتی_کم			(1UL << 20)
#تعریف_کرو CKF_SO_PIN_FINAL_TRY			(1UL << 21)
#تعریف_کرو CKF_SO_PIN_LOCKED			(1UL << 22)
#تعریف_کرو CKF_SO_PIN_مقصد_BE_بدلا		(1UL << 23)

#تعریف_کرو CK_UNAVAILABLE_INFORMATION	((غیرعلامتی طویل) -1)
#تعریف_کرو CK_EFFECTIVELY_INFINITE		(0UL)


قسمتعریف غیرعلامتی طویل ck_session_handle_t;

#تعریف_کرو CK_INVALID_HANDLE	(0UL)


قسمتعریف غیرعلامتی طویل ck_user_type_t;

#تعریف_کرو CKU_SO			(0UL)
#تعریف_کرو CKU_USER		(1UL)
#تعریف_کرو CKU_CONTEXT_SPECIFIC	(2UL)


قسمتعریف غیرعلامتی طویل ck_state_t;

#تعریف_کرو CKS_RO_عوامی_SESSION	(0UL)
#تعریف_کرو CKS_RO_USER_FUNCTIONS	(1UL)
#تعریف_کرو CKS_RW_عوامی_SESSION	(2UL)
#تعریف_کرو CKS_RW_USER_FUNCTIONS	(3UL)
#تعریف_کرو CKS_RW_SO_FUNCTIONS	(4UL)


ساخت ck_session_info
{
  ck_خانہ_id_t خانہ_id;
  ck_state_t state;
  ck_flags_t flags;
  غیرعلامتی طویل device_error;
};

#تعریف_کرو CKF_RW_SESSION		(1UL << 1)
#تعریف_کرو CKF_SERIAL_SESSION	(1UL << 2)


قسمتعریف غیرعلامتی طویل ck_object_handle_t;


قسمتعریف غیرعلامتی طویل ck_object_class_t;

#تعریف_کرو CKO_ڈیٹا		(0UL)
#تعریف_کرو CKO_CERTIFICATE		(1UL)
#تعریف_کرو CKO_عوامی_کلید		(2UL)
#تعریف_کرو CKO_نجی_کلید		(3UL)
#تعریف_کرو CKO_SECRET_کلید		(4UL)
#تعریف_کرو CKO_HW_FEATURE		(5UL)
#تعریف_کرو CKO_DOMAIN_PARAMETERS	(6UL)
#تعریف_کرو CKO_MECHANISM		(7UL)
#تعریف_کرو CKO_OTP_کلید		(8UL)
#تعریف_کرو CKO_PROFILE		(9UL)
#تعریف_کرو CKO_VENDOR_DEFINED	(1UL << 31)

#تعریف_کرو CKP_INVALID_ID                (0UL)
#تعریف_کرو CKP_BASELINE_PROVIDER         (1UL)
#تعریف_کرو CKP_EXTENDED_PROVIDER         (2UL)
#تعریف_کرو CKP_AUTHENTICATION_TOKEN      (3UL)
#تعریف_کرو CKP_عوامی_CERTIFICATES_TOKEN (4UL)
#تعریف_کرو CKP_VENDOR_DEFINED            (1UL << 31)

قسمتعریف غیرعلامتی طویل ck_hw_feature_type_t;

#تعریف_کرو CKH_MONOTONIC_شمار	(1UL)
#تعریف_کرو CKH_CLOCK		(2UL)
#تعریف_کرو CKH_USER_INTERFACE	(3UL)
#تعریف_کرو CKH_VENDOR_DEFINED	(1UL << 31)


قسمتعریف غیرعلامتی طویل ck_کلید_type_t;

#تعریف_کرو CKK_RSA			(0UL)
#تعریف_کرو CKK_DSA			(1UL)
#تعریف_کرو CKK_DH			(2UL)
#تعریف_کرو CKK_ECDSA		(3UL)
#تعریف_کرو CKK_EC			(3UL)
#تعریف_کرو CKK_X9_42_DH		(4UL)
#تعریف_کرو CKK_KEA			(5UL)
#تعریف_کرو CKK_GENERIC_SECRET	(0x10UL)
#تعریف_کرو CKK_RC2			(0x11UL)
#تعریف_کرو CKK_RC4			(0x12UL)
#تعریف_کرو CKK_DES			(0x13UL)
#تعریف_کرو CKK_DES2		(0x14UL)
#تعریف_کرو CKK_DES3		(0x15UL)
#تعریف_کرو CKK_CAST		(0x16UL)
#تعریف_کرو CKK_CAST3		(0x17UL)
#تعریف_کرو CKK_CAST128		(0x18UL)
#تعریف_کرو CKK_RC5			(0x19UL)
#تعریف_کرو CKK_IDEA		(0x1aUL)
#تعریف_کرو CKK_SKIPJACK		(0x1bUL)
#تعریف_کرو CKK_BATON		(0x1cUL)
#تعریف_کرو CKK_JUNIPER		(0x1dUL)
#تعریف_کرو CKK_CDMF		(0x1eUL)
#تعریف_کرو CKK_AES			(0x1fUL)
#تعریف_کرو CKK_BLOWFISH		(0x20UL)
#تعریف_کرو CKK_TWOFISH		(0x21UL)
#تعریف_کرو CKK_GOSTR3410		(0x30UL)
#تعریف_کرو CKK_GOSTR3411		(0x31UL)
#تعریف_کرو CKK_GOST28147		(0x32UL)
#تعریف_کرو CKK_EC_EDWARDS		(0x40UL)
#تعریف_کرو CKK_EC_MONTGOMERY	(0x41UL)
#تعریف_کرو CKK_HKDF		(0x42UL)
#تعریف_کرو CKK_VENDOR_DEFINED	(1UL << 31)

/*
 * A mask for new GOST algorithms.
 * For details visit https://tc26.ru/standarts/perevody/guidelines-the-pkcs-11-extensions-for-implementing-the-gost-r-34-10-2012-and-gost-r-34-11-2012-russian-standards-.html
 */
#تعریف_کرو NSSCK_VENDOR_PKCS11_RU_TEAM     (CKK_VENDOR_DEFINED | 0x54321000)
#تعریف_کرو CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

#تعریف_کرو CKK_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

قسمتعریف غیرعلامتی طویل ck_certificate_type_t;

#تعریف_کرو CKC_X_509		(0UL)
#تعریف_کرو CKC_X_509_ATTR_CERT	(1UL)
#تعریف_کرو CKC_WTLS		(2UL)
#تعریف_کرو CKC_VENDOR_DEFINED	(1UL << 31)


قسمتعریف غیرعلامتی طویل ck_attribute_type_t;

#تعریف_کرو CKA_CLASS			(0UL)
#تعریف_کرو CKA_TOKEN			(1UL)
#تعریف_کرو CKA_نجی			(2UL)
#تعریف_کرو CKA_LABEL			(3UL)
#تعریف_کرو CKA_UNIQUE_ID		(4UL)
#تعریف_کرو CKA_APPLICATION			(0x10UL)
#تعریف_کرو CKA_قدر			(0x11UL)
#تعریف_کرو CKA_OBJECT_ID			(0x12UL)
#تعریف_کرو CKA_CERTIFICATE_TYPE		(0x80UL)
#تعریف_کرو CKA_ISSUER			(0x81UL)
#تعریف_کرو CKA_SERIAL_نمبر		(0x82UL)
#تعریف_کرو CKA_AC_ISSUER			(0x83UL)
#تعریف_کرو CKA_OWNER			(0x84UL)
#تعریف_کرو CKA_ATTR_TYPES			(0x85UL)
#تعریف_کرو CKA_TRUSTED			(0x86UL)
#تعریف_کرو CKA_CERTIFICATE_CATEGORY	(0x87UL)
#تعریف_کرو CKA_JAVA_MIDP_SECURITY_DOMAIN	(0x88UL)
#تعریف_کرو CKA_URL				(0x89UL)
#تعریف_کرو CKA_HASH_کا_SUBJECT_عوامی_کلید	(0x8aUL)
#تعریف_کرو CKA_HASH_کا_ISSUER_عوامی_کلید	(0x8bUL)
#تعریف_کرو CKA_CHECK_قدر			(0x90UL)
#تعریف_کرو CKA_کلید_TYPE			(0x100UL)
#تعریف_کرو CKA_SUBJECT			(0x101UL)
#تعریف_کرو CKA_ID				(0x102UL)
#تعریف_کرو CKA_SENSITIVE			(0x103UL)
#تعریف_کرو CKA_ENCRYPT			(0x104UL)
#تعریف_کرو CKA_DECRYPT			(0x105UL)
#تعریف_کرو CKA_WRAP			(0x106UL)
#تعریف_کرو CKA_UNWRAP			(0x107UL)
#تعریف_کرو CKA_SIGN			(0x108UL)
#تعریف_کرو CKA_SIGN_RECOVER		(0x109UL)
#تعریف_کرو CKA_VERIFY			(0x10aUL)
#تعریف_کرو CKA_VERIFY_RECOVER		(0x10bUL)
#تعریف_کرو CKA_DERIVE			(0x10cUL)
#تعریف_کرو CKA_آغاز_DATE			(0x110UL)
#تعریف_کرو CKA_انتہا_DATE			(0x111UL)
#تعریف_کرو CKA_MODULUS			(0x120UL)
#تعریف_کرو CKA_MODULUS_بٹ		(0x121UL)
#تعریف_کرو CKA_عوامی_EXPONENT		(0x122UL)
#تعریف_کرو CKA_نجی_EXPONENT		(0x123UL)
#تعریف_کرو CKA_مفرد_1			(0x124UL)
#تعریف_کرو CKA_مفرد_2			(0x125UL)
#تعریف_کرو CKA_EXPONENT_1			(0x126UL)
#تعریف_کرو CKA_EXPONENT_2			(0x127UL)
#تعریف_کرو CKA_COEFFICIENT			(0x128UL)
#تعریف_کرو CKA_عوامی_کلید_INFO		(0x129UL)
#تعریف_کرو CKA_مفرد			(0x130UL)
#تعریف_کرو CKA_SUBPRIME			(0x131UL)
#تعریف_کرو CKA_بنیاد			(0x132UL)
#تعریف_کرو CKA_مفرد_بٹ			(0x133UL)
#تعریف_کرو CKA_SUB_مفرد_بٹ		(0x134UL)
#تعریف_کرو CKA_قدر_بٹ			(0x160UL)
#تعریف_کرو CKA_قدر_LEN			(0x161UL)
#تعریف_کرو CKA_EXTRACTABLE			(0x162UL)
#تعریف_کرو CKA_LOCAL			(0x163UL)
#تعریف_کرو CKA_NEVER_EXTRACTABLE		(0x164UL)
#تعریف_کرو CKA_ALWAYS_SENSITIVE		(0x165UL)
#تعریف_کرو CKA_کلید_GEN_MECHANISM		(0x166UL)
#تعریف_کرو CKA_MODIFIABLE			(0x170UL)
#تعریف_کرو CKA_COPYABLE			(0x171UL)
#تعریف_کرو CKA_DESTROYABLE			(0x172UL)
#تعریف_کرو CKA_ECDSA_PARAMS		(0x180UL)
#تعریف_کرو CKA_EC_PARAMS			(0x180UL)
#تعریف_کرو CKA_EC_نقطہ			(0x181UL)
#تعریف_کرو CKA_SECONDARY_AUTH		(0x200UL)
#تعریف_کرو CKA_AUTH_PIN_FLAGS		(0x201UL)
#تعریف_کرو CKA_ALWAYS_AUTHENTICATE		(0x202UL)
#تعریف_کرو CKA_WRAP_WITH_TRUSTED		(0x210UL)
#تعریف_کرو CKA_GOSTR3410_PARAMS		(0x250UL)
#تعریف_کرو CKA_GOSTR3411_PARAMS		(0x251UL)
#تعریف_کرو CKA_GOST28147_PARAMS		(0x252UL)
#تعریف_کرو CKA_HW_FEATURE_TYPE		(0x300UL)
#تعریف_کرو CKA_RESET_ON_INIT		(0x301UL)
#تعریف_کرو CKA_HAS_RESET			(0x302UL)
#تعریف_کرو CKA_PIXEL_X			(0x400UL)
#تعریف_کرو CKA_PIXEL_Y			(0x401UL)
#تعریف_کرو CKA_RESOLUTION			(0x402UL)
#تعریف_کرو CKA_CHAR_صفیں			(0x403UL)
#تعریف_کرو CKA_CHAR_COLUMNS		(0x404UL)
#تعریف_کرو CKA_COLOR			(0x405UL)
#تعریف_کرو CKA_بٹ_فی_PIXEL		(0x406UL)
#تعریف_کرو CKA_CHAR_SETS			(0x480UL)
#تعریف_کرو CKA_ENCODING_METHODS		(0x481UL)
#تعریف_کرو CKA_MIME_TYPES			(0x482UL)
#تعریف_کرو CKA_MECHANISM_TYPE		(0x500UL)
#تعریف_کرو CKA_REQUIRED_CMS_اوصاف	(0x501UL)
#تعریف_کرو CKA_DEFAULT_CMS_اوصاف	(0x502UL)
#تعریف_کرو CKA_SUPPORTED_CMS_اوصاف	(0x503UL)
#تعریف_کرو CKA_WRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x211UL)
#تعریف_کرو CKA_UNWRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x212UL)
#تعریف_کرو CKA_OTP_FORMAT			(0x220UL)
#تعریف_کرو CKA_OTP_لمبائی			(0x221UL)
#تعریف_کرو CKA_OTP_وقت_INTERVAL		(0x222UL)
#تعریف_کرو CKA_OTP_USER_FRIENDLY_منوال	(0x223UL)
#تعریف_کرو CKA_OTP_CHALLENGE_REQUIREMENT	(0x224UL)
#تعریف_کرو CKA_OTP_وقت_REQUIREMENT	(0x225UL)
#تعریف_کرو CKA_OTP_شمار_REQUIREMENT	(0x226UL)
#تعریف_کرو CKA_OTP_PIN_REQUIREMENT		(0x227UL)
#تعریف_کرو CKA_OTP_USER_IDENTIFIER		(0x22AUL)
#تعریف_کرو CKA_OTP_SERVICE_IDENTIFIER	(0x22BUL)
#تعریف_کرو CKA_OTP_SERVICE_LOGO		(0x22CUL)
#تعریف_کرو CKA_OTP_SERVICE_LOGO_TYPE	(0x22DUL)
#تعریف_کرو CKA_OTP_شمار			(0x22EUL)
#تعریف_کرو CKA_OTP_وقت			(0x22FUL)
#تعریف_کرو CKA_ALLOWED_MECHANISMS		(CKF_ARRAY_ATTRIBUTE | 0x600UL)
#تعریف_کرو CKA_PROFILE_ID			(0x601UL)
#تعریف_کرو CKA_VENDOR_DEFINED		(1UL << 31)


ساخت ck_attribute
{
  ck_attribute_type_t type;
  خالی *قدر;
  غیرعلامتی طویل قدر_len;
};


ساخت ck_date
{
  غیرعلامتی حرف year[4];
  غیرعلامتی حرف month[2];
  غیرعلامتی حرف day[2];
};


قسمتعریف غیرعلامتی طویل ck_mechanism_type_t;

#تعریف_کرو CKM_RSA_PKCS_کلید_PAIR_GEN	(0UL)
#تعریف_کرو CKM_RSA_PKCS			(1UL)
#تعریف_کرو CKM_RSA_9796			(2UL)
#تعریف_کرو CKM_RSA_X_509			(3UL)
#تعریف_کرو CKM_MD2_RSA_PKCS		(4UL)
#تعریف_کرو CKM_MD5_RSA_PKCS		(5UL)
#تعریف_کرو CKM_SHA1_RSA_PKCS		(6UL)
#تعریف_کرو CKM_RIPEMD128_RSA_PKCS		(7UL)
#تعریف_کرو CKM_RIPEMD160_RSA_PKCS		(8UL)
#تعریف_کرو CKM_RSA_PKCS_OAEP		(9UL)
#تعریف_کرو CKM_RSA_X9_31_کلید_PAIR_GEN	(0xaUL)
#تعریف_کرو CKM_RSA_X9_31			(0xbUL)
#تعریف_کرو CKM_SHA1_RSA_X9_31		(0xcUL)
#تعریف_کرو CKM_RSA_PKCS_PSS		(0xdUL)
#تعریف_کرو CKM_SHA1_RSA_PKCS_PSS		(0xeUL)
#تعریف_کرو CKM_DSA_کلید_PAIR_GEN		(0x10UL)
#تعریف_کرو	CKM_DSA				(0x11UL)
#تعریف_کرو CKM_DSA_SHA1			(0x12UL)
#تعریف_کرو CKM_DSA_SHA224			(0x13UL)
#تعریف_کرو CKM_DSA_SHA256			(0x14UL)
#تعریف_کرو CKM_DSA_SHA384			(0x15UL)
#تعریف_کرو CKM_DSA_SHA512			(0x16UL)
#تعریف_کرو CKM_DH_PKCS_کلید_PAIR_GEN	(0x20UL)
#تعریف_کرو CKM_DH_PKCS_DERIVE		(0x21UL)
#تعریف_کرو	CKM_X9_42_DH_کلید_PAIR_GEN	(0x30UL)
#تعریف_کرو CKM_X9_42_DH_DERIVE		(0x31UL)
#تعریف_کرو CKM_X9_42_DH_HYBRID_DERIVE	(0x32UL)
#تعریف_کرو CKM_X9_42_MQV_DERIVE		(0x33UL)
#تعریف_کرو CKM_SHA256_RSA_PKCS		(0x40UL)
#تعریف_کرو CKM_SHA384_RSA_PKCS		(0x41UL)
#تعریف_کرو CKM_SHA512_RSA_PKCS		(0x42UL)
#تعریف_کرو CKM_SHA256_RSA_PKCS_PSS		(0x43UL)
#تعریف_کرو CKM_SHA384_RSA_PKCS_PSS		(0x44UL)
#تعریف_کرو CKM_SHA512_RSA_PKCS_PSS		(0x45UL)
#تعریف_کرو CKM_SHA224_RSA_PKCS		(0x46UL)
#تعریف_کرو CKM_SHA224_RSA_PKCS_PSS		(0x47UL)
#تعریف_کرو CKM_SHA3_256_RSA_PKCS		(0x60UL)
#تعریف_کرو CKM_SHA3_384_RSA_PKCS		(0x61UL)
#تعریف_کرو CKM_SHA3_512_RSA_PKCS		(0x62UL)
#تعریف_کرو CKM_SHA3_256_RSA_PKCS_PSS	(0x63UL)
#تعریف_کرو CKM_SHA3_384_RSA_PKCS_PSS	(0x64UL)
#تعریف_کرو CKM_SHA3_512_RSA_PKCS_PSS	(0x65UL)
#تعریف_کرو CKM_SHA3_224_RSA_PKCS		(0x66UL)
#تعریف_کرو CKM_SHA3_224_RSA_PKCS_PSS	(0x67UL)
#تعریف_کرو CKM_RC2_کلید_GEN			(0x100UL)
#تعریف_کرو CKM_RC2_ECB			(0x101UL)
#تعریف_کرو	CKM_RC2_CBC			(0x102UL)
#تعریف_کرو	CKM_RC2_MAC			(0x103UL)
#تعریف_کرو CKM_RC2_MAC_GENERAL		(0x104UL)
#تعریف_کرو CKM_RC2_CBC_PAD			(0x105UL)
#تعریف_کرو CKM_RC4_کلید_GEN			(0x110UL)
#تعریف_کرو CKM_RC4				(0x111UL)
#تعریف_کرو CKM_DES_کلید_GEN			(0x120UL)
#تعریف_کرو CKM_DES_ECB			(0x121UL)
#تعریف_کرو CKM_DES_CBC			(0x122UL)
#تعریف_کرو CKM_DES_MAC			(0x123UL)
#تعریف_کرو CKM_DES_MAC_GENERAL		(0x124UL)
#تعریف_کرو CKM_DES_CBC_PAD			(0x125UL)
#تعریف_کرو CKM_DES2_کلید_GEN		(0x130UL)
#تعریف_کرو CKM_DES3_کلید_GEN		(0x131UL)
#تعریف_کرو CKM_DES3_ECB			(0x132UL)
#تعریف_کرو CKM_DES3_CBC			(0x133UL)
#تعریف_کرو CKM_DES3_MAC			(0x134UL)
#تعریف_کرو CKM_DES3_MAC_GENERAL		(0x135UL)
#تعریف_کرو CKM_DES3_CBC_PAD		(0x136UL)
#تعریف_کرو CKM_DES3_CMAC_GENERAL		(0x137UL)
#تعریف_کرو CKM_DES3_CMAC			(0x138UL)
#تعریف_کرو CKM_CDMF_کلید_GEN		(0x140UL)
#تعریف_کرو CKM_CDMF_ECB			(0x141UL)
#تعریف_کرو CKM_CDMF_CBC			(0x142UL)
#تعریف_کرو CKM_CDMF_MAC			(0x143UL)
#تعریف_کرو CKM_CDMF_MAC_GENERAL		(0x144UL)
#تعریف_کرو CKM_CDMF_CBC_PAD		(0x145UL)
#تعریف_کرو CKM_MD2				(0x200UL)
#تعریف_کرو CKM_MD2_HMAC			(0x201UL)
#تعریف_کرو CKM_MD2_HMAC_GENERAL		(0x202UL)
#تعریف_کرو CKM_MD5				(0x210UL)
#تعریف_کرو CKM_MD5_HMAC			(0x211UL)
#تعریف_کرو CKM_MD5_HMAC_GENERAL		(0x212UL)
#تعریف_کرو CKM_SHA_1			(0x220UL)
#تعریف_کرو CKM_SHA_1_HMAC			(0x221UL)
#تعریف_کرو CKM_SHA_1_HMAC_GENERAL		(0x222UL)
#تعریف_کرو CKM_RIPEMD128			(0x230UL)
#تعریف_کرو CKM_RIPEMD128_HMAC		(0x231UL)
#تعریف_کرو CKM_RIPEMD128_HMAC_GENERAL	(0x232UL)
#تعریف_کرو CKM_RIPEMD160			(0x240UL)
#تعریف_کرو CKM_RIPEMD160_HMAC		(0x241UL)
#تعریف_کرو CKM_RIPEMD160_HMAC_GENERAL	(0x242UL)
#تعریف_کرو CKM_SHA256			(0x250UL)
#تعریف_کرو CKM_SHA256_HMAC			(0x251UL)
#تعریف_کرو CKM_SHA256_HMAC_GENERAL		(0x252UL)
#تعریف_کرو CKM_SHA224			(0x255UL)
#تعریف_کرو CKM_SHA224_HMAC			(0x256UL)
#تعریف_کرو CKM_SHA224_HMAC_GENERAL		(0x257UL)
#تعریف_کرو CKM_SHA384			(0x260UL)
#تعریف_کرو CKM_SHA384_HMAC			(0x261UL)
#تعریف_کرو CKM_SHA384_HMAC_GENERAL		(0x262UL)
#تعریف_کرو CKM_SHA512			(0x270UL)
#تعریف_کرو CKM_SHA512_HMAC			(0x271UL)
#تعریف_کرو CKM_SHA512_HMAC_GENERAL		(0x272UL)
#تعریف_کرو CKM_SHA3_256			(0x2B0UL)
#تعریف_کرو CKM_SHA3_256_HMAC		(0x2B1UL)
#تعریف_کرو CKM_SHA3_256_HMAC_GENERAL	(0x2B2UL)
#تعریف_کرو CKM_SHA3_256_کلید_GEN		(0x2B3UL)
#تعریف_کرو CKM_SHA3_224			(0x2B5UL)
#تعریف_کرو CKM_SHA3_224_HMAC		(0x2B6UL)
#تعریف_کرو CKM_SHA3_224_HMAC_GENERAL	(0x2B7UL)
#تعریف_کرو CKM_SHA3_224_کلید_GEN		(0x2B8UL)
#تعریف_کرو CKM_SHA3_384			(0x2C0UL)
#تعریف_کرو CKM_SHA3_384_HMAC		(0x2C1UL)
#تعریف_کرو CKM_SHA3_384_HMAC_GENERAL	(0x2C2UL)
#تعریف_کرو CKM_SHA3_384_کلید_GEN		(0x2C3UL)
#تعریف_کرو CKM_SHA3_512			(0x2D0UL)
#تعریف_کرو CKM_SHA3_512_HMAC		(0x2D1UL)
#تعریف_کرو CKM_SHA3_512_HMAC_GENERAL	(0x2D2UL)
#تعریف_کرو CKM_SHA3_512_کلید_GEN		(0x2D3UL)
#تعریف_کرو CKM_CAST_کلید_GEN		(0x300UL)
#تعریف_کرو CKM_CAST_ECB			(0x301UL)
#تعریف_کرو CKM_CAST_CBC			(0x302UL)
#تعریف_کرو CKM_CAST_MAC			(0x303UL)
#تعریف_کرو CKM_CAST_MAC_GENERAL		(0x304UL)
#تعریف_کرو CKM_CAST_CBC_PAD		(0x305UL)
#تعریف_کرو CKM_CAST3_کلید_GEN		(0x310UL)
#تعریف_کرو CKM_CAST3_ECB			(0x311UL)
#تعریف_کرو CKM_CAST3_CBC			(0x312UL)
#تعریف_کرو CKM_CAST3_MAC			(0x313UL)
#تعریف_کرو CKM_CAST3_MAC_GENERAL		(0x314UL)
#تعریف_کرو CKM_CAST3_CBC_PAD		(0x315UL)
#تعریف_کرو CKM_CAST5_کلید_GEN		(0x320UL)
#تعریف_کرو CKM_CAST128_کلید_GEN		(0x320UL)
#تعریف_کرو CKM_CAST5_ECB			(0x321UL)
#تعریف_کرو CKM_CAST128_ECB			(0x321UL)
#تعریف_کرو CKM_CAST5_CBC			(0x322UL)
#تعریف_کرو CKM_CAST128_CBC			(0x322UL)
#تعریف_کرو CKM_CAST5_MAC			(0x323UL)
#تعریف_کرو	CKM_CAST128_MAC			(0x323UL)
#تعریف_کرو CKM_CAST5_MAC_GENERAL		(0x324UL)
#تعریف_کرو CKM_CAST128_MAC_GENERAL		(0x324UL)
#تعریف_کرو CKM_CAST5_CBC_PAD		(0x325UL)
#تعریف_کرو CKM_CAST128_CBC_PAD		(0x325UL)
#تعریف_کرو CKM_RC5_کلید_GEN			(0x330UL)
#تعریف_کرو CKM_RC5_ECB			(0x331UL)
#تعریف_کرو CKM_RC5_CBC			(0x332UL)
#تعریف_کرو CKM_RC5_MAC			(0x333UL)
#تعریف_کرو CKM_RC5_MAC_GENERAL		(0x334UL)
#تعریف_کرو CKM_RC5_CBC_PAD			(0x335UL)
#تعریف_کرو CKM_IDEA_کلید_GEN		(0x340UL)
#تعریف_کرو CKM_IDEA_ECB			(0x341UL)
#تعریف_کرو	CKM_IDEA_CBC			(0x342UL)
#تعریف_کرو CKM_IDEA_MAC			(0x343UL)
#تعریف_کرو CKM_IDEA_MAC_GENERAL		(0x344UL)
#تعریف_کرو CKM_IDEA_CBC_PAD		(0x345UL)
#تعریف_کرو CKM_GENERIC_SECRET_کلید_GEN	(0x350UL)
#تعریف_کرو CKM_CONCATENATE_بنیاد_AND_کلید	(0x360UL)
#تعریف_کرو CKM_CONCATENATE_بنیاد_AND_ڈیٹا	(0x362UL)
#تعریف_کرو CKM_CONCATENATE_ڈیٹا_AND_بنیاد	(0x363UL)
#تعریف_کرو CKM_XOR_بنیاد_AND_ڈیٹا		(0x364UL)
#تعریف_کرو CKM_نکالو_کلید_FROM_کلید	(0x365UL)
#تعریف_کرو CKM_SSL3_PRE_MASTER_کلید_GEN	(0x370UL)
#تعریف_کرو CKM_SSL3_MASTER_کلید_DERIVE	(0x371UL)
#تعریف_کرو CKM_SSL3_کلید_AND_MAC_DERIVE	(0x372UL)
#تعریف_کرو CKM_SSL3_MASTER_کلید_DERIVE_DH	(0x373UL)
#تعریف_کرو CKM_TLS_PRE_MASTER_کلید_GEN	(0x374UL)
#تعریف_کرو CKM_TLS_MASTER_کلید_DERIVE	(0x375UL)
#تعریف_کرو CKM_TLS_کلید_AND_MAC_DERIVE	(0x376UL)
#تعریف_کرو CKM_TLS_MASTER_کلید_DERIVE_DH	(0x377UL)
#تعریف_کرو CKM_SSL3_MD5_MAC		(0x380UL)
#تعریف_کرو CKM_SSL3_SHA1_MAC		(0x381UL)
#تعریف_کرو CKM_MD5_کلید_DERIVATION		(0x390UL)
#تعریف_کرو CKM_MD2_کلید_DERIVATION		(0x391UL)
#تعریف_کرو CKM_SHA1_کلید_DERIVATION		(0x392UL)
#تعریف_کرو CKM_PBE_MD2_DES_CBC		(0x3a0UL)
#تعریف_کرو CKM_PBE_MD5_DES_CBC		(0x3a1UL)
#تعریف_کرو CKM_PBE_MD5_CAST_CBC		(0x3a2UL)
#تعریف_کرو CKM_PBE_MD5_CAST3_CBC		(0x3a3UL)
#تعریف_کرو CKM_PBE_MD5_CAST5_CBC		(0x3a4UL)
#تعریف_کرو CKM_PBE_MD5_CAST128_CBC		(0x3a4UL)
#تعریف_کرو CKM_PBE_SHA1_CAST5_CBC		(0x3a5UL)
#تعریف_کرو CKM_PBE_SHA1_CAST128_CBC	(0x3a5UL)
#تعریف_کرو CKM_PBE_SHA1_RC4_128		(0x3a6UL)
#تعریف_کرو CKM_PBE_SHA1_RC4_40		(0x3a7UL)
#تعریف_کرو CKM_PBE_SHA1_DES3_EDE_CBC	(0x3a8UL)
#تعریف_کرو CKM_PBE_SHA1_DES2_EDE_CBC	(0x3a9UL)
#تعریف_کرو CKM_PBE_SHA1_RC2_128_CBC	(0x3aaUL)
#تعریف_کرو CKM_PBE_SHA1_RC2_40_CBC		(0x3abUL)
#تعریف_کرو CKM_PKCS5_PBKD2			(0x3b0UL)
#تعریف_کرو CKM_PBA_SHA1_WITH_SHA1_HMAC	(0x3c0UL)
#تعریف_کرو CKM_کلید_WRAP_LYNKS		(0x400UL)
#تعریف_کرو CKM_کلید_WRAP_سیٹ_OAEP		(0x401UL)
#تعریف_کرو CKM_SKIPJACK_کلید_GEN		(0x1000UL)
#تعریف_کرو CKM_SKIPJACK_ECB64		(0x1001UL)
#تعریف_کرو CKM_SKIPJACK_CBC64		(0x1002UL)
#تعریف_کرو CKM_SKIPJACK_OFB64		(0x1003UL)
#تعریف_کرو CKM_SKIPJACK_CFB64		(0x1004UL)
#تعریف_کرو CKM_SKIPJACK_CFB32		(0x1005UL)
#تعریف_کرو CKM_SKIPJACK_CFB16		(0x1006UL)
#تعریف_کرو CKM_SKIPJACK_CFB8		(0x1007UL)
#تعریف_کرو CKM_SKIPJACK_WRAP		(0x1008UL)
#تعریف_کرو CKM_SKIPJACK_نجی_WRAP	(0x1009UL)
#تعریف_کرو CKM_SKIPJACK_RELAYX		(0x100aUL)
#تعریف_کرو CKM_KEA_کلید_PAIR_GEN		(0x1010UL)
#تعریف_کرو CKM_KEA_کلید_DERIVE		(0x1011UL)
#تعریف_کرو CKM_FORTEZZA_TIMESTAMP		(0x1020UL)
#تعریف_کرو CKM_BATON_کلید_GEN		(0x1030UL)
#تعریف_کرو CKM_BATON_ECB128		(0x1031UL)
#تعریف_کرو CKM_BATON_ECB96			(0x1032UL)
#تعریف_کرو CKM_BATON_CBC128		(0x1033UL)
#تعریف_کرو CKM_BATON_شمار		(0x1034UL)
#تعریف_کرو CKM_BATON_SHUFFLE		(0x1035UL)
#تعریف_کرو CKM_BATON_WRAP			(0x1036UL)
#تعریف_کرو CKM_ECDSA_کلید_PAIR_GEN		(0x1040UL)
#تعریف_کرو CKM_EC_کلید_PAIR_GEN		(0x1040UL)
#تعریف_کرو CKM_ECDSA			(0x1041UL)
#تعریف_کرو CKM_ECDSA_SHA1			(0x1042UL)
#تعریف_کرو CKM_ECDSA_SHA224		(0x1043UL)
#تعریف_کرو CKM_ECDSA_SHA256		(0x1044UL)
#تعریف_کرو CKM_ECDSA_SHA384		(0x1045UL)
#تعریف_کرو CKM_ECDSA_SHA512		(0x1046UL)
#تعریف_کرو CKM_ECDSA_SHA3_224		(0x1047UL)
#تعریف_کرو CKM_ECDSA_SHA3_256		(0x1048UL)
#تعریف_کرو CKM_ECDSA_SHA3_384		(0x1049UL)
#تعریف_کرو CKM_ECDSA_SHA3_512		(0x104AUL)
#تعریف_کرو CKM_ECDH1_DERIVE		(0x1050UL)
#تعریف_کرو CKM_ECDH1_COFACTOR_DERIVE	(0x1051UL)
#تعریف_کرو CKM_ECMQV_DERIVE		(0x1052UL)
#تعریف_کرو CKM_EC_EDWARDS_کلید_PAIR_GEN     (0x1055UL)
#تعریف_کرو CKM_EC_MONTGOMERY_کلید_PAIR_GEN  (0x1056UL)
#تعریف_کرو CKM_EDDSA			(0x1057UL)
#تعریف_کرو CKM_JUNIPER_کلید_GEN		(0x1060UL)
#تعریف_کرو CKM_JUNIPER_ECB128		(0x1061UL)
#تعریف_کرو CKM_JUNIPER_CBC128		(0x1062UL)
#تعریف_کرو CKM_JUNIPER_شمار		(0x1063UL)
#تعریف_کرو CKM_JUNIPER_SHUFFLE		(0x1064UL)
#تعریف_کرو CKM_JUNIPER_WRAP		(0x1065UL)
#تعریف_کرو CKM_FASTHASH			(0x1070UL)
#تعریف_کرو CKM_AES_کلید_GEN			(0x1080UL)
#تعریف_کرو CKM_AES_ECB			(0x1081UL)
#تعریف_کرو CKM_AES_CBC			(0x1082UL)
#تعریف_کرو CKM_AES_MAC			(0x1083UL)
#تعریف_کرو CKM_AES_MAC_GENERAL		(0x1084UL)
#تعریف_کرو CKM_AES_CBC_PAD			(0x1085UL)
#تعریف_کرو CKM_AES_CTR				(0x1086UL)
#تعریف_کرو CKM_AES_GCM				(0x1087UL)
#تعریف_کرو CKM_AES_CCM				(0x1088UL)
#تعریف_کرو CKM_AES_CTS				(0x1089UL)
#تعریف_کرو CKM_AES_CMAC			(0x108AUL)
#تعریف_کرو CKM_AES_CMAC_GENERAL		(0x108BUL)
#تعریف_کرو CKM_AES_XCBC_MAC		(0x108CUL)
#تعریف_کرو CKM_AES_XCBC_MAC_96		(0x108DUL)
#تعریف_کرو CKM_AES_GMAC			(0x108EUL)
#تعریف_کرو CKM_BLOWFISH_کلید_GEN    (0x1090UL)
#تعریف_کرو CKM_BLOWFISH_CBC        (0x1091UL)
#تعریف_کرو CKM_TWOFISH_کلید_GEN     (0x1092UL)
#تعریف_کرو CKM_TWOFISH_CBC         (0x1093UL)
#تعریف_کرو CKM_DES_ECB_ENCRYPT_ڈیٹا	(0x1100UL)
#تعریف_کرو CKM_DES_CBC_ENCRYPT_ڈیٹا	(0x1101UL)
#تعریف_کرو CKM_DES3_ECB_ENCRYPT_ڈیٹا	(0x1102UL)
#تعریف_کرو CKM_DES3_CBC_ENCRYPT_ڈیٹا	(0x1103UL)
#تعریف_کرو CKM_AES_ECB_ENCRYPT_ڈیٹا	(0x1104UL)
#تعریف_کرو CKM_AES_CBC_ENCRYPT_ڈیٹا	(0x1105UL)
#تعریف_کرو CKM_GOSTR3410_کلید_PAIR_GEN	(0x1200UL)
#تعریف_کرو CKM_GOSTR3410			(0x1201UL)
#تعریف_کرو CKM_GOSTR3410_WITH_GOSTR3411	(0x1202UL)
#تعریف_کرو CKM_GOSTR3410_کلید_WRAP  (0x1203UL)
#تعریف_کرو CKM_GOSTR3410_DERIVE    (0x1204UL)
#تعریف_کرو CKM_GOSTR3410_512_کلید_PAIR_GEN	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#تعریف_کرو CKM_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#تعریف_کرو CKM_GOSTR3410_12_DERIVE	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#تعریف_کرو CKM_GOSTR3410_WITH_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#تعریف_کرو CKM_GOSTR3410_WITH_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#تعریف_کرو CKM_GOSTR3411			(0x1210UL)
#تعریف_کرو CKM_GOSTR3411_HMAC      (0x1211UL)
#تعریف_کرو CKM_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#تعریف_کرو CKM_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#تعریف_کرو CKM_GOSTR3411_12_256_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#تعریف_کرو CKM_GOSTR3411_12_512_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#تعریف_کرو CKM_GOST28147_کلید_GEN   (0x1220UL)
#تعریف_کرو CKM_GOST28147_ECB       (0x1221UL)
#تعریف_کرو CKM_GOST28147           (0x1222UL)
#تعریف_کرو CKM_GOST28147_MAC       (0x1223UL)
#تعریف_کرو CKM_GOST28147_کلید_WRAP  (0x1224UL)

#تعریف_کرو CKM_DSA_PARAMETER_GEN		(0x2000UL)
#تعریف_کرو CKM_DH_PKCS_PARAMETER_GEN	(0x2001UL)
#تعریف_کرو CKM_X9_42_DH_PARAMETER_GEN	(0x2002UL)
#تعریف_کرو CKM_AES_OFB			(0x2104UL)
#تعریف_کرو CKM_AES_CFB64			(0x2105UL)
#تعریف_کرو CKM_AES_CFB8			(0x2106UL)
#تعریف_کرو CKM_AES_CFB128			(0x2107UL)
#تعریف_کرو CKM_AES_CFB1			(0x2108UL)
#تعریف_کرو CKM_AES_کلید_WRAP		(0x2109UL)
#تعریف_کرو CKM_AES_کلید_WRAP_PAD		(0x210AUL)
#تعریف_کرو CKM_XEDDSA			(0x4029UL)
#تعریف_کرو CKM_HKDF_DERIVE			(0x402AUL)
#تعریف_کرو CKM_HKDF_ڈیٹا			(0x402BUL)
#تعریف_کرو CKM_HKDF_کلید_GEN		(0x402CUL)

#تعریف_کرو CKM_VENDOR_DEFINED		(1UL << 31)

ساخت ck_mechanism
{
  ck_mechanism_type_t mechanism;
  خالی *parameter;
  غیرعلامتی طویل parameter_len;
};


ساخت ck_mechanism_info
{
  غیرعلامتی طویل min_کلید_سائز;
  غیرعلامتی طویل max_کلید_سائز;
  ck_flags_t flags;
};

#تعریف_کرو CKF_HW			(1UL << 0)

#تعریف_کرو CKF_پیغام_ENCRYPT	(1UL << 1)
#تعریف_کرو CKF_پیغام_DECRYPT	(1UL << 2)
#تعریف_کرو CKF_پیغام_SIGN	(1UL << 3)
#تعریف_کرو CKF_پیغام_VERIFY	(1UL << 4)
#تعریف_کرو CKF_MULTI_پیغام	(1UL << 5)
#تعریف_کرو CKF_ڈھونڈو_OBJECTS	(1UL << 6)

#تعریف_کرو CKF_ENCRYPT		(1UL << 8)
#تعریف_کرو CKF_DECRYPT		(1UL << 9)
#تعریف_کرو CKF_DIGEST		(1UL << 10)
#تعریف_کرو CKF_SIGN		(1UL << 11)
#تعریف_کرو CKF_SIGN_RECOVER	(1UL << 12)
#تعریف_کرو CKF_VERIFY		(1UL << 13)
#تعریف_کرو CKF_VERIFY_RECOVER	(1UL << 14)
#تعریف_کرو CKF_GENERATE		(1UL << 15)
#تعریف_کرو CKF_GENERATE_کلید_PAIR	(1UL << 16)
#تعریف_کرو CKF_WRAP		(1UL << 17)
#تعریف_کرو CKF_UNWRAP		(1UL << 18)
#تعریف_کرو CKF_DERIVE		(1UL << 19)
#تعریف_کرو CKF_EXTENSION		(1UL << 31)

#تعریف_کرو CKF_EC_F_P			(1UL << 20)
#تعریف_کرو CKF_EC_F_2M			(1UL << 21)
#تعریف_کرو CKF_EC_ECPARAMETERS	(1UL << 22)
#تعریف_کرو CKF_EC_OID		(1UL << 23)
#تعریف_کرو CKF_EC_NAMEDCURVE	CKF_EC_OID
#تعریف_کرو CKF_EC_UNCOMPRESS	(1UL << 24)
#تعریف_کرو CKF_EC_COMPRESS		(1UL << 25)
#تعریف_کرو CKF_EC_CURVENAME	(1UL << 26)

/* Flags for C_WaitForSlotEvent.  */
#تعریف_کرو CKF_DONT_بلاک				(1UL)

/* Flags for Key derivation */
#تعریف_کرو CKD_NULL			(0x1UL)
#تعریف_کرو CKD_SHA1_KDF			(0x2UL)
#تعریف_کرو CKD_SHA224_KDF			(0x5UL)
#تعریف_کرو CKD_SHA256_KDF			(0x6UL)
#تعریف_کرو CKD_SHA384_KDF			(0x7UL)
#تعریف_کرو CKD_SHA512_KDF			(0x8UL)

قسمتعریف ساخت CK_ECDH1_DERIVE_PARAMS {
	غیرعلامتی طویل  kdf;
	غیرعلامتی طویل  ul_Shared_ڈیٹا_Len;
	غیرعلامتی حرف *  p_Shared_ڈیٹا;
	غیرعلامتی طویل  ul_عوامی_ڈیٹا_Len;
	غیرعلامتی حرف *  p_عوامی_ڈیٹا;
} CK_ECDH1_DERIVE_PARAMS;

قسمتعریف ساخت CK_ECMQV_DERIVE_PARAMS {
	غیرعلامتی طویل kdf;
	غیرعلامتی طویل ul_Shared_ڈیٹا_Len;
	غیرعلامتی حرف * p_Shared_ڈیٹا;
	غیرعلامتی طویل ul_عوامی_ڈیٹا_Len;
	غیرعلامتی حرف * p_عوامی_ڈیٹا;
	غیرعلامتی طویل ul_نجی_ڈیٹا_Len;
	CK_OBJECT_HANDLE h_نجی_ڈیٹا;
	غیرعلامتی طویل ul_عوامی_ڈیٹا_Len2;
	غیرعلامتی حرف * p_عوامی_Data2;
	CK_OBJECT_HANDLE عوامی_کلید_2;
} CK_ECMQV_DERIVE_PARAMS;

قسمتعریف غیرعلامتی طویل ck_rsa_pkcs_mgf_type_t;
قسمتعریف غیرعلامتی طویل CK_RSA_PKCS_OAEP_ماخذ_TYPE;

قسمتعریف ساخت CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_ماخذ_TYPE ماخذ;
	خالی *p_ماخذ_ڈیٹا;
	غیرعلامتی طویل ul_ماخذ_ڈیٹا_Len;
} CK_RSA_PKCS_OAEP_PARAMS;

قسمتعریف ساخت CK_RSA_PKCS_PSS_PARAMS {
	ck_mechanism_type_t hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	غیرعلامتی طویل sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#تعریف_کرو CKG_MGF1_SHA1			(0x00000001UL)
#تعریف_کرو CKG_MGF1_SHA224		(0x00000005UL)
#تعریف_کرو CKG_MGF1_SHA256		(0x00000002UL)
#تعریف_کرو CKG_MGF1_SHA384		(0x00000003UL)
#تعریف_کرو CKG_MGF1_SHA512		(0x00000004UL)
#تعریف_کرو CKG_MGF1_SHA3_224	(0x00000006UL)
#تعریف_کرو CKG_MGF1_SHA3_256	(0x00000007UL)
#تعریف_کرو CKG_MGF1_SHA3_384	(0x00000008UL)
#تعریف_کرو CKG_MGF1_SHA3_512	(0x00000009UL)

#تعریف_کرو CKZ_ڈیٹا_SPECIFIED	(0x00000001UL)

قسمتعریف ساخت CK_GCM_PARAMS {
	خالی * pIv;
	غیرعلامتی طویل ulIvLen;
	غیرعلامتی طویل ul_Iv_بٹ;
	خالی * pAAD;
	غیرعلامتی طویل ulAADLen;
	غیرعلامتی طویل ul_لیبل_بٹ;
} CK_GCM_PARAMS;

قسمتعریف ساخت CK_CCM_PARAMS {
	غیرعلامتی طویل ul_ڈیٹا_Len;
	غیرعلامتی حرف *pNonce;
	غیرعلامتی طویل ulNonceLen;
	غیرعلامتی حرف *pAAD;
	غیرعلامتی طویل ulAADLen;
	غیرعلامتی طویل ulMACLen;
} CK_CCM_PARAMS;

/* EDDSA */
قسمتعریف ساخت CK_EDDSA_PARAMS {
	غیرعلامتی حرف phFlag;
	غیرعلامتی طویل ul_Context_ڈیٹا_Len;
	غیرعلامتی حرف *p_Context_ڈیٹا;
} CK_EDDSA_PARAMS;

قسمتعریف CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

/* XEDDSA */
قسمتعریف ساخت CK_XEDDSA_PARAMS {
	غیرعلامتی طویل hash;
} CK_XEDDSA_PARAMS;

قسمتعریف CK_XEDDSA_PARAMS *CK_XEDDSA_PARAMS_PTR;

قسمتعریف ساخت CK_AES_CTR_PARAMS {
    غیرعلامتی طویل ul_شمار_بٹ;
    غیرعلامتی حرف cb[16];
} CK_AES_CTR_PARAMS;

قسمتعریف CK_AES_CTR_PARAMS *CK_AES_CTR_PARAMS_PTR;

قسمتعریف غیرعلامتی طویل CK_MAC_GENERAL_PARAMS;

قسمتعریف CK_MAC_GENERAL_PARAMS *CK_MAC_GENERAL_PARAMS_PTR;

قسمتعریف غیرعلامتی طویل ck_rv_t;


قسمتعریف ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, خالی *application);

ساخت ck_interface {
  حرف * pInterfaceName;
  خالی * pFunctionList;
  ck_flags_t flags;
};

#تعریف_کرو CKF_INTERFACE_FORK_محفوظ	(0x00000001UL)

/* Forward reference.  */
ساخت ck_function_list;
ساخت ck_function_list_3_0;

#تعریف_کرو _CK_DECLARE_FUNCTION(name, دلائل)	\
قسمتعریف ck_rv_t (*CK_ ## name) دلائل;		\
ck_rv_t CK_SPEC name دلائل

_CK_DECLARE_FUNCTION (C_Initialize, (خالی *init_دلائل));
_CK_DECLARE_FUNCTION (C_Finalize, (خالی *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (ساخت ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (ساخت ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_Get_خانہ_List,
		      (غیرعلامتی حرف token_present, ck_خانہ_id_t *خانہ_list,
		       غیرعلامتی طویل *گنتی));
_CK_DECLARE_FUNCTION (C_Get_خانہ_Info,
		      (ck_خانہ_id_t خانہ_id, ساخت ck_خانہ_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_خانہ_id_t خانہ_id, ساخت ck_token_info *info));
_CK_DECLARE_FUNCTION (C_Wait_For_خانہ_Event,
		      (ck_flags_t flags, ck_خانہ_id_t *خانہ, خالی *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_خانہ_id_t خانہ_id,
		       ck_mechanism_type_t *mechanism_list,
		       غیرعلامتی طویل *گنتی));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_خانہ_id_t خانہ_id, ck_mechanism_type_t type,
		       ساخت ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_خانہ_id_t خانہ_id, غیرعلامتی حرف *pin,
		       غیرعلامتی طویل pin_len, غیرعلامتی حرف *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, غیرعلامتی حرف *pin,
		       غیرعلامتی طویل pin_len));
_CK_DECLARE_FUNCTION (C_سیٹ_PIN,
		      (ck_session_handle_t session, غیرعلامتی حرف *old_pin,
		       غیرعلامتی طویل old_len, غیرعلامتی حرف *new_pin,
		       غیرعلامتی طویل new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_خانہ_id_t خانہ_id, ck_flags_t flags,
		       خالی *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_خانہ_id_t خانہ_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       ساخت ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *operation_state,
		       غیرعلامتی طویل *operation_state_len));
_CK_DECLARE_FUNCTION (C_سیٹ_Operation_State,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *operation_state,
		       غیرعلامتی طویل operation_state_len,
		       ck_object_handle_t encryption_کلید,
		       ck_object_handle_t authentication_کلید));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       غیرعلامتی حرف *pin, غیرعلامتی طویل pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       ساخت ck_attribute *templ,
		       غیرعلامتی طویل گنتی, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       ساخت ck_attribute *templ, غیرعلامتی طویل گنتی,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_Get_Object_سائز,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       غیرعلامتی طویل *سائز));
_CK_DECLARE_FUNCTION (C_Get_Attribute_قدر,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       ساخت ck_attribute *templ,
		       غیرعلامتی طویل گنتی));
_CK_DECLARE_FUNCTION (C_سیٹ_Attribute_قدر,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       ساخت ck_attribute *templ,
		       غیرعلامتی طویل گنتی));
_CK_DECLARE_FUNCTION (C_ڈھونڈو_Objects_Init,
		      (ck_session_handle_t session,
		       ساخت ck_attribute *templ,
		       غیرعلامتی طویل گنتی));
_CK_DECLARE_FUNCTION (C_ڈھونڈو_Objects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       غیرعلامتی طویل max_object_گنتی,
		       غیرعلامتی طویل *object_گنتی));
_CK_DECLARE_FUNCTION (C_ڈھونڈو_Objects_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *ڈیٹا, غیرعلامتی طویل ڈیٹا_len,
		       غیرعلامتی حرف *encrypted_ڈیٹا,
		       غیرعلامتی طویل *encrypted_ڈیٹا_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *part, غیرعلامتی طویل part_len,
		       غیرعلامتی حرف *encrypted_part,
		       غیرعلامتی طویل *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *آخری_encrypted_part,
		       غیرعلامتی طویل *آخری_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *encrypted_ڈیٹا,
		       غیرعلامتی طویل encrypted_ڈیٹا_len,
		       غیرعلامتی حرف *ڈیٹا, غیرعلامتی طویل *ڈیٹا_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *encrypted_part,
		       غیرعلامتی طویل encrypted_part_len,
		       غیرعلامتی حرف *part, غیرعلامتی طویل *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *آخری_part,
		       غیرعلامتی طویل *آخری_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *ڈیٹا, غیرعلامتی طویل ڈیٹا_len,
		       غیرعلامتی حرف *digest,
		       غیرعلامتی طویل *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *part, غیرعلامتی طویل part_len));
_CK_DECLARE_FUNCTION (C_Digest_کلید,
		      (ck_session_handle_t session, ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *digest,
		       غیرعلامتی طویل *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *ڈیٹا, غیرعلامتی طویل ڈیٹا_len,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *part, غیرعلامتی طویل part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *ڈیٹا, غیرعلامتی طویل ڈیٹا_len,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *ڈیٹا, غیرعلامتی طویل ڈیٹا_len,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *part, غیرعلامتی طویل part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل signature_len,
		       غیرعلامتی حرف *ڈیٹا,
		       غیرعلامتی طویل *ڈیٹا_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *part, غیرعلامتی طویل part_len,
		       غیرعلامتی حرف *encrypted_part,
		       غیرعلامتی طویل *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *encrypted_part,
		       غیرعلامتی طویل encrypted_part_len,
		       غیرعلامتی حرف *part,
		       غیرعلامتی طویل *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *part, غیرعلامتی طویل part_len,
		       غیرعلامتی حرف *encrypted_part,
		       غیرعلامتی طویل *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *encrypted_part,
		       غیرعلامتی طویل encrypted_part_len,
		       غیرعلامتی حرف *part,
		       غیرعلامتی طویل *part_len));

_CK_DECLARE_FUNCTION (C_Generate_کلید,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ساخت ck_attribute *templ,
		       غیرعلامتی طویل گنتی,
		       ck_object_handle_t *کلید));
_CK_DECLARE_FUNCTION (C_Generate_کلید_Pair,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ساخت ck_attribute *عوامی_کلید_template,
		       غیرعلامتی طویل عوامی_کلید_attribute_گنتی,
		       ساخت ck_attribute *نجی_کلید_template,
		       غیرعلامتی طویل نجی_کلید_attribute_گنتی,
		       ck_object_handle_t *عوامی_کلید,
		       ck_object_handle_t *نجی_کلید));
_CK_DECLARE_FUNCTION (C_Wrap_کلید,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_کلید,
		       ck_object_handle_t کلید,
		       غیرعلامتی حرف *wrapped_کلید,
		       غیرعلامتی طویل *wrapped_کلید_len));
_CK_DECLARE_FUNCTION (C_Unwrap_کلید,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_کلید,
		       غیرعلامتی حرف *wrapped_کلید,
		       غیرعلامتی طویل wrapped_کلید_len,
		       ساخت ck_attribute *templ,
		       غیرعلامتی طویل attribute_گنتی,
		       ck_object_handle_t *کلید));
_CK_DECLARE_FUNCTION (C_Derive_کلید,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t بنیاد_کلید,
		       ساخت ck_attribute *templ,
		       غیرعلامتی طویل attribute_گنتی,
		       ck_object_handle_t *کلید));

_CK_DECLARE_FUNCTION (C_بیج_Random,
		      (ck_session_handle_t session, غیرعلامتی حرف *بیج,
		       غیرعلامتی طویل بیج_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       غیرعلامتی حرف *random_data,
		       غیرعلامتی طویل random_len));

_CK_DECLARE_FUNCTION (C_Get_Function_حالت, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_GetInterfaceList,
		      (ساخت ck_interface *interfaces_list,
		       غیرعلامتی طویل *گنتی));
_CK_DECLARE_FUNCTION (C_GetInterface,
		      (غیرعلامتی حرف *interface_name,
		       ساخت ck_نسخہ *نسخہ,
		       ساخت ck_interface **interface_ptr,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_LoginUser,
		      (ck_session_handle_t session,
		       ck_user_type_t user_type,
		       غیرعلامتی حرف *pin,
		       غیرعلامتی طویل pin_len,
		       غیرعلامتی حرف *username,
		       غیرعلامتی طویل username_len));

_CK_DECLARE_FUNCTION (C_SessionCancel,
		      (ck_session_handle_t session,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_پیغام_Encrypt_Init,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Encrypt_پیغام,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *associated_ڈیٹا,
		       غیرعلامتی طویل associated_ڈیٹا_len,
		       غیرعلامتی حرف *plaintext,
		       غیرعلامتی طویل plaintext_len,
		       غیرعلامتی حرف *ciphertext,
		       غیرعلامتی طویل *ciphertext_len));
_CK_DECLARE_FUNCTION (C_Encrypt_پیغام_Begin,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *associated_ڈیٹا,
		       غیرعلامتی طویل associated_ڈیٹا_len));
_CK_DECLARE_FUNCTION (C_Encrypt_پیغام_اگلا,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *plaintext_part,
		       غیرعلامتی طویل plaintext_part_len,
		       غیرعلامتی حرف *ciphertext_part,
		       غیرعلامتی طویل *ciphertext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_پیغام_Encrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پیغام_Decrypt_Init,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Decrypt_پیغام,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *associated_ڈیٹا,
		       غیرعلامتی طویل associated_ڈیٹا_len,
		       غیرعلامتی حرف *ciphertext,
		       غیرعلامتی طویل ciphertext_len,
		       غیرعلامتی حرف *plaintext,
		       غیرعلامتی طویل *plaintext_len));
_CK_DECLARE_FUNCTION (C_Decrypt_پیغام_Begin,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *associated_ڈیٹا,
		       غیرعلامتی طویل associated_ڈیٹا_len));
_CK_DECLARE_FUNCTION (C_Decrypt_پیغام_اگلا,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *ciphertext_part,
		       غیرعلامتی طویل ciphertext_part_len,
		       غیرعلامتی حرف *plaintext_part,
		       غیرعلامتی طویل *plaintext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_پیغام_Decrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پیغام_Sign_Init,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Sign_پیغام,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *ڈیٹا,
		       غیرعلامتی طویل ڈیٹا_len,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل *signature_len));
_CK_DECLARE_FUNCTION (C_Sign_پیغام_Begin,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len));
_CK_DECLARE_FUNCTION (C_Sign_پیغام_اگلا,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *ڈیٹا,
		       غیرعلامتی طویل ڈیٹا_len,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل *signature_len));
_CK_DECLARE_FUNCTION (C_پیغام_Sign_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پیغام_Verify_Init,
		      (ck_session_handle_t session,
		       ساخت ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Verify_پیغام,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *ڈیٹا,
		       غیرعلامتی طویل ڈیٹا_len,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل signature_len));
_CK_DECLARE_FUNCTION (C_Verify_پیغام_Begin,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len));
_CK_DECLARE_FUNCTION (C_Verify_پیغام_اگلا,
		      (ck_session_handle_t session,
		       خالی *parameter,
		       غیرعلامتی طویل parameter_len,
		       غیرعلامتی حرف *ڈیٹا,
		       غیرعلامتی طویل ڈیٹا_len,
		       غیرعلامتی حرف *signature,
		       غیرعلامتی طویل signature_len));
_CK_DECLARE_FUNCTION (C_پیغام_Verify_Final,
		      (ck_session_handle_t session));

/* Flags in Message-based encryption/decryption API */
#تعریف_کرو CKF_انتہا_کا_پیغام	(0x00000001UL)

ساخت ck_function_list
{
  ساخت ck_نسخہ نسخہ;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_خانہ_List C_Get_خانہ_List;
  CK_C_Get_خانہ_Info C_Get_خانہ_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_سیٹ_PIN C_سیٹ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_سیٹ_Operation_State C_سیٹ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_سائز C_Get_Object_سائز;
  CK_C_Get_Attribute_قدر C_Get_Attribute_قدر;
  CK_C_سیٹ_Attribute_قدر C_سیٹ_Attribute_قدر;
  CK_C_ڈھونڈو_Objects_Init C_ڈھونڈو_Objects_Init;
  CK_C_ڈھونڈو_Objects C_ڈھونڈو_Objects;
  CK_C_ڈھونڈو_Objects_Final C_ڈھونڈو_Objects_Final;
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
  CK_C_Digest_کلید C_Digest_کلید;
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
  CK_C_Generate_کلید C_Generate_کلید;
  CK_C_Generate_کلید_Pair C_Generate_کلید_Pair;
  CK_C_Wrap_کلید C_Wrap_کلید;
  CK_C_Unwrap_کلید C_Unwrap_کلید;
  CK_C_Derive_کلید C_Derive_کلید;
  CK_C_بیج_Random C_بیج_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_حالت C_Get_Function_حالت;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_خانہ_Event C_Wait_For_خانہ_Event;
};

ساخت ck_function_list_3_0
{
  ساخت ck_نسخہ نسخہ;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_خانہ_List C_Get_خانہ_List;
  CK_C_Get_خانہ_Info C_Get_خانہ_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_سیٹ_PIN C_سیٹ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_سیٹ_Operation_State C_سیٹ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_سائز C_Get_Object_سائز;
  CK_C_Get_Attribute_قدر C_Get_Attribute_قدر;
  CK_C_سیٹ_Attribute_قدر C_سیٹ_Attribute_قدر;
  CK_C_ڈھونڈو_Objects_Init C_ڈھونڈو_Objects_Init;
  CK_C_ڈھونڈو_Objects C_ڈھونڈو_Objects;
  CK_C_ڈھونڈو_Objects_Final C_ڈھونڈو_Objects_Final;
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
  CK_C_Digest_کلید C_Digest_کلید;
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
  CK_C_Generate_کلید C_Generate_کلید;
  CK_C_Generate_کلید_Pair C_Generate_کلید_Pair;
  CK_C_Wrap_کلید C_Wrap_کلید;
  CK_C_Unwrap_کلید C_Unwrap_کلید;
  CK_C_Derive_کلید C_Derive_کلید;
  CK_C_بیج_Random C_بیج_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_حالت C_Get_Function_حالت;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_خانہ_Event C_Wait_For_خانہ_Event;
  /* PKCS #11 3.0 functions */
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  CK_C_پیغام_Encrypt_Init C_پیغام_Encrypt_Init;
  CK_C_Encrypt_پیغام C_Encrypt_پیغام;
  CK_C_Encrypt_پیغام_Begin C_Encrypt_پیغام_Begin;
  CK_C_Encrypt_پیغام_اگلا C_Encrypt_پیغام_اگلا;
  CK_C_پیغام_Encrypt_Final C_پیغام_Encrypt_Final;
  CK_C_پیغام_Decrypt_Init C_پیغام_Decrypt_Init;
  CK_C_Decrypt_پیغام C_Decrypt_پیغام;
  CK_C_Decrypt_پیغام_Begin C_Decrypt_پیغام_Begin;
  CK_C_Decrypt_پیغام_اگلا C_Decrypt_پیغام_اگلا;
  CK_C_پیغام_Decrypt_Final C_پیغام_Decrypt_Final;
  CK_C_پیغام_Sign_Init C_پیغام_Sign_Init;
  CK_C_Sign_پیغام C_Sign_پیغام;
  CK_C_Sign_پیغام_Begin C_Sign_پیغام_Begin;
  CK_C_Sign_پیغام_اگلا C_Sign_پیغام_اگلا;
  CK_C_پیغام_Sign_Final C_پیغام_Sign_Final;
  CK_C_پیغام_Verify_Init C_پیغام_Verify_Init;
  CK_C_Verify_پیغام C_Verify_پیغام;
  CK_C_Verify_پیغام_Begin C_Verify_پیغام_Begin;
  CK_C_Verify_پیغام_اگلا C_Verify_پیغام_اگلا;
  CK_C_پیغام_Verify_Final C_پیغام_Verify_Final;
};



قسمتعریف ck_rv_t (*ck_createmutex_t) (خالی **mutex);
قسمتعریف ck_rv_t (*ck_destroymutex_t) (خالی *mutex);
قسمتعریف ck_rv_t (*ck_lockmutex_t) (خالی *mutex);
قسمتعریف ck_rv_t (*ck_unlockmutex_t) (خالی *mutex);


ساخت ck_c_initialize_دلائل
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t تالا_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  خالی *reserved;
};


#تعریف_کرو CKF_LIBRARY_CANT_CREATE_OS_دھاگے	(1UL << 0)
#تعریف_کرو CKF_OS_LOCKING_OK			(1UL << 1)

#تعریف_کرو CKR_OK					(0UL)
#تعریف_کرو CKR_CANCEL				(1UL)
#تعریف_کرو CKR_HOST_حافظہ				(2UL)
#تعریف_کرو CKR_خانہ_ID_INVALID			(3UL)
#تعریف_کرو CKR_GENERAL_ERROR			(5UL)
#تعریف_کرو CKR_FUNCTION_FAILED			(6UL)
#تعریف_کرو CKR_ARGUMENTS_BAD			(7UL)
#تعریف_کرو CKR_NO_EVENT				(8UL)
#تعریف_کرو CKR_NEED_مقصد_CREATE_دھاگے		(9UL)
#تعریف_کرو CKR_CANT_تالا				(0xaUL)
#تعریف_کرو CKR_ATTRIBUTE_READ_ONLY			(0x10UL)
#تعریف_کرو CKR_ATTRIBUTE_SENSITIVE			(0x11UL)
#تعریف_کرو CKR_ATTRIBUTE_TYPE_INVALID		(0x12UL)
#تعریف_کرو CKR_ATTRIBUTE_قدر_INVALID		(0x13UL)
#تعریف_کرو CKR_ACTION_PROHIBITED			(0x1BUL)
#تعریف_کرو CKR_ڈیٹا_INVALID			(0x20UL)
#تعریف_کرو CKR_ڈیٹا_LEN_RANGE			(0x21UL)
#تعریف_کرو CKR_DEVICE_ERROR			(0x30UL)
#تعریف_کرو CKR_DEVICE_حافظہ			(0x31UL)
#تعریف_کرو CKR_DEVICE_REMOVED			(0x32UL)
#تعریف_کرو CKR_ENCRYPTED_ڈیٹا_INVALID		(0x40UL)
#تعریف_کرو CKR_ENCRYPTED_ڈیٹا_LEN_RANGE		(0x41UL)
#تعریف_کرو CKR_FUNCTION_CANCELED			(0x50UL)
#تعریف_کرو CKR_FUNCTION_NOT_PARALLEL		(0x51UL)
#تعریف_کرو CKR_FUNCTION_NOT_SUPPORTED		(0x54UL)
#تعریف_کرو CKR_کلید_HANDLE_INVALID			(0x60UL)
#تعریف_کرو CKR_کلید_سائز_RANGE			(0x62UL)
#تعریف_کرو CKR_کلید_TYPE_INCONSISTENT		(0x63UL)
#تعریف_کرو CKR_کلید_NOT_NEEDED			(0x64UL)
#تعریف_کرو CKR_کلید_بدلا				(0x65UL)
#تعریف_کرو CKR_کلید_NEEDED				(0x66UL)
#تعریف_کرو CKR_کلید_INDIGESTIBLE			(0x67UL)
#تعریف_کرو CKR_کلید_FUNCTION_NOT_PERMITTED		(0x68UL)
#تعریف_کرو CKR_کلید_NOT_WRAPPABLE			(0x69UL)
#تعریف_کرو CKR_کلید_UNEXTRACTABLE			(0x6aUL)
#تعریف_کرو CKR_MECHANISM_INVALID			(0x70UL)
#تعریف_کرو CKR_MECHANISM_PARAM_INVALID		(0x71UL)
#تعریف_کرو CKR_OBJECT_HANDLE_INVALID		(0x82UL)
#تعریف_کرو CKR_OPERATION_فعال			(0x90UL)
#تعریف_کرو CKR_OPERATION_NOT_INITIALIZED		(0x91UL)
#تعریف_کرو CKR_PIN_INCORRECT			(0xa0UL)
#تعریف_کرو CKR_PIN_INVALID				(0xa1UL)
#تعریف_کرو CKR_PIN_LEN_RANGE			(0xa2UL)
#تعریف_کرو CKR_PIN_EXPIRED				(0xa3UL)
#تعریف_کرو CKR_PIN_LOCKED				(0xa4UL)
#تعریف_کرو CKR_SESSION_CLOSED			(0xb0UL)
#تعریف_کرو CKR_SESSION_گنتی			(0xb1UL)
#تعریف_کرو CKR_SESSION_HANDLE_INVALID		(0xb3UL)
#تعریف_کرو CKR_SESSION_PARALLEL_NOT_SUPPORTED	(0xb4UL)
#تعریف_کرو CKR_SESSION_READ_ONLY			(0xb5UL)
#تعریف_کرو CKR_SESSION_EXISTS			(0xb6UL)
#تعریف_کرو CKR_SESSION_READ_ONLY_EXISTS		(0xb7UL)
#تعریف_کرو CKR_SESSION_READ_WRITE_SO_EXISTS	(0xb8UL)
#تعریف_کرو CKR_SIGNATURE_INVALID			(0xc0UL)
#تعریف_کرو CKR_SIGNATURE_LEN_RANGE			(0xc1UL)
#تعریف_کرو CKR_TEMPLATE_INCOMPLETE			(0xd0UL)
#تعریف_کرو CKR_TEMPLATE_INCONSISTENT		(0xd1UL)
#تعریف_کرو CKR_TOKEN_NOT_PRESENT			(0xe0UL)
#تعریف_کرو CKR_TOKEN_NOT_RECOGNIZED		(0xe1UL)
#تعریف_کرو CKR_TOKEN_WRITE_PROTECTED		(0xe2UL)
#تعریف_کرو	CKR_UNWRAPPING_کلید_HANDLE_INVALID	(0xf0UL)
#تعریف_کرو CKR_UNWRAPPING_کلید_سائز_RANGE		(0xf1UL)
#تعریف_کرو CKR_UNWRAPPING_کلید_TYPE_INCONSISTENT	(0xf2UL)
#تعریف_کرو CKR_USER_ALREADY_LOGGED_اندر		(0x100UL)
#تعریف_کرو CKR_USER_NOT_LOGGED_اندر			(0x101UL)
#تعریف_کرو CKR_USER_PIN_NOT_INITIALIZED		(0x102UL)
#تعریف_کرو CKR_USER_TYPE_INVALID			(0x103UL)
#تعریف_کرو CKR_USER_ANOTHER_ALREADY_LOGGED_اندر	(0x104UL)
#تعریف_کرو CKR_USER_TOO_MANY_TYPES			(0x105UL)
#تعریف_کرو CKR_WRAPPED_کلید_INVALID			(0x110UL)
#تعریف_کرو CKR_WRAPPED_کلید_LEN_RANGE		(0x112UL)
#تعریف_کرو CKR_WRAPPING_کلید_HANDLE_INVALID		(0x113UL)
#تعریف_کرو CKR_WRAPPING_کلید_سائز_RANGE		(0x114UL)
#تعریف_کرو CKR_WRAPPING_کلید_TYPE_INCONSISTENT	(0x115UL)
#تعریف_کرو CKR_RANDOM_بیج_NOT_SUPPORTED		(0x120UL)
#تعریف_کرو CKR_RANDOM_NO_RNG			(0x121UL)
#تعریف_کرو CKR_DOMAIN_PARAMS_INVALID		(0x130UL)
#تعریف_کرو CKR_خم_NOT_SUPPORTED			(0x140UL)
#تعریف_کرو CKR_بفر_TOO_SMALL			(0x150UL)
#تعریف_کرو CKR_SAVED_STATE_INVALID			(0x160UL)
#تعریف_کرو CKR_INFORMATION_SENSITIVE		(0x170UL)
#تعریف_کرو CKR_STATE_UNSAVEABLE			(0x180UL)
#تعریف_کرو CKR_CRYPTOKI_NOT_INITIALIZED		(0x190UL)
#تعریف_کرو CKR_CRYPTOKI_ALREADY_INITIALIZED	(0x191UL)
#تعریف_کرو CKR_MUTEX_BAD				(0x1a0UL)
#تعریف_کرو CKR_MUTEX_NOT_LOCKED			(0x1a1UL)
#تعریف_کرو CKR_FUNCTION_REJECTED			(0x200UL)
#تعریف_کرو CKR_VENDOR_DEFINED			(1UL << 31)


/* Compatibility layer.  */

#اگر_تعریف_شدہ CRYPTOKI_COMPAT

#تعریف_منسوخ CK_DEFINE_FUNCTION
#تعریف_کرو CK_DEFINE_FUNCTION(retval, name) retval CK_SPEC name

/* For NULL.  */
#شامل <stddef.h>

قسمتعریف غیرعلامتی حرف CK_BYTE;
قسمتعریف غیرعلامتی حرف CK_CHAR;
قسمتعریف غیرعلامتی حرف CK_UTF8CHAR;
قسمتعریف غیرعلامتی حرف CK_BBOOL;
قسمتعریف غیرعلامتی طویل صحیح CK_ULONG;
قسمتعریف طویل صحیح CK_LONG;
قسمتعریف CK_BYTE *CK_BYTE_PTR;
قسمتعریف CK_CHAR *CK_CHAR_PTR;
قسمتعریف CK_UTF8CHAR *CK_UTF8CHAR_PTR;
قسمتعریف CK_ULONG *CK_ULONG_PTR;
قسمتعریف خالی *CK_VOID_PTR;
قسمتعریف خالی **CK_VOID_PTR_PTR;
#تعریف_کرو CK_FALSE 0
#تعریف_کرو CK_TRUE 1
#اگر_غیر_تعریف_شدہ CK_DISABLE_TRUE_FALSE
#اگر_غیر_تعریف_شدہ FALSE
#تعریف_کرو FALSE 0
#اگر_ختم
#اگر_غیر_تعریف_شدہ TRUE
#تعریف_کرو TRUE 1
#اگر_ختم
#اگر_ختم

قسمتعریف ساخت CK_HKDF_PARAMS {
	CK_BBOOL b_نکالو;
	CK_BBOOL bExpand;
	CK_MECHANISM_TYPE prfHashMechanism;
	CK_ULONG ulSaltType;
	CK_BYTE_PTR pSalt;
	CK_ULONG ulSaltLen;
	CK_OBJECT_HANDLE h_Salt_کلید;
	CK_BYTE_PTR pInfo;
	CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

#تعریف_کرو CKF_HKDF_SALT_NULL 0x00000001UL
#تعریف_کرو CKF_HKDF_SALT_ڈیٹا 0x00000002UL
#تعریف_کرو CKF_HKDF_SALT_کلید  0x00000004UL

قسمتعریف ساخت ck_نسخہ CK_نسخہ_2;
قسمتعریف ساخت ck_نسخہ *CK_نسخہ_PTR;

قسمتعریف ساخت ck_info CK_INFO;
قسمتعریف ساخت ck_info *CK_INFO_PTR;

قسمتعریف ck_خانہ_id_t *CK_خانہ_ID_PTR;

قسمتعریف ساخت ck_خانہ_info CK_خانہ_INFO_2;
قسمتعریف ساخت ck_خانہ_info *CK_خانہ_INFO_PTR;

قسمتعریف ساخت ck_token_info CK_TOKEN_INFO;
قسمتعریف ساخت ck_token_info *CK_TOKEN_INFO_PTR;

قسمتعریف ck_session_handle_t *CK_SESSION_HANDLE_PTR;

قسمتعریف ساخت ck_session_info CK_SESSION_INFO;
قسمتعریف ساخت ck_session_info *CK_SESSION_INFO_PTR;

قسمتعریف ck_object_handle_t *CK_OBJECT_HANDLE_PTR;

قسمتعریف ck_object_class_t *CK_OBJECT_CLASS_PTR;

قسمتعریف ساخت ck_attribute CK_ATTRIBUTE;
قسمتعریف ساخت ck_attribute *CK_ATTRIBUTE_PTR;

قسمتعریف ساخت ck_date CK_DATE;
قسمتعریف ساخت ck_date *CK_DATE_PTR;

قسمتعریف ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;

قسمتعریف ck_rsa_pkcs_mgf_type_t *CK_RSA_PKCS_MGF_TYPE_PTR;

قسمتعریف ساخت ck_mechanism CK_MECHANISM;
قسمتعریف ساخت ck_mechanism *CK_MECHANISM_PTR;

قسمتعریف ساخت ck_mechanism_info CK_MECHANISM_INFO;
قسمتعریف ساخت ck_mechanism_info *CK_MECHANISM_INFO_PTR;

قسمتعریف ساخت ck_interface CK_INTERFACE;
قسمتعریف ساخت ck_interface *CK_INTERFACE_PTR;
قسمتعریف ساخت ck_interface **CK_INTERFACE_PTR_PTR;

قسمتعریف ساخت ck_function_list CK_FUNCTION_LIST;
قسمتعریف ساخت ck_function_list *CK_FUNCTION_LIST_PTR;
قسمتعریف ساخت ck_function_list **CK_FUNCTION_LIST_PTR_PTR;

قسمتعریف ساخت ck_function_list_3_0 CK_FUNCTION_LIST_3_0;
قسمتعریف ساخت ck_function_list_3_0 *CK_FUNCTION_LIST_3_0_PTR;
قسمتعریف ساخت ck_function_list_3_0 **CK_FUNCTION_LIST_3_0_PTR_PTR;

قسمتعریف ساخت ck_c_initialize_دلائل CK_C_INITIALIZE_دلائل_2;
قسمتعریف ساخت ck_c_initialize_دلائل *CK_C_INITIALIZE_دلائل_PTR;

#تعریف_کرو NULL_PTR تہی

/* Delete the helper macros defined at the top of the file.  */
#تعریف_منسوخ ck_flags_t
#تعریف_منسوخ ck_نسخہ

#تعریف_منسوخ ck_info
#تعریف_منسوخ cryptoki_نسخہ
#تعریف_منسوخ manufacturer_id
#تعریف_منسوخ library_description
#تعریف_منسوخ library_نسخہ

#تعریف_منسوخ ck_notification_t
#تعریف_منسوخ ck_خانہ_id_t

#تعریف_منسوخ ck_خانہ_info
#تعریف_منسوخ خانہ_description
#تعریف_منسوخ hardware_نسخہ
#تعریف_منسوخ firmware_نسخہ

#تعریف_منسوخ ck_token_info
#تعریف_منسوخ serial_نمبر
#تعریف_منسوخ max_session_گنتی
#تعریف_منسوخ session_گنتی
#تعریف_منسوخ max_rw_session_گنتی
#تعریف_منسوخ rw_session_گنتی
#تعریف_منسوخ max_pin_len
#تعریف_منسوخ min_pin_len
#تعریف_منسوخ کل_عوامی_حافظہ
#تعریف_منسوخ free_عوامی_حافظہ
#تعریف_منسوخ کل_نجی_حافظہ
#تعریف_منسوخ free_نجی_حافظہ
#تعریف_منسوخ utc_وقت

#تعریف_منسوخ ck_session_handle_t
#تعریف_منسوخ ck_user_type_t
#تعریف_منسوخ ck_state_t

#تعریف_منسوخ ck_session_info
#تعریف_منسوخ خانہ_id
#تعریف_منسوخ device_error

#تعریف_منسوخ ck_object_handle_t
#تعریف_منسوخ ck_object_class_t
#تعریف_منسوخ ck_hw_feature_type_t
#تعریف_منسوخ ck_کلید_type_t
#تعریف_منسوخ ck_certificate_type_t
#تعریف_منسوخ ck_attribute_type_t

#تعریف_منسوخ ck_attribute
#تعریف_منسوخ قدر
#تعریف_منسوخ قدر_len

#تعریف_منسوخ ck_date

#تعریف_منسوخ ck_mechanism_type_t

#تعریف_منسوخ ck_rsa_pkcs_mgf_type_t

#تعریف_منسوخ ck_mechanism
#تعریف_منسوخ parameter
#تعریف_منسوخ parameter_len

#تعریف_منسوخ ck_mechanism_info
#تعریف_منسوخ min_کلید_سائز
#تعریف_منسوخ max_کلید_سائز

#تعریف_منسوخ ck_rv_t
#تعریف_منسوخ ck_notify_t

#تعریف_منسوخ ck_interface

#تعریف_منسوخ ck_function_list
#تعریف_منسوخ ck_function_list_3_0

#تعریف_منسوخ ck_createmutex_t
#تعریف_منسوخ ck_destroymutex_t
#تعریف_منسوخ ck_lockmutex_t
#تعریف_منسوخ ck_unlockmutex_t

#تعریف_منسوخ ck_c_initialize_دلائل
#تعریف_منسوخ create_mutex
#تعریف_منسوخ destroy_mutex
#تعریف_منسوخ تالا_mutex
#تعریف_منسوخ unlock_mutex
#تعریف_منسوخ reserved

#اگر_ختم	/* CRYPTOKI_COMPAT */

/* System dependencies.  */
#اگر defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#ہدایت pack(نکالو, cryptoki)
#اگر_ختم

#اگر defined(__cplusplus)
}
#اگر_ختم

#اگر_ختم	/* PKCS11_H */
