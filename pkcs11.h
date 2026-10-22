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

#اگر_تعریف_نشده PKCS11_H
#تعریف_کن PKCS11_H 1

#إذا defined(__cplusplus)
خارجي "C" {
#پایان_اگر


/* The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  */
#تعریف_کن CRYPTOKI_نسخه_MAJOR		3
#تعریف_کن CRYPTOKI_نسخه_MINOR		0
#تعریف_کن CRYPTOKI_نسخه_REVISION	0


/* Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  */
#اگر_تعریف_نشده CRYPTOKI_GNU
#اگر_تعریف_نشده CRYPTOKI_COMPAT
#تعریف_کن CRYPTOKI_COMPAT 1
#پایان_اگر
#پایان_اگر

/* System dependencies.  */

#إذا defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#رهنمود pack(افزودن, cryptoki, 1)

#اگر_تعریف_شده CRYPTOKI_EXPORTS
#تعریف_کن CK_SPEC __declspec(dllexport)
#وإلا
#تعریف_کن CK_SPEC __declspec(dllimport)
#پایان_اگر

#وإلا

#تعریف_کن CK_SPEC

#پایان_اگر

#اگر_تعریف_شده CRYPTOKI_COMPAT
  /* If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  */

#تعریف_کن ck_flags_t CK_FLAGS
#تعریف_کن ck_نسخه CK_نسخه

#تعریف_کن ck_info _CK_INFO
#تعریف_کن cryptoki_نسخه cryptoki_نسخه_2
#تعریف_کن manufacturer_id manufacturerID
#تعریف_کن library_description libraryDescription
#تعریف_کن library_نسخه library_نسخه_2

#تعریف_کن ck_notification_t CK_NOTIFICATION
#تعریف_کن ck_جایگاه_id_t CK_جایگاه_ID

#تعریف_کن ck_جایگاه_info CK_جایگاه_INFO
#تعریف_کن جایگاه_description جایگاه_Description
#تعریف_کن hardware_نسخه hardware_نسخه_2
#تعریف_کن firmware_نسخه firmware_نسخه_2

#تعریف_کن ck_token_info _CK_TOKEN_INFO
#تعریف_کن serial_عدد serial_عدد_2
#تعریف_کن max_session_شمار ul_Max_Session_شمار
#تعریف_کن session_شمار ul_Session_شمار
#تعریف_کن max_rw_session_شمار ul_Max_Rw_Session_شمار
#تعریف_کن rw_session_شمار ul_Rw_Session_شمار
#تعریف_کن max_pin_len ulMaxPinLen
#تعریف_کن min_pin_len ulMinPinLen
#تعریف_کن مجموع_عمومی_حافظه ul_مجموع_عمومی_حافظه
#تعریف_کن free_عمومی_حافظه ul_Free_عمومی_حافظه
#تعریف_کن مجموع_خصوصی_حافظه ul_مجموع_خصوصی_حافظه
#تعریف_کن free_خصوصی_حافظه ul_Free_خصوصی_حافظه
#تعریف_کن utc_زمان utc_زمان_2

#تعریف_کن ck_session_handle_t CK_SESSION_HANDLE
#تعریف_کن ck_user_type_t CK_USER_TYPE
#تعریف_کن ck_state_t CK_STATE

#تعریف_کن ck_session_info _CK_SESSION_INFO
#تعریف_کن جایگاه_id جایگاه_ID
#تعریف_کن device_error ulDeviceError

#تعریف_کن ck_object_handle_t CK_OBJECT_HANDLE
#تعریف_کن ck_object_class_t CK_OBJECT_CLASS
#تعریف_کن ck_hw_feature_type_t CK_HW_FEATURE_TYPE
#تعریف_کن ck_کلید_type_t CK_کلید_TYPE
#تعریف_کن ck_certificate_type_t CK_CERTIFICATE_TYPE
#تعریف_کن ck_attribute_type_t CK_ATTRIBUTE_TYPE

#تعریف_کن ck_attribute _CK_ATTRIBUTE
#تعریف_کن مقدار p_مقدار
#تعریف_کن مقدار_len ul_مقدار_Len

#تعریف_کن ck_date _CK_DATE

#تعریف_کن ck_mechanism_type_t CK_MECHANISM_TYPE

#تعریف_کن ck_rsa_pkcs_mgf_type_t CK_RSA_PKCS_MGF_TYPE

#تعریف_کن ck_mechanism _CK_MECHANISM
#تعریف_کن parameter pParameter
#تعریف_کن parameter_len ulParameterLen

#تعریف_کن ck_mechanism_info _CK_MECHANISM_INFO
#تعریف_کن min_کلید_اندازه ul_Min_کلید_اندازه
#تعریف_کن max_کلید_اندازه ul_Max_کلید_اندازه

#تعریف_کن ck_rv_t CK_RV
#تعریف_کن ck_notify_t CK_NOTIFY

#تعریف_کن ck_interface CK_INTERFACE

#تعریف_کن ck_function_list _CK_FUNCTION_LIST
#تعریف_کن ck_function_list_3_0 _CK_FUNCTION_LIST_3_0

#تعریف_کن ck_createmutex_t CK_CREATEMUTEX
#تعریف_کن ck_destroymutex_t CK_DESTROYMUTEX
#تعریف_کن ck_lockmutex_t CK_LOCKMUTEX
#تعریف_کن ck_unlockmutex_t CK_UNLOCKMUTEX

#تعریف_کن ck_c_initialize_آرگومانها CK_C_INITIALIZE_آرگومانها
#تعریف_کن create_mutex CreateMutex
#تعریف_کن destroy_mutex DestroyMutex
#تعریف_کن قفل_mutex قفل_Mutex
#تعریف_کن unlock_mutex UnlockMutex
#تعریف_کن reserved pReserved

#پایان_اگر	/* CRYPTOKI_COMPAT */


تعريفنوع بیعلامت دراز ck_flags_t;

بنية ck_نسخه
{
  بیعلامت حرف major;
  بیعلامت حرف minor;
};


بنية ck_info
{
  بنية ck_نسخه cryptoki_نسخه;
  بیعلامت حرف manufacturer_id[32];
  ck_flags_t flags;
  بیعلامت حرف library_description[32];
  بنية ck_نسخه library_نسخه;
};


تعريفنوع بیعلامت دراز ck_notification_t;

#تعریف_کن CKN_SURRENDER	(0UL)


تعريفنوع بیعلامت دراز ck_جایگاه_id_t;


بنية ck_جایگاه_info
{
  بیعلامت حرف جایگاه_description[64];
  بیعلامت حرف manufacturer_id[32];
  ck_flags_t flags;
  بنية ck_نسخه hardware_نسخه;
  بنية ck_نسخه firmware_نسخه;
};


#تعریف_کن CKF_TOKEN_PRESENT	(1UL << 0)
#تعریف_کن CKF_REMOVABLE_DEVICE	(1UL << 1)
#تعریف_کن CKF_HW_جایگاه		(1UL << 2)
#تعریف_کن CKF_ARRAY_ATTRIBUTE	(1UL << 30)


بنية ck_token_info
{
  بیعلامت حرف label[32];
  بیعلامت حرف manufacturer_id[32];
  بیعلامت حرف model[16];
  بیعلامت حرف serial_عدد[16];
  ck_flags_t flags;
  بیعلامت دراز max_session_شمار;
  بیعلامت دراز session_شمار;
  بیعلامت دراز max_rw_session_شمار;
  بیعلامت دراز rw_session_شمار;
  بیعلامت دراز max_pin_len;
  بیعلامت دراز min_pin_len;
  بیعلامت دراز مجموع_عمومی_حافظه;
  بیعلامت دراز free_عمومی_حافظه;
  بیعلامت دراز مجموع_خصوصی_حافظه;
  بیعلامت دراز free_خصوصی_حافظه;
  بنية ck_نسخه hardware_نسخه;
  بنية ck_نسخه firmware_نسخه;
  بیعلامت حرف utc_زمان[16];
};


#تعریف_کن CKF_RNG					(1UL << 0)
#تعریف_کن CKF_WRITE_PROTECTED			(1UL << 1)
#تعریف_کن CKF_LOGIN_REQUIRED			(1UL << 2)
#تعریف_کن CKF_USER_PIN_INITIALIZED		(1UL << 3)
#تعریف_کن CKF_RESTORE_کلید_NOT_NEEDED		(1UL << 5)
#تعریف_کن CKF_CLOCK_ON_TOKEN			(1UL << 6)
#تعریف_کن CKF_PROTECTED_AUTHENTICATION_مسیر	(1UL << 8)
#تعریف_کن CKF_DUAL_CRYPTO_OPERATIONS		(1UL << 9)
#تعریف_کن CKF_TOKEN_INITIALIZED			(1UL << 10)
#تعریف_کن CKF_SECONDARY_AUTHENTICATION		(1UL << 11)
#تعریف_کن CKF_USER_PIN_شمار_کم			(1UL << 16)
#تعریف_کن CKF_USER_PIN_FINAL_TRY			(1UL << 17)
#تعریف_کن CKF_USER_PIN_LOCKED			(1UL << 18)
#تعریف_کن CKF_USER_PIN_مقصد_BE_تغییریافته		(1UL << 19)
#تعریف_کن CKF_SO_PIN_شمار_کم			(1UL << 20)
#تعریف_کن CKF_SO_PIN_FINAL_TRY			(1UL << 21)
#تعریف_کن CKF_SO_PIN_LOCKED			(1UL << 22)
#تعریف_کن CKF_SO_PIN_مقصد_BE_تغییریافته		(1UL << 23)

#تعریف_کن CK_UNAVAILABLE_INFORMATION	((بیعلامت دراز) -1)
#تعریف_کن CK_EFFECTIVELY_INFINITE		(0UL)


تعريفنوع بیعلامت دراز ck_session_handle_t;

#تعریف_کن CK_INVALID_HANDLE	(0UL)


تعريفنوع بیعلامت دراز ck_user_type_t;

#تعریف_کن CKU_SO			(0UL)
#تعریف_کن CKU_USER		(1UL)
#تعریف_کن CKU_CONTEXT_SPECIFIC	(2UL)


تعريفنوع بیعلامت دراز ck_state_t;

#تعریف_کن CKS_RO_عمومی_SESSION	(0UL)
#تعریف_کن CKS_RO_USER_FUNCTIONS	(1UL)
#تعریف_کن CKS_RW_عمومی_SESSION	(2UL)
#تعریف_کن CKS_RW_USER_FUNCTIONS	(3UL)
#تعریف_کن CKS_RW_SO_FUNCTIONS	(4UL)


بنية ck_session_info
{
  ck_جایگاه_id_t جایگاه_id;
  ck_state_t state;
  ck_flags_t flags;
  بیعلامت دراز device_error;
};

#تعریف_کن CKF_RW_SESSION		(1UL << 1)
#تعریف_کن CKF_SERIAL_SESSION	(1UL << 2)


تعريفنوع بیعلامت دراز ck_object_handle_t;


تعريفنوع بیعلامت دراز ck_object_class_t;

#تعریف_کن CKO_داده		(0UL)
#تعریف_کن CKO_CERTIFICATE		(1UL)
#تعریف_کن CKO_عمومی_کلید		(2UL)
#تعریف_کن CKO_خصوصی_کلید		(3UL)
#تعریف_کن CKO_SECRET_کلید		(4UL)
#تعریف_کن CKO_HW_FEATURE		(5UL)
#تعریف_کن CKO_DOMAIN_PARAMETERS	(6UL)
#تعریف_کن CKO_MECHANISM		(7UL)
#تعریف_کن CKO_OTP_کلید		(8UL)
#تعریف_کن CKO_PROFILE		(9UL)
#تعریف_کن CKO_VENDOR_DEFINED	(1UL << 31)

#تعریف_کن CKP_INVALID_ID                (0UL)
#تعریف_کن CKP_BASELINE_PROVIDER         (1UL)
#تعریف_کن CKP_EXTENDED_PROVIDER         (2UL)
#تعریف_کن CKP_AUTHENTICATION_TOKEN      (3UL)
#تعریف_کن CKP_عمومی_CERTIFICATES_TOKEN (4UL)
#تعریف_کن CKP_VENDOR_DEFINED            (1UL << 31)

تعريفنوع بیعلامت دراز ck_hw_feature_type_t;

#تعریف_کن CKH_MONOTONIC_COUNTER	(1UL)
#تعریف_کن CKH_CLOCK		(2UL)
#تعریف_کن CKH_USER_INTERFACE	(3UL)
#تعریف_کن CKH_VENDOR_DEFINED	(1UL << 31)


تعريفنوع بیعلامت دراز ck_کلید_type_t;

#تعریف_کن CKK_RSA			(0UL)
#تعریف_کن CKK_DSA			(1UL)
#تعریف_کن CKK_DH			(2UL)
#تعریف_کن CKK_ECDSA		(3UL)
#تعریف_کن CKK_EC			(3UL)
#تعریف_کن CKK_X9_42_DH		(4UL)
#تعریف_کن CKK_KEA			(5UL)
#تعریف_کن CKK_GENERIC_SECRET	(0x10UL)
#تعریف_کن CKK_RC2			(0x11UL)
#تعریف_کن CKK_RC4			(0x12UL)
#تعریف_کن CKK_DES			(0x13UL)
#تعریف_کن CKK_DES2		(0x14UL)
#تعریف_کن CKK_DES3		(0x15UL)
#تعریف_کن CKK_CAST		(0x16UL)
#تعریف_کن CKK_CAST3		(0x17UL)
#تعریف_کن CKK_CAST128		(0x18UL)
#تعریف_کن CKK_RC5			(0x19UL)
#تعریف_کن CKK_IDEA		(0x1aUL)
#تعریف_کن CKK_SKIPJACK		(0x1bUL)
#تعریف_کن CKK_BATON		(0x1cUL)
#تعریف_کن CKK_JUNIPER		(0x1dUL)
#تعریف_کن CKK_CDMF		(0x1eUL)
#تعریف_کن CKK_AES			(0x1fUL)
#تعریف_کن CKK_BLOWFISH		(0x20UL)
#تعریف_کن CKK_TWOFISH		(0x21UL)
#تعریف_کن CKK_GOSTR3410		(0x30UL)
#تعریف_کن CKK_GOSTR3411		(0x31UL)
#تعریف_کن CKK_GOST28147		(0x32UL)
#تعریف_کن CKK_EC_EDWARDS		(0x40UL)
#تعریف_کن CKK_EC_MONTGOMERY	(0x41UL)
#تعریف_کن CKK_HKDF		(0x42UL)
#تعریف_کن CKK_VENDOR_DEFINED	(1UL << 31)

/*
 * A mask for new GOST algorithms.
 * For details visit https://tc26.ru/standarts/perevody/guidelines-the-pkcs-11-extensions-for-implementing-the-gost-r-34-10-2012-and-gost-r-34-11-2012-russian-standards-.html
 */
#تعریف_کن NSSCK_VENDOR_PKCS11_RU_TEAM     (CKK_VENDOR_DEFINED | 0x54321000)
#تعریف_کن CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

#تعریف_کن CKK_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

تعريفنوع بیعلامت دراز ck_certificate_type_t;

#تعریف_کن CKC_X_509		(0UL)
#تعریف_کن CKC_X_509_ATTR_CERT	(1UL)
#تعریف_کن CKC_WTLS		(2UL)
#تعریف_کن CKC_VENDOR_DEFINED	(1UL << 31)


تعريفنوع بیعلامت دراز ck_attribute_type_t;

#تعریف_کن CKA_CLASS			(0UL)
#تعریف_کن CKA_TOKEN			(1UL)
#تعریف_کن CKA_خصوصی			(2UL)
#تعریف_کن CKA_LABEL			(3UL)
#تعریف_کن CKA_UNIQUE_ID		(4UL)
#تعریف_کن CKA_APPLICATION			(0x10UL)
#تعریف_کن CKA_مقدار			(0x11UL)
#تعریف_کن CKA_OBJECT_ID			(0x12UL)
#تعریف_کن CKA_CERTIFICATE_TYPE		(0x80UL)
#تعریف_کن CKA_ISSUER			(0x81UL)
#تعریف_کن CKA_SERIAL_عدد		(0x82UL)
#تعریف_کن CKA_AC_ISSUER			(0x83UL)
#تعریف_کن CKA_OWNER			(0x84UL)
#تعریف_کن CKA_ATTR_TYPES			(0x85UL)
#تعریف_کن CKA_TRUSTED			(0x86UL)
#تعریف_کن CKA_CERTIFICATE_CATEGORY	(0x87UL)
#تعریف_کن CKA_JAVA_MIDP_SECURITY_DOMAIN	(0x88UL)
#تعریف_کن CKA_URL				(0x89UL)
#تعریف_کن CKA_HASH_از_SUBJECT_عمومی_کلید	(0x8aUL)
#تعریف_کن CKA_HASH_از_ISSUER_عمومی_کلید	(0x8bUL)
#تعریف_کن CKA_CHECK_مقدار			(0x90UL)
#تعریف_کن CKA_کلید_TYPE			(0x100UL)
#تعریف_کن CKA_SUBJECT			(0x101UL)
#تعریف_کن CKA_ID				(0x102UL)
#تعریف_کن CKA_SENSITIVE			(0x103UL)
#تعریف_کن CKA_ENCRYPT			(0x104UL)
#تعریف_کن CKA_DECRYPT			(0x105UL)
#تعریف_کن CKA_WRAP			(0x106UL)
#تعریف_کن CKA_UNWRAP			(0x107UL)
#تعریف_کن CKA_SIGN			(0x108UL)
#تعریف_کن CKA_SIGN_RECOVER		(0x109UL)
#تعریف_کن CKA_VERIFY			(0x10aUL)
#تعریف_کن CKA_VERIFY_RECOVER		(0x10bUL)
#تعریف_کن CKA_DERIVE			(0x10cUL)
#تعریف_کن CKA_شروع_DATE			(0x110UL)
#تعریف_کن CKA_انتها_DATE			(0x111UL)
#تعریف_کن CKA_MODULUS			(0x120UL)
#تعریف_کن CKA_MODULUS_بیتها		(0x121UL)
#تعریف_کن CKA_عمومی_EXPONENT		(0x122UL)
#تعریف_کن CKA_خصوصی_EXPONENT		(0x123UL)
#تعریف_کن CKA_اول_1			(0x124UL)
#تعریف_کن CKA_اول_2			(0x125UL)
#تعریف_کن CKA_EXPONENT_1			(0x126UL)
#تعریف_کن CKA_EXPONENT_2			(0x127UL)
#تعریف_کن CKA_COEFFICIENT			(0x128UL)
#تعریف_کن CKA_عمومی_کلید_INFO		(0x129UL)
#تعریف_کن CKA_اول			(0x130UL)
#تعریف_کن CKA_SUBPRIME			(0x131UL)
#تعریف_کن CKA_پایه			(0x132UL)
#تعریف_کن CKA_اول_بیتها			(0x133UL)
#تعریف_کن CKA_SUB_اول_بیتها		(0x134UL)
#تعریف_کن CKA_مقدار_بیتها			(0x160UL)
#تعریف_کن CKA_مقدار_LEN			(0x161UL)
#تعریف_کن CKA_EXTRACTABLE			(0x162UL)
#تعریف_کن CKA_LOCAL			(0x163UL)
#تعریف_کن CKA_NEVER_EXTRACTABLE		(0x164UL)
#تعریف_کن CKA_ALWAYS_SENSITIVE		(0x165UL)
#تعریف_کن CKA_کلید_GEN_MECHANISM		(0x166UL)
#تعریف_کن CKA_MODIFIABLE			(0x170UL)
#تعریف_کن CKA_COPYABLE			(0x171UL)
#تعریف_کن CKA_DESTROYABLE			(0x172UL)
#تعریف_کن CKA_ECDSA_PARAMS		(0x180UL)
#تعریف_کن CKA_EC_PARAMS			(0x180UL)
#تعریف_کن CKA_EC_نقطه			(0x181UL)
#تعریف_کن CKA_SECONDARY_AUTH		(0x200UL)
#تعریف_کن CKA_AUTH_PIN_FLAGS		(0x201UL)
#تعریف_کن CKA_ALWAYS_AUTHENTICATE		(0x202UL)
#تعریف_کن CKA_WRAP_WITH_TRUSTED		(0x210UL)
#تعریف_کن CKA_GOSTR3410_PARAMS		(0x250UL)
#تعریف_کن CKA_GOSTR3411_PARAMS		(0x251UL)
#تعریف_کن CKA_GOST28147_PARAMS		(0x252UL)
#تعریف_کن CKA_HW_FEATURE_TYPE		(0x300UL)
#تعریف_کن CKA_RESET_ON_INIT		(0x301UL)
#تعریف_کن CKA_HAS_RESET			(0x302UL)
#تعریف_کن CKA_PIXEL_X			(0x400UL)
#تعریف_کن CKA_PIXEL_Y			(0x401UL)
#تعریف_کن CKA_RESOLUTION			(0x402UL)
#تعریف_کن CKA_CHAR_ردیفها			(0x403UL)
#تعریف_کن CKA_CHAR_COLUMNS		(0x404UL)
#تعریف_کن CKA_COLOR			(0x405UL)
#تعریف_کن CKA_بیتها_در_هر_PIXEL		(0x406UL)
#تعریف_کن CKA_CHAR_SETS			(0x480UL)
#تعریف_کن CKA_ENCODING_METHODS		(0x481UL)
#تعریف_کن CKA_MIME_TYPES			(0x482UL)
#تعریف_کن CKA_MECHANISM_TYPE		(0x500UL)
#تعریف_کن CKA_REQUIRED_CMS_صفات	(0x501UL)
#تعریف_کن CKA_DEFAULT_CMS_صفات	(0x502UL)
#تعریف_کن CKA_SUPPORTED_CMS_صفات	(0x503UL)
#تعریف_کن CKA_WRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x211UL)
#تعریف_کن CKA_UNWRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x212UL)
#تعریف_کن CKA_OTP_FORMAT			(0x220UL)
#تعریف_کن CKA_OTP_درازی			(0x221UL)
#تعریف_کن CKA_OTP_زمان_INTERVAL		(0x222UL)
#تعریف_کن CKA_OTP_USER_FRIENDLY_نما	(0x223UL)
#تعریف_کن CKA_OTP_CHALLENGE_REQUIREMENT	(0x224UL)
#تعریف_کن CKA_OTP_زمان_REQUIREMENT	(0x225UL)
#تعریف_کن CKA_OTP_COUNTER_REQUIREMENT	(0x226UL)
#تعریف_کن CKA_OTP_PIN_REQUIREMENT		(0x227UL)
#تعریف_کن CKA_OTP_USER_IDENTIFIER		(0x22AUL)
#تعریف_کن CKA_OTP_SERVICE_IDENTIFIER	(0x22BUL)
#تعریف_کن CKA_OTP_SERVICE_LOGO		(0x22CUL)
#تعریف_کن CKA_OTP_SERVICE_LOGO_TYPE	(0x22DUL)
#تعریف_کن CKA_OTP_COUNTER			(0x22EUL)
#تعریف_کن CKA_OTP_زمان			(0x22FUL)
#تعریف_کن CKA_ALLOWED_MECHANISMS		(CKF_ARRAY_ATTRIBUTE | 0x600UL)
#تعریف_کن CKA_PROFILE_ID			(0x601UL)
#تعریف_کن CKA_VENDOR_DEFINED		(1UL << 31)


بنية ck_attribute
{
  ck_attribute_type_t type;
  فراغ *مقدار;
  بیعلامت دراز مقدار_len;
};


بنية ck_date
{
  بیعلامت حرف year[4];
  بیعلامت حرف month[2];
  بیعلامت حرف day[2];
};


تعريفنوع بیعلامت دراز ck_mechanism_type_t;

#تعریف_کن CKM_RSA_PKCS_کلید_PAIR_GEN	(0UL)
#تعریف_کن CKM_RSA_PKCS			(1UL)
#تعریف_کن CKM_RSA_9796			(2UL)
#تعریف_کن CKM_RSA_X_509			(3UL)
#تعریف_کن CKM_MD2_RSA_PKCS		(4UL)
#تعریف_کن CKM_MD5_RSA_PKCS		(5UL)
#تعریف_کن CKM_SHA1_RSA_PKCS		(6UL)
#تعریف_کن CKM_RIPEMD128_RSA_PKCS		(7UL)
#تعریف_کن CKM_RIPEMD160_RSA_PKCS		(8UL)
#تعریف_کن CKM_RSA_PKCS_OAEP		(9UL)
#تعریف_کن CKM_RSA_X9_31_کلید_PAIR_GEN	(0xaUL)
#تعریف_کن CKM_RSA_X9_31			(0xbUL)
#تعریف_کن CKM_SHA1_RSA_X9_31		(0xcUL)
#تعریف_کن CKM_RSA_PKCS_PSS		(0xdUL)
#تعریف_کن CKM_SHA1_RSA_PKCS_PSS		(0xeUL)
#تعریف_کن CKM_DSA_کلید_PAIR_GEN		(0x10UL)
#تعریف_کن	CKM_DSA				(0x11UL)
#تعریف_کن CKM_DSA_SHA1			(0x12UL)
#تعریف_کن CKM_DSA_SHA224			(0x13UL)
#تعریف_کن CKM_DSA_SHA256			(0x14UL)
#تعریف_کن CKM_DSA_SHA384			(0x15UL)
#تعریف_کن CKM_DSA_SHA512			(0x16UL)
#تعریف_کن CKM_DH_PKCS_کلید_PAIR_GEN	(0x20UL)
#تعریف_کن CKM_DH_PKCS_DERIVE		(0x21UL)
#تعریف_کن	CKM_X9_42_DH_کلید_PAIR_GEN	(0x30UL)
#تعریف_کن CKM_X9_42_DH_DERIVE		(0x31UL)
#تعریف_کن CKM_X9_42_DH_HYBRID_DERIVE	(0x32UL)
#تعریف_کن CKM_X9_42_MQV_DERIVE		(0x33UL)
#تعریف_کن CKM_SHA256_RSA_PKCS		(0x40UL)
#تعریف_کن CKM_SHA384_RSA_PKCS		(0x41UL)
#تعریف_کن CKM_SHA512_RSA_PKCS		(0x42UL)
#تعریف_کن CKM_SHA256_RSA_PKCS_PSS		(0x43UL)
#تعریف_کن CKM_SHA384_RSA_PKCS_PSS		(0x44UL)
#تعریف_کن CKM_SHA512_RSA_PKCS_PSS		(0x45UL)
#تعریف_کن CKM_SHA224_RSA_PKCS		(0x46UL)
#تعریف_کن CKM_SHA224_RSA_PKCS_PSS		(0x47UL)
#تعریف_کن CKM_SHA3_256_RSA_PKCS		(0x60UL)
#تعریف_کن CKM_SHA3_384_RSA_PKCS		(0x61UL)
#تعریف_کن CKM_SHA3_512_RSA_PKCS		(0x62UL)
#تعریف_کن CKM_SHA3_256_RSA_PKCS_PSS	(0x63UL)
#تعریف_کن CKM_SHA3_384_RSA_PKCS_PSS	(0x64UL)
#تعریف_کن CKM_SHA3_512_RSA_PKCS_PSS	(0x65UL)
#تعریف_کن CKM_SHA3_224_RSA_PKCS		(0x66UL)
#تعریف_کن CKM_SHA3_224_RSA_PKCS_PSS	(0x67UL)
#تعریف_کن CKM_RC2_کلید_GEN			(0x100UL)
#تعریف_کن CKM_RC2_ECB			(0x101UL)
#تعریف_کن	CKM_RC2_CBC			(0x102UL)
#تعریف_کن	CKM_RC2_MAC			(0x103UL)
#تعریف_کن CKM_RC2_MAC_GENERAL		(0x104UL)
#تعریف_کن CKM_RC2_CBC_PAD			(0x105UL)
#تعریف_کن CKM_RC4_کلید_GEN			(0x110UL)
#تعریف_کن CKM_RC4				(0x111UL)
#تعریف_کن CKM_DES_کلید_GEN			(0x120UL)
#تعریف_کن CKM_DES_ECB			(0x121UL)
#تعریف_کن CKM_DES_CBC			(0x122UL)
#تعریف_کن CKM_DES_MAC			(0x123UL)
#تعریف_کن CKM_DES_MAC_GENERAL		(0x124UL)
#تعریف_کن CKM_DES_CBC_PAD			(0x125UL)
#تعریف_کن CKM_DES2_کلید_GEN		(0x130UL)
#تعریف_کن CKM_DES3_کلید_GEN		(0x131UL)
#تعریف_کن CKM_DES3_ECB			(0x132UL)
#تعریف_کن CKM_DES3_CBC			(0x133UL)
#تعریف_کن CKM_DES3_MAC			(0x134UL)
#تعریف_کن CKM_DES3_MAC_GENERAL		(0x135UL)
#تعریف_کن CKM_DES3_CBC_PAD		(0x136UL)
#تعریف_کن CKM_DES3_CMAC_GENERAL		(0x137UL)
#تعریف_کن CKM_DES3_CMAC			(0x138UL)
#تعریف_کن CKM_CDMF_کلید_GEN		(0x140UL)
#تعریف_کن CKM_CDMF_ECB			(0x141UL)
#تعریف_کن CKM_CDMF_CBC			(0x142UL)
#تعریف_کن CKM_CDMF_MAC			(0x143UL)
#تعریف_کن CKM_CDMF_MAC_GENERAL		(0x144UL)
#تعریف_کن CKM_CDMF_CBC_PAD		(0x145UL)
#تعریف_کن CKM_MD2				(0x200UL)
#تعریف_کن CKM_MD2_HMAC			(0x201UL)
#تعریف_کن CKM_MD2_HMAC_GENERAL		(0x202UL)
#تعریف_کن CKM_MD5				(0x210UL)
#تعریف_کن CKM_MD5_HMAC			(0x211UL)
#تعریف_کن CKM_MD5_HMAC_GENERAL		(0x212UL)
#تعریف_کن CKM_SHA_1			(0x220UL)
#تعریف_کن CKM_SHA_1_HMAC			(0x221UL)
#تعریف_کن CKM_SHA_1_HMAC_GENERAL		(0x222UL)
#تعریف_کن CKM_RIPEMD128			(0x230UL)
#تعریف_کن CKM_RIPEMD128_HMAC		(0x231UL)
#تعریف_کن CKM_RIPEMD128_HMAC_GENERAL	(0x232UL)
#تعریف_کن CKM_RIPEMD160			(0x240UL)
#تعریف_کن CKM_RIPEMD160_HMAC		(0x241UL)
#تعریف_کن CKM_RIPEMD160_HMAC_GENERAL	(0x242UL)
#تعریف_کن CKM_SHA256			(0x250UL)
#تعریف_کن CKM_SHA256_HMAC			(0x251UL)
#تعریف_کن CKM_SHA256_HMAC_GENERAL		(0x252UL)
#تعریف_کن CKM_SHA224			(0x255UL)
#تعریف_کن CKM_SHA224_HMAC			(0x256UL)
#تعریف_کن CKM_SHA224_HMAC_GENERAL		(0x257UL)
#تعریف_کن CKM_SHA384			(0x260UL)
#تعریف_کن CKM_SHA384_HMAC			(0x261UL)
#تعریف_کن CKM_SHA384_HMAC_GENERAL		(0x262UL)
#تعریف_کن CKM_SHA512			(0x270UL)
#تعریف_کن CKM_SHA512_HMAC			(0x271UL)
#تعریف_کن CKM_SHA512_HMAC_GENERAL		(0x272UL)
#تعریف_کن CKM_SHA3_256			(0x2B0UL)
#تعریف_کن CKM_SHA3_256_HMAC		(0x2B1UL)
#تعریف_کن CKM_SHA3_256_HMAC_GENERAL	(0x2B2UL)
#تعریف_کن CKM_SHA3_256_کلید_GEN		(0x2B3UL)
#تعریف_کن CKM_SHA3_224			(0x2B5UL)
#تعریف_کن CKM_SHA3_224_HMAC		(0x2B6UL)
#تعریف_کن CKM_SHA3_224_HMAC_GENERAL	(0x2B7UL)
#تعریف_کن CKM_SHA3_224_کلید_GEN		(0x2B8UL)
#تعریف_کن CKM_SHA3_384			(0x2C0UL)
#تعریف_کن CKM_SHA3_384_HMAC		(0x2C1UL)
#تعریف_کن CKM_SHA3_384_HMAC_GENERAL	(0x2C2UL)
#تعریف_کن CKM_SHA3_384_کلید_GEN		(0x2C3UL)
#تعریف_کن CKM_SHA3_512			(0x2D0UL)
#تعریف_کن CKM_SHA3_512_HMAC		(0x2D1UL)
#تعریف_کن CKM_SHA3_512_HMAC_GENERAL	(0x2D2UL)
#تعریف_کن CKM_SHA3_512_کلید_GEN		(0x2D3UL)
#تعریف_کن CKM_CAST_کلید_GEN		(0x300UL)
#تعریف_کن CKM_CAST_ECB			(0x301UL)
#تعریف_کن CKM_CAST_CBC			(0x302UL)
#تعریف_کن CKM_CAST_MAC			(0x303UL)
#تعریف_کن CKM_CAST_MAC_GENERAL		(0x304UL)
#تعریف_کن CKM_CAST_CBC_PAD		(0x305UL)
#تعریف_کن CKM_CAST3_کلید_GEN		(0x310UL)
#تعریف_کن CKM_CAST3_ECB			(0x311UL)
#تعریف_کن CKM_CAST3_CBC			(0x312UL)
#تعریف_کن CKM_CAST3_MAC			(0x313UL)
#تعریف_کن CKM_CAST3_MAC_GENERAL		(0x314UL)
#تعریف_کن CKM_CAST3_CBC_PAD		(0x315UL)
#تعریف_کن CKM_CAST5_کلید_GEN		(0x320UL)
#تعریف_کن CKM_CAST128_کلید_GEN		(0x320UL)
#تعریف_کن CKM_CAST5_ECB			(0x321UL)
#تعریف_کن CKM_CAST128_ECB			(0x321UL)
#تعریف_کن CKM_CAST5_CBC			(0x322UL)
#تعریف_کن CKM_CAST128_CBC			(0x322UL)
#تعریف_کن CKM_CAST5_MAC			(0x323UL)
#تعریف_کن	CKM_CAST128_MAC			(0x323UL)
#تعریف_کن CKM_CAST5_MAC_GENERAL		(0x324UL)
#تعریف_کن CKM_CAST128_MAC_GENERAL		(0x324UL)
#تعریف_کن CKM_CAST5_CBC_PAD		(0x325UL)
#تعریف_کن CKM_CAST128_CBC_PAD		(0x325UL)
#تعریف_کن CKM_RC5_کلید_GEN			(0x330UL)
#تعریف_کن CKM_RC5_ECB			(0x331UL)
#تعریف_کن CKM_RC5_CBC			(0x332UL)
#تعریف_کن CKM_RC5_MAC			(0x333UL)
#تعریف_کن CKM_RC5_MAC_GENERAL		(0x334UL)
#تعریف_کن CKM_RC5_CBC_PAD			(0x335UL)
#تعریف_کن CKM_IDEA_کلید_GEN		(0x340UL)
#تعریف_کن CKM_IDEA_ECB			(0x341UL)
#تعریف_کن	CKM_IDEA_CBC			(0x342UL)
#تعریف_کن CKM_IDEA_MAC			(0x343UL)
#تعریف_کن CKM_IDEA_MAC_GENERAL		(0x344UL)
#تعریف_کن CKM_IDEA_CBC_PAD		(0x345UL)
#تعریف_کن CKM_GENERIC_SECRET_کلید_GEN	(0x350UL)
#تعریف_کن CKM_CONCATENATE_پایه_AND_کلید	(0x360UL)
#تعریف_کن CKM_CONCATENATE_پایه_AND_داده	(0x362UL)
#تعریف_کن CKM_CONCATENATE_داده_AND_پایه	(0x363UL)
#تعریف_کن CKM_XOR_پایه_AND_داده		(0x364UL)
#تعریف_کن CKM_استخراج_کلید_FROM_کلید	(0x365UL)
#تعریف_کن CKM_SSL3_PRE_MASTER_کلید_GEN	(0x370UL)
#تعریف_کن CKM_SSL3_MASTER_کلید_DERIVE	(0x371UL)
#تعریف_کن CKM_SSL3_کلید_AND_MAC_DERIVE	(0x372UL)
#تعریف_کن CKM_SSL3_MASTER_کلید_DERIVE_DH	(0x373UL)
#تعریف_کن CKM_TLS_PRE_MASTER_کلید_GEN	(0x374UL)
#تعریف_کن CKM_TLS_MASTER_کلید_DERIVE	(0x375UL)
#تعریف_کن CKM_TLS_کلید_AND_MAC_DERIVE	(0x376UL)
#تعریف_کن CKM_TLS_MASTER_کلید_DERIVE_DH	(0x377UL)
#تعریف_کن CKM_SSL3_MD5_MAC		(0x380UL)
#تعریف_کن CKM_SSL3_SHA1_MAC		(0x381UL)
#تعریف_کن CKM_MD5_کلید_DERIVATION		(0x390UL)
#تعریف_کن CKM_MD2_کلید_DERIVATION		(0x391UL)
#تعریف_کن CKM_SHA1_کلید_DERIVATION		(0x392UL)
#تعریف_کن CKM_PBE_MD2_DES_CBC		(0x3a0UL)
#تعریف_کن CKM_PBE_MD5_DES_CBC		(0x3a1UL)
#تعریف_کن CKM_PBE_MD5_CAST_CBC		(0x3a2UL)
#تعریف_کن CKM_PBE_MD5_CAST3_CBC		(0x3a3UL)
#تعریف_کن CKM_PBE_MD5_CAST5_CBC		(0x3a4UL)
#تعریف_کن CKM_PBE_MD5_CAST128_CBC		(0x3a4UL)
#تعریف_کن CKM_PBE_SHA1_CAST5_CBC		(0x3a5UL)
#تعریف_کن CKM_PBE_SHA1_CAST128_CBC	(0x3a5UL)
#تعریف_کن CKM_PBE_SHA1_RC4_128		(0x3a6UL)
#تعریف_کن CKM_PBE_SHA1_RC4_40		(0x3a7UL)
#تعریف_کن CKM_PBE_SHA1_DES3_EDE_CBC	(0x3a8UL)
#تعریف_کن CKM_PBE_SHA1_DES2_EDE_CBC	(0x3a9UL)
#تعریف_کن CKM_PBE_SHA1_RC2_128_CBC	(0x3aaUL)
#تعریف_کن CKM_PBE_SHA1_RC2_40_CBC		(0x3abUL)
#تعریف_کن CKM_PKCS5_PBKD2			(0x3b0UL)
#تعریف_کن CKM_PBA_SHA1_WITH_SHA1_HMAC	(0x3c0UL)
#تعریف_کن CKM_کلید_WRAP_LYNKS		(0x400UL)
#تعریف_کن CKM_کلید_WRAP_مجموعه_OAEP		(0x401UL)
#تعریف_کن CKM_SKIPJACK_کلید_GEN		(0x1000UL)
#تعریف_کن CKM_SKIPJACK_ECB64		(0x1001UL)
#تعریف_کن CKM_SKIPJACK_CBC64		(0x1002UL)
#تعریف_کن CKM_SKIPJACK_OFB64		(0x1003UL)
#تعریف_کن CKM_SKIPJACK_CFB64		(0x1004UL)
#تعریف_کن CKM_SKIPJACK_CFB32		(0x1005UL)
#تعریف_کن CKM_SKIPJACK_CFB16		(0x1006UL)
#تعریف_کن CKM_SKIPJACK_CFB8		(0x1007UL)
#تعریف_کن CKM_SKIPJACK_WRAP		(0x1008UL)
#تعریف_کن CKM_SKIPJACK_خصوصی_WRAP	(0x1009UL)
#تعریف_کن CKM_SKIPJACK_RELAYX		(0x100aUL)
#تعریف_کن CKM_KEA_کلید_PAIR_GEN		(0x1010UL)
#تعریف_کن CKM_KEA_کلید_DERIVE		(0x1011UL)
#تعریف_کن CKM_FORTEZZA_TIMESTAMP		(0x1020UL)
#تعریف_کن CKM_BATON_کلید_GEN		(0x1030UL)
#تعریف_کن CKM_BATON_ECB128		(0x1031UL)
#تعریف_کن CKM_BATON_ECB96			(0x1032UL)
#تعریف_کن CKM_BATON_CBC128		(0x1033UL)
#تعریف_کن CKM_BATON_COUNTER		(0x1034UL)
#تعریف_کن CKM_BATON_SHUFFLE		(0x1035UL)
#تعریف_کن CKM_BATON_WRAP			(0x1036UL)
#تعریف_کن CKM_ECDSA_کلید_PAIR_GEN		(0x1040UL)
#تعریف_کن CKM_EC_کلید_PAIR_GEN		(0x1040UL)
#تعریف_کن CKM_ECDSA			(0x1041UL)
#تعریف_کن CKM_ECDSA_SHA1			(0x1042UL)
#تعریف_کن CKM_ECDSA_SHA224		(0x1043UL)
#تعریف_کن CKM_ECDSA_SHA256		(0x1044UL)
#تعریف_کن CKM_ECDSA_SHA384		(0x1045UL)
#تعریف_کن CKM_ECDSA_SHA512		(0x1046UL)
#تعریف_کن CKM_ECDSA_SHA3_224		(0x1047UL)
#تعریف_کن CKM_ECDSA_SHA3_256		(0x1048UL)
#تعریف_کن CKM_ECDSA_SHA3_384		(0x1049UL)
#تعریف_کن CKM_ECDSA_SHA3_512		(0x104AUL)
#تعریف_کن CKM_ECDH1_DERIVE		(0x1050UL)
#تعریف_کن CKM_ECDH1_COFACTOR_DERIVE	(0x1051UL)
#تعریف_کن CKM_ECMQV_DERIVE		(0x1052UL)
#تعریف_کن CKM_EC_EDWARDS_کلید_PAIR_GEN     (0x1055UL)
#تعریف_کن CKM_EC_MONTGOMERY_کلید_PAIR_GEN  (0x1056UL)
#تعریف_کن CKM_EDDSA			(0x1057UL)
#تعریف_کن CKM_JUNIPER_کلید_GEN		(0x1060UL)
#تعریف_کن CKM_JUNIPER_ECB128		(0x1061UL)
#تعریف_کن CKM_JUNIPER_CBC128		(0x1062UL)
#تعریف_کن CKM_JUNIPER_COUNTER		(0x1063UL)
#تعریف_کن CKM_JUNIPER_SHUFFLE		(0x1064UL)
#تعریف_کن CKM_JUNIPER_WRAP		(0x1065UL)
#تعریف_کن CKM_FASTHASH			(0x1070UL)
#تعریف_کن CKM_AES_کلید_GEN			(0x1080UL)
#تعریف_کن CKM_AES_ECB			(0x1081UL)
#تعریف_کن CKM_AES_CBC			(0x1082UL)
#تعریف_کن CKM_AES_MAC			(0x1083UL)
#تعریف_کن CKM_AES_MAC_GENERAL		(0x1084UL)
#تعریف_کن CKM_AES_CBC_PAD			(0x1085UL)
#تعریف_کن CKM_AES_CTR				(0x1086UL)
#تعریف_کن CKM_AES_GCM				(0x1087UL)
#تعریف_کن CKM_AES_CCM				(0x1088UL)
#تعریف_کن CKM_AES_CTS				(0x1089UL)
#تعریف_کن CKM_AES_CMAC			(0x108AUL)
#تعریف_کن CKM_AES_CMAC_GENERAL		(0x108BUL)
#تعریف_کن CKM_AES_XCBC_MAC		(0x108CUL)
#تعریف_کن CKM_AES_XCBC_MAC_96		(0x108DUL)
#تعریف_کن CKM_AES_GMAC			(0x108EUL)
#تعریف_کن CKM_BLOWFISH_کلید_GEN    (0x1090UL)
#تعریف_کن CKM_BLOWFISH_CBC        (0x1091UL)
#تعریف_کن CKM_TWOFISH_کلید_GEN     (0x1092UL)
#تعریف_کن CKM_TWOFISH_CBC         (0x1093UL)
#تعریف_کن CKM_DES_ECB_ENCRYPT_داده	(0x1100UL)
#تعریف_کن CKM_DES_CBC_ENCRYPT_داده	(0x1101UL)
#تعریف_کن CKM_DES3_ECB_ENCRYPT_داده	(0x1102UL)
#تعریف_کن CKM_DES3_CBC_ENCRYPT_داده	(0x1103UL)
#تعریف_کن CKM_AES_ECB_ENCRYPT_داده	(0x1104UL)
#تعریف_کن CKM_AES_CBC_ENCRYPT_داده	(0x1105UL)
#تعریف_کن CKM_GOSTR3410_کلید_PAIR_GEN	(0x1200UL)
#تعریف_کن CKM_GOSTR3410			(0x1201UL)
#تعریف_کن CKM_GOSTR3410_WITH_GOSTR3411	(0x1202UL)
#تعریف_کن CKM_GOSTR3410_کلید_WRAP  (0x1203UL)
#تعریف_کن CKM_GOSTR3410_DERIVE    (0x1204UL)
#تعریف_کن CKM_GOSTR3410_512_کلید_PAIR_GEN	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#تعریف_کن CKM_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#تعریف_کن CKM_GOSTR3410_12_DERIVE	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#تعریف_کن CKM_GOSTR3410_WITH_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#تعریف_کن CKM_GOSTR3410_WITH_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#تعریف_کن CKM_GOSTR3411			(0x1210UL)
#تعریف_کن CKM_GOSTR3411_HMAC      (0x1211UL)
#تعریف_کن CKM_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#تعریف_کن CKM_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#تعریف_کن CKM_GOSTR3411_12_256_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#تعریف_کن CKM_GOSTR3411_12_512_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#تعریف_کن CKM_GOST28147_کلید_GEN   (0x1220UL)
#تعریف_کن CKM_GOST28147_ECB       (0x1221UL)
#تعریف_کن CKM_GOST28147           (0x1222UL)
#تعریف_کن CKM_GOST28147_MAC       (0x1223UL)
#تعریف_کن CKM_GOST28147_کلید_WRAP  (0x1224UL)

#تعریف_کن CKM_DSA_PARAMETER_GEN		(0x2000UL)
#تعریف_کن CKM_DH_PKCS_PARAMETER_GEN	(0x2001UL)
#تعریف_کن CKM_X9_42_DH_PARAMETER_GEN	(0x2002UL)
#تعریف_کن CKM_AES_OFB			(0x2104UL)
#تعریف_کن CKM_AES_CFB64			(0x2105UL)
#تعریف_کن CKM_AES_CFB8			(0x2106UL)
#تعریف_کن CKM_AES_CFB128			(0x2107UL)
#تعریف_کن CKM_AES_CFB1			(0x2108UL)
#تعریف_کن CKM_AES_کلید_WRAP		(0x2109UL)
#تعریف_کن CKM_AES_کلید_WRAP_PAD		(0x210AUL)
#تعریف_کن CKM_XEDDSA			(0x4029UL)
#تعریف_کن CKM_HKDF_DERIVE			(0x402AUL)
#تعریف_کن CKM_HKDF_داده			(0x402BUL)
#تعریف_کن CKM_HKDF_کلید_GEN		(0x402CUL)

#تعریف_کن CKM_VENDOR_DEFINED		(1UL << 31)

بنية ck_mechanism
{
  ck_mechanism_type_t mechanism;
  فراغ *parameter;
  بیعلامت دراز parameter_len;
};


بنية ck_mechanism_info
{
  بیعلامت دراز min_کلید_اندازه;
  بیعلامت دراز max_کلید_اندازه;
  ck_flags_t flags;
};

#تعریف_کن CKF_HW			(1UL << 0)

#تعریف_کن CKF_پیام_ENCRYPT	(1UL << 1)
#تعریف_کن CKF_پیام_DECRYPT	(1UL << 2)
#تعریف_کن CKF_پیام_SIGN	(1UL << 3)
#تعریف_کن CKF_پیام_VERIFY	(1UL << 4)
#تعریف_کن CKF_MULTI_پیام	(1UL << 5)
#تعریف_کن CKF_پیدا_کن_OBJECTS	(1UL << 6)

#تعریف_کن CKF_ENCRYPT		(1UL << 8)
#تعریف_کن CKF_DECRYPT		(1UL << 9)
#تعریف_کن CKF_DIGEST		(1UL << 10)
#تعریف_کن CKF_SIGN		(1UL << 11)
#تعریف_کن CKF_SIGN_RECOVER	(1UL << 12)
#تعریف_کن CKF_VERIFY		(1UL << 13)
#تعریف_کن CKF_VERIFY_RECOVER	(1UL << 14)
#تعریف_کن CKF_GENERATE		(1UL << 15)
#تعریف_کن CKF_GENERATE_کلید_PAIR	(1UL << 16)
#تعریف_کن CKF_WRAP		(1UL << 17)
#تعریف_کن CKF_UNWRAP		(1UL << 18)
#تعریف_کن CKF_DERIVE		(1UL << 19)
#تعریف_کن CKF_EXTENSION		(1UL << 31)

#تعریف_کن CKF_EC_F_P			(1UL << 20)
#تعریف_کن CKF_EC_F_2M			(1UL << 21)
#تعریف_کن CKF_EC_ECPARAMETERS	(1UL << 22)
#تعریف_کن CKF_EC_OID		(1UL << 23)
#تعریف_کن CKF_EC_NAMEDCURVE	CKF_EC_OID
#تعریف_کن CKF_EC_UNCOMPRESS	(1UL << 24)
#تعریف_کن CKF_EC_COMPRESS		(1UL << 25)
#تعریف_کن CKF_EC_CURVENAME	(1UL << 26)

/* Flags for C_WaitForSlotEvent.  */
#تعریف_کن CKF_DONT_بلوک				(1UL)

/* Flags for Key derivation */
#تعریف_کن CKD_NULL			(0x1UL)
#تعریف_کن CKD_SHA1_KDF			(0x2UL)
#تعریف_کن CKD_SHA224_KDF			(0x5UL)
#تعریف_کن CKD_SHA256_KDF			(0x6UL)
#تعریف_کن CKD_SHA384_KDF			(0x7UL)
#تعریف_کن CKD_SHA512_KDF			(0x8UL)

تعريفنوع بنية CK_ECDH1_DERIVE_PARAMS {
	بیعلامت دراز  kdf;
	بیعلامت دراز  ul_Shared_داده_Len;
	بیعلامت حرف *  p_Shared_داده;
	بیعلامت دراز  ul_عمومی_داده_Len;
	بیعلامت حرف *  p_عمومی_داده;
} CK_ECDH1_DERIVE_PARAMS;

تعريفنوع بنية CK_ECMQV_DERIVE_PARAMS {
	بیعلامت دراز kdf;
	بیعلامت دراز ul_Shared_داده_Len;
	بیعلامت حرف * p_Shared_داده;
	بیعلامت دراز ul_عمومی_داده_Len;
	بیعلامت حرف * p_عمومی_داده;
	بیعلامت دراز ul_خصوصی_داده_Len;
	CK_OBJECT_HANDLE h_خصوصی_داده;
	بیعلامت دراز ul_عمومی_داده_Len2;
	بیعلامت حرف * p_عمومی_Data2;
	CK_OBJECT_HANDLE عمومی_کلید_2;
} CK_ECMQV_DERIVE_PARAMS;

تعريفنوع بیعلامت دراز ck_rsa_pkcs_mgf_type_t;
تعريفنوع بیعلامت دراز CK_RSA_PKCS_OAEP_منبع_TYPE;

تعريفنوع بنية CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_منبع_TYPE منبع;
	فراغ *p_منبع_داده;
	بیعلامت دراز ul_منبع_داده_Len;
} CK_RSA_PKCS_OAEP_PARAMS;

تعريفنوع بنية CK_RSA_PKCS_PSS_PARAMS {
	ck_mechanism_type_t hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	بیعلامت دراز sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#تعریف_کن CKG_MGF1_SHA1			(0x00000001UL)
#تعریف_کن CKG_MGF1_SHA224		(0x00000005UL)
#تعریف_کن CKG_MGF1_SHA256		(0x00000002UL)
#تعریف_کن CKG_MGF1_SHA384		(0x00000003UL)
#تعریف_کن CKG_MGF1_SHA512		(0x00000004UL)
#تعریف_کن CKG_MGF1_SHA3_224	(0x00000006UL)
#تعریف_کن CKG_MGF1_SHA3_256	(0x00000007UL)
#تعریف_کن CKG_MGF1_SHA3_384	(0x00000008UL)
#تعریف_کن CKG_MGF1_SHA3_512	(0x00000009UL)

#تعریف_کن CKZ_داده_SPECIFIED	(0x00000001UL)

تعريفنوع بنية CK_GCM_PARAMS {
	فراغ * pIv;
	بیعلامت دراز ulIvLen;
	بیعلامت دراز ul_Iv_بیتها;
	فراغ * pAAD;
	بیعلامت دراز ulAADLen;
	بیعلامت دراز ul_برچسب_بیتها;
} CK_GCM_PARAMS;

تعريفنوع بنية CK_CCM_PARAMS {
	بیعلامت دراز ul_داده_Len;
	بیعلامت حرف *pNonce;
	بیعلامت دراز ulNonceLen;
	بیعلامت حرف *pAAD;
	بیعلامت دراز ulAADLen;
	بیعلامت دراز ulMACLen;
} CK_CCM_PARAMS;

/* EDDSA */
تعريفنوع بنية CK_EDDSA_PARAMS {
	بیعلامت حرف phFlag;
	بیعلامت دراز ul_Context_داده_Len;
	بیعلامت حرف *p_Context_داده;
} CK_EDDSA_PARAMS;

تعريفنوع CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

/* XEDDSA */
تعريفنوع بنية CK_XEDDSA_PARAMS {
	بیعلامت دراز hash;
} CK_XEDDSA_PARAMS;

تعريفنوع CK_XEDDSA_PARAMS *CK_XEDDSA_PARAMS_PTR;

تعريفنوع بنية CK_AES_CTR_PARAMS {
    بیعلامت دراز ul_Counter_بیتها;
    بیعلامت حرف cb[16];
} CK_AES_CTR_PARAMS;

تعريفنوع CK_AES_CTR_PARAMS *CK_AES_CTR_PARAMS_PTR;

تعريفنوع بیعلامت دراز CK_MAC_GENERAL_PARAMS;

تعريفنوع CK_MAC_GENERAL_PARAMS *CK_MAC_GENERAL_PARAMS_PTR;

تعريفنوع بیعلامت دراز ck_rv_t;


تعريفنوع ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, فراغ *application);

بنية ck_interface {
  حرف * pInterfaceName;
  فراغ * pFunctionList;
  ck_flags_t flags;
};

#تعریف_کن CKF_INTERFACE_FORK_امن	(0x00000001UL)

/* Forward reference.  */
بنية ck_function_list;
بنية ck_function_list_3_0;

#تعریف_کن _CK_DECLARE_FUNCTION(name, آرگومانها)	\
تعريفنوع ck_rv_t (*CK_ ## name) آرگومانها;		\
ck_rv_t CK_SPEC name آرگومانها

_CK_DECLARE_FUNCTION (C_Initialize, (فراغ *init_آرگومانها));
_CK_DECLARE_FUNCTION (C_Finalize, (فراغ *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (بنية ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (بنية ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_Get_جایگاه_List,
		      (بیعلامت حرف token_present, ck_جایگاه_id_t *جایگاه_list,
		       بیعلامت دراز *شمار));
_CK_DECLARE_FUNCTION (C_Get_جایگاه_Info,
		      (ck_جایگاه_id_t جایگاه_id, بنية ck_جایگاه_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_جایگاه_id_t جایگاه_id, بنية ck_token_info *info));
_CK_DECLARE_FUNCTION (C_Wait_For_جایگاه_Event,
		      (ck_flags_t flags, ck_جایگاه_id_t *جایگاه, فراغ *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_جایگاه_id_t جایگاه_id,
		       ck_mechanism_type_t *mechanism_list,
		       بیعلامت دراز *شمار));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_جایگاه_id_t جایگاه_id, ck_mechanism_type_t type,
		       بنية ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_جایگاه_id_t جایگاه_id, بیعلامت حرف *pin,
		       بیعلامت دراز pin_len, بیعلامت حرف *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, بیعلامت حرف *pin,
		       بیعلامت دراز pin_len));
_CK_DECLARE_FUNCTION (C_مجموعه_PIN,
		      (ck_session_handle_t session, بیعلامت حرف *old_pin,
		       بیعلامت دراز old_len, بیعلامت حرف *new_pin,
		       بیعلامت دراز new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_جایگاه_id_t جایگاه_id, ck_flags_t flags,
		       فراغ *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_جایگاه_id_t جایگاه_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       بنية ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       بیعلامت حرف *operation_state,
		       بیعلامت دراز *operation_state_len));
_CK_DECLARE_FUNCTION (C_مجموعه_Operation_State,
		      (ck_session_handle_t session,
		       بیعلامت حرف *operation_state,
		       بیعلامت دراز operation_state_len,
		       ck_object_handle_t encryption_کلید,
		       ck_object_handle_t authentication_کلید));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       بیعلامت حرف *pin, بیعلامت دراز pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       بنية ck_attribute *templ,
		       بیعلامت دراز شمار, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       بنية ck_attribute *templ, بیعلامت دراز شمار,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_Get_Object_اندازه,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       بیعلامت دراز *اندازه));
_CK_DECLARE_FUNCTION (C_Get_Attribute_مقدار,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       بنية ck_attribute *templ,
		       بیعلامت دراز شمار));
_CK_DECLARE_FUNCTION (C_مجموعه_Attribute_مقدار,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       بنية ck_attribute *templ,
		       بیعلامت دراز شمار));
_CK_DECLARE_FUNCTION (C_پیدا_کن_Objects_Init,
		      (ck_session_handle_t session,
		       بنية ck_attribute *templ,
		       بیعلامت دراز شمار));
_CK_DECLARE_FUNCTION (C_پیدا_کن_Objects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       بیعلامت دراز max_object_شمار,
		       بیعلامت دراز *object_شمار));
_CK_DECLARE_FUNCTION (C_پیدا_کن_Objects_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       بیعلامت حرف *داده, بیعلامت دراز داده_len,
		       بیعلامت حرف *encrypted_داده,
		       بیعلامت دراز *encrypted_داده_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       بیعلامت حرف *part, بیعلامت دراز part_len,
		       بیعلامت حرف *encrypted_part,
		       بیعلامت دراز *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       بیعلامت حرف *آخرین_encrypted_part,
		       بیعلامت دراز *آخرین_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       بیعلامت حرف *encrypted_داده,
		       بیعلامت دراز encrypted_داده_len,
		       بیعلامت حرف *داده, بیعلامت دراز *داده_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       بیعلامت حرف *encrypted_part,
		       بیعلامت دراز encrypted_part_len,
		       بیعلامت حرف *part, بیعلامت دراز *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       بیعلامت حرف *آخرین_part,
		       بیعلامت دراز *آخرین_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       بیعلامت حرف *داده, بیعلامت دراز داده_len,
		       بیعلامت حرف *digest,
		       بیعلامت دراز *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       بیعلامت حرف *part, بیعلامت دراز part_len));
_CK_DECLARE_FUNCTION (C_Digest_کلید,
		      (ck_session_handle_t session, ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       بیعلامت حرف *digest,
		       بیعلامت دراز *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       بیعلامت حرف *داده, بیعلامت دراز داده_len,
		       بیعلامت حرف *signature,
		       بیعلامت دراز *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       بیعلامت حرف *part, بیعلامت دراز part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       بیعلامت حرف *signature,
		       بیعلامت دراز *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       بیعلامت حرف *داده, بیعلامت دراز داده_len,
		       بیعلامت حرف *signature,
		       بیعلامت دراز *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       بیعلامت حرف *داده, بیعلامت دراز داده_len,
		       بیعلامت حرف *signature,
		       بیعلامت دراز signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       بیعلامت حرف *part, بیعلامت دراز part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       بیعلامت حرف *signature,
		       بیعلامت دراز signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       بیعلامت حرف *signature,
		       بیعلامت دراز signature_len,
		       بیعلامت حرف *داده,
		       بیعلامت دراز *داده_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       بیعلامت حرف *part, بیعلامت دراز part_len,
		       بیعلامت حرف *encrypted_part,
		       بیعلامت دراز *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       بیعلامت حرف *encrypted_part,
		       بیعلامت دراز encrypted_part_len,
		       بیعلامت حرف *part,
		       بیعلامت دراز *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       بیعلامت حرف *part, بیعلامت دراز part_len,
		       بیعلامت حرف *encrypted_part,
		       بیعلامت دراز *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       بیعلامت حرف *encrypted_part,
		       بیعلامت دراز encrypted_part_len,
		       بیعلامت حرف *part,
		       بیعلامت دراز *part_len));

_CK_DECLARE_FUNCTION (C_Generate_کلید,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       بنية ck_attribute *templ,
		       بیعلامت دراز شمار,
		       ck_object_handle_t *کلید));
_CK_DECLARE_FUNCTION (C_Generate_کلید_Pair,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       بنية ck_attribute *عمومی_کلید_template,
		       بیعلامت دراز عمومی_کلید_attribute_شمار,
		       بنية ck_attribute *خصوصی_کلید_template,
		       بیعلامت دراز خصوصی_کلید_attribute_شمار,
		       ck_object_handle_t *عمومی_کلید,
		       ck_object_handle_t *خصوصی_کلید));
_CK_DECLARE_FUNCTION (C_Wrap_کلید,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_کلید,
		       ck_object_handle_t کلید,
		       بیعلامت حرف *wrapped_کلید,
		       بیعلامت دراز *wrapped_کلید_len));
_CK_DECLARE_FUNCTION (C_Unwrap_کلید,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_کلید,
		       بیعلامت حرف *wrapped_کلید,
		       بیعلامت دراز wrapped_کلید_len,
		       بنية ck_attribute *templ,
		       بیعلامت دراز attribute_شمار,
		       ck_object_handle_t *کلید));
_CK_DECLARE_FUNCTION (C_Derive_کلید,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t پایه_کلید,
		       بنية ck_attribute *templ,
		       بیعلامت دراز attribute_شمار,
		       ck_object_handle_t *کلید));

_CK_DECLARE_FUNCTION (C_دانه_Random,
		      (ck_session_handle_t session, بیعلامت حرف *دانه,
		       بیعلامت دراز دانه_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       بیعلامت حرف *random_data,
		       بیعلامت دراز random_len));

_CK_DECLARE_FUNCTION (C_Get_Function_وضعیت, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_GetInterfaceList,
		      (بنية ck_interface *interfaces_list,
		       بیعلامت دراز *شمار));
_CK_DECLARE_FUNCTION (C_GetInterface,
		      (بیعلامت حرف *interface_name,
		       بنية ck_نسخه *نسخه,
		       بنية ck_interface **interface_ptr,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_LoginUser,
		      (ck_session_handle_t session,
		       ck_user_type_t user_type,
		       بیعلامت حرف *pin,
		       بیعلامت دراز pin_len,
		       بیعلامت حرف *username,
		       بیعلامت دراز username_len));

_CK_DECLARE_FUNCTION (C_SessionCancel,
		      (ck_session_handle_t session,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_پیام_Encrypt_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Encrypt_پیام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *associated_داده,
		       بیعلامت دراز associated_داده_len,
		       بیعلامت حرف *plaintext,
		       بیعلامت دراز plaintext_len,
		       بیعلامت حرف *ciphertext,
		       بیعلامت دراز *ciphertext_len));
_CK_DECLARE_FUNCTION (C_Encrypt_پیام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *associated_داده,
		       بیعلامت دراز associated_داده_len));
_CK_DECLARE_FUNCTION (C_Encrypt_پیام_بعدی,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *plaintext_part,
		       بیعلامت دراز plaintext_part_len,
		       بیعلامت حرف *ciphertext_part,
		       بیعلامت دراز *ciphertext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_پیام_Encrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پیام_Decrypt_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Decrypt_پیام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *associated_داده,
		       بیعلامت دراز associated_داده_len,
		       بیعلامت حرف *ciphertext,
		       بیعلامت دراز ciphertext_len,
		       بیعلامت حرف *plaintext,
		       بیعلامت دراز *plaintext_len));
_CK_DECLARE_FUNCTION (C_Decrypt_پیام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *associated_داده,
		       بیعلامت دراز associated_داده_len));
_CK_DECLARE_FUNCTION (C_Decrypt_پیام_بعدی,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *ciphertext_part,
		       بیعلامت دراز ciphertext_part_len,
		       بیعلامت حرف *plaintext_part,
		       بیعلامت دراز *plaintext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_پیام_Decrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پیام_Sign_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Sign_پیام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *داده,
		       بیعلامت دراز داده_len,
		       بیعلامت حرف *signature,
		       بیعلامت دراز *signature_len));
_CK_DECLARE_FUNCTION (C_Sign_پیام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len));
_CK_DECLARE_FUNCTION (C_Sign_پیام_بعدی,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *داده,
		       بیعلامت دراز داده_len,
		       بیعلامت حرف *signature,
		       بیعلامت دراز *signature_len));
_CK_DECLARE_FUNCTION (C_پیام_Sign_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پیام_Verify_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلید));
_CK_DECLARE_FUNCTION (C_Verify_پیام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *داده,
		       بیعلامت دراز داده_len,
		       بیعلامت حرف *signature,
		       بیعلامت دراز signature_len));
_CK_DECLARE_FUNCTION (C_Verify_پیام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len));
_CK_DECLARE_FUNCTION (C_Verify_پیام_بعدی,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بیعلامت دراز parameter_len,
		       بیعلامت حرف *داده,
		       بیعلامت دراز داده_len,
		       بیعلامت حرف *signature,
		       بیعلامت دراز signature_len));
_CK_DECLARE_FUNCTION (C_پیام_Verify_Final,
		      (ck_session_handle_t session));

/* Flags in Message-based encryption/decryption API */
#تعریف_کن CKF_انتها_از_پیام	(0x00000001UL)

بنية ck_function_list
{
  بنية ck_نسخه نسخه;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_جایگاه_List C_Get_جایگاه_List;
  CK_C_Get_جایگاه_Info C_Get_جایگاه_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_مجموعه_PIN C_مجموعه_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_مجموعه_Operation_State C_مجموعه_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_اندازه C_Get_Object_اندازه;
  CK_C_Get_Attribute_مقدار C_Get_Attribute_مقدار;
  CK_C_مجموعه_Attribute_مقدار C_مجموعه_Attribute_مقدار;
  CK_C_پیدا_کن_Objects_Init C_پیدا_کن_Objects_Init;
  CK_C_پیدا_کن_Objects C_پیدا_کن_Objects;
  CK_C_پیدا_کن_Objects_Final C_پیدا_کن_Objects_Final;
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
  CK_C_دانه_Random C_دانه_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_وضعیت C_Get_Function_وضعیت;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_جایگاه_Event C_Wait_For_جایگاه_Event;
};

بنية ck_function_list_3_0
{
  بنية ck_نسخه نسخه;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_جایگاه_List C_Get_جایگاه_List;
  CK_C_Get_جایگاه_Info C_Get_جایگاه_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_مجموعه_PIN C_مجموعه_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_مجموعه_Operation_State C_مجموعه_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_اندازه C_Get_Object_اندازه;
  CK_C_Get_Attribute_مقدار C_Get_Attribute_مقدار;
  CK_C_مجموعه_Attribute_مقدار C_مجموعه_Attribute_مقدار;
  CK_C_پیدا_کن_Objects_Init C_پیدا_کن_Objects_Init;
  CK_C_پیدا_کن_Objects C_پیدا_کن_Objects;
  CK_C_پیدا_کن_Objects_Final C_پیدا_کن_Objects_Final;
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
  CK_C_دانه_Random C_دانه_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_وضعیت C_Get_Function_وضعیت;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_جایگاه_Event C_Wait_For_جایگاه_Event;
  /* PKCS #11 3.0 functions */
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  CK_C_پیام_Encrypt_Init C_پیام_Encrypt_Init;
  CK_C_Encrypt_پیام C_Encrypt_پیام;
  CK_C_Encrypt_پیام_Begin C_Encrypt_پیام_Begin;
  CK_C_Encrypt_پیام_بعدی C_Encrypt_پیام_بعدی;
  CK_C_پیام_Encrypt_Final C_پیام_Encrypt_Final;
  CK_C_پیام_Decrypt_Init C_پیام_Decrypt_Init;
  CK_C_Decrypt_پیام C_Decrypt_پیام;
  CK_C_Decrypt_پیام_Begin C_Decrypt_پیام_Begin;
  CK_C_Decrypt_پیام_بعدی C_Decrypt_پیام_بعدی;
  CK_C_پیام_Decrypt_Final C_پیام_Decrypt_Final;
  CK_C_پیام_Sign_Init C_پیام_Sign_Init;
  CK_C_Sign_پیام C_Sign_پیام;
  CK_C_Sign_پیام_Begin C_Sign_پیام_Begin;
  CK_C_Sign_پیام_بعدی C_Sign_پیام_بعدی;
  CK_C_پیام_Sign_Final C_پیام_Sign_Final;
  CK_C_پیام_Verify_Init C_پیام_Verify_Init;
  CK_C_Verify_پیام C_Verify_پیام;
  CK_C_Verify_پیام_Begin C_Verify_پیام_Begin;
  CK_C_Verify_پیام_بعدی C_Verify_پیام_بعدی;
  CK_C_پیام_Verify_Final C_پیام_Verify_Final;
};



تعريفنوع ck_rv_t (*ck_createmutex_t) (فراغ **mutex);
تعريفنوع ck_rv_t (*ck_destroymutex_t) (فراغ *mutex);
تعريفنوع ck_rv_t (*ck_lockmutex_t) (فراغ *mutex);
تعريفنوع ck_rv_t (*ck_unlockmutex_t) (فراغ *mutex);


بنية ck_c_initialize_آرگومانها
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t قفل_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  فراغ *reserved;
};


#تعریف_کن CKF_LIBRARY_CANT_CREATE_OS_نخها	(1UL << 0)
#تعریف_کن CKF_OS_LOCKING_OK			(1UL << 1)

#تعریف_کن CKR_OK					(0UL)
#تعریف_کن CKR_CANCEL				(1UL)
#تعریف_کن CKR_HOST_حافظه				(2UL)
#تعریف_کن CKR_جایگاه_ID_INVALID			(3UL)
#تعریف_کن CKR_GENERAL_ERROR			(5UL)
#تعریف_کن CKR_FUNCTION_FAILED			(6UL)
#تعریف_کن CKR_ARGUMENTS_BAD			(7UL)
#تعریف_کن CKR_NO_EVENT				(8UL)
#تعریف_کن CKR_NEED_مقصد_CREATE_نخها		(9UL)
#تعریف_کن CKR_CANT_قفل				(0xaUL)
#تعریف_کن CKR_ATTRIBUTE_READ_ONLY			(0x10UL)
#تعریف_کن CKR_ATTRIBUTE_SENSITIVE			(0x11UL)
#تعریف_کن CKR_ATTRIBUTE_TYPE_INVALID		(0x12UL)
#تعریف_کن CKR_ATTRIBUTE_مقدار_INVALID		(0x13UL)
#تعریف_کن CKR_ACTION_PROHIBITED			(0x1BUL)
#تعریف_کن CKR_داده_INVALID			(0x20UL)
#تعریف_کن CKR_داده_LEN_RANGE			(0x21UL)
#تعریف_کن CKR_DEVICE_ERROR			(0x30UL)
#تعریف_کن CKR_DEVICE_حافظه			(0x31UL)
#تعریف_کن CKR_DEVICE_REMOVED			(0x32UL)
#تعریف_کن CKR_ENCRYPTED_داده_INVALID		(0x40UL)
#تعریف_کن CKR_ENCRYPTED_داده_LEN_RANGE		(0x41UL)
#تعریف_کن CKR_FUNCTION_CANCELED			(0x50UL)
#تعریف_کن CKR_FUNCTION_NOT_PARALLEL		(0x51UL)
#تعریف_کن CKR_FUNCTION_NOT_SUPPORTED		(0x54UL)
#تعریف_کن CKR_کلید_HANDLE_INVALID			(0x60UL)
#تعریف_کن CKR_کلید_اندازه_RANGE			(0x62UL)
#تعریف_کن CKR_کلید_TYPE_INCONSISTENT		(0x63UL)
#تعریف_کن CKR_کلید_NOT_NEEDED			(0x64UL)
#تعریف_کن CKR_کلید_تغییریافته				(0x65UL)
#تعریف_کن CKR_کلید_NEEDED				(0x66UL)
#تعریف_کن CKR_کلید_INDIGESTIBLE			(0x67UL)
#تعریف_کن CKR_کلید_FUNCTION_NOT_PERMITTED		(0x68UL)
#تعریف_کن CKR_کلید_NOT_WRAPPABLE			(0x69UL)
#تعریف_کن CKR_کلید_UNEXTRACTABLE			(0x6aUL)
#تعریف_کن CKR_MECHANISM_INVALID			(0x70UL)
#تعریف_کن CKR_MECHANISM_PARAM_INVALID		(0x71UL)
#تعریف_کن CKR_OBJECT_HANDLE_INVALID		(0x82UL)
#تعریف_کن CKR_OPERATION_فعال			(0x90UL)
#تعریف_کن CKR_OPERATION_NOT_INITIALIZED		(0x91UL)
#تعریف_کن CKR_PIN_INCORRECT			(0xa0UL)
#تعریف_کن CKR_PIN_INVALID				(0xa1UL)
#تعریف_کن CKR_PIN_LEN_RANGE			(0xa2UL)
#تعریف_کن CKR_PIN_EXPIRED				(0xa3UL)
#تعریف_کن CKR_PIN_LOCKED				(0xa4UL)
#تعریف_کن CKR_SESSION_CLOSED			(0xb0UL)
#تعریف_کن CKR_SESSION_شمار			(0xb1UL)
#تعریف_کن CKR_SESSION_HANDLE_INVALID		(0xb3UL)
#تعریف_کن CKR_SESSION_PARALLEL_NOT_SUPPORTED	(0xb4UL)
#تعریف_کن CKR_SESSION_READ_ONLY			(0xb5UL)
#تعریف_کن CKR_SESSION_EXISTS			(0xb6UL)
#تعریف_کن CKR_SESSION_READ_ONLY_EXISTS		(0xb7UL)
#تعریف_کن CKR_SESSION_READ_WRITE_SO_EXISTS	(0xb8UL)
#تعریف_کن CKR_SIGNATURE_INVALID			(0xc0UL)
#تعریف_کن CKR_SIGNATURE_LEN_RANGE			(0xc1UL)
#تعریف_کن CKR_TEMPLATE_INCOMPLETE			(0xd0UL)
#تعریف_کن CKR_TEMPLATE_INCONSISTENT		(0xd1UL)
#تعریف_کن CKR_TOKEN_NOT_PRESENT			(0xe0UL)
#تعریف_کن CKR_TOKEN_NOT_RECOGNIZED		(0xe1UL)
#تعریف_کن CKR_TOKEN_WRITE_PROTECTED		(0xe2UL)
#تعریف_کن	CKR_UNWRAPPING_کلید_HANDLE_INVALID	(0xf0UL)
#تعریف_کن CKR_UNWRAPPING_کلید_اندازه_RANGE		(0xf1UL)
#تعریف_کن CKR_UNWRAPPING_کلید_TYPE_INCONSISTENT	(0xf2UL)
#تعریف_کن CKR_USER_ALREADY_LOGGED_درون		(0x100UL)
#تعریف_کن CKR_USER_NOT_LOGGED_درون			(0x101UL)
#تعریف_کن CKR_USER_PIN_NOT_INITIALIZED		(0x102UL)
#تعریف_کن CKR_USER_TYPE_INVALID			(0x103UL)
#تعریف_کن CKR_USER_ANOTHER_ALREADY_LOGGED_درون	(0x104UL)
#تعریف_کن CKR_USER_TOO_MANY_TYPES			(0x105UL)
#تعریف_کن CKR_WRAPPED_کلید_INVALID			(0x110UL)
#تعریف_کن CKR_WRAPPED_کلید_LEN_RANGE		(0x112UL)
#تعریف_کن CKR_WRAPPING_کلید_HANDLE_INVALID		(0x113UL)
#تعریف_کن CKR_WRAPPING_کلید_اندازه_RANGE		(0x114UL)
#تعریف_کن CKR_WRAPPING_کلید_TYPE_INCONSISTENT	(0x115UL)
#تعریف_کن CKR_RANDOM_دانه_NOT_SUPPORTED		(0x120UL)
#تعریف_کن CKR_RANDOM_NO_RNG			(0x121UL)
#تعریف_کن CKR_DOMAIN_PARAMS_INVALID		(0x130UL)
#تعریف_کن CKR_منحنی_NOT_SUPPORTED			(0x140UL)
#تعریف_کن CKR_میانگیر_TOO_SMALL			(0x150UL)
#تعریف_کن CKR_SAVED_STATE_INVALID			(0x160UL)
#تعریف_کن CKR_INFORMATION_SENSITIVE		(0x170UL)
#تعریف_کن CKR_STATE_UNSAVEABLE			(0x180UL)
#تعریف_کن CKR_CRYPTOKI_NOT_INITIALIZED		(0x190UL)
#تعریف_کن CKR_CRYPTOKI_ALREADY_INITIALIZED	(0x191UL)
#تعریف_کن CKR_MUTEX_BAD				(0x1a0UL)
#تعریف_کن CKR_MUTEX_NOT_LOCKED			(0x1a1UL)
#تعریف_کن CKR_FUNCTION_REJECTED			(0x200UL)
#تعریف_کن CKR_VENDOR_DEFINED			(1UL << 31)


/* Compatibility layer.  */

#اگر_تعریف_شده CRYPTOKI_COMPAT

#لغو_تعریف CK_DEFINE_FUNCTION
#تعریف_کن CK_DEFINE_FUNCTION(retval, name) retval CK_SPEC name

/* For NULL.  */
#ضمن <stddef.h>

تعريفنوع بیعلامت حرف CK_BYTE;
تعريفنوع بیعلامت حرف CK_CHAR;
تعريفنوع بیعلامت حرف CK_UTF8CHAR;
تعريفنوع بیعلامت حرف CK_BBOOL;
تعريفنوع بیعلامت دراز صحيح CK_ULONG;
تعريفنوع دراز صحيح CK_LONG;
تعريفنوع CK_BYTE *CK_BYTE_PTR;
تعريفنوع CK_CHAR *CK_CHAR_PTR;
تعريفنوع CK_UTF8CHAR *CK_UTF8CHAR_PTR;
تعريفنوع CK_ULONG *CK_ULONG_PTR;
تعريفنوع فراغ *CK_VOID_PTR;
تعريفنوع فراغ **CK_VOID_PTR_PTR;
#تعریف_کن CK_FALSE 0
#تعریف_کن CK_TRUE 1
#اگر_تعریف_نشده CK_DISABLE_TRUE_FALSE
#اگر_تعریف_نشده FALSE
#تعریف_کن FALSE 0
#پایان_اگر
#اگر_تعریف_نشده TRUE
#تعریف_کن TRUE 1
#پایان_اگر
#پایان_اگر

تعريفنوع بنية CK_HKDF_PARAMS {
	CK_BBOOL b_استخراج;
	CK_BBOOL bExpand;
	CK_MECHANISM_TYPE prfHashMechanism;
	CK_ULONG ulSaltType;
	CK_BYTE_PTR pSalt;
	CK_ULONG ulSaltLen;
	CK_OBJECT_HANDLE h_Salt_کلید;
	CK_BYTE_PTR pInfo;
	CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

#تعریف_کن CKF_HKDF_SALT_NULL 0x00000001UL
#تعریف_کن CKF_HKDF_SALT_داده 0x00000002UL
#تعریف_کن CKF_HKDF_SALT_کلید  0x00000004UL

تعريفنوع بنية ck_نسخه CK_نسخه_2;
تعريفنوع بنية ck_نسخه *CK_نسخه_PTR;

تعريفنوع بنية ck_info CK_INFO;
تعريفنوع بنية ck_info *CK_INFO_PTR;

تعريفنوع ck_جایگاه_id_t *CK_جایگاه_ID_PTR;

تعريفنوع بنية ck_جایگاه_info CK_جایگاه_INFO_2;
تعريفنوع بنية ck_جایگاه_info *CK_جایگاه_INFO_PTR;

تعريفنوع بنية ck_token_info CK_TOKEN_INFO;
تعريفنوع بنية ck_token_info *CK_TOKEN_INFO_PTR;

تعريفنوع ck_session_handle_t *CK_SESSION_HANDLE_PTR;

تعريفنوع بنية ck_session_info CK_SESSION_INFO;
تعريفنوع بنية ck_session_info *CK_SESSION_INFO_PTR;

تعريفنوع ck_object_handle_t *CK_OBJECT_HANDLE_PTR;

تعريفنوع ck_object_class_t *CK_OBJECT_CLASS_PTR;

تعريفنوع بنية ck_attribute CK_ATTRIBUTE;
تعريفنوع بنية ck_attribute *CK_ATTRIBUTE_PTR;

تعريفنوع بنية ck_date CK_DATE;
تعريفنوع بنية ck_date *CK_DATE_PTR;

تعريفنوع ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;

تعريفنوع ck_rsa_pkcs_mgf_type_t *CK_RSA_PKCS_MGF_TYPE_PTR;

تعريفنوع بنية ck_mechanism CK_MECHANISM;
تعريفنوع بنية ck_mechanism *CK_MECHANISM_PTR;

تعريفنوع بنية ck_mechanism_info CK_MECHANISM_INFO;
تعريفنوع بنية ck_mechanism_info *CK_MECHANISM_INFO_PTR;

تعريفنوع بنية ck_interface CK_INTERFACE;
تعريفنوع بنية ck_interface *CK_INTERFACE_PTR;
تعريفنوع بنية ck_interface **CK_INTERFACE_PTR_PTR;

تعريفنوع بنية ck_function_list CK_FUNCTION_LIST;
تعريفنوع بنية ck_function_list *CK_FUNCTION_LIST_PTR;
تعريفنوع بنية ck_function_list **CK_FUNCTION_LIST_PTR_PTR;

تعريفنوع بنية ck_function_list_3_0 CK_FUNCTION_LIST_3_0;
تعريفنوع بنية ck_function_list_3_0 *CK_FUNCTION_LIST_3_0_PTR;
تعريفنوع بنية ck_function_list_3_0 **CK_FUNCTION_LIST_3_0_PTR_PTR;

تعريفنوع بنية ck_c_initialize_آرگومانها CK_C_INITIALIZE_آرگومانها_2;
تعريفنوع بنية ck_c_initialize_آرگومانها *CK_C_INITIALIZE_آرگومانها_PTR;

#تعریف_کن NULL_PTR عدم

/* Delete the helper macros defined at the top of the file.  */
#لغو_تعریف ck_flags_t
#لغو_تعریف ck_نسخه

#لغو_تعریف ck_info
#لغو_تعریف cryptoki_نسخه
#لغو_تعریف manufacturer_id
#لغو_تعریف library_description
#لغو_تعریف library_نسخه

#لغو_تعریف ck_notification_t
#لغو_تعریف ck_جایگاه_id_t

#لغو_تعریف ck_جایگاه_info
#لغو_تعریف جایگاه_description
#لغو_تعریف hardware_نسخه
#لغو_تعریف firmware_نسخه

#لغو_تعریف ck_token_info
#لغو_تعریف serial_عدد
#لغو_تعریف max_session_شمار
#لغو_تعریف session_شمار
#لغو_تعریف max_rw_session_شمار
#لغو_تعریف rw_session_شمار
#لغو_تعریف max_pin_len
#لغو_تعریف min_pin_len
#لغو_تعریف مجموع_عمومی_حافظه
#لغو_تعریف free_عمومی_حافظه
#لغو_تعریف مجموع_خصوصی_حافظه
#لغو_تعریف free_خصوصی_حافظه
#لغو_تعریف utc_زمان

#لغو_تعریف ck_session_handle_t
#لغو_تعریف ck_user_type_t
#لغو_تعریف ck_state_t

#لغو_تعریف ck_session_info
#لغو_تعریف جایگاه_id
#لغو_تعریف device_error

#لغو_تعریف ck_object_handle_t
#لغو_تعریف ck_object_class_t
#لغو_تعریف ck_hw_feature_type_t
#لغو_تعریف ck_کلید_type_t
#لغو_تعریف ck_certificate_type_t
#لغو_تعریف ck_attribute_type_t

#لغو_تعریف ck_attribute
#لغو_تعریف مقدار
#لغو_تعریف مقدار_len

#لغو_تعریف ck_date

#لغو_تعریف ck_mechanism_type_t

#لغو_تعریف ck_rsa_pkcs_mgf_type_t

#لغو_تعریف ck_mechanism
#لغو_تعریف parameter
#لغو_تعریف parameter_len

#لغو_تعریف ck_mechanism_info
#لغو_تعریف min_کلید_اندازه
#لغو_تعریف max_کلید_اندازه

#لغو_تعریف ck_rv_t
#لغو_تعریف ck_notify_t

#لغو_تعریف ck_interface

#لغو_تعریف ck_function_list
#لغو_تعریف ck_function_list_3_0

#لغو_تعریف ck_createmutex_t
#لغو_تعریف ck_destroymutex_t
#لغو_تعریف ck_lockmutex_t
#لغو_تعریف ck_unlockmutex_t

#لغو_تعریف ck_c_initialize_آرگومانها
#لغو_تعریف create_mutex
#لغو_تعریف destroy_mutex
#لغو_تعریف قفل_mutex
#لغو_تعریف unlock_mutex
#لغو_تعریف reserved

#پایان_اگر	/* CRYPTOKI_COMPAT */

/* System dependencies.  */
#إذا defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#رهنمود pack(برداشت, cryptoki)
#پایان_اگر

#إذا defined(__cplusplus)
}
#پایان_اگر

#پایان_اگر	/* PKCS11_H */
