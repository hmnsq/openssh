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

#अगर_अघोषित PKCS11_H
#घोषणा PKCS11_H 1

#अगर defined(__cplusplus)
बाह्य "C" {
#पूर्ण_अगर


/* The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  */
#घोषणा CRYPTOKI_VERSION_MAJOR		3
#घोषणा CRYPTOKI_VERSION_MINOR		0
#घोषणा CRYPTOKI_VERSION_REVISION	0


/* Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  */
#अगर_अघोषित CRYPTOKI_GNU
#अगर_अघोषित CRYPTOKI_COMPAT
#घोषणा CRYPTOKI_COMPAT 1
#पूर्ण_अगर
#पूर्ण_अगर

/* System dependencies.  */

#अगर defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#आशय pack(धकेलो, cryptoki, 1)

#अगर_घोषित CRYPTOKI_EXPORTS
#घोषणा CK_SPEC __declspec(dllexport)
#अन्यथा
#घोषणा CK_SPEC __declspec(dllimport)
#पूर्ण_अगर

#अन्यथा

#घोषणा CK_SPEC

#पूर्ण_अगर

#अगर_घोषित CRYPTOKI_COMPAT
  /* If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  */

#घोषणा ck_flags_t CK_FLAGS
#घोषणा ck_version _CK_VERSION

#घोषणा ck_info _CK_INFO
#घोषणा cryptoki_version cryptokiVersion
#घोषणा manufacturer_id manufacturerID
#घोषणा library_description libraryDescription
#घोषणा library_version libraryVersion

#घोषणा ck_notification_t CK_NOTIFICATION
#घोषणा ck_slot_id_t CK_SLOT_ID

#घोषणा ck_slot_info _CK_SLOT_INFO
#घोषणा slot_description slotDescription
#घोषणा hardware_version hardwareVersion
#घोषणा firmware_version firmwareVersion

#घोषणा ck_token_info _CK_TOKEN_INFO
#घोषणा serial_संख्या serial_संख्या_2
#घोषणा max_session_गिनती ul_Max_Session_गिनती
#घोषणा session_गिनती ul_Session_गिनती
#घोषणा max_rw_session_गिनती ul_Max_Rw_Session_गिनती
#घोषणा rw_session_गिनती ul_Rw_Session_गिनती
#घोषणा max_pin_len ulMaxPinLen
#घोषणा min_pin_len ulMinPinLen
#घोषणा योग_public_memory ul_योग_Public_Memory
#घोषणा free_public_memory ulFreePublicMemory
#घोषणा योग_private_memory ul_योग_Private_Memory
#घोषणा free_private_memory ulFreePrivateMemory
#घोषणा utc_time utcTime

#घोषणा ck_session_handle_t CK_SESSION_HANDLE
#घोषणा ck_user_type_t CK_USER_TYPE
#घोषणा ck_state_t CK_STATE

#घोषणा ck_session_info _CK_SESSION_INFO
#घोषणा slot_id slotID
#घोषणा device_error ulDeviceError

#घोषणा ck_object_handle_t CK_OBJECT_HANDLE
#घोषणा ck_object_class_t CK_OBJECT_CLASS
#घोषणा ck_hw_feature_type_t CK_HW_FEATURE_TYPE
#घोषणा ck_कुंजी_type_t CK_कुंजी_TYPE
#घोषणा ck_certificate_type_t CK_CERTIFICATE_TYPE
#घोषणा ck_attribute_type_t CK_ATTRIBUTE_TYPE

#घोषणा ck_attribute _CK_ATTRIBUTE
#घोषणा मूल्य p_मूल्य
#घोषणा मूल्य_len ul_मूल्य_Len

#घोषणा ck_date _CK_DATE

#घोषणा ck_mechanism_type_t CK_MECHANISM_TYPE

#घोषणा ck_rsa_pkcs_mgf_type_t CK_RSA_PKCS_MGF_TYPE

#घोषणा ck_mechanism _CK_MECHANISM
#घोषणा parameter pParameter
#घोषणा parameter_len ulParameterLen

#घोषणा ck_mechanism_info _CK_MECHANISM_INFO
#घोषणा min_कुंजी_आकार ul_Min_कुंजी_आकार
#घोषणा max_कुंजी_आकार ul_Max_कुंजी_आकार

#घोषणा ck_rv_t CK_RV
#घोषणा ck_notify_t CK_NOTIFY

#घोषणा ck_interface CK_INTERFACE

#घोषणा ck_function_list _CK_FUNCTION_LIST
#घोषणा ck_function_list_3_0 _CK_FUNCTION_LIST_3_0

#घोषणा ck_createmutex_t CK_CREATEMUTEX
#घोषणा ck_destroymutex_t CK_DESTROYMUTEX
#घोषणा ck_lockmutex_t CK_LOCKMUTEX
#घोषणा ck_unlockmutex_t CK_UNLOCKMUTEX

#घोषणा ck_c_initialize_args _CK_C_INITIALIZE_ARGS
#घोषणा create_mutex CreateMutex
#घोषणा destroy_mutex DestroyMutex
#घोषणा lock_mutex LockMutex
#घोषणा unlock_mutex UnlockMutex
#घोषणा reserved pReserved

#पूर्ण_अगर	/* CRYPTOKI_COMPAT */


प्रकार अचिन्हित दीर्घ ck_flags_t;

काष्ठा ck_version
{
  अचिन्हित अक्षर major;
  अचिन्हित अक्षर minor;
};


काष्ठा ck_info
{
  काष्ठा ck_version cryptoki_version;
  अचिन्हित अक्षर manufacturer_id[32];
  ck_flags_t flags;
  अचिन्हित अक्षर library_description[32];
  काष्ठा ck_version library_version;
};


प्रकार अचिन्हित दीर्घ ck_notification_t;

#घोषणा CKN_SURRENDER	(0UL)


प्रकार अचिन्हित दीर्घ ck_slot_id_t;


काष्ठा ck_slot_info
{
  अचिन्हित अक्षर slot_description[64];
  अचिन्हित अक्षर manufacturer_id[32];
  ck_flags_t flags;
  काष्ठा ck_version hardware_version;
  काष्ठा ck_version firmware_version;
};


#घोषणा CKF_TOKEN_PRESENT	(1UL << 0)
#घोषणा CKF_REMOVABLE_DEVICE	(1UL << 1)
#घोषणा CKF_HW_SLOT		(1UL << 2)
#घोषणा CKF_ARRAY_ATTRIBUTE	(1UL << 30)


काष्ठा ck_token_info
{
  अचिन्हित अक्षर label[32];
  अचिन्हित अक्षर manufacturer_id[32];
  अचिन्हित अक्षर model[16];
  अचिन्हित अक्षर serial_संख्या[16];
  ck_flags_t flags;
  अचिन्हित दीर्घ max_session_गिनती;
  अचिन्हित दीर्घ session_गिनती;
  अचिन्हित दीर्घ max_rw_session_गिनती;
  अचिन्हित दीर्घ rw_session_गिनती;
  अचिन्हित दीर्घ max_pin_len;
  अचिन्हित दीर्घ min_pin_len;
  अचिन्हित दीर्घ योग_public_memory;
  अचिन्हित दीर्घ free_public_memory;
  अचिन्हित दीर्घ योग_private_memory;
  अचिन्हित दीर्घ free_private_memory;
  काष्ठा ck_version hardware_version;
  काष्ठा ck_version firmware_version;
  अचिन्हित अक्षर utc_time[16];
};


#घोषणा CKF_RNG					(1UL << 0)
#घोषणा CKF_WRITE_PROTECTED			(1UL << 1)
#घोषणा CKF_LOGIN_REQUIRED			(1UL << 2)
#घोषणा CKF_USER_PIN_INITIALIZED		(1UL << 3)
#घोषणा CKF_RESTORE_कुंजी_NOT_NEEDED		(1UL << 5)
#घोषणा CKF_CLOCK_ON_TOKEN			(1UL << 6)
#घोषणा CKF_PROTECTED_AUTHENTICATION_PATH	(1UL << 8)
#घोषणा CKF_DUAL_CRYPTO_OPERATIONS		(1UL << 9)
#घोषणा CKF_TOKEN_INITIALIZED			(1UL << 10)
#घोषणा CKF_SECONDARY_AUTHENTICATION		(1UL << 11)
#घोषणा CKF_USER_PIN_गिनती_निचला			(1UL << 16)
#घोषणा CKF_USER_PIN_FINAL_TRY			(1UL << 17)
#घोषणा CKF_USER_PIN_LOCKED			(1UL << 18)
#घोषणा CKF_USER_PIN_TO_BE_CHANGED		(1UL << 19)
#घोषणा CKF_SO_PIN_गिनती_निचला			(1UL << 20)
#घोषणा CKF_SO_PIN_FINAL_TRY			(1UL << 21)
#घोषणा CKF_SO_PIN_LOCKED			(1UL << 22)
#घोषणा CKF_SO_PIN_TO_BE_CHANGED		(1UL << 23)

#घोषणा CK_UNAVAILABLE_INFORMATION	((अचिन्हित दीर्घ) -1)
#घोषणा CK_EFFECTIVELY_INFINITE		(0UL)


प्रकार अचिन्हित दीर्घ ck_session_handle_t;

#घोषणा CK_INVALID_HANDLE	(0UL)


प्रकार अचिन्हित दीर्घ ck_user_type_t;

#घोषणा CKU_SO			(0UL)
#घोषणा CKU_USER		(1UL)
#घोषणा CKU_CONTEXT_SPECIFIC	(2UL)


प्रकार अचिन्हित दीर्घ ck_state_t;

#घोषणा CKS_RO_PUBLIC_SESSION	(0UL)
#घोषणा CKS_RO_USER_FUNCTIONS	(1UL)
#घोषणा CKS_RW_PUBLIC_SESSION	(2UL)
#घोषणा CKS_RW_USER_FUNCTIONS	(3UL)
#घोषणा CKS_RW_SO_FUNCTIONS	(4UL)


काष्ठा ck_session_info
{
  ck_slot_id_t slot_id;
  ck_state_t state;
  ck_flags_t flags;
  अचिन्हित दीर्घ device_error;
};

#घोषणा CKF_RW_SESSION		(1UL << 1)
#घोषणा CKF_SERIAL_SESSION	(1UL << 2)


प्रकार अचिन्हित दीर्घ ck_object_handle_t;


प्रकार अचिन्हित दीर्घ ck_object_class_t;

#घोषणा CKO_तथ्य		(0UL)
#घोषणा CKO_CERTIFICATE		(1UL)
#घोषणा CKO_PUBLIC_कुंजी		(2UL)
#घोषणा CKO_PRIVATE_कुंजी		(3UL)
#घोषणा CKO_SECRET_कुंजी		(4UL)
#घोषणा CKO_HW_FEATURE		(5UL)
#घोषणा CKO_DOMAIN_PARAMETERS	(6UL)
#घोषणा CKO_MECHANISM		(7UL)
#घोषणा CKO_OTP_कुंजी		(8UL)
#घोषणा CKO_PROFILE		(9UL)
#घोषणा CKO_VENDOR_DEFINED	(1UL << 31)

#घोषणा CKP_INVALID_ID                (0UL)
#घोषणा CKP_BASELINE_PROVIDER         (1UL)
#घोषणा CKP_EXTENDED_PROVIDER         (2UL)
#घोषणा CKP_AUTHENTICATION_TOKEN      (3UL)
#घोषणा CKP_PUBLIC_CERTIFICATES_TOKEN (4UL)
#घोषणा CKP_VENDOR_DEFINED            (1UL << 31)

प्रकार अचिन्हित दीर्घ ck_hw_feature_type_t;

#घोषणा CKH_MONOTONIC_गणक	(1UL)
#घोषणा CKH_CLOCK		(2UL)
#घोषणा CKH_USER_INTERFACE	(3UL)
#घोषणा CKH_VENDOR_DEFINED	(1UL << 31)


प्रकार अचिन्हित दीर्घ ck_कुंजी_type_t;

#घोषणा CKK_RSA			(0UL)
#घोषणा CKK_DSA			(1UL)
#घोषणा CKK_DH			(2UL)
#घोषणा CKK_ECDSA		(3UL)
#घोषणा CKK_EC			(3UL)
#घोषणा CKK_X9_42_DH		(4UL)
#घोषणा CKK_KEA			(5UL)
#घोषणा CKK_GENERIC_SECRET	(0x10UL)
#घोषणा CKK_RC2			(0x11UL)
#घोषणा CKK_RC4			(0x12UL)
#घोषणा CKK_DES			(0x13UL)
#घोषणा CKK_DES2		(0x14UL)
#घोषणा CKK_DES3		(0x15UL)
#घोषणा CKK_CAST		(0x16UL)
#घोषणा CKK_CAST3		(0x17UL)
#घोषणा CKK_CAST128		(0x18UL)
#घोषणा CKK_RC5			(0x19UL)
#घोषणा CKK_IDEA		(0x1aUL)
#घोषणा CKK_SKIPJACK		(0x1bUL)
#घोषणा CKK_BATON		(0x1cUL)
#घोषणा CKK_JUNIPER		(0x1dUL)
#घोषणा CKK_CDMF		(0x1eUL)
#घोषणा CKK_AES			(0x1fUL)
#घोषणा CKK_BLOWFISH		(0x20UL)
#घोषणा CKK_TWOFISH		(0x21UL)
#घोषणा CKK_GOSTR3410		(0x30UL)
#घोषणा CKK_GOSTR3411		(0x31UL)
#घोषणा CKK_GOST28147		(0x32UL)
#घोषणा CKK_EC_EDWARDS		(0x40UL)
#घोषणा CKK_EC_MONTGOMERY	(0x41UL)
#घोषणा CKK_HKDF		(0x42UL)
#घोषणा CKK_VENDOR_DEFINED	(1UL << 31)

/*
 * A mask for new GOST algorithms.
 * For details visit https://tc26.ru/standarts/perevody/guidelines-the-pkcs-11-extensions-for-implementing-the-gost-r-34-10-2012-and-gost-r-34-11-2012-russian-standards-.html
 */
#घोषणा NSSCK_VENDOR_PKCS11_RU_TEAM     (CKK_VENDOR_DEFINED | 0x54321000)
#घोषणा CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

#घोषणा CKK_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

प्रकार अचिन्हित दीर्घ ck_certificate_type_t;

#घोषणा CKC_X_509		(0UL)
#घोषणा CKC_X_509_ATTR_CERT	(1UL)
#घोषणा CKC_WTLS		(2UL)
#घोषणा CKC_VENDOR_DEFINED	(1UL << 31)


प्रकार अचिन्हित दीर्घ ck_attribute_type_t;

#घोषणा CKA_CLASS			(0UL)
#घोषणा CKA_TOKEN			(1UL)
#घोषणा CKA_PRIVATE			(2UL)
#घोषणा CKA_LABEL			(3UL)
#घोषणा CKA_UNIQUE_ID		(4UL)
#घोषणा CKA_APPLICATION			(0x10UL)
#घोषणा CKA_मूल्य			(0x11UL)
#घोषणा CKA_OBJECT_ID			(0x12UL)
#घोषणा CKA_CERTIFICATE_TYPE		(0x80UL)
#घोषणा CKA_ISSUER			(0x81UL)
#घोषणा CKA_SERIAL_संख्या		(0x82UL)
#घोषणा CKA_AC_ISSUER			(0x83UL)
#घोषणा CKA_OWNER			(0x84UL)
#घोषणा CKA_ATTR_TYPES			(0x85UL)
#घोषणा CKA_TRUSTED			(0x86UL)
#घोषणा CKA_CERTIFICATE_CATEGORY	(0x87UL)
#घोषणा CKA_JAVA_MIDP_SECURITY_DOMAIN	(0x88UL)
#घोषणा CKA_URL				(0x89UL)
#घोषणा CKA_HASH_OF_SUBJECT_PUBLIC_कुंजी	(0x8aUL)
#घोषणा CKA_HASH_OF_ISSUER_PUBLIC_कुंजी	(0x8bUL)
#घोषणा CKA_CHECK_मूल्य			(0x90UL)
#घोषणा CKA_कुंजी_TYPE			(0x100UL)
#घोषणा CKA_SUBJECT			(0x101UL)
#घोषणा CKA_ID				(0x102UL)
#घोषणा CKA_SENSITIVE			(0x103UL)
#घोषणा CKA_ENCRYPT			(0x104UL)
#घोषणा CKA_DECRYPT			(0x105UL)
#घोषणा CKA_WRAP			(0x106UL)
#घोषणा CKA_UNWRAP			(0x107UL)
#घोषणा CKA_SIGN			(0x108UL)
#घोषणा CKA_SIGN_RECOVER		(0x109UL)
#घोषणा CKA_VERIFY			(0x10aUL)
#घोषणा CKA_VERIFY_RECOVER		(0x10bUL)
#घोषणा CKA_DERIVE			(0x10cUL)
#घोषणा CKA_START_DATE			(0x110UL)
#घोषणा CKA_END_DATE			(0x111UL)
#घोषणा CKA_MODULUS			(0x120UL)
#घोषणा CKA_MODULUS_BITS		(0x121UL)
#घोषणा CKA_PUBLIC_EXPONENT		(0x122UL)
#घोषणा CKA_PRIVATE_EXPONENT		(0x123UL)
#घोषणा CKA_अभाज्य_1			(0x124UL)
#घोषणा CKA_अभाज्य_2			(0x125UL)
#घोषणा CKA_EXPONENT_1			(0x126UL)
#घोषणा CKA_EXPONENT_2			(0x127UL)
#घोषणा CKA_COEFFICIENT			(0x128UL)
#घोषणा CKA_PUBLIC_कुंजी_INFO		(0x129UL)
#घोषणा CKA_अभाज्य			(0x130UL)
#घोषणा CKA_SUBPRIME			(0x131UL)
#घोषणा CKA_BASE			(0x132UL)
#घोषणा CKA_अभाज्य_BITS			(0x133UL)
#घोषणा CKA_SUB_अभाज्य_BITS		(0x134UL)
#घोषणा CKA_मूल्य_BITS			(0x160UL)
#घोषणा CKA_मूल्य_LEN			(0x161UL)
#घोषणा CKA_EXTRACTABLE			(0x162UL)
#घोषणा CKA_LOCAL			(0x163UL)
#घोषणा CKA_NEVER_EXTRACTABLE		(0x164UL)
#घोषणा CKA_ALWAYS_SENSITIVE		(0x165UL)
#घोषणा CKA_कुंजी_GEN_MECHANISM		(0x166UL)
#घोषणा CKA_MODIFIABLE			(0x170UL)
#घोषणा CKA_COPYABLE			(0x171UL)
#घोषणा CKA_DESTROYABLE			(0x172UL)
#घोषणा CKA_ECDSA_PARAMS		(0x180UL)
#घोषणा CKA_EC_PARAMS			(0x180UL)
#घोषणा CKA_EC_POINT			(0x181UL)
#घोषणा CKA_SECONDARY_AUTH		(0x200UL)
#घोषणा CKA_AUTH_PIN_FLAGS		(0x201UL)
#घोषणा CKA_ALWAYS_AUTHENTICATE		(0x202UL)
#घोषणा CKA_WRAP_WITH_TRUSTED		(0x210UL)
#घोषणा CKA_GOSTR3410_PARAMS		(0x250UL)
#घोषणा CKA_GOSTR3411_PARAMS		(0x251UL)
#घोषणा CKA_GOST28147_PARAMS		(0x252UL)
#घोषणा CKA_HW_FEATURE_TYPE		(0x300UL)
#घोषणा CKA_RESET_ON_INIT		(0x301UL)
#घोषणा CKA_HAS_RESET			(0x302UL)
#घोषणा CKA_PIXEL_X			(0x400UL)
#घोषणा CKA_PIXEL_Y			(0x401UL)
#घोषणा CKA_RESOLUTION			(0x402UL)
#घोषणा CKA_CHAR_ROWS			(0x403UL)
#घोषणा CKA_CHAR_COLUMNS		(0x404UL)
#घोषणा CKA_COLOR			(0x405UL)
#घोषणा CKA_BITS_PER_PIXEL		(0x406UL)
#घोषणा CKA_CHAR_SETS			(0x480UL)
#घोषणा CKA_ENCODING_METHODS		(0x481UL)
#घोषणा CKA_MIME_TYPES			(0x482UL)
#घोषणा CKA_MECHANISM_TYPE		(0x500UL)
#घोषणा CKA_REQUIRED_CMS_ATTRIBUTES	(0x501UL)
#घोषणा CKA_DEFAULT_CMS_ATTRIBUTES	(0x502UL)
#घोषणा CKA_SUPPORTED_CMS_ATTRIBUTES	(0x503UL)
#घोषणा CKA_WRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x211UL)
#घोषणा CKA_UNWRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x212UL)
#घोषणा CKA_OTP_FORMAT			(0x220UL)
#घोषणा CKA_OTP_लंबाई			(0x221UL)
#घोषणा CKA_OTP_TIME_INTERVAL		(0x222UL)
#घोषणा CKA_OTP_USER_FRIENDLY_MODE	(0x223UL)
#घोषणा CKA_OTP_CHALLENGE_REQUIREMENT	(0x224UL)
#घोषणा CKA_OTP_TIME_REQUIREMENT	(0x225UL)
#घोषणा CKA_OTP_गणक_REQUIREMENT	(0x226UL)
#घोषणा CKA_OTP_PIN_REQUIREMENT		(0x227UL)
#घोषणा CKA_OTP_USER_IDENTIFIER		(0x22AUL)
#घोषणा CKA_OTP_SERVICE_IDENTIFIER	(0x22BUL)
#घोषणा CKA_OTP_SERVICE_LOGO		(0x22CUL)
#घोषणा CKA_OTP_SERVICE_LOGO_TYPE	(0x22DUL)
#घोषणा CKA_OTP_गणक			(0x22EUL)
#घोषणा CKA_OTP_TIME			(0x22FUL)
#घोषणा CKA_ALLOWED_MECHANISMS		(CKF_ARRAY_ATTRIBUTE | 0x600UL)
#घोषणा CKA_PROFILE_ID			(0x601UL)
#घोषणा CKA_VENDOR_DEFINED		(1UL << 31)


काष्ठा ck_attribute
{
  ck_attribute_type_t type;
  व्योम *मूल्य;
  अचिन्हित दीर्घ मूल्य_len;
};


काष्ठा ck_date
{
  अचिन्हित अक्षर year[4];
  अचिन्हित अक्षर month[2];
  अचिन्हित अक्षर day[2];
};


प्रकार अचिन्हित दीर्घ ck_mechanism_type_t;

#घोषणा CKM_RSA_PKCS_कुंजी_PAIR_GEN	(0UL)
#घोषणा CKM_RSA_PKCS			(1UL)
#घोषणा CKM_RSA_9796			(2UL)
#घोषणा CKM_RSA_X_509			(3UL)
#घोषणा CKM_MD2_RSA_PKCS		(4UL)
#घोषणा CKM_MD5_RSA_PKCS		(5UL)
#घोषणा CKM_SHA1_RSA_PKCS		(6UL)
#घोषणा CKM_RIPEMD128_RSA_PKCS		(7UL)
#घोषणा CKM_RIPEMD160_RSA_PKCS		(8UL)
#घोषणा CKM_RSA_PKCS_OAEP		(9UL)
#घोषणा CKM_RSA_X9_31_कुंजी_PAIR_GEN	(0xaUL)
#घोषणा CKM_RSA_X9_31			(0xbUL)
#घोषणा CKM_SHA1_RSA_X9_31		(0xcUL)
#घोषणा CKM_RSA_PKCS_PSS		(0xdUL)
#घोषणा CKM_SHA1_RSA_PKCS_PSS		(0xeUL)
#घोषणा CKM_DSA_कुंजी_PAIR_GEN		(0x10UL)
#घोषणा	CKM_DSA				(0x11UL)
#घोषणा CKM_DSA_SHA1			(0x12UL)
#घोषणा CKM_DSA_SHA224			(0x13UL)
#घोषणा CKM_DSA_SHA256			(0x14UL)
#घोषणा CKM_DSA_SHA384			(0x15UL)
#घोषणा CKM_DSA_SHA512			(0x16UL)
#घोषणा CKM_DH_PKCS_कुंजी_PAIR_GEN	(0x20UL)
#घोषणा CKM_DH_PKCS_DERIVE		(0x21UL)
#घोषणा	CKM_X9_42_DH_कुंजी_PAIR_GEN	(0x30UL)
#घोषणा CKM_X9_42_DH_DERIVE		(0x31UL)
#घोषणा CKM_X9_42_DH_HYBRID_DERIVE	(0x32UL)
#घोषणा CKM_X9_42_MQV_DERIVE		(0x33UL)
#घोषणा CKM_SHA256_RSA_PKCS		(0x40UL)
#घोषणा CKM_SHA384_RSA_PKCS		(0x41UL)
#घोषणा CKM_SHA512_RSA_PKCS		(0x42UL)
#घोषणा CKM_SHA256_RSA_PKCS_PSS		(0x43UL)
#घोषणा CKM_SHA384_RSA_PKCS_PSS		(0x44UL)
#घोषणा CKM_SHA512_RSA_PKCS_PSS		(0x45UL)
#घोषणा CKM_SHA224_RSA_PKCS		(0x46UL)
#घोषणा CKM_SHA224_RSA_PKCS_PSS		(0x47UL)
#घोषणा CKM_SHA3_256_RSA_PKCS		(0x60UL)
#घोषणा CKM_SHA3_384_RSA_PKCS		(0x61UL)
#घोषणा CKM_SHA3_512_RSA_PKCS		(0x62UL)
#घोषणा CKM_SHA3_256_RSA_PKCS_PSS	(0x63UL)
#घोषणा CKM_SHA3_384_RSA_PKCS_PSS	(0x64UL)
#घोषणा CKM_SHA3_512_RSA_PKCS_PSS	(0x65UL)
#घोषणा CKM_SHA3_224_RSA_PKCS		(0x66UL)
#घोषणा CKM_SHA3_224_RSA_PKCS_PSS	(0x67UL)
#घोषणा CKM_RC2_कुंजी_GEN			(0x100UL)
#घोषणा CKM_RC2_ECB			(0x101UL)
#घोषणा	CKM_RC2_CBC			(0x102UL)
#घोषणा	CKM_RC2_MAC			(0x103UL)
#घोषणा CKM_RC2_MAC_GENERAL		(0x104UL)
#घोषणा CKM_RC2_CBC_PAD			(0x105UL)
#घोषणा CKM_RC4_कुंजी_GEN			(0x110UL)
#घोषणा CKM_RC4				(0x111UL)
#घोषणा CKM_DES_कुंजी_GEN			(0x120UL)
#घोषणा CKM_DES_ECB			(0x121UL)
#घोषणा CKM_DES_CBC			(0x122UL)
#घोषणा CKM_DES_MAC			(0x123UL)
#घोषणा CKM_DES_MAC_GENERAL		(0x124UL)
#घोषणा CKM_DES_CBC_PAD			(0x125UL)
#घोषणा CKM_DES2_कुंजी_GEN		(0x130UL)
#घोषणा CKM_DES3_कुंजी_GEN		(0x131UL)
#घोषणा CKM_DES3_ECB			(0x132UL)
#घोषणा CKM_DES3_CBC			(0x133UL)
#घोषणा CKM_DES3_MAC			(0x134UL)
#घोषणा CKM_DES3_MAC_GENERAL		(0x135UL)
#घोषणा CKM_DES3_CBC_PAD		(0x136UL)
#घोषणा CKM_DES3_CMAC_GENERAL		(0x137UL)
#घोषणा CKM_DES3_CMAC			(0x138UL)
#घोषणा CKM_CDMF_कुंजी_GEN		(0x140UL)
#घोषणा CKM_CDMF_ECB			(0x141UL)
#घोषणा CKM_CDMF_CBC			(0x142UL)
#घोषणा CKM_CDMF_MAC			(0x143UL)
#घोषणा CKM_CDMF_MAC_GENERAL		(0x144UL)
#घोषणा CKM_CDMF_CBC_PAD		(0x145UL)
#घोषणा CKM_MD2				(0x200UL)
#घोषणा CKM_MD2_HMAC			(0x201UL)
#घोषणा CKM_MD2_HMAC_GENERAL		(0x202UL)
#घोषणा CKM_MD5				(0x210UL)
#घोषणा CKM_MD5_HMAC			(0x211UL)
#घोषणा CKM_MD5_HMAC_GENERAL		(0x212UL)
#घोषणा CKM_SHA_1			(0x220UL)
#घोषणा CKM_SHA_1_HMAC			(0x221UL)
#घोषणा CKM_SHA_1_HMAC_GENERAL		(0x222UL)
#घोषणा CKM_RIPEMD128			(0x230UL)
#घोषणा CKM_RIPEMD128_HMAC		(0x231UL)
#घोषणा CKM_RIPEMD128_HMAC_GENERAL	(0x232UL)
#घोषणा CKM_RIPEMD160			(0x240UL)
#घोषणा CKM_RIPEMD160_HMAC		(0x241UL)
#घोषणा CKM_RIPEMD160_HMAC_GENERAL	(0x242UL)
#घोषणा CKM_SHA256			(0x250UL)
#घोषणा CKM_SHA256_HMAC			(0x251UL)
#घोषणा CKM_SHA256_HMAC_GENERAL		(0x252UL)
#घोषणा CKM_SHA224			(0x255UL)
#घोषणा CKM_SHA224_HMAC			(0x256UL)
#घोषणा CKM_SHA224_HMAC_GENERAL		(0x257UL)
#घोषणा CKM_SHA384			(0x260UL)
#घोषणा CKM_SHA384_HMAC			(0x261UL)
#घोषणा CKM_SHA384_HMAC_GENERAL		(0x262UL)
#घोषणा CKM_SHA512			(0x270UL)
#घोषणा CKM_SHA512_HMAC			(0x271UL)
#घोषणा CKM_SHA512_HMAC_GENERAL		(0x272UL)
#घोषणा CKM_SHA3_256			(0x2B0UL)
#घोषणा CKM_SHA3_256_HMAC		(0x2B1UL)
#घोषणा CKM_SHA3_256_HMAC_GENERAL	(0x2B2UL)
#घोषणा CKM_SHA3_256_कुंजी_GEN		(0x2B3UL)
#घोषणा CKM_SHA3_224			(0x2B5UL)
#घोषणा CKM_SHA3_224_HMAC		(0x2B6UL)
#घोषणा CKM_SHA3_224_HMAC_GENERAL	(0x2B7UL)
#घोषणा CKM_SHA3_224_कुंजी_GEN		(0x2B8UL)
#घोषणा CKM_SHA3_384			(0x2C0UL)
#घोषणा CKM_SHA3_384_HMAC		(0x2C1UL)
#घोषणा CKM_SHA3_384_HMAC_GENERAL	(0x2C2UL)
#घोषणा CKM_SHA3_384_कुंजी_GEN		(0x2C3UL)
#घोषणा CKM_SHA3_512			(0x2D0UL)
#घोषणा CKM_SHA3_512_HMAC		(0x2D1UL)
#घोषणा CKM_SHA3_512_HMAC_GENERAL	(0x2D2UL)
#घोषणा CKM_SHA3_512_कुंजी_GEN		(0x2D3UL)
#घोषणा CKM_CAST_कुंजी_GEN		(0x300UL)
#घोषणा CKM_CAST_ECB			(0x301UL)
#घोषणा CKM_CAST_CBC			(0x302UL)
#घोषणा CKM_CAST_MAC			(0x303UL)
#घोषणा CKM_CAST_MAC_GENERAL		(0x304UL)
#घोषणा CKM_CAST_CBC_PAD		(0x305UL)
#घोषणा CKM_CAST3_कुंजी_GEN		(0x310UL)
#घोषणा CKM_CAST3_ECB			(0x311UL)
#घोषणा CKM_CAST3_CBC			(0x312UL)
#घोषणा CKM_CAST3_MAC			(0x313UL)
#घोषणा CKM_CAST3_MAC_GENERAL		(0x314UL)
#घोषणा CKM_CAST3_CBC_PAD		(0x315UL)
#घोषणा CKM_CAST5_कुंजी_GEN		(0x320UL)
#घोषणा CKM_CAST128_कुंजी_GEN		(0x320UL)
#घोषणा CKM_CAST5_ECB			(0x321UL)
#घोषणा CKM_CAST128_ECB			(0x321UL)
#घोषणा CKM_CAST5_CBC			(0x322UL)
#घोषणा CKM_CAST128_CBC			(0x322UL)
#घोषणा CKM_CAST5_MAC			(0x323UL)
#घोषणा	CKM_CAST128_MAC			(0x323UL)
#घोषणा CKM_CAST5_MAC_GENERAL		(0x324UL)
#घोषणा CKM_CAST128_MAC_GENERAL		(0x324UL)
#घोषणा CKM_CAST5_CBC_PAD		(0x325UL)
#घोषणा CKM_CAST128_CBC_PAD		(0x325UL)
#घोषणा CKM_RC5_कुंजी_GEN			(0x330UL)
#घोषणा CKM_RC5_ECB			(0x331UL)
#घोषणा CKM_RC5_CBC			(0x332UL)
#घोषणा CKM_RC5_MAC			(0x333UL)
#घोषणा CKM_RC5_MAC_GENERAL		(0x334UL)
#घोषणा CKM_RC5_CBC_PAD			(0x335UL)
#घोषणा CKM_IDEA_कुंजी_GEN		(0x340UL)
#घोषणा CKM_IDEA_ECB			(0x341UL)
#घोषणा	CKM_IDEA_CBC			(0x342UL)
#घोषणा CKM_IDEA_MAC			(0x343UL)
#घोषणा CKM_IDEA_MAC_GENERAL		(0x344UL)
#घोषणा CKM_IDEA_CBC_PAD		(0x345UL)
#घोषणा CKM_GENERIC_SECRET_कुंजी_GEN	(0x350UL)
#घोषणा CKM_CONCATENATE_BASE_AND_कुंजी	(0x360UL)
#घोषणा CKM_CONCATENATE_BASE_AND_तथ्य	(0x362UL)
#घोषणा CKM_CONCATENATE_तथ्य_AND_BASE	(0x363UL)
#घोषणा CKM_XOR_BASE_AND_तथ्य		(0x364UL)
#घोषणा CKM_EXTRACT_कुंजी_FROM_कुंजी	(0x365UL)
#घोषणा CKM_SSL3_PRE_MASTER_कुंजी_GEN	(0x370UL)
#घोषणा CKM_SSL3_MASTER_कुंजी_DERIVE	(0x371UL)
#घोषणा CKM_SSL3_कुंजी_AND_MAC_DERIVE	(0x372UL)
#घोषणा CKM_SSL3_MASTER_कुंजी_DERIVE_DH	(0x373UL)
#घोषणा CKM_TLS_PRE_MASTER_कुंजी_GEN	(0x374UL)
#घोषणा CKM_TLS_MASTER_कुंजी_DERIVE	(0x375UL)
#घोषणा CKM_TLS_कुंजी_AND_MAC_DERIVE	(0x376UL)
#घोषणा CKM_TLS_MASTER_कुंजी_DERIVE_DH	(0x377UL)
#घोषणा CKM_SSL3_MD5_MAC		(0x380UL)
#घोषणा CKM_SSL3_SHA1_MAC		(0x381UL)
#घोषणा CKM_MD5_कुंजी_DERIVATION		(0x390UL)
#घोषणा CKM_MD2_कुंजी_DERIVATION		(0x391UL)
#घोषणा CKM_SHA1_कुंजी_DERIVATION		(0x392UL)
#घोषणा CKM_PBE_MD2_DES_CBC		(0x3a0UL)
#घोषणा CKM_PBE_MD5_DES_CBC		(0x3a1UL)
#घोषणा CKM_PBE_MD5_CAST_CBC		(0x3a2UL)
#घोषणा CKM_PBE_MD5_CAST3_CBC		(0x3a3UL)
#घोषणा CKM_PBE_MD5_CAST5_CBC		(0x3a4UL)
#घोषणा CKM_PBE_MD5_CAST128_CBC		(0x3a4UL)
#घोषणा CKM_PBE_SHA1_CAST5_CBC		(0x3a5UL)
#घोषणा CKM_PBE_SHA1_CAST128_CBC	(0x3a5UL)
#घोषणा CKM_PBE_SHA1_RC4_128		(0x3a6UL)
#घोषणा CKM_PBE_SHA1_RC4_40		(0x3a7UL)
#घोषणा CKM_PBE_SHA1_DES3_EDE_CBC	(0x3a8UL)
#घोषणा CKM_PBE_SHA1_DES2_EDE_CBC	(0x3a9UL)
#घोषणा CKM_PBE_SHA1_RC2_128_CBC	(0x3aaUL)
#घोषणा CKM_PBE_SHA1_RC2_40_CBC		(0x3abUL)
#घोषणा CKM_PKCS5_PBKD2			(0x3b0UL)
#घोषणा CKM_PBA_SHA1_WITH_SHA1_HMAC	(0x3c0UL)
#घोषणा CKM_कुंजी_WRAP_LYNKS		(0x400UL)
#घोषणा CKM_कुंजी_WRAP_SET_OAEP		(0x401UL)
#घोषणा CKM_SKIPJACK_कुंजी_GEN		(0x1000UL)
#घोषणा CKM_SKIPJACK_ECB64		(0x1001UL)
#घोषणा CKM_SKIPJACK_CBC64		(0x1002UL)
#घोषणा CKM_SKIPJACK_OFB64		(0x1003UL)
#घोषणा CKM_SKIPJACK_CFB64		(0x1004UL)
#घोषणा CKM_SKIPJACK_CFB32		(0x1005UL)
#घोषणा CKM_SKIPJACK_CFB16		(0x1006UL)
#घोषणा CKM_SKIPJACK_CFB8		(0x1007UL)
#घोषणा CKM_SKIPJACK_WRAP		(0x1008UL)
#घोषणा CKM_SKIPJACK_PRIVATE_WRAP	(0x1009UL)
#घोषणा CKM_SKIPJACK_RELAYX		(0x100aUL)
#घोषणा CKM_KEA_कुंजी_PAIR_GEN		(0x1010UL)
#घोषणा CKM_KEA_कुंजी_DERIVE		(0x1011UL)
#घोषणा CKM_FORTEZZA_TIMESTAMP		(0x1020UL)
#घोषणा CKM_BATON_कुंजी_GEN		(0x1030UL)
#घोषणा CKM_BATON_ECB128		(0x1031UL)
#घोषणा CKM_BATON_ECB96			(0x1032UL)
#घोषणा CKM_BATON_CBC128		(0x1033UL)
#घोषणा CKM_BATON_गणक		(0x1034UL)
#घोषणा CKM_BATON_SHUFFLE		(0x1035UL)
#घोषणा CKM_BATON_WRAP			(0x1036UL)
#घोषणा CKM_ECDSA_कुंजी_PAIR_GEN		(0x1040UL)
#घोषणा CKM_EC_कुंजी_PAIR_GEN		(0x1040UL)
#घोषणा CKM_ECDSA			(0x1041UL)
#घोषणा CKM_ECDSA_SHA1			(0x1042UL)
#घोषणा CKM_ECDSA_SHA224		(0x1043UL)
#घोषणा CKM_ECDSA_SHA256		(0x1044UL)
#घोषणा CKM_ECDSA_SHA384		(0x1045UL)
#घोषणा CKM_ECDSA_SHA512		(0x1046UL)
#घोषणा CKM_ECDSA_SHA3_224		(0x1047UL)
#घोषणा CKM_ECDSA_SHA3_256		(0x1048UL)
#घोषणा CKM_ECDSA_SHA3_384		(0x1049UL)
#घोषणा CKM_ECDSA_SHA3_512		(0x104AUL)
#घोषणा CKM_ECDH1_DERIVE		(0x1050UL)
#घोषणा CKM_ECDH1_COFACTOR_DERIVE	(0x1051UL)
#घोषणा CKM_ECMQV_DERIVE		(0x1052UL)
#घोषणा CKM_EC_EDWARDS_कुंजी_PAIR_GEN     (0x1055UL)
#घोषणा CKM_EC_MONTGOMERY_कुंजी_PAIR_GEN  (0x1056UL)
#घोषणा CKM_EDDSA			(0x1057UL)
#घोषणा CKM_JUNIPER_कुंजी_GEN		(0x1060UL)
#घोषणा CKM_JUNIPER_ECB128		(0x1061UL)
#घोषणा CKM_JUNIPER_CBC128		(0x1062UL)
#घोषणा CKM_JUNIPER_गणक		(0x1063UL)
#घोषणा CKM_JUNIPER_SHUFFLE		(0x1064UL)
#घोषणा CKM_JUNIPER_WRAP		(0x1065UL)
#घोषणा CKM_FASTHASH			(0x1070UL)
#घोषणा CKM_AES_कुंजी_GEN			(0x1080UL)
#घोषणा CKM_AES_ECB			(0x1081UL)
#घोषणा CKM_AES_CBC			(0x1082UL)
#घोषणा CKM_AES_MAC			(0x1083UL)
#घोषणा CKM_AES_MAC_GENERAL		(0x1084UL)
#घोषणा CKM_AES_CBC_PAD			(0x1085UL)
#घोषणा CKM_AES_CTR				(0x1086UL)
#घोषणा CKM_AES_GCM				(0x1087UL)
#घोषणा CKM_AES_CCM				(0x1088UL)
#घोषणा CKM_AES_CTS				(0x1089UL)
#घोषणा CKM_AES_CMAC			(0x108AUL)
#घोषणा CKM_AES_CMAC_GENERAL		(0x108BUL)
#घोषणा CKM_AES_XCBC_MAC		(0x108CUL)
#घोषणा CKM_AES_XCBC_MAC_96		(0x108DUL)
#घोषणा CKM_AES_GMAC			(0x108EUL)
#घोषणा CKM_BLOWFISH_कुंजी_GEN    (0x1090UL)
#घोषणा CKM_BLOWFISH_CBC        (0x1091UL)
#घोषणा CKM_TWOFISH_कुंजी_GEN     (0x1092UL)
#घोषणा CKM_TWOFISH_CBC         (0x1093UL)
#घोषणा CKM_DES_ECB_ENCRYPT_तथ्य	(0x1100UL)
#घोषणा CKM_DES_CBC_ENCRYPT_तथ्य	(0x1101UL)
#घोषणा CKM_DES3_ECB_ENCRYPT_तथ्य	(0x1102UL)
#घोषणा CKM_DES3_CBC_ENCRYPT_तथ्य	(0x1103UL)
#घोषणा CKM_AES_ECB_ENCRYPT_तथ्य	(0x1104UL)
#घोषणा CKM_AES_CBC_ENCRYPT_तथ्य	(0x1105UL)
#घोषणा CKM_GOSTR3410_कुंजी_PAIR_GEN	(0x1200UL)
#घोषणा CKM_GOSTR3410			(0x1201UL)
#घोषणा CKM_GOSTR3410_WITH_GOSTR3411	(0x1202UL)
#घोषणा CKM_GOSTR3410_कुंजी_WRAP  (0x1203UL)
#घोषणा CKM_GOSTR3410_DERIVE    (0x1204UL)
#घोषणा CKM_GOSTR3410_512_कुंजी_PAIR_GEN	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#घोषणा CKM_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#घोषणा CKM_GOSTR3410_12_DERIVE	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#घोषणा CKM_GOSTR3410_WITH_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#घोषणा CKM_GOSTR3410_WITH_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#घोषणा CKM_GOSTR3411			(0x1210UL)
#घोषणा CKM_GOSTR3411_HMAC      (0x1211UL)
#घोषणा CKM_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#घोषणा CKM_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#घोषणा CKM_GOSTR3411_12_256_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#घोषणा CKM_GOSTR3411_12_512_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#घोषणा CKM_GOST28147_कुंजी_GEN   (0x1220UL)
#घोषणा CKM_GOST28147_ECB       (0x1221UL)
#घोषणा CKM_GOST28147           (0x1222UL)
#घोषणा CKM_GOST28147_MAC       (0x1223UL)
#घोषणा CKM_GOST28147_कुंजी_WRAP  (0x1224UL)

#घोषणा CKM_DSA_PARAMETER_GEN		(0x2000UL)
#घोषणा CKM_DH_PKCS_PARAMETER_GEN	(0x2001UL)
#घोषणा CKM_X9_42_DH_PARAMETER_GEN	(0x2002UL)
#घोषणा CKM_AES_OFB			(0x2104UL)
#घोषणा CKM_AES_CFB64			(0x2105UL)
#घोषणा CKM_AES_CFB8			(0x2106UL)
#घोषणा CKM_AES_CFB128			(0x2107UL)
#घोषणा CKM_AES_CFB1			(0x2108UL)
#घोषणा CKM_AES_कुंजी_WRAP		(0x2109UL)
#घोषणा CKM_AES_कुंजी_WRAP_PAD		(0x210AUL)
#घोषणा CKM_XEDDSA			(0x4029UL)
#घोषणा CKM_HKDF_DERIVE			(0x402AUL)
#घोषणा CKM_HKDF_तथ्य			(0x402BUL)
#घोषणा CKM_HKDF_कुंजी_GEN		(0x402CUL)

#घोषणा CKM_VENDOR_DEFINED		(1UL << 31)

काष्ठा ck_mechanism
{
  ck_mechanism_type_t mechanism;
  व्योम *parameter;
  अचिन्हित दीर्घ parameter_len;
};


काष्ठा ck_mechanism_info
{
  अचिन्हित दीर्घ min_कुंजी_आकार;
  अचिन्हित दीर्घ max_कुंजी_आकार;
  ck_flags_t flags;
};

#घोषणा CKF_HW			(1UL << 0)

#घोषणा CKF_MESSAGE_ENCRYPT	(1UL << 1)
#घोषणा CKF_MESSAGE_DECRYPT	(1UL << 2)
#घोषणा CKF_MESSAGE_SIGN	(1UL << 3)
#घोषणा CKF_MESSAGE_VERIFY	(1UL << 4)
#घोषणा CKF_MULTI_MESSAGE	(1UL << 5)
#घोषणा CKF_FIND_OBJECTS	(1UL << 6)

#घोषणा CKF_ENCRYPT		(1UL << 8)
#घोषणा CKF_DECRYPT		(1UL << 9)
#घोषणा CKF_DIGEST		(1UL << 10)
#घोषणा CKF_SIGN		(1UL << 11)
#घोषणा CKF_SIGN_RECOVER	(1UL << 12)
#घोषणा CKF_VERIFY		(1UL << 13)
#घोषणा CKF_VERIFY_RECOVER	(1UL << 14)
#घोषणा CKF_GENERATE		(1UL << 15)
#घोषणा CKF_GENERATE_कुंजी_PAIR	(1UL << 16)
#घोषणा CKF_WRAP		(1UL << 17)
#घोषणा CKF_UNWRAP		(1UL << 18)
#घोषणा CKF_DERIVE		(1UL << 19)
#घोषणा CKF_EXTENSION		(1UL << 31)

#घोषणा CKF_EC_F_P			(1UL << 20)
#घोषणा CKF_EC_F_2M			(1UL << 21)
#घोषणा CKF_EC_ECPARAMETERS	(1UL << 22)
#घोषणा CKF_EC_OID		(1UL << 23)
#घोषणा CKF_EC_NAMEDCURVE	CKF_EC_OID
#घोषणा CKF_EC_UNCOMPRESS	(1UL << 24)
#घोषणा CKF_EC_COMPRESS		(1UL << 25)
#घोषणा CKF_EC_CURVENAME	(1UL << 26)

/* Flags for C_WaitForSlotEvent.  */
#घोषणा CKF_DONT_BLOCK				(1UL)

/* Flags for Key derivation */
#घोषणा CKD_NULL			(0x1UL)
#घोषणा CKD_SHA1_KDF			(0x2UL)
#घोषणा CKD_SHA224_KDF			(0x5UL)
#घोषणा CKD_SHA256_KDF			(0x6UL)
#घोषणा CKD_SHA384_KDF			(0x7UL)
#घोषणा CKD_SHA512_KDF			(0x8UL)

प्रकार काष्ठा CK_ECDH1_DERIVE_PARAMS {
	अचिन्हित दीर्घ  kdf;
	अचिन्हित दीर्घ  ul_Shared_तथ्य_Len;
	अचिन्हित अक्षर *  p_Shared_तथ्य;
	अचिन्हित दीर्घ  ul_Public_तथ्य_Len;
	अचिन्हित अक्षर *  p_Public_तथ्य;
} CK_ECDH1_DERIVE_PARAMS;

प्रकार काष्ठा CK_ECMQV_DERIVE_PARAMS {
	अचिन्हित दीर्घ kdf;
	अचिन्हित दीर्घ ul_Shared_तथ्य_Len;
	अचिन्हित अक्षर * p_Shared_तथ्य;
	अचिन्हित दीर्घ ul_Public_तथ्य_Len;
	अचिन्हित अक्षर * p_Public_तथ्य;
	अचिन्हित दीर्घ ul_Private_तथ्य_Len;
	CK_OBJECT_HANDLE h_Private_तथ्य;
	अचिन्हित दीर्घ ul_Public_तथ्य_Len2;
	अचिन्हित अक्षर * pPublicData2;
	CK_OBJECT_HANDLE public_कुंजी_2;
} CK_ECMQV_DERIVE_PARAMS;

प्रकार अचिन्हित दीर्घ ck_rsa_pkcs_mgf_type_t;
प्रकार अचिन्हित दीर्घ CK_RSA_PKCS_OAEP_SOURCE_TYPE;

प्रकार काष्ठा CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
	व्योम *p_Source_तथ्य;
	अचिन्हित दीर्घ ul_Source_तथ्य_Len;
} CK_RSA_PKCS_OAEP_PARAMS;

प्रकार काष्ठा CK_RSA_PKCS_PSS_PARAMS {
	ck_mechanism_type_t hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	अचिन्हित दीर्घ sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#घोषणा CKG_MGF1_SHA1			(0x00000001UL)
#घोषणा CKG_MGF1_SHA224		(0x00000005UL)
#घोषणा CKG_MGF1_SHA256		(0x00000002UL)
#घोषणा CKG_MGF1_SHA384		(0x00000003UL)
#घोषणा CKG_MGF1_SHA512		(0x00000004UL)
#घोषणा CKG_MGF1_SHA3_224	(0x00000006UL)
#घोषणा CKG_MGF1_SHA3_256	(0x00000007UL)
#घोषणा CKG_MGF1_SHA3_384	(0x00000008UL)
#घोषणा CKG_MGF1_SHA3_512	(0x00000009UL)

#घोषणा CKZ_तथ्य_SPECIFIED	(0x00000001UL)

प्रकार काष्ठा CK_GCM_PARAMS {
	व्योम * pIv;
	अचिन्हित दीर्घ ulIvLen;
	अचिन्हित दीर्घ ulIvBits;
	व्योम * pAAD;
	अचिन्हित दीर्घ ulAADLen;
	अचिन्हित दीर्घ ulTagBits;
} CK_GCM_PARAMS;

प्रकार काष्ठा CK_CCM_PARAMS {
	अचिन्हित दीर्घ ul_तथ्य_Len;
	अचिन्हित अक्षर *pNonce;
	अचिन्हित दीर्घ ulNonceLen;
	अचिन्हित अक्षर *pAAD;
	अचिन्हित दीर्घ ulAADLen;
	अचिन्हित दीर्घ ulMACLen;
} CK_CCM_PARAMS;

/* EDDSA */
प्रकार काष्ठा CK_EDDSA_PARAMS {
	अचिन्हित अक्षर phFlag;
	अचिन्हित दीर्घ ul_Context_तथ्य_Len;
	अचिन्हित अक्षर *p_Context_तथ्य;
} CK_EDDSA_PARAMS;

प्रकार CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

/* XEDDSA */
प्रकार काष्ठा CK_XEDDSA_PARAMS {
	अचिन्हित दीर्घ hash;
} CK_XEDDSA_PARAMS;

प्रकार CK_XEDDSA_PARAMS *CK_XEDDSA_PARAMS_PTR;

प्रकार काष्ठा CK_AES_CTR_PARAMS {
    अचिन्हित दीर्घ ul_गणक_Bits;
    अचिन्हित अक्षर cb[16];
} CK_AES_CTR_PARAMS;

प्रकार CK_AES_CTR_PARAMS *CK_AES_CTR_PARAMS_PTR;

प्रकार अचिन्हित दीर्घ CK_MAC_GENERAL_PARAMS;

प्रकार CK_MAC_GENERAL_PARAMS *CK_MAC_GENERAL_PARAMS_PTR;

प्रकार अचिन्हित दीर्घ ck_rv_t;


प्रकार ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, व्योम *application);

काष्ठा ck_interface {
  अक्षर * pInterfaceName;
  व्योम * pFunctionList;
  ck_flags_t flags;
};

#घोषणा CKF_INTERFACE_FORK_SAFE	(0x00000001UL)

/* Forward reference.  */
काष्ठा ck_function_list;
काष्ठा ck_function_list_3_0;

#घोषणा _CK_DECLARE_FUNCTION(name, args)	\
प्रकार ck_rv_t (*CK_ ## name) args;		\
ck_rv_t CK_SPEC name args

_CK_DECLARE_FUNCTION (C_Initialize, (व्योम *init_args));
_CK_DECLARE_FUNCTION (C_Finalize, (व्योम *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (काष्ठा ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (काष्ठा ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_GetSlotList,
		      (अचिन्हित अक्षर token_present, ck_slot_id_t *slot_list,
		       अचिन्हित दीर्घ *गिनती));
_CK_DECLARE_FUNCTION (C_GetSlotInfo,
		      (ck_slot_id_t slot_id, काष्ठा ck_slot_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_slot_id_t slot_id, काष्ठा ck_token_info *info));
_CK_DECLARE_FUNCTION (C_WaitForSlotEvent,
		      (ck_flags_t flags, ck_slot_id_t *slot, व्योम *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_slot_id_t slot_id,
		       ck_mechanism_type_t *mechanism_list,
		       अचिन्हित दीर्घ *गिनती));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_slot_id_t slot_id, ck_mechanism_type_t type,
		       काष्ठा ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_slot_id_t slot_id, अचिन्हित अक्षर *pin,
		       अचिन्हित दीर्घ pin_len, अचिन्हित अक्षर *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, अचिन्हित अक्षर *pin,
		       अचिन्हित दीर्घ pin_len));
_CK_DECLARE_FUNCTION (C_SetPIN,
		      (ck_session_handle_t session, अचिन्हित अक्षर *old_pin,
		       अचिन्हित दीर्घ old_len, अचिन्हित अक्षर *new_pin,
		       अचिन्हित दीर्घ new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_slot_id_t slot_id, ck_flags_t flags,
		       व्योम *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_slot_id_t slot_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       काष्ठा ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *operation_state,
		       अचिन्हित दीर्घ *operation_state_len));
_CK_DECLARE_FUNCTION (C_SetOperationState,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *operation_state,
		       अचिन्हित दीर्घ operation_state_len,
		       ck_object_handle_t encryption_कुंजी,
		       ck_object_handle_t authentication_कुंजी));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       अचिन्हित अक्षर *pin, अचिन्हित दीर्घ pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       काष्ठा ck_attribute *templ,
		       अचिन्हित दीर्घ गिनती, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       काष्ठा ck_attribute *templ, अचिन्हित दीर्घ गिनती,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_Get_Object_आकार,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       अचिन्हित दीर्घ *आकार));
_CK_DECLARE_FUNCTION (C_Get_Attribute_मूल्य,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       काष्ठा ck_attribute *templ,
		       अचिन्हित दीर्घ गिनती));
_CK_DECLARE_FUNCTION (C_Set_Attribute_मूल्य,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       काष्ठा ck_attribute *templ,
		       अचिन्हित दीर्घ गिनती));
_CK_DECLARE_FUNCTION (C_FindObjectsInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_attribute *templ,
		       अचिन्हित दीर्घ गिनती));
_CK_DECLARE_FUNCTION (C_FindObjects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       अचिन्हित दीर्घ max_object_गिनती,
		       अचिन्हित दीर्घ *object_गिनती));
_CK_DECLARE_FUNCTION (C_FindObjectsFinal,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *तथ्य, अचिन्हित दीर्घ तथ्य_len,
		       अचिन्हित अक्षर *encrypted_तथ्य,
		       अचिन्हित दीर्घ *encrypted_तथ्य_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *part, अचिन्हित दीर्घ part_len,
		       अचिन्हित अक्षर *encrypted_part,
		       अचिन्हित दीर्घ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *last_encrypted_part,
		       अचिन्हित दीर्घ *last_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *encrypted_तथ्य,
		       अचिन्हित दीर्घ encrypted_तथ्य_len,
		       अचिन्हित अक्षर *तथ्य, अचिन्हित दीर्घ *तथ्य_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *encrypted_part,
		       अचिन्हित दीर्घ encrypted_part_len,
		       अचिन्हित अक्षर *part, अचिन्हित दीर्घ *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *last_part,
		       अचिन्हित दीर्घ *last_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *तथ्य, अचिन्हित दीर्घ तथ्य_len,
		       अचिन्हित अक्षर *digest,
		       अचिन्हित दीर्घ *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *part, अचिन्हित दीर्घ part_len));
_CK_DECLARE_FUNCTION (C_Digest_कुंजी,
		      (ck_session_handle_t session, ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *digest,
		       अचिन्हित दीर्घ *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *तथ्य, अचिन्हित दीर्घ तथ्य_len,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *part, अचिन्हित दीर्घ part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *तथ्य, अचिन्हित दीर्घ तथ्य_len,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *तथ्य, अचिन्हित दीर्घ तथ्य_len,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *part, अचिन्हित दीर्घ part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ signature_len,
		       अचिन्हित अक्षर *तथ्य,
		       अचिन्हित दीर्घ *तथ्य_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *part, अचिन्हित दीर्घ part_len,
		       अचिन्हित अक्षर *encrypted_part,
		       अचिन्हित दीर्घ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *encrypted_part,
		       अचिन्हित दीर्घ encrypted_part_len,
		       अचिन्हित अक्षर *part,
		       अचिन्हित दीर्घ *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *part, अचिन्हित दीर्घ part_len,
		       अचिन्हित अक्षर *encrypted_part,
		       अचिन्हित दीर्घ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *encrypted_part,
		       अचिन्हित दीर्घ encrypted_part_len,
		       अचिन्हित अक्षर *part,
		       अचिन्हित दीर्घ *part_len));

_CK_DECLARE_FUNCTION (C_Generate_कुंजी,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       काष्ठा ck_attribute *templ,
		       अचिन्हित दीर्घ गिनती,
		       ck_object_handle_t *कुंजी));
_CK_DECLARE_FUNCTION (C_Generate_कुंजी_Pair,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       काष्ठा ck_attribute *public_कुंजी_template,
		       अचिन्हित दीर्घ public_कुंजी_attribute_गिनती,
		       काष्ठा ck_attribute *private_कुंजी_template,
		       अचिन्हित दीर्घ private_कुंजी_attribute_गिनती,
		       ck_object_handle_t *public_कुंजी,
		       ck_object_handle_t *private_कुंजी));
_CK_DECLARE_FUNCTION (C_Wrap_कुंजी,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_कुंजी,
		       ck_object_handle_t कुंजी,
		       अचिन्हित अक्षर *wrapped_कुंजी,
		       अचिन्हित दीर्घ *wrapped_कुंजी_len));
_CK_DECLARE_FUNCTION (C_Unwrap_कुंजी,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_कुंजी,
		       अचिन्हित अक्षर *wrapped_कुंजी,
		       अचिन्हित दीर्घ wrapped_कुंजी_len,
		       काष्ठा ck_attribute *templ,
		       अचिन्हित दीर्घ attribute_गिनती,
		       ck_object_handle_t *कुंजी));
_CK_DECLARE_FUNCTION (C_Derive_कुंजी,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t base_कुंजी,
		       काष्ठा ck_attribute *templ,
		       अचिन्हित दीर्घ attribute_गिनती,
		       ck_object_handle_t *कुंजी));

_CK_DECLARE_FUNCTION (C_SeedRandom,
		      (ck_session_handle_t session, अचिन्हित अक्षर *seed,
		       अचिन्हित दीर्घ seed_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       अचिन्हित अक्षर *random_data,
		       अचिन्हित दीर्घ random_len));

_CK_DECLARE_FUNCTION (C_GetFunctionStatus, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_GetInterfaceList,
		      (काष्ठा ck_interface *interfaces_list,
		       अचिन्हित दीर्घ *गिनती));
_CK_DECLARE_FUNCTION (C_GetInterface,
		      (अचिन्हित अक्षर *interface_name,
		       काष्ठा ck_version *version,
		       काष्ठा ck_interface **interface_ptr,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_LoginUser,
		      (ck_session_handle_t session,
		       ck_user_type_t user_type,
		       अचिन्हित अक्षर *pin,
		       अचिन्हित दीर्घ pin_len,
		       अचिन्हित अक्षर *username,
		       अचिन्हित दीर्घ username_len));

_CK_DECLARE_FUNCTION (C_SessionCancel,
		      (ck_session_handle_t session,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_MessageEncryptInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_EncryptMessage,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *associated_तथ्य,
		       अचिन्हित दीर्घ associated_तथ्य_len,
		       अचिन्हित अक्षर *plaintext,
		       अचिन्हित दीर्घ plaintext_len,
		       अचिन्हित अक्षर *ciphertext,
		       अचिन्हित दीर्घ *ciphertext_len));
_CK_DECLARE_FUNCTION (C_EncryptMessageBegin,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *associated_तथ्य,
		       अचिन्हित दीर्घ associated_तथ्य_len));
_CK_DECLARE_FUNCTION (C_Encrypt_Message_अग्र,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *plaintext_part,
		       अचिन्हित दीर्घ plaintext_part_len,
		       अचिन्हित अक्षर *ciphertext_part,
		       अचिन्हित दीर्घ *ciphertext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_MessageEncryptFinal,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_MessageDecryptInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_DecryptMessage,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *associated_तथ्य,
		       अचिन्हित दीर्घ associated_तथ्य_len,
		       अचिन्हित अक्षर *ciphertext,
		       अचिन्हित दीर्घ ciphertext_len,
		       अचिन्हित अक्षर *plaintext,
		       अचिन्हित दीर्घ *plaintext_len));
_CK_DECLARE_FUNCTION (C_DecryptMessageBegin,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *associated_तथ्य,
		       अचिन्हित दीर्घ associated_तथ्य_len));
_CK_DECLARE_FUNCTION (C_Decrypt_Message_अग्र,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *ciphertext_part,
		       अचिन्हित दीर्घ ciphertext_part_len,
		       अचिन्हित अक्षर *plaintext_part,
		       अचिन्हित दीर्घ *plaintext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_MessageDecryptFinal,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_MessageSignInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_SignMessage,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *तथ्य,
		       अचिन्हित दीर्घ तथ्य_len,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ *signature_len));
_CK_DECLARE_FUNCTION (C_SignMessageBegin,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len));
_CK_DECLARE_FUNCTION (C_Sign_Message_अग्र,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *तथ्य,
		       अचिन्हित दीर्घ तथ्य_len,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ *signature_len));
_CK_DECLARE_FUNCTION (C_MessageSignFinal,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_MessageVerifyInit,
		      (ck_session_handle_t session,
		       काष्ठा ck_mechanism *mechanism,
		       ck_object_handle_t कुंजी));
_CK_DECLARE_FUNCTION (C_VerifyMessage,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *तथ्य,
		       अचिन्हित दीर्घ तथ्य_len,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyMessageBegin,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len));
_CK_DECLARE_FUNCTION (C_Verify_Message_अग्र,
		      (ck_session_handle_t session,
		       व्योम *parameter,
		       अचिन्हित दीर्घ parameter_len,
		       अचिन्हित अक्षर *तथ्य,
		       अचिन्हित दीर्घ तथ्य_len,
		       अचिन्हित अक्षर *signature,
		       अचिन्हित दीर्घ signature_len));
_CK_DECLARE_FUNCTION (C_MessageVerifyFinal,
		      (ck_session_handle_t session));

/* Flags in Message-based encryption/decryption API */
#घोषणा CKF_END_OF_MESSAGE	(0x00000001UL)

काष्ठा ck_function_list
{
  काष्ठा ck_version version;
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
  CK_C_SetPIN C_SetPIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_SetOperationState C_SetOperationState;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_आकार C_Get_Object_आकार;
  CK_C_Get_Attribute_मूल्य C_Get_Attribute_मूल्य;
  CK_C_Set_Attribute_मूल्य C_Set_Attribute_मूल्य;
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
  CK_C_Digest_कुंजी C_Digest_कुंजी;
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
  CK_C_Generate_कुंजी C_Generate_कुंजी;
  CK_C_Generate_कुंजी_Pair C_Generate_कुंजी_Pair;
  CK_C_Wrap_कुंजी C_Wrap_कुंजी;
  CK_C_Unwrap_कुंजी C_Unwrap_कुंजी;
  CK_C_Derive_कुंजी C_Derive_कुंजी;
  CK_C_SeedRandom C_SeedRandom;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_GetFunctionStatus C_GetFunctionStatus;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

काष्ठा ck_function_list_3_0
{
  काष्ठा ck_version version;
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
  CK_C_SetPIN C_SetPIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_SetOperationState C_SetOperationState;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_आकार C_Get_Object_आकार;
  CK_C_Get_Attribute_मूल्य C_Get_Attribute_मूल्य;
  CK_C_Set_Attribute_मूल्य C_Set_Attribute_मूल्य;
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
  CK_C_Digest_कुंजी C_Digest_कुंजी;
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
  CK_C_Generate_कुंजी C_Generate_कुंजी;
  CK_C_Generate_कुंजी_Pair C_Generate_कुंजी_Pair;
  CK_C_Wrap_कुंजी C_Wrap_कुंजी;
  CK_C_Unwrap_कुंजी C_Unwrap_कुंजी;
  CK_C_Derive_कुंजी C_Derive_कुंजी;
  CK_C_SeedRandom C_SeedRandom;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_GetFunctionStatus C_GetFunctionStatus;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_WaitForSlotEvent C_WaitForSlotEvent;
  /* PKCS #11 3.0 functions */
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  CK_C_MessageEncryptInit C_MessageEncryptInit;
  CK_C_EncryptMessage C_EncryptMessage;
  CK_C_EncryptMessageBegin C_EncryptMessageBegin;
  CK_C_Encrypt_Message_अग्र C_Encrypt_Message_अग्र;
  CK_C_MessageEncryptFinal C_MessageEncryptFinal;
  CK_C_MessageDecryptInit C_MessageDecryptInit;
  CK_C_DecryptMessage C_DecryptMessage;
  CK_C_DecryptMessageBegin C_DecryptMessageBegin;
  CK_C_Decrypt_Message_अग्र C_Decrypt_Message_अग्र;
  CK_C_MessageDecryptFinal C_MessageDecryptFinal;
  CK_C_MessageSignInit C_MessageSignInit;
  CK_C_SignMessage C_SignMessage;
  CK_C_SignMessageBegin C_SignMessageBegin;
  CK_C_Sign_Message_अग्र C_Sign_Message_अग्र;
  CK_C_MessageSignFinal C_MessageSignFinal;
  CK_C_MessageVerifyInit C_MessageVerifyInit;
  CK_C_VerifyMessage C_VerifyMessage;
  CK_C_VerifyMessageBegin C_VerifyMessageBegin;
  CK_C_Verify_Message_अग्र C_Verify_Message_अग्र;
  CK_C_MessageVerifyFinal C_MessageVerifyFinal;
};



प्रकार ck_rv_t (*ck_createmutex_t) (व्योम **mutex);
प्रकार ck_rv_t (*ck_destroymutex_t) (व्योम *mutex);
प्रकार ck_rv_t (*ck_lockmutex_t) (व्योम *mutex);
प्रकार ck_rv_t (*ck_unlockmutex_t) (व्योम *mutex);


काष्ठा ck_c_initialize_args
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t lock_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  व्योम *reserved;
};


#घोषणा CKF_LIBRARY_CANT_CREATE_OS_THREADS	(1UL << 0)
#घोषणा CKF_OS_LOCKING_OK			(1UL << 1)

#घोषणा CKR_OK					(0UL)
#घोषणा CKR_CANCEL				(1UL)
#घोषणा CKR_HOST_MEMORY				(2UL)
#घोषणा CKR_SLOT_ID_INVALID			(3UL)
#घोषणा CKR_GENERAL_ERROR			(5UL)
#घोषणा CKR_FUNCTION_FAILED			(6UL)
#घोषणा CKR_ARGUMENTS_BAD			(7UL)
#घोषणा CKR_NO_EVENT				(8UL)
#घोषणा CKR_NEED_TO_CREATE_THREADS		(9UL)
#घोषणा CKR_CANT_LOCK				(0xaUL)
#घोषणा CKR_ATTRIBUTE_READ_ONLY			(0x10UL)
#घोषणा CKR_ATTRIBUTE_SENSITIVE			(0x11UL)
#घोषणा CKR_ATTRIBUTE_TYPE_INVALID		(0x12UL)
#घोषणा CKR_ATTRIBUTE_मूल्य_INVALID		(0x13UL)
#घोषणा CKR_ACTION_PROHIBITED			(0x1BUL)
#घोषणा CKR_तथ्य_INVALID			(0x20UL)
#घोषणा CKR_तथ्य_LEN_RANGE			(0x21UL)
#घोषणा CKR_DEVICE_ERROR			(0x30UL)
#घोषणा CKR_DEVICE_MEMORY			(0x31UL)
#घोषणा CKR_DEVICE_REMOVED			(0x32UL)
#घोषणा CKR_ENCRYPTED_तथ्य_INVALID		(0x40UL)
#घोषणा CKR_ENCRYPTED_तथ्य_LEN_RANGE		(0x41UL)
#घोषणा CKR_FUNCTION_CANCELED			(0x50UL)
#घोषणा CKR_FUNCTION_NOT_PARALLEL		(0x51UL)
#घोषणा CKR_FUNCTION_NOT_SUPPORTED		(0x54UL)
#घोषणा CKR_कुंजी_HANDLE_INVALID			(0x60UL)
#घोषणा CKR_कुंजी_आकार_RANGE			(0x62UL)
#घोषणा CKR_कुंजी_TYPE_INCONSISTENT		(0x63UL)
#घोषणा CKR_कुंजी_NOT_NEEDED			(0x64UL)
#घोषणा CKR_कुंजी_CHANGED				(0x65UL)
#घोषणा CKR_कुंजी_NEEDED				(0x66UL)
#घोषणा CKR_कुंजी_INDIGESTIBLE			(0x67UL)
#घोषणा CKR_कुंजी_FUNCTION_NOT_PERMITTED		(0x68UL)
#घोषणा CKR_कुंजी_NOT_WRAPPABLE			(0x69UL)
#घोषणा CKR_कुंजी_UNEXTRACTABLE			(0x6aUL)
#घोषणा CKR_MECHANISM_INVALID			(0x70UL)
#घोषणा CKR_MECHANISM_PARAM_INVALID		(0x71UL)
#घोषणा CKR_OBJECT_HANDLE_INVALID		(0x82UL)
#घोषणा CKR_OPERATION_ACTIVE			(0x90UL)
#घोषणा CKR_OPERATION_NOT_INITIALIZED		(0x91UL)
#घोषणा CKR_PIN_INCORRECT			(0xa0UL)
#घोषणा CKR_PIN_INVALID				(0xa1UL)
#घोषणा CKR_PIN_LEN_RANGE			(0xa2UL)
#घोषणा CKR_PIN_EXPIRED				(0xa3UL)
#घोषणा CKR_PIN_LOCKED				(0xa4UL)
#घोषणा CKR_SESSION_CLOSED			(0xb0UL)
#घोषणा CKR_SESSION_गिनती			(0xb1UL)
#घोषणा CKR_SESSION_HANDLE_INVALID		(0xb3UL)
#घोषणा CKR_SESSION_PARALLEL_NOT_SUPPORTED	(0xb4UL)
#घोषणा CKR_SESSION_READ_ONLY			(0xb5UL)
#घोषणा CKR_SESSION_EXISTS			(0xb6UL)
#घोषणा CKR_SESSION_READ_ONLY_EXISTS		(0xb7UL)
#घोषणा CKR_SESSION_READ_WRITE_SO_EXISTS	(0xb8UL)
#घोषणा CKR_SIGNATURE_INVALID			(0xc0UL)
#घोषणा CKR_SIGNATURE_LEN_RANGE			(0xc1UL)
#घोषणा CKR_TEMPLATE_INCOMPLETE			(0xd0UL)
#घोषणा CKR_TEMPLATE_INCONSISTENT		(0xd1UL)
#घोषणा CKR_TOKEN_NOT_PRESENT			(0xe0UL)
#घोषणा CKR_TOKEN_NOT_RECOGNIZED		(0xe1UL)
#घोषणा CKR_TOKEN_WRITE_PROTECTED		(0xe2UL)
#घोषणा	CKR_UNWRAPPING_कुंजी_HANDLE_INVALID	(0xf0UL)
#घोषणा CKR_UNWRAPPING_कुंजी_आकार_RANGE		(0xf1UL)
#घोषणा CKR_UNWRAPPING_कुंजी_TYPE_INCONSISTENT	(0xf2UL)
#घोषणा CKR_USER_ALREADY_LOGGED_IN		(0x100UL)
#घोषणा CKR_USER_NOT_LOGGED_IN			(0x101UL)
#घोषणा CKR_USER_PIN_NOT_INITIALIZED		(0x102UL)
#घोषणा CKR_USER_TYPE_INVALID			(0x103UL)
#घोषणा CKR_USER_ANOTHER_ALREADY_LOGGED_IN	(0x104UL)
#घोषणा CKR_USER_TOO_MANY_TYPES			(0x105UL)
#घोषणा CKR_WRAPPED_कुंजी_INVALID			(0x110UL)
#घोषणा CKR_WRAPPED_कुंजी_LEN_RANGE		(0x112UL)
#घोषणा CKR_WRAPPING_कुंजी_HANDLE_INVALID		(0x113UL)
#घोषणा CKR_WRAPPING_कुंजी_आकार_RANGE		(0x114UL)
#घोषणा CKR_WRAPPING_कुंजी_TYPE_INCONSISTENT	(0x115UL)
#घोषणा CKR_RANDOM_SEED_NOT_SUPPORTED		(0x120UL)
#घोषणा CKR_RANDOM_NO_RNG			(0x121UL)
#घोषणा CKR_DOMAIN_PARAMS_INVALID		(0x130UL)
#घोषणा CKR_CURVE_NOT_SUPPORTED			(0x140UL)
#घोषणा CKR_बफर_TOO_SMALL			(0x150UL)
#घोषणा CKR_SAVED_STATE_INVALID			(0x160UL)
#घोषणा CKR_INFORMATION_SENSITIVE		(0x170UL)
#घोषणा CKR_STATE_UNSAVEABLE			(0x180UL)
#घोषणा CKR_CRYPTOKI_NOT_INITIALIZED		(0x190UL)
#घोषणा CKR_CRYPTOKI_ALREADY_INITIALIZED	(0x191UL)
#घोषणा CKR_MUTEX_BAD				(0x1a0UL)
#घोषणा CKR_MUTEX_NOT_LOCKED			(0x1a1UL)
#घोषणा CKR_FUNCTION_REJECTED			(0x200UL)
#घोषणा CKR_VENDOR_DEFINED			(1UL << 31)


/* Compatibility layer.  */

#अगर_घोषित CRYPTOKI_COMPAT

#अघोषित CK_DEFINE_FUNCTION
#घोषणा CK_DEFINE_FUNCTION(retval, name) retval CK_SPEC name

/* For NULL.  */
#समावेश <stddef.h>

प्रकार अचिन्हित अक्षर CK_BYTE;
प्रकार अचिन्हित अक्षर CK_CHAR;
प्रकार अचिन्हित अक्षर CK_UTF8CHAR;
प्रकार अचिन्हित अक्षर CK_BBOOL;
प्रकार अचिन्हित दीर्घ पूर्णांक CK_ULONG;
प्रकार दीर्घ पूर्णांक CK_LONG;
प्रकार CK_BYTE *CK_BYTE_PTR;
प्रकार CK_CHAR *CK_CHAR_PTR;
प्रकार CK_UTF8CHAR *CK_UTF8CHAR_PTR;
प्रकार CK_ULONG *CK_ULONG_PTR;
प्रकार व्योम *CK_VOID_PTR;
प्रकार व्योम **CK_VOID_PTR_PTR;
#घोषणा CK_FALSE 0
#घोषणा CK_TRUE 1
#अगर_अघोषित CK_DISABLE_TRUE_FALSE
#अगर_अघोषित FALSE
#घोषणा FALSE 0
#पूर्ण_अगर
#अगर_अघोषित TRUE
#घोषणा TRUE 1
#पूर्ण_अगर
#पूर्ण_अगर

प्रकार काष्ठा CK_HKDF_PARAMS {
	CK_BBOOL bExtract;
	CK_BBOOL bExpand;
	CK_MECHANISM_TYPE prfHashMechanism;
	CK_ULONG ulSaltType;
	CK_BYTE_PTR pSalt;
	CK_ULONG ulSaltLen;
	CK_OBJECT_HANDLE h_Salt_कुंजी;
	CK_BYTE_PTR pInfo;
	CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

#घोषणा CKF_HKDF_SALT_NULL 0x00000001UL
#घोषणा CKF_HKDF_SALT_तथ्य 0x00000002UL
#घोषणा CKF_HKDF_SALT_कुंजी  0x00000004UL

प्रकार काष्ठा ck_version CK_VERSION;
प्रकार काष्ठा ck_version *CK_VERSION_PTR;

प्रकार काष्ठा ck_info CK_INFO;
प्रकार काष्ठा ck_info *CK_INFO_PTR;

प्रकार ck_slot_id_t *CK_SLOT_ID_PTR;

प्रकार काष्ठा ck_slot_info CK_SLOT_INFO;
प्रकार काष्ठा ck_slot_info *CK_SLOT_INFO_PTR;

प्रकार काष्ठा ck_token_info CK_TOKEN_INFO;
प्रकार काष्ठा ck_token_info *CK_TOKEN_INFO_PTR;

प्रकार ck_session_handle_t *CK_SESSION_HANDLE_PTR;

प्रकार काष्ठा ck_session_info CK_SESSION_INFO;
प्रकार काष्ठा ck_session_info *CK_SESSION_INFO_PTR;

प्रकार ck_object_handle_t *CK_OBJECT_HANDLE_PTR;

प्रकार ck_object_class_t *CK_OBJECT_CLASS_PTR;

प्रकार काष्ठा ck_attribute CK_ATTRIBUTE;
प्रकार काष्ठा ck_attribute *CK_ATTRIBUTE_PTR;

प्रकार काष्ठा ck_date CK_DATE;
प्रकार काष्ठा ck_date *CK_DATE_PTR;

प्रकार ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;

प्रकार ck_rsa_pkcs_mgf_type_t *CK_RSA_PKCS_MGF_TYPE_PTR;

प्रकार काष्ठा ck_mechanism CK_MECHANISM;
प्रकार काष्ठा ck_mechanism *CK_MECHANISM_PTR;

प्रकार काष्ठा ck_mechanism_info CK_MECHANISM_INFO;
प्रकार काष्ठा ck_mechanism_info *CK_MECHANISM_INFO_PTR;

प्रकार काष्ठा ck_interface CK_INTERFACE;
प्रकार काष्ठा ck_interface *CK_INTERFACE_PTR;
प्रकार काष्ठा ck_interface **CK_INTERFACE_PTR_PTR;

प्रकार काष्ठा ck_function_list CK_FUNCTION_LIST;
प्रकार काष्ठा ck_function_list *CK_FUNCTION_LIST_PTR;
प्रकार काष्ठा ck_function_list **CK_FUNCTION_LIST_PTR_PTR;

प्रकार काष्ठा ck_function_list_3_0 CK_FUNCTION_LIST_3_0;
प्रकार काष्ठा ck_function_list_3_0 *CK_FUNCTION_LIST_3_0_PTR;
प्रकार काष्ठा ck_function_list_3_0 **CK_FUNCTION_LIST_3_0_PTR_PTR;

प्रकार काष्ठा ck_c_initialize_args CK_C_INITIALIZE_ARGS;
प्रकार काष्ठा ck_c_initialize_args *CK_C_INITIALIZE_ARGS_PTR;

#घोषणा NULL_PTR शून्य

/* Delete the helper macros defined at the top of the file.  */
#अघोषित ck_flags_t
#अघोषित ck_version

#अघोषित ck_info
#अघोषित cryptoki_version
#अघोषित manufacturer_id
#अघोषित library_description
#अघोषित library_version

#अघोषित ck_notification_t
#अघोषित ck_slot_id_t

#अघोषित ck_slot_info
#अघोषित slot_description
#अघोषित hardware_version
#अघोषित firmware_version

#अघोषित ck_token_info
#अघोषित serial_संख्या
#अघोषित max_session_गिनती
#अघोषित session_गिनती
#अघोषित max_rw_session_गिनती
#अघोषित rw_session_गिनती
#अघोषित max_pin_len
#अघोषित min_pin_len
#अघोषित योग_public_memory
#अघोषित free_public_memory
#अघोषित योग_private_memory
#अघोषित free_private_memory
#अघोषित utc_time

#अघोषित ck_session_handle_t
#अघोषित ck_user_type_t
#अघोषित ck_state_t

#अघोषित ck_session_info
#अघोषित slot_id
#अघोषित device_error

#अघोषित ck_object_handle_t
#अघोषित ck_object_class_t
#अघोषित ck_hw_feature_type_t
#अघोषित ck_कुंजी_type_t
#अघोषित ck_certificate_type_t
#अघोषित ck_attribute_type_t

#अघोषित ck_attribute
#अघोषित मूल्य
#अघोषित मूल्य_len

#अघोषित ck_date

#अघोषित ck_mechanism_type_t

#अघोषित ck_rsa_pkcs_mgf_type_t

#अघोषित ck_mechanism
#अघोषित parameter
#अघोषित parameter_len

#अघोषित ck_mechanism_info
#अघोषित min_कुंजी_आकार
#अघोषित max_कुंजी_आकार

#अघोषित ck_rv_t
#अघोषित ck_notify_t

#अघोषित ck_interface

#अघोषित ck_function_list
#अघोषित ck_function_list_3_0

#अघोषित ck_createmutex_t
#अघोषित ck_destroymutex_t
#अघोषित ck_lockmutex_t
#अघोषित ck_unlockmutex_t

#अघोषित ck_c_initialize_args
#अघोषित create_mutex
#अघोषित destroy_mutex
#अघोषित lock_mutex
#अघोषित unlock_mutex
#अघोषित reserved

#पूर्ण_अगर	/* CRYPTOKI_COMPAT */

/* System dependencies.  */
#अगर defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#आशय pack(निकालो, cryptoki)
#पूर्ण_अगर

#अगर defined(__cplusplus)
}
#पूर्ण_अगर

#पूर्ण_अगर	/* PKCS11_H */
