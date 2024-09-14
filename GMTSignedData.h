#ifndef _GMTSignedData_H
#define _GMTSignedData_H
 
#include <openssl\asn1.h>
#include <openssl\asn1t.h>
#include <openssl\safestack.h>
#include <openssl\evp.h>
#include <openssl\pkcs7.h>
#include <openssl\x509.h>
 
# ifdef __cplusplus
extern "C" {
# endif
 
/*oid refer to GM/T 0006*/
#define OID_SM2_1 "1.2.156.10197.1.301.1"           /*sm2-1 数字签名算法 */
#define OID_SM2_3 "1.2.156.10197.1.301.3"           /*sm2-3 公钥加密算法*/
#define OID_SM3 "1.2.156.10197.1.401"               /*SM3密码杂凑算法*/
#define OID_SM4 "1.2.156.10197.1.104"               /*SM4分组密码算法*/
 
/*oid refer to GM/T 0010*/
#define OID_SM2_Data               "1.2.156.10197.6.1.4.2.1"    //SM2算法消息语法规范- 数据类型
#define OID_SM2_Signed             "1.2.156.10197.6.1.4.2.2"    //SM2算法消息语法规范- 签名数据类型
#define OID_SM2_Enveloped          "1.2.156.10197.6.1.4.2.3"    //SM2算法消息语法规范- 数字信封数据类型  
#define OID_SM2_SignedAndEnveloped "1.2.156.10197.6.1.4.2.4"    //SM2算法消息语法规范- 签名及数字信封数据类型
#define OID_SM2_Encrypted          "1.2.156.10197.6.1.4.2.5"    //SM2算法消息语法规范- 加密数据类型
#define OID_SM2_KeyAgreementInfo   "1.2.156.10197.6.1.4.2.6"    //SM2算法消息语法规范- 密钥协商数据类型
 
typedef struct sm2_signed_st {
	ASN1_INTEGER *version;      /* version 1 */
	STACK_OF(X509_ALGOR) *md_algs; /* md used */
	struct SM2ContentInfo_st *contents;
	STACK_OF(X509) *cert;       /* [ 0 ] */
	STACK_OF(X509_CRL) *crl;    /* [ 1 ] */
	STACK_OF(PKCS7_SIGNER_INFO) *signer_info;
} SM2_SIGNED;
 
typedef struct SM2_SignedData_st {
	int type;
	union {
		/* NID_pkcs7_data */
		ASN1_OCTET_STRING *data;
		/* sm2_signed */
		SM2_SIGNED *sign;
		/* NID_pkcs7_enveloped */
		PKCS7_ENVELOPE *enveloped;
		/* NID_pkcs7_signedAndEnveloped */
		PKCS7_SIGN_ENVELOPE *signed_and_enveloped;
		/* NID_pkcs7_digest */
		PKCS7_DIGEST *digest;
		/* NID_pkcs7_encrypted */
		PKCS7_ENCRYPT *encrypted;
		/* Anything else */
		ASN1_TYPE *other;
	} d;
} SM2_SignedData;
 
DECLARE_ASN1_FUNCTIONS(SM2_SignedData)
 
typedef	struct SM2ContentInfo_st
{
	ASN1_OBJECT *type;
	SM2_SignedData* sd;
} SM2ContentInfo;
 
DECLARE_ASN1_FUNCTIONS(SM2ContentInfo)
 
 
#  ifdef  __cplusplus
}
#  endif
 
#endif	//_GMTSignedData_H