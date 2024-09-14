
#include "GMTSignedData.h"
 
ASN1_NDEF_SEQUENCE(SM2_SIGNED) = {
		ASN1_SIMPLE(SM2_SIGNED, version, ASN1_INTEGER),
		ASN1_SET_OF(SM2_SIGNED, md_algs, X509_ALGOR),
		ASN1_SIMPLE(SM2_SIGNED, contents, SM2ContentInfo),
		ASN1_IMP_SEQUENCE_OF_OPT(SM2_SIGNED, cert, X509, 0),
		ASN1_IMP_SET_OF_OPT(SM2_SIGNED, crl, X509_CRL, 1),
		ASN1_SET_OF(SM2_SIGNED, signer_info, PKCS7_SIGNER_INFO)
} ASN1_NDEF_SEQUENCE_END(SM2_SIGNED)
 
IMPLEMENT_ASN1_FUNCTIONS(SM2_SIGNED)
 
ASN1_CHOICE(SM2_SignedData) =
{
	ASN1_SIMPLE(SM2_SignedData, d.data, ASN1_OCTET_STRING),
	ASN1_OPT(SM2_SignedData, d.sign, SM2_SIGNED),
	ASN1_OPT(SM2_SignedData, d.enveloped, PKCS7_ENVELOPE),
	ASN1_OPT(SM2_SignedData, d.signed_and_enveloped, PKCS7_SIGN_ENVELOPE),
	ASN1_OPT(SM2_SignedData, d.digest, PKCS7_DIGEST),
	ASN1_OPT(SM2_SignedData, d.encrypted, PKCS7_ENCRYPT),
	ASN1_OPT(SM2_SignedData, d.other, ASN1_ANY)
}ASN1_CHOICE_END(SM2_SignedData)
IMPLEMENT_ASN1_FUNCTIONS(SM2_SignedData)
 
ASN1_SEQUENCE(SM2ContentInfo) =
{
	ASN1_SIMPLE(SM2ContentInfo, type, ASN1_OBJECT),
	ASN1_EXP(SM2ContentInfo, sd, SM2_SignedData, 0)
}ASN1_SEQUENCE_END(SM2ContentInfo)
IMPLEMENT_ASN1_FUNCTIONS(SM2ContentInfo)

/*
void test()
{
    //puchData为数据内容，nDataLen为数据长度。自行定义。
    SM2ContentInfo* p7 = NULL;
 
	p7 = d2i_SM2ContentInfo(&p7, &puchData, nDataLen);
 
	char oid1[255] = { 0 };
	OBJ_obj2txt(oid1, 255, p7->type, 0);
}
*/
 