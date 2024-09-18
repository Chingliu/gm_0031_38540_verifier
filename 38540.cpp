#include "38540.h"


ASN1_SEQUENCE(SESv1_ExtensionData) {
  ASN1_SIMPLE(SESv1_ExtensionData, extnID, ASN1_OBJECT),
  ASN1_SIMPLE(SESv1_ExtensionData, critical, ASN1_BOOLEAN),
    ASN1_SIMPLE(SESv1_ExtensionData, extnValue, ASN1_OCTET_STRING)
} static_ASN1_NDEF_SEQUENCE_END(SESv1_ExtensionData)
IMPLEMENT_ASN1_FUNCTIONS(SESv1_ExtensionData)

ASN1_SEQUENCE(CertDigestObj)  {
    ASN1_SIMPLE(CertDigestObj, type, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(CertDigestObj, value, ASN1_OCTET_STRING)
} static_ASN1_NDEF_SEQUENCE_END(CertDigestObj)
IMPLEMENT_ASN1_FUNCTIONS(CertDigestObj)

ASN1_SEQUENCE(SES_Header)  {
    ASN1_SIMPLE(SES_Header, id, ASN1_IA5STRING),
      ASN1_SIMPLE(SES_Header, version, ASN1_INTEGER),
    ASN1_SIMPLE(SES_Header, vid, ASN1_IA5STRING)
} static_ASN1_NDEF_SEQUENCE_END(SES_Header)
IMPLEMENT_ASN1_FUNCTIONS(SES_Header)

ASN1_SEQUENCE(SES_ESPictureInfo)  {
    ASN1_SIMPLE(SES_ESPictureInfo, type, ASN1_IA5STRING),
    ASN1_SIMPLE(SES_ESPictureInfo, data, ASN1_OCTET_STRING),
      ASN1_SIMPLE(SES_ESPictureInfo, width, ASN1_INTEGER),
      ASN1_SIMPLE(SES_ESPictureInfo, height, ASN1_INTEGER)
} static_ASN1_NDEF_SEQUENCE_END(SES_ESPictureInfo)
IMPLEMENT_ASN1_FUNCTIONS(SES_ESPictureInfo)

ASN1_SEQUENCE(SESv2_ESPropertyInfo)  {
      ASN1_SIMPLE(SESv2_ESPropertyInfo, type, ASN1_INTEGER),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, name, ASN1_UTF8STRING),
    ASN1_SEQUENCE_OF(SESv2_ESPropertyInfo, certs, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, createDate, ASN1_UTCTIME),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, validStart, ASN1_UTCTIME),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, validEnd, ASN1_UTCTIME)
} static_ASN1_NDEF_SEQUENCE_END(SESv2_ESPropertyInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_ESPropertyInfo)

ASN1_SEQUENCE(SESv4_ESPropertyInfo)  {
    ASN1_SIMPLE(SESv4_ESPropertyInfo, type, ASN1_INTEGER),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, name, ASN1_UTF8STRING),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, certListType, ASN1_INTEGER),
    ASN1_SEQUENCE_OF_OPT(SESv4_ESPropertyInfo, certs, ASN1_OCTET_STRING),
    ASN1_SEQUENCE_OF_OPT(SESv4_ESPropertyInfo, certDigestList, CertDigestObj),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, createDate, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, validStart, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, validEnd, ASN1_GENERALIZEDTIME)
} static_ASN1_NDEF_SEQUENCE_END(SESv4_ESPropertyInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv4_ESPropertyInfo)

ASN1_SEQUENCE(SESv2_SealInfo)  {
    ASN1_SIMPLE(SESv2_SealInfo, header, SES_Header),
    ASN1_SIMPLE(SESv2_SealInfo, esid, ASN1_IA5STRING),
    ASN1_SIMPLE(SESv2_SealInfo, property, SESv2_ESPropertyInfo),
    ASN1_SIMPLE(SESv2_SealInfo, picture, SES_ESPictureInfo),
    ASN1_SEQUENCE_OF_OPT(SESv2_SealInfo, extDatas, SESv1_ExtensionData)
} static_ASN1_NDEF_SEQUENCE_END(SESv2_SealInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_SealInfo)

ASN1_SEQUENCE(SESv4_SealInfo)  {
    ASN1_SIMPLE(SESv4_SealInfo, header, SES_Header),
    ASN1_SIMPLE(SESv4_SealInfo, esid, ASN1_IA5STRING),
    ASN1_SIMPLE(SESv4_SealInfo, property, SESv4_ESPropertyInfo),
    ASN1_SIMPLE(SESv4_SealInfo, picture, SES_ESPictureInfo),
    ASN1_SEQUENCE_OF_OPT(SESv4_SealInfo, extDatas, SESv1_ExtensionData)
} static_ASN1_NDEF_SEQUENCE_END(SESv4_SealInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv4_SealInfo)

ASN1_SEQUENCE(SESv2_SignInfo)  {
    ASN1_SIMPLE(SESv2_SignInfo, cert, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SESv2_SignInfo, signalgid, ASN1_OBJECT),
    ASN1_SIMPLE(SESv2_SignInfo, signedvalue, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SESv2_SignInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_SignInfo)

ASN1_SEQUENCE(SESv2_Seal)  {
    ASN1_SIMPLE(SESv2_Seal, sealinfo, SESv2_SealInfo),
    ASN1_SIMPLE(SESv2_Seal, signinfo, SESv2_SignInfo)
} ASN1_SEQUENCE_END(SESv2_Seal)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_Seal)

ASN1_SEQUENCE(SESv4_Seal)  {
    ASN1_SIMPLE(SESv4_Seal, sealinfo, SESv4_SealInfo),
    ASN1_SIMPLE(SESv4_Seal, cert, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SESv4_Seal, signalgid, ASN1_OBJECT),
    ASN1_SIMPLE(SESv4_Seal, signedvalue, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SESv4_Seal)
IMPLEMENT_ASN1_FUNCTIONS(SESv4_Seal)

ASN1_SEQUENCE(TBSv2_Sign)  {
    ASN1_SIMPLE(TBSv2_Sign, version, ASN1_INTEGER),
    ASN1_SIMPLE(TBSv2_Sign, eseal, SESv2_Seal),
    ASN1_SIMPLE(TBSv2_Sign, timeinfo, ASN1_BIT_STRING),
    ASN1_SIMPLE(TBSv2_Sign, datahash, ASN1_BIT_STRING),
    ASN1_SIMPLE(TBSv2_Sign, propertyinfo, ASN1_IA5STRING),
    ASN1_SIMPLE(TBSv2_Sign, cert, ASN1_OCTET_STRING),
    ASN1_SIMPLE(TBSv2_Sign, signalgid, ASN1_OBJECT)
} static_ASN1_NDEF_SEQUENCE_END(TBSv2_Sign)
IMPLEMENT_ASN1_FUNCTIONS(TBSv2_Sign)

ASN1_SEQUENCE(TBSv4_Sign)  {
    ASN1_SIMPLE(TBSv4_Sign, version, ASN1_INTEGER),
    ASN1_SIMPLE(TBSv4_Sign, eseal, SESv4_Seal),
    ASN1_SIMPLE(TBSv4_Sign, timeinfo, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(TBSv4_Sign, datahash, ASN1_BIT_STRING),
    ASN1_SIMPLE(TBSv4_Sign, propertyinfo, ASN1_IA5STRING),
    ASN1_SEQUENCE_OF_OPT(TBSv4_Sign, extDatas, X509_EXTENSION)
} static_ASN1_NDEF_SEQUENCE_END(TBSv4_Sign)
IMPLEMENT_ASN1_FUNCTIONS(TBSv4_Sign)

ASN1_SEQUENCE(SESv2_Signature)  {
    ASN1_SIMPLE(SESv2_Signature, tosign, TBSv2_Sign),
    ASN1_SIMPLE(SESv2_Signature, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SESv2_Signature)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_Signature)

ASN1_SEQUENCE(SESv4_Signature)  {
    ASN1_SIMPLE(SESv4_Signature, tosign, TBSv4_Sign),
    ASN1_SIMPLE(SESv4_Signature, cert, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SESv4_Signature, signalgid, ASN1_OBJECT),
    ASN1_SIMPLE(SESv4_Signature, signedvalue, ASN1_BIT_STRING),
    ASN1_OPT(SESv4_Signature, timestamp, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SESv4_Signature)
IMPLEMENT_ASN1_FUNCTIONS(SESv4_Signature)

namespace gm {

      void v4deleter(SESv4_Signature* ptr) {
        if (ptr)SESv4_Signature_free(ptr);
      }
      void v2deleter(SESv2_Signature* ptr) {
        if (ptr)SESv2_Signature_free(ptr);
      }

      C38540::C38540(const unsigned char *data, long len):m_psign(d2i_SESv4_Signature(NULL, &data, len), &v4deleter){

      }
      C38540::~C38540() {

      }

      int C38540::sign_verify(void *sign_handler, unsigned char * digest, long digest_len) {
        return 0;
      }
      int C38540::sign_get_cert() {
        return 0;
      }
      int C38540::sign_get_picture() {
        return 0;
      }
      int C38540::sign_get_seal_name() {
        return 0;
      }



      C0031::C0031(const unsigned char *data, long len) :m_psign(d2i_SESv2_Signature(NULL, &data, len), &v2deleter) {

      }
      C0031::~C0031() {

      }

      int C0031::sign_verify(void *sign_handler, unsigned char * digest, long digest_len) {
        return 0;
      }
      int C0031::sign_get_cert() {
        return 0;
      }
      int C0031::sign_get_picture() {
        return 0;
      }
      int C0031::sign_get_seal_name() {
        return 0;
      }
}