#include "openssl\asn1.h"
#include "openssl\asn1t.h"
#include "openssl\x509.h"
typedef struct CertDigestObj_t {
    ASN1_PRINTABLESTRING *type;
    ASN1_OCTET_STRING *value;
}CertDigestObj;
DECLARE_ASN1_FUNCTIONS(CertDigestObj);
// 印章头
typedef struct SES_Header_t {
    ASN1_IA5STRING *id; //标识固定为ES
    ASN1_INTEGER *version; //印章版本号
    ASN1_IA5STRING *vid; //厂商标识
}SES_Header;
DECLARE_ASN1_FUNCTIONS(SES_Header);
typedef struct SES_ESPictureInfo_t {
    ASN1_IA5STRING *type; //印章图片类型png, jpg等
    ASN1_OCTET_STRING *data; //印章图片数据
    ASN1_INTEGER *width; //印章宽度,单位毫米
    ASN1_INTEGER *height; //印章高度,单位毫米
}SES_ESPictureInfo;
DECLARE_ASN1_FUNCTIONS(SES_ESPictureInfo);

/*GMT0031-2014 安全电子签章密码应用技术规范 */
typedef struct SESv1_ESPropertyInfo_t {
    ASN1_INTEGER  *type; //印章类型
    ASN1_UTF8STRING *name; //印章名称
    STACK_OF(ASN1_OCTET_STRING) *certs; //签章者的列表&#xff08;最终用章的人的证书列表&#xff09;
    ASN1_UTCTIME *createDate;
    ASN1_UTCTIME *validStart;
    ASN1_UTCTIME *validEnd;
}SESv2_ESPropertyInfo;
DECLARE_ASN1_FUNCTIONS(SESv2_ESPropertyInfo);

typedef struct SESv1_ExtensionData_t {
  ASN1_OBJECT *extnID;
  ASN1_BOOLEAN *critical;
  ASN1_OCTET_STRING *extnValue;
}SESv1_ExtensionData;
DECLARE_ASN1_FUNCTIONS(SESv1_ExtensionData);
typedef struct SESv1_SealInfo_t {
    SES_Header *header;
    ASN1_IA5STRING *esid; // 印章的唯一标识码
    SESv2_ESPropertyInfo *property;
    SES_ESPictureInfo *picture;
    STACK_OF(SESv1_ExtensionData) *extDatas;
}SESv2_SealInfo;
DECLARE_ASN1_FUNCTIONS(SESv2_SealInfo);

typedef struct SESv2_SignInfo_t {
    ASN1_OCTET_STRING *cert;
    ASN1_OBJECT *signalgid;
    ASN1_BIT_STRING *signedvalue;
}SESv2_SignInfo;
DECLARE_ASN1_FUNCTIONS(SESv2_SignInfo);
typedef struct SESv2_Seal_t {
    SESv2_SealInfo *sealinfo;
    SESv2_SignInfo *signinfo;
}SESv2_Seal;
DECLARE_ASN1_FUNCTIONS(SESv2_Seal);

typedef struct TBSv2_Sign_t {
    ASN1_INTEGER *version;
    SESv2_Seal *eseal;
    ASN1_BIT_STRING *timeinfo;
    ASN1_BIT_STRING *datahash;
    ASN1_IA5STRING *propertyinfo;
    ASN1_OCTET_STRING *cert;
    ASN1_OBJECT *signalgid;
}TBSv2_Sign;
DECLARE_ASN1_FUNCTIONS(TBSv2_Sign);

typedef struct SESv2_Signature_t {
    TBSv2_Sign *tosign;
    ASN1_BIT_STRING *signature;
}SESv2_Signature;
DECLARE_ASN1_FUNCTIONS(SESv2_Signature);


/*GB∕T 38540-2020信息安全技术 安全电子签章密码技术规范*/
typedef struct SESv4_ESPropertyInfo_t {
  ASN1_INTEGER  *type;
  ASN1_UTF8STRING *name;
  ASN1_INTEGER *certListType; //v4版本 有类型,证书列表或者证书摘要的列表
  STACK_OF(ASN1_OCTET_STRING) *certs;
  STACK_OF(CertDigestObj) *certDigestList;
  ASN1_GENERALIZEDTIME *createDate;
  ASN1_GENERALIZEDTIME *validStart;
  ASN1_GENERALIZEDTIME *validEnd;
}SESv4_ESPropertyInfo;
DECLARE_ASN1_FUNCTIONS(SESv4_ESPropertyInfo);
typedef struct SESv4_SealInfo_t {
  SES_Header *header;
  ASN1_IA5STRING *esid;
  SESv4_ESPropertyInfo *property;
  SES_ESPictureInfo *picture;
  STACK_OF(SESv1_ExtensionData) *extDatas;
}SESv4_SealInfo;
DECLARE_ASN1_FUNCTIONS(SESv4_SealInfo);
typedef struct SESv4_Seal_t {
  SESv4_SealInfo *sealinfo;
  ASN1_OCTET_STRING *cert;
  ASN1_OBJECT *signalgid;
  ASN1_BIT_STRING *signedvalue;
}SESv4_Seal;
DECLARE_ASN1_FUNCTIONS(SESv4_Seal);
typedef struct TBSv4_Sign_t {
  ASN1_INTEGER *version;
  SESv4_Seal *eseal;
  ASN1_GENERALIZEDTIME *timeinfo;
  ASN1_BIT_STRING *datahash;
  ASN1_IA5STRING *propertyinfo;
  STACK_OF(X509_EXTENSION) *extDatas;
}TBSv4_Sign;
DECLARE_ASN1_FUNCTIONS(TBSv4_Sign);
typedef struct SESv4_Signature_t {
    TBSv4_Sign *tosign;
    ASN1_OCTET_STRING *cert;
    ASN1_OBJECT *signalgid;
    ASN1_BIT_STRING *signedvalue;
    ASN1_BIT_STRING *timestamp;
}SESv4_Signature;
DECLARE_ASN1_FUNCTIONS(SESv4_Signature);