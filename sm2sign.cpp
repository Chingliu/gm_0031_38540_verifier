#define _CRT_SECURE_NO_WARNINGS 1
#include "sm2sign.h"
#include <stdio.h>
#include <openssl/applink.c>
// 读取 .pfx 文件并提取 EVP_PKEY 和 X509 证书
int load_pfx_file(const char *filename, const char *password, EVP_PKEY **pkey, X509 **cert) {
  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    perror("打开PFX文件失败");
    return 0;
  }

  PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
  fclose(fp);

  if (!p12) {
    fprintf(stderr, "读取PFX文件失败: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return 0;
  }

  if (!PKCS12_parse(p12, password, pkey, cert, NULL)) {
    fprintf(stderr, "解析PFX文件失败: %s\n", ERR_error_string(ERR_get_error(), NULL));
    PKCS12_free(p12);
    return 0;
  }

  PKCS12_free(p12);
  return 1;
}

sm2PrivateKey::sm2PrivateKey(EVP_PKEY * pkey) {
  if (pkey)
  {
    EVP_CUNSTOM * cst = new EVP_CUNSTOM{ pkey };
    M_PKEY = std::shared_ptr<EVP_CUNSTOM>(cst);
  }
}
sm2PrivateKey::sm2PrivateKey() {
  EVP_PKEY *ret = NULL;

  EVP_PKEY_CTX *pkctx = NULL;

  pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);//创建sm2 上下文
  if (pkctx == NULL) {
    errorL("EVP_PKEY_CTX_new_id");
    return;
  }
  int retV = 1;
  retV = EVP_PKEY_keygen_init(pkctx);//初始化sm2 上下文

  if (retV <= 0) {
    errorL("EVP_PKEY_keygen_init:" << GetErrorStr());
    EVP_PKEY_CTX_free(pkctx);
    return;
  }


  retV = EVP_PKEY_keygen(pkctx, &ret);//生成密钥对
  if (retV <= 0) {
    errorL("EVP_PKEY_keygen:" << GetErrorStr());
    EVP_PKEY_CTX_free(pkctx);
    return;
  }
  EVP_CUNSTOM * cst = new EVP_CUNSTOM{ ret };
  M_PKEY = std::shared_ptr<EVP_CUNSTOM>(cst);
  EVP_PKEY_CTX_free(pkctx);
}


//导出公钥和导入公钥


sm2PublicKey sm2PrivateKey::CreatePublic() {
  unsigned char *buffer = nullptr;
  int retV = i2d_PUBKEY(M_PKEY.get()->pkey, &buffer);//导出
  if (retV <= 0) {
    errorL("i2d_PUBKEY:" << GetErrorStr());
    return sm2PublicKey{};
  }
  //buffer 里的是公钥二进制
  sm2PublicKey pub(buffer, retV);
  //OPENSSL_free(buffer);
  return pub;
}

sm2PublicKey::sm2PublicKey(const unsigned char * pub_str, size_t len) {
  EVP_PKEY * pkey_t = NULL;
  //pkey_t=d2i_PublicKey(EVP_PKEY_SM2,NULL, &pub_str, len);
  pkey_t = d2i_PUBKEY(NULL, &pub_str, len);//导入
  std::string error;
  if (pkey_t == NULL) {
    error = GetErrorStr();
    errorL(error);
    return;
  }
  EVP_CUNSTOM *cst = new EVP_CUNSTOM{ pkey_t };
  m_pkey = std::shared_ptr<EVP_CUNSTOM>(cst);
}


//公钥加密
std::string sm2PublicKey::Encrypt(const std::string &message, std::string &error) {
  std::string encodedstr;
  EVP_PKEY_CTX *pkctx = NULL;
  int retV = 1;
  if (!(pkctx = EVP_PKEY_CTX_new(m_pkey.get()->pkey, NULL))) {//生成上下文
    error = GetErrorStr();
    errorL("EVP_PKEY_CTX_new:" << error);
    EVP_PKEY_CTX_free(pkctx);
    return "";
  }
  retV = EVP_PKEY_encrypt_init(pkctx);//加密初始化
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_PKEY_encrypt_init:" << error);
    EVP_PKEY_CTX_free(pkctx);
    return "";
  }

  size_t outbuflen = 0;
  unsigned char * outbuf = NULL;
  retV = EVP_PKEY_encrypt(pkctx, NULL, &outbuflen,
    (const unsigned char *)message.c_str(), message.size());//加密 （传NULL 仅获取密文长度）
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_PKEY_encrypt:" << error);
    EVP_PKEY_CTX_free(pkctx);
    return "";
  }
  if (outbuflen == 0) {
    errorL("EVP_PKEY_encrypt:" << "no memery");
    EVP_PKEY_CTX_free(pkctx);
    return "";
  }

  outbuf = new unsigned char[outbuflen];

  retV = EVP_PKEY_encrypt(pkctx, outbuf, &outbuflen,
    (const unsigned char *)message.c_str(), message.size());//加密
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_PKEY_encrypt:" << error);
    EVP_PKEY_CTX_free(pkctx);
    delete[] outbuf;
    return "";
  }
  encodedstr = std::string((const char *)outbuf, outbuflen);//获取结果
  delete[] outbuf;
  EVP_PKEY_CTX_free(pkctx);
  return encodedstr;
}
//私钥解密

std::string sm2PrivateKey::Decrypt(const std::string &encoded,
  std::string &error) {
  std::string decodedstr;
  EVP_PKEY_CTX *pkctx = NULL;
  unsigned char * outbuf = NULL;
  size_t outlen = 0;

  int retV = 1;
  if (!(pkctx = EVP_PKEY_CTX_new(M_PKEY.get()->pkey, NULL))) {//创建EVP 上下文
    error = GetErrorStr();
    errorL("EVP_PKEY_CTX_new:" << error);
    EVP_PKEY_CTX_free(pkctx);
    return "";
  }
  retV = EVP_PKEY_decrypt_init(pkctx);// 解密初始化
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_PKEY_decrypt_init:" << error);
    EVP_PKEY_CTX_free(pkctx);
    return "";
  }
  retV = EVP_PKEY_decrypt(pkctx, NULL, &outlen,
    (const unsigned char *)encoded.c_str(), encoded.size());//解密
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_PKEY_encrypt_init:" << error);
    EVP_PKEY_CTX_free(pkctx);
    return "";
  }

  if (outlen == 0) {
    errorL("EVP_PKEY_decrypt:" << error);
    EVP_PKEY_CTX_free(pkctx);
    return "";
  }

  outbuf = new unsigned char[outlen];

  retV = EVP_PKEY_decrypt(pkctx, outbuf, &outlen,
    (const unsigned char *)encoded.c_str(), encoded.size());//解密
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_PKEY_encrypt_init:" << error);
    EVP_PKEY_CTX_free(pkctx);
    delete[] outbuf;
    return "";
  }

  decodedstr = std::string((const char *)outbuf, outlen);
  delete[] outbuf;

  EVP_PKEY_CTX_free(pkctx);
  return decodedstr;
}


//私钥签名
std::vector<unsigned char> sm2PrivateKey::Signature(const std::string & message, std::string & error) {
  std::string signatured;
  EVP_MD_CTX *mdctx = NULL;
  size_t outbuflen = 0;
  std::vector<unsigned char> outbuf;
  int retV = 0;
  if (!(mdctx = EVP_MD_CTX_create())) {//创建摘要上下文
    error = GetErrorStr();
    errorL("EVP_MD_CTX_create:" << error);
    return outbuf;
  }
  retV = EVP_DigestSignInit(mdctx, NULL, EVP_sm3(),//使用sm3 摘要算法
    NULL, M_PKEY.get()->pkey);//签名初始化
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_DigestSignInit:" << error);
    EVP_MD_CTX_free(mdctx);
    return outbuf;
  }


  retV = EVP_DigestSignUpdate(mdctx, message.c_str(), message.size());//更新签名内容
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_DigestSignUpdate:" << error);
    EVP_MD_CTX_free(mdctx);
    return outbuf;
  }

  retV = EVP_DigestSignFinal(mdctx, NULL, &outbuflen);//获取签名长度
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_DigestSignFinal:" << error);
    EVP_MD_CTX_free(mdctx);
    return outbuf;
  }

  //outbuf = new unsigned char[outbuflen];
  
  outbuf.resize(outbuflen);

  retV = EVP_DigestSignFinal(mdctx, &outbuf[0], &outbuflen);//获取签名结果
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_DigestSignFinal:" << error);
    EVP_MD_CTX_free(mdctx);
    return outbuf;
  }

  return outbuf;
}


//公钥验签


bool sm2PublicKey::SignatureVerification(const std::vector<unsigned char> &signature, const std::string &message, std::string &error) {
  std::string signatured;
  EVP_MD_CTX *mdctx = NULL;
  int retV = 0;
  if (!(mdctx = EVP_MD_CTX_create())) {//创建摘要上下文
    error = GetErrorStr();
    errorL("EVP_MD_CTX_create:" << error);
    return false;
  }
  retV = EVP_DigestVerifyInit(mdctx, NULL, EVP_sm3(), NULL, m_pkey.get()->pkey);//验签初始化
  if (retV <= 0) {
    error = GetErrorStr();
    errorL("EVP_DigestVerifyInit:" << error);
    EVP_MD_CTX_free(mdctx);
    return false;
  }

  retV = EVP_DigestVerifyUpdate(mdctx, message.c_str(), message.size());//更新验签内容
  if (retV <= 0) {
    error = GetErrorStr();
    EVP_MD_CTX_free(mdctx);
    errorL("EVP_DigestVerifyUpdate:" << error);
    return false;
  }
  retV = EVP_DigestVerifyFinal(mdctx, (const unsigned char *)&signature[0], signature.size());//验证签名
  if (retV <= 0) {
    error = GetErrorStr();
    EVP_MD_CTX_free(mdctx);
    errorL("EVP_DigestVerifyFinal:" << error);
    return false;
  }
  EVP_MD_CTX_free(mdctx);
  return true;
}