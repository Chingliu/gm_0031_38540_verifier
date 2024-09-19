#pragma once
#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include "openssl/crypto.h"
#include "openssl/types.h"
#include "openssl/x509.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

int load_pfx_file(const char *filename, const char *password, EVP_PKEY **pkey, X509 **cert);
class sm2PrivateKey;

struct EVP_CUNSTOM {
  EVP_PKEY * pkey = NULL;
  ~EVP_CUNSTOM() {
    if (pkey != NULL) {
      EVP_PKEY_free(pkey);
    }
  }
};

class sm2PublicKey {
public:
  sm2PublicKey() = default;

  sm2PublicKey(const sm2PublicKey & other) {
    m_pkey = other.m_pkey;
  }

  //sm2PublicKey(const std::string & pub_str);

  sm2PublicKey(const unsigned char * pub_str, size_t len);

  std::string Encrypt(const std::string  & message, std::string & error);

  bool SignatureVerification(const std::vector<unsigned char> & signature, const std::string & message, std::string & error);

  int PkeyVerification(const std::vector<unsigned char> & signature, unsigned char hash[32]);


  //std::string GetPublicString();

  //std::string GetPublicStringBase64();
private:

  std::shared_ptr<EVP_CUNSTOM> m_pkey = nullptr;//使用shared_ptr 防止拷贝构造的时候造成内存泄漏和意外释放
};


class sm2PrivateKey {
public:

  sm2PrivateKey();

  //sm2PrivateKey(const std::string & priv_str);
  sm2PrivateKey(EVP_PKEY * pkey);
  sm2PublicKey CreatePublic();

  std::string Decrypt(const std::string & encoded, std::string & error);

  std::vector<unsigned char> Signature(const std::string & message, std::string & error);
  std::vector<unsigned char> PkeySign(unsigned char hash[32]);
  //std::string GetPrivateString();

private:
  unsigned long m_error = 0;
  std::shared_ptr<EVP_CUNSTOM>  M_PKEY = nullptr;
};

#define RED_t "\033[31m"
#define YELLOW_t "\033[33m"
#define GREEN_t "\033[32m"
#define WRITE "\033[0m"

#define errorL(msg) \
	std::cout << RED_t <<"Error:["<< __FILE__  << ":"<< __LINE__ << "]:"<< msg << WRITE <<std::endl;
#define debugL(msg) \
	std::cout << YELLOW_t <<"debug:["<< __FILE__ << ":"<< __LINE__ << "]:"<< msg << WRITE << std::endl;
#define infoL(msg) \
	std::cout << GREEN_t <<"infor:["<< __FILE__ << ":" << __LINE__ << "]:"<< msg << WRITE << std::endl;


static inline std::string GetErrorStr() {
  unsigned long er = 0;

  char erbuf[512] = { 0 };

  size_t erlen = 512;

  er = ERR_get_error();
  ERR_error_string_n(er, erbuf, erlen);
  return std::string(erbuf, erlen);
}

class CDigest {
public:
  CDigest(const CDigest&) = delete;
  CDigest(CDigest&&) = delete;
  CDigest& operator=(const CDigest&) = delete;
  CDigest& operator=(CDigest&&) = delete;
public:
  CDigest(std::string digest_name);
  ~CDigest();
public:
  unsigned long digest_update(const unsigned char * data, size_t len);
  unsigned long get_digest(unsigned char *md_value);
private:
  EVP_MD_CTX *mdctx;
  unsigned long m_error;
};

class CGuardOpenssl {
public:
  CGuardOpenssl();
  ~CGuardOpenssl();
};