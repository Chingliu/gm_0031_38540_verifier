#include "hare_crypto_export.h"
#include <memory>
#include "38540.h"
namespace {


  template<typename T, typename... Args>
  std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
  }
};
#ifdef __cplusplus
extern "C" {
#endif

  HARECRYPTO_API void * hare_crypto_sign_new(const unsigned char *data, long len) {
    gm::CGMVerifier_if *pret = nullptr;
    gm::C38540 * p38540 = new gm::C38540(data, len);
    if (p38540->data_parsed())
    {
      return pret = p38540;
    }
    gm::C0031 *p0031 = new gm::C0031(data, len);
    if (p0031->data_parsed())
    {
      return pret = p0031;
    }
    return pret;
  }
  HARECRYPTO_API void hare_crypto_sign_free(void *psign) {
    if (psign)
    {
      gm::CGMVerifier_if *p = (gm::CGMVerifier_if*)psign;
      delete p;
    }
  }

  HARECRYPTO_API char * hare_crypto_sign_digest_method(const void *psign) {
    gm::CGMVerifier_if *pverifier = (gm::CGMVerifier_if*)(psign);
    if (!pverifier)
    {
      return nullptr;
    }
    return pverifier->sign_digest_method();
  }
  HARECRYPTO_API int hare_crypto_sign_verify(const void *psign, const unsigned char * digest, long digest_len) {
    gm::CGMVerifier_if *pverifier = (gm::CGMVerifier_if*)(psign);
    if (!pverifier)
    {
      return -1;
    }
    return pverifier->sign_verify(digest, digest_len);
  }

#ifdef __cplusplus
}
#endif