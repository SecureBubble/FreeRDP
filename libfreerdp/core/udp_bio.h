
#ifndef FREERDP_LIB_CORE_UDP_BIO_H_
#define FREERDP_LIB_CORE_UDP_BIO_H_

#include <openssl/bio.h>
#include <winpr/winsock.h>

BIO *BIO_udpPoller(SOCKET fd);


#endif /* FREERDP_LIB_CORE_UDP_BIO_H_ */
