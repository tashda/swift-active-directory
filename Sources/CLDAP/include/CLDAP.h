#ifndef CLDAP_H
#define CLDAP_H

#define LDAP_DEPRECATED 1

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>

#pragma clang diagnostic pop

#endif /* CLDAP_H */
