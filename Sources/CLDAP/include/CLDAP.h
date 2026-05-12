#ifndef CLDAP_H
#define CLDAP_H

#define LDAP_DEPRECATED 1

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>

#pragma clang diagnostic pop

#include "ad_bind.h"
#include "ad_srv.h"
#include "ad_search.h"

#endif /* CLDAP_H */
