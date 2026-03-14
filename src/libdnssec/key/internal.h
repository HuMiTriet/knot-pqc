/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <gnutls/abstract.h>
#include <stdint.h>

#include "libdnssec/binary.h"
#include "libdnssec/key.h"
#include "libdnssec/shared/dname.h"

/*!
 * DNSSEC key.
 */
struct dnssec_key {
  uint8_t *dname;
  dnssec_binary_t rdata;

  gnutls_pubkey_t public_key;
  gnutls_privkey_t private_key;
  unsigned bits;

#ifdef ENABLE_OQS
  dnssec_binary_t pqc_public_key;
  dnssec_binary_t pqc_private_key;
#endif
};
