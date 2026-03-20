/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <gnutls/gnutls.h>

#include "libdnssec/key.h"

#ifdef ENABLE_OQS
/*!
 * Our own PQC PK algorithm IDs, numerically matching GnuTLS 3.8.11 values
 * but defined here so the code compiles with older GnuTLS (e.g. 3.8.3)
 * that lacks the GNUTLS_PK_MLDSA* symbols.
 */
#define OQS_PK_MLDSA44  15
#define OQS_PK_MLDSA65  16
#define OQS_PK_MLDSA87  17
#endif /* ENABLE_OQS */

/*!
 * Convert DNSKEY algorithm identifier to GnuTLS identifier.
 *
 * \param dnssec  DNSSEC DNSKEY algorithm identifier.
 *
 * \return GnuTLS private key algorithm identifier, GNUTLS_PK_UNKNOWN on error.
 */
gnutls_pk_algorithm_t algorithm_to_gnutls(dnssec_key_algorithm_t dnssec);

#ifdef ENABLE_OQS
/*!
 * Return true if the given OQS_PK_* constant is a supported PQC algorithm.
 * Takes an int (not gnutls_pk_algorithm_t) to avoid dependency on GnuTLS 3.8.11.
 */
bool supported_pqc_algorithm(int algo);
#endif // ENABLE_OQS
