/*
 * Powerdns logger daemon
 * ----------------------
 *
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (C) 2017, Spamhaus Technology Ltd, London
 *
 * The Initial developer of the Original code is:
 * Massimo Cetra
 *
 */

#include "pdns-logger.h"

/* *INDENT-OFF* */
struct dns_nameval {
  int val;
  const char *name;
};

const struct dns_nameval dns_classtab[] = {
    {DNS_C_INVALID,     "INVALID"},
    {DNS_C_IN,          "IN"},
    {DNS_C_CH,          "CH"},
    {DNS_C_HS,          "HS"},
    {DNS_C_ANY,         "ANY"},
    {0,0}
};

const struct dns_nameval dns_typetab[] = {
    {DNS_T_INVALID,     "INVALID"},
    {DNS_T_A,           "A"},
    {DNS_T_NS,          "NS"},
    {DNS_T_MD,          "MD"},
    {DNS_T_MF,          "MF"},
    {DNS_T_CNAME,       "CNAME"},
    {DNS_T_SOA,         "SOA"},
    {DNS_T_MB,          "MB"},
    {DNS_T_MG,          "MG"},
    {DNS_T_MR,          "MR"},
    {DNS_T_NULL,        "NULL"},
    {DNS_T_WKS,         "WKS"},
    {DNS_T_PTR,         "PTR"},
    {DNS_T_HINFO,       "HINFO"},
    {DNS_T_MINFO,       "MINFO"},
    {DNS_T_MX,          "MX"},
    {DNS_T_TXT,         "TXT"},
    {DNS_T_RP,          "RP"},
    {DNS_T_AFSDB,       "AFSDB"},
    {DNS_T_X25,         "X25"},
    {DNS_T_ISDN,        "ISDN"},
    {DNS_T_RT,          "RT"},
    {DNS_T_NSAP,        "NSAP"},
    {DNS_T_NSAP_PTR,    "NSAP_PTR"},
    {DNS_T_SIG,         "SIG"},
    {DNS_T_KEY,         "KEY"},
    {DNS_T_PX,          "PX"},
    {DNS_T_GPOS,        "GPOS"},
    {DNS_T_AAAA,        "AAAA"},
    {DNS_T_LOC,         "LOC"},
    {DNS_T_NXT,         "NXT"},
    {DNS_T_EID,         "EID"},
    {DNS_T_NIMLOC,      "NIMLOC"},
    {DNS_T_SRV,         "SRV"},
    {DNS_T_ATMA,        "ATMA"},
    {DNS_T_NAPTR,       "NAPTR"},
    {DNS_T_KX,          "KX"},
    {DNS_T_CERT,        "CERT"},
    {DNS_T_A6,          "A6"},
    {DNS_T_DNAME,       "DNAME"},
    {DNS_T_SINK,        "SINK"},
    {DNS_T_OPT,         "OPT"},
    {DNS_T_APL,         "APL"},
    {DNS_T_DS,          "DS"},
    {DNS_T_SSHFP,       "SSHFP"},
    {DNS_T_IPSECKEY,    "IPSECKEY"},
    {DNS_T_RRSIG,       "RRSIG"},
    {DNS_T_NSEC,        "NSEC"},
    {DNS_T_DNSKEY,      "DNSKEY"},
    {DNS_T_DHCID,       "DHCID"},
    {DNS_T_NSEC3,       "NSEC3"},
    {DNS_T_NSEC3PARAM,  "NSEC3PARAM"},
    {DNS_T_TLSA,        "TLSA"},
    {DNS_T_SMIMEA,      "SMIMEA"},
    {DNS_T_HIP,         "HIP"},
    {DNS_T_NINFO,       "NINFO"},
    {DNS_T_RKEY,        "RKEY"},
    {DNS_T_TALINK,      "TALINK"},
    {DNS_T_CDS,         "CDS"},
    {DNS_T_CDNSKEY,     "CDNSKEY"},
    {DNS_T_OPENPGPKEY,  "OPENPGPKEY"},
    {DNS_T_CSYNC,       "CSYNC"},
    {DNS_T_ZONEMD,      "ZONEMD"},
    {DNS_T_SVCB,        "SVCB"},
    {DNS_T_HTTPS,       "HTTPS"},
    {DNS_T_SPF,         "SPF"},
    {DNS_T_NID,         "NID"},
    {DNS_T_L32,         "L32"},
    {DNS_T_L64,         "L64"},
    {DNS_T_LP,          "LP"},
    {DNS_T_EUI48,       "EUI48"},
    {DNS_T_EUI64,       "EUI64"},
    {DNS_T_TKEY,        "TKEY"},
    {DNS_T_TSIG,        "TSIG"},
    {DNS_T_IXFR,        "IXFR"},
    {DNS_T_AXFR,        "AXFR"},
    {DNS_T_MAILB,       "MAILB"},
    {DNS_T_MAILA,       "MAILA"},
    {DNS_T_ANY,         "ANY"},
    {DNS_T_ZXFR,        "ZXFR"},
    {DNS_T_MAX,         "MAX"},
    {0,0}
};

const struct dns_nameval dns_rcodetab[] = {
    {DNS_R_NOERROR,     "NOERROR"},
    {DNS_R_FORMERR,     "FORMERR"},
    {DNS_R_SERVFAIL,    "SERVFAIL"},
    {DNS_R_NXDOMAIN,    "NXDOMAIN"},
    {DNS_R_NOTIMPL,     "NOTIMPL"},
    {DNS_R_REFUSED,     "REFUSED"},
    {DNS_R_YXDOMAIN,    "YXDOMAIN"},
    {DNS_R_YXRRSET,     "YXRRSET"},
    {DNS_R_NXRRSET,     "NXRRSET"},
    {DNS_R_NOTAUTH,     "NOTAUTH"},
    {DNS_R_NOTZONE,     "NOTZONE"},
    {DNS_R_BADSIG,      "BADSIG"},
    {DNS_R_BADKEY,      "BADKEY"},
    {DNS_R_BADTIME,     "BADTIME"},
    {0,0}
};
/* *INDENT-ON* */

const char *pdns_logger_rcode2p(enum dns_rcode_e i) {
    for (size_t j = 0; j < sizeof(dns_rcodetab) / sizeof(dns_rcodetab[0]); j++) {
        if (dns_rcodetab[j].val == (int)i) {
            return dns_rcodetab[j].name;
        }
    }
    return "UNKNOWN";
}

const char *pdns_logger_type2p(enum dns_type_e i) {
    for (size_t j = 0; j < sizeof(dns_typetab) / sizeof(dns_typetab[0]); j++) {
        if (dns_typetab[j].val == (int)i) {
            return dns_typetab[j].name;
        }
    }
    return "UNKNOWN";
}

const char *pdns_logger_class2p(enum dns_class_e i) {
    for (size_t j = 0; j < sizeof(dns_classtab) / sizeof(dns_classtab[0]); j++) {
        if (dns_classtab[j].val == (int)i) {
            return dns_classtab[j].name;
        }
    }
    return "UNKNOWN";
}
