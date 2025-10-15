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

#include <syslog.h>
#include "inih/ini.h"
#include "pdns-logger.h"
#include "dnsmessage.pb-c.h"

static struct {
    int facility;
    const char *name;
} facility_names[] = {
    {
    LOG_AUTH, "auth"}, {
    LOG_AUTHPRIV, "authpriv"}, {
    LOG_CRON, "cron"}, {
    LOG_DAEMON, "daemon"}, {
    LOG_FTP, "ftp"}, {
    LOG_KERN, "kern"}, {
    LOG_LOCAL0, "local0"}, {
    LOG_LOCAL1, "local1"}, {
    LOG_LOCAL2, "local2"}, {
    LOG_LOCAL3, "local3"}, {
    LOG_LOCAL4, "local4"}, {
    LOG_LOCAL5, "local5"}, {
    LOG_LOCAL6, "local6"}, {
    LOG_LOCAL7, "local7"}, {
    LOG_LPR, "lpr"}, {
    LOG_MAIL, "mail"}, {
    LOG_NEWS, "news"}, {
    LOG_SYSLOG, "syslog"}, {
    LOG_USER, "user"}, {
LOG_UUCP, "uucp"},};

static char *ident = "pdns-logger";
static char *facility = "daemon";
static char rewrites_only = 1;
static char disabled = 0;

static int logfacility_lookup(const char *nfacility, int *logfacility) {
    unsigned int t;

    if (logfacility == NULL) {
        return 0;
    }

    for (t = 0; t < sizeof(facility_names) / sizeof(facility_names[0]); t++) {
        if (!strncmp(facility_names[t].name, nfacility, strlen(facility_names[t].name) + 1)) {
            *logfacility = facility_names[t].facility;
            return 1;
        }
    }

    *logfacility = LOG_DAEMON;

    return 0;
}

static int opt_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
    (void) user;

    if (zstr(section) || zstr(name) || zstr(value)) {
        return 1;
    }

    if (!strncmp(section, "syslog", sizeof("syslog"))) {
        if (!strncmp(name, "ident", sizeof("ident"))) {
        } else if (!strncmp(name, "facility", sizeof("facility"))) {
        } else if (!strncmp(name, "level", sizeof("level"))) {
        } else if (!strncmp(name, "only-rewrites", sizeof("only-rewrites"))) {
            rewrites_only = atoi(value) ? 1 : 0;
        } else if (!strncmp(name, "disabled", sizeof("disabled"))) {
            disabled = atoi(value) ? 1 : 0;
        } else {
            fprintf(stderr, "Unmanaged INI option '%s' at line %d\n", name, lineno);
        }
        return 1;
    }

    return 1;
}

static pdns_status_t syslog_init(const char *inifile) {
    int logf;

    if (zstr(inifile)) {
        return PDNS_NO;
    }

    if (ini_parse(inifile, opt_handler, NULL) != 0) {
        fprintf(stderr, "syslog: Can't read .ini file: '%s'\n", inifile);
        return PDNS_NO;
    }

    if (disabled) {
        fprintf(stderr, "syslog: Disabled according to configuration\n");
        return PDNS_OK;
    }

    logfacility_lookup(facility, &logf);

    openlog(!zstr(ident) ? ident : "pdns-logger", LOG_NDELAY | LOG_PID, logf);

    return PDNS_OK;
}

static pdns_status_t syslog_rotate(void) {
    return PDNS_OK;
}

static pdns_status_t syslog_stop(void) {
    closelog();
    return PDNS_OK;
}


static pdns_status_t syslog_log(void *rawpb) {
    PBDNSMessage *msg = rawpb;
    PBDNSMessage__DNSQuestion *q;
    PBDNSMessage__DNSResponse *r;
    char str[2048] = "";
    char *p = str;
    size_t len = sizeof(str);
    int ret;

    if (disabled) {
        return PDNS_OK;
    }

    if (msg == NULL || msg->response == NULL) {
        return PDNS_OK;
    }

    if (rewrites_only != 0) {
        if (msg->response != NULL && zstr(msg->response->appliedpolicy)) {
            return PDNS_OK;
        }
    }

    if (msg->has_id) {
        ret = snprintf(p, len, "QID: %d ", msg->id);
        if (ret < 0 || (size_t)ret >= len) goto end;
        p += ret;
        len -= ret;
    }

    if (msg->has_from) {
        if (msg->from.len == 4) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, (const void *) msg->from.data, ip, sizeof(ip));
            ret = snprintf(p, len, "from: %s ", ip);
            if (ret < 0 || (size_t)ret >= len) goto end;
            p += ret;
            len -= ret;
        } else if (msg->from.len == 16) {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, (const void *) msg->from.data, ip, sizeof(ip));
            ret = snprintf(p, len, "from: %s ", ip);
            if (ret < 0 || (size_t)ret >= len) goto end;
            p += ret;
            len -= ret;
        }
    }

    q = msg->question;
    if (q != NULL) {
        if (q->has_qtype) {
            ret = snprintf(p, len, "qtype: %s ", pdns_logger_type2p(q->qtype));
            if (ret < 0 || (size_t)ret >= len) goto end;
            p += ret;
            len -= ret;
        }

        if (q->has_qclass) {
            ret = snprintf(p, len, "qclass: %s ", pdns_logger_class2p(q->qclass));
            if (ret < 0 || (size_t)ret >= len) goto end;
            p += ret;
            len -= ret;
        }

        ret = snprintf(p, len, "qname: %s ", q->qname);
        if (ret < 0 || (size_t)ret >= len) goto end;
        p += ret;
        len -= ret;
    }

    r = msg->response;
    if (r != NULL) {
        if (r->has_rcode) {
            ret = snprintf(p, len, "rcode: %s ", pdns_logger_rcode2p(r->rcode));
            if (ret < 0 || (size_t)ret >= len) goto end;
            p += ret;
            len -= ret;
        }

        ret = snprintf(p, len, "rrcount: %zu ", r->n_rrs);
        if (ret < 0 || (size_t)ret >= len) goto end;
        p += ret;
        len -= ret;

        if (!zstr(r->appliedpolicy)) {
            ret = snprintf(p, len, "policy: '%s' ", r->appliedpolicy);
            if (ret < 0 || (size_t)ret >= len) goto end;
            p += ret;
            len -= ret;
        }

        if (r->n_rrs > 0) {
            unsigned int t;
            PBDNSMessage__DNSResponse__DNSRR *rr;

            for (t = 1; t <= r->n_rrs; t++) {
                rr = r->rrs[t - 1];

                ret = snprintf(p, len, "rname-%d: %s ", t, rr->name);
                if (ret < 0 || (size_t)ret >= len) goto end;
                p += ret;
                len -= ret;

                if (rr->has_type) {
                    ret = snprintf(p, len, "rtype-%d: %s ", t, pdns_logger_type2p(rr->type));
                    if (ret < 0 || (size_t)ret >= len) goto end;
                    p += ret;
                    len -= ret;
                }

                if (rr->has_class_) {
                    ret = snprintf(p, len, "rclass-%d: %s ", t, pdns_logger_class2p(rr->class_));
                    if (ret < 0 || (size_t)ret >= len) goto end;
                    p += ret;
                    len -= ret;
                }

                if (rr->has_ttl) {
                    ret = snprintf(p, len, "rttl-%d: %d ", t, rr->ttl);
                    if (ret < 0 || (size_t)ret >= len) goto end;
                    p += ret;
                    len -= ret;
                }

                if (rr->has_rdata) {
                    if (rr->has_type && rr->type == 1 && rr->rdata.len == 4) {
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, (const void *) rr->rdata.data, ip, sizeof(ip));
                        ret = snprintf(p, len, "rdata-%d: %s ", t, ip);
                        if (ret < 0 || (size_t)ret >= len) goto end;
                        p += ret;
                        len -= ret;
                    } else if (rr->has_type && rr->type == 28 && rr->rdata.len == 16) {
                        char ip[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, (const void *) rr->rdata.data, ip, sizeof(ip));
                        ret = snprintf(p, len, "rdata-%d: %s ", t, ip);
                        if (ret < 0 || (size_t)ret >= len) goto end;
                        p += ret;
                        len -= ret;
                    } else if (rr->has_type && ((rr->type == 2) || (rr->type == 5) || (rr->type == 6) || (rr->type == 15))) {
                        ret = snprintf(p, len, "rdata-%d: %.*s ", t, (int)rr->rdata.len, (char*)rr->rdata.data);
                        if (ret < 0 || (size_t)ret >= len) goto end;
                        p += ret;
                        len -= ret;
                    } else {
                        ret = snprintf(p, len, "rdata (not supported) ");
                        if (ret < 0 || (size_t)ret >= len) goto end;
                        p += ret;
                        len -= ret;
                    }
                }
            }
        }
    }

end:
    syslog(LOG_NOTICE, "%s", str);

    return PDNS_OK;
}

pdns_logger_t syslog_engine = {
    syslog_init,
    syslog_rotate,
    syslog_stop,
    syslog_log
};
