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

#include <time.h>
#include "inih/ini.h"
#include "pdns-logger.h"
#include "dnsmessage.pb-c.h"

static FILE *fp = NULL;
static char *file = NULL;
static int force_flush = 0;
static char rewrites_only = 1;
static char disabled = 0;

static int opt_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
    (void) user;

    if (zstr(section) || zstr(name) || zstr(value)) {
        return 1;
    }

    if (!strncmp(section, "logfile", sizeof("logfile"))) {
        if (!strncmp(name, "logfile", sizeof("logfile"))) {
            file = strdup(value);
        } else if (!strncmp(name, "force-flush", sizeof("force-flush"))) {
            force_flush = atoi(value) ? 1 : 0;
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

static pdns_status_t logfile_init(const char *inifile) {
    if (zstr(inifile)) {
        return PDNS_NO;
    }

    if (ini_parse(inifile, opt_handler, NULL) != 0) {
        fprintf(stderr, "logfile: Can't read .ini file: '%s'\n", inifile);
        return PDNS_NO;
    }

    if (disabled) {
        fprintf(stderr, "logfile: Disabled according to configuration\n");
        return PDNS_OK;
    }

    if (zstr(file)) {
        fprintf(stderr, "logfile: no log file set. Disabling.\n");
        return PDNS_NO;
    }

    fp = fopen(file, "a");
    if (fp == NULL) {
        fprintf(stderr, "logfile: cannot open '%s' for writing\n", file);
        return PDNS_NO;
    }

    return PDNS_OK;
}

static pdns_status_t logfile_rotate(void) {
    if (fp != NULL) {
        fp = freopen(file, "a", fp);
        if (fp == NULL) {
            fprintf(stderr, "logfile: cannot open '%s' for writing\n", file);
            return PDNS_NO;
        }
    }

    return PDNS_OK;
}

static pdns_status_t logfile_stop(void) {
    safe_free(file);

    if (fp != NULL) {
        fclose(fp);
    }

    return PDNS_OK;
}


static pdns_status_t logfile_log(void *rawpb) {
    PBDNSMessage *msg = rawpb;
    PBDNSMessage__DNSQuestion *q;
    PBDNSMessage__DNSResponse *r;
    char str[4096] = "";
    char *p = str;
    size_t len = sizeof(str);
    int ret;
    time_t timestamp;
    struct tm tm_utc;

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

    // Add UTC timestamp prefix
    if (msg->has_timesec) {
        timestamp = (time_t)msg->timesec;
        gmtime_r(&timestamp, &tm_utc);
        ret = snprintf(p, len, "[%04d-%02d-%02d %02d:%02d:%02d +0000] ",
                       tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
                       tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
        if (ret < 0 || (size_t)ret >= len) goto end;
        p += ret;
        len -= ret;
    }

    if (msg->has_from) {
        if (msg->from.len == 4) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, (const void *) msg->from.data, ip, sizeof(ip));
            ret = snprintf(p, len, "%s ", ip);
            if (ret < 0 || (size_t)ret >= len) goto end;
            p += ret;
            len -= ret;
        } else if (msg->from.len == 16) {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, (const void *) msg->from.data, ip, sizeof(ip));
            ret = snprintf(p, len, "%s ", ip);
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
                        ret = snprintf(p, len, "rdata-%d: %s ", t, rr->rdata.data);
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
    if (fp != NULL) {
        fprintf(fp, "%s\n", str);
        if (force_flush) {
            fflush(fp);
        }
    }

    return PDNS_OK;
}

pdns_logger_t logfile_engine = {
    logfile_init,
    logfile_rotate,
    logfile_stop,
    logfile_log
};
