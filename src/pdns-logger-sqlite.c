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

#include <pthread.h>
#include <sqlite3.h>

#include "inih/ini.h"
#include "pdns-logger.h"
#include "dnsmessage.pb-c.h"

static char *dbfile = NULL;
static struct sqlite3 *db = NULL;
static char rewrites_only = 1;
static fifo_t *fifo = NULL;
static pthread_t bgthread;
static char bgrunning = 0;
static char disabled = 0;
static char autocommit = 1;

/* *************************************************************************** */
/* *************************************************************************** */
/* *************************************************************************** */

/* *INDENT-OFF* */

#define SQL_CREATE_TABLE \
    "CREATE TABLE IF NOT EXISTS logs ( " \
    "   ts      INTEGER NOT NULL, " \
    "   querier VARCHAR(48), " \
    "   id      INTEGER NOT NULL, " \
    "   qtype   VARCHAR(10), " \
    "   qclass  VARCHAR(10), " \
    "   qname   VARCHAR(256), " \
    "   rcode   VARCHAR(16), " \
    "   rcount  INTEGER, " \
    "   rname   VARCHAR(256), " \
    "   rtype   VARCHAR(10), " \
    "   rclass  VARCHAR(10), " \
    "   rttl    INTEGER, " \
    "   rdata   VARCHAR(256), " \
    "   policy  VARCHAR(100)" \
    ")"

// EDNS

#define SQL_INSERT \
    "INSERT INTO logs (" \
    "  ts, querier, id, qtype, qclass, qname, rcode, rcount, rname, rtype, rclass, rttl, rdata, policy " \
    ") VALUES (" \
    "  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? " \
    ")"

#define SQL_CREATE_INDEX \
    "CREATE INDEX IF NOT EXISTS logs_ts_idx      ON  logs(ts);" \
    "CREATE INDEX IF NOT EXISTS logs_querier_idx ON  logs(querier);" \
    "CREATE INDEX IF NOT EXISTS logs_qname_idx   ON  logs(qname);" \
    "CREATE INDEX IF NOT EXISTS logs_policy_idx  ON logs(policy);"

/* *INDENT-ON* */

/* *************************************************************************** */
/* *************************************************************************** */
/* *************************************************************************** */

static pdns_status_t db_flush(void);

static int counter = 0;
static pdns_status_t db_exec(const char *sql, char log) {
    int res;
    char *zErr = NULL;

    counter++;

    res = sqlite3_exec(db, sql, NULL, NULL, &zErr);
    if (res != 0) {
        if (zErr != NULL) {
            if (log != 0) {
                fprintf(stderr, "Error executing query: %s (%s)\n", sql, zErr);
            }
            sqlite3_free(zErr);
        }
        return PDNS_NO;
    }

    /* From time to time, flush the tables... */
    if (counter >= 50) {
        counter = 0;
        db_flush();
    }

    if (zErr != NULL) {
        sqlite3_free(zErr);
    }

    return PDNS_OK;
}

static pdns_status_t db_flush(void) {
    if ( autocommit == 0 ) {
        if (!sqlite3_get_autocommit(db)) {
            printf("Flushing and committing SQLite3 DB\n");
            db_exec("COMMIT", 1);
        }
        db_exec("BEGIN", 1);
    }

    return PDNS_OK;
}

static pdns_status_t db_open(const char *file) {
    int err;

    err = sqlite3_open_v2(file, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (err != SQLITE_OK) {
        fprintf(stderr, "sqlite: cannot open sqlite database file '%s'\n", file);
        return PDNS_NO;
    }

    db_exec(SQL_CREATE_TABLE, 1);
    db_exec(SQL_CREATE_INDEX, 1);

    db_flush();

    return PDNS_OK;
}

static pdns_status_t db_close(void) {
    sqlite3_close(db);
    return PDNS_OK;
}

/* *************************************************************************** */
/* *************************************************************************** */
/* *************************************************************************** */

static void *bg_thread_exec(void *data) {
    sqlite3_stmt *stmt;

    (void) data;

    bgrunning = 1;

    while (bgrunning) {
        stmt = fifo_pop_item(fifo);
        if (stmt != NULL) {
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    return NULL;
}

static void bg_thread_stop(void) {
    bgrunning = 0;
    pthread_join(bgthread, NULL);
    return;
}

static pdns_status_t bg_thread_start(void) {
    pthread_create(&bgthread, NULL, &bg_thread_exec, NULL);
    return PDNS_OK;
}

/* *************************************************************************** */
/* *************************************************************************** */
/* *************************************************************************** */

static int opt_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
    (void) user;

    if (zstr(section) || zstr(name) || zstr(value)) {
        return 1;
    }

    if (!strncmp(section, "sqlite3", sizeof("sqlite3"))) {
        if (!strncmp(name, "dbfile", sizeof("dbfile"))) {
            dbfile = strdup(value);
        } else if (!strncmp(name, "only-rewrites", sizeof("only-rewrites"))) {
            rewrites_only = atoi(value) ? 1 : 0;
        } else if (!strncmp(name, "disabled", sizeof("disabled"))) {
            disabled = atoi(value) ? 1 : 0;
        } else if (!strncmp(name, "autocommit", sizeof("autocommit"))) {
            autocommit = atoi(value) ? 1 : 0;
        } else {
            fprintf(stderr, "Unmanaged INI option '%s' at line %d\n", name, lineno);
        }
        return 1;
    }
    return 1;
}

static pdns_status_t logsqlite_init(const char *inifile) {
    if (zstr(inifile)) {
        fprintf(stderr, "logsqlite: No inifile to read\n");
        return PDNS_NO;
    }

    if (ini_parse(inifile, opt_handler, NULL) != 0) {
        fprintf(stderr, "logsqlite: Can't read .ini file: '%s'\n", inifile);
        return PDNS_NO;
    }

    if (disabled) {
        fprintf(stderr, "logsqlite: Disabled according to configuration\n");
        return PDNS_OK;
    }

    if (zstr(dbfile)) {
        fprintf(stderr, "logsqlite: DB file is not set\n");
        return PDNS_NO;
    }

    fifo = fifo_init();
    bg_thread_start();

    return db_open(dbfile);
}

static pdns_status_t logsqlite_rotate(void) {
    if (db != NULL) {
        fifo_lock(fifo);
        db_close();
        db_open(dbfile);
        fifo_unlock(fifo);
    }
    return PDNS_OK;
}

static pdns_status_t logsqlite_stop(void) {
    bg_thread_stop();
    safe_free(dbfile);
    return db_close();
}


static void prepare_and_queue_statement(
    int ts, const char *from, int msgid, const char *qtype, const char *qclass,
    const char *qname, const char *rcode, int rcount, const char *rname,
    const char *rtype, const char *rclass, int rttl, const char *rdata,
    const char *policy) {

    sqlite3_stmt *stmt;
    int ret = sqlite3_prepare_v2(db, SQL_INSERT, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "sqlite: failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }
    sqlite3_bind_int(stmt, 1, ts);
    sqlite3_bind_text(stmt, 2, !zstr(from) ? from : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, msgid);
    sqlite3_bind_text(stmt, 4, qtype ? qtype : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, qclass ? qclass : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, qname ? qname : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, rcode ? rcode : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, rcount);
    sqlite3_bind_text(stmt, 9, rname ? rname : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, rtype ? rtype : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, rclass ? rclass : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 12, rttl);
    sqlite3_bind_text(stmt, 13, rdata ? rdata : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 14, policy ? policy : "", -1, SQLITE_TRANSIENT);
    fifo_push_item(fifo, stmt);
}

static pdns_status_t logsqlite_log(void *rawpb) {
    char ip4[INET_ADDRSTRLEN];
    char ip6[INET6_ADDRSTRLEN];
    char dnsname[256];
    PBDNSMessage *msg = rawpb;
    PBDNSMessage__DNSQuestion *q;
    PBDNSMessage__DNSResponse *r;
    int ts = 0;
    char from[INET6_ADDRSTRLEN] = "";
    int msgid = 0;
    const char *qtype = NULL;
    const char *qclass = NULL;
    const char *qname = NULL;
    const char *rcode = NULL;
    int rcount = 0;
    char *rname = NULL;
    const char *rtype = NULL;
    const char *rclass = NULL;
    int rttl = 0;
    char *rdata = NULL;
    char *policy = NULL;


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

    if (msg->has_timesec) {
        ts = msg->timesec;
    }

    if (msg->has_from) {
        if (msg->from.len == 4) {
            inet_ntop(AF_INET, (const void *) msg->from.data, from, sizeof(from));
        } else if (msg->from.len == 16) {
            inet_ntop(AF_INET6, (const void *) msg->from.data, from, sizeof(from));
        }
    }

    if (msg->has_id) {
        msgid = msg->id;
    }

    q = msg->question;
    if (q != NULL) {
        if (q->has_qtype) {
            qtype = pdns_logger_type2p(q->qtype);
        }

        if (q->has_qclass) {
            qclass = pdns_logger_class2p(q->qclass);
        }

        qname = q->qname;
    }

    r = msg->response;
    if (r != NULL) {
        if (r->has_rcode) {
            rcode = pdns_logger_rcode2p(r->rcode);
        }

        if (!zstr(r->appliedpolicy)) {
            policy = r->appliedpolicy;
        }

        rcount = r->n_rrs;

        if (r->n_rrs > 0) {
            unsigned int t;
            PBDNSMessage__DNSResponse__DNSRR *rr;

            for (t = 1; t <= r->n_rrs; t++) {
                rr = r->rrs[t - 1];
                rname = rr->name;

                if (rr->has_type) {
                    rtype = pdns_logger_type2p(rr->type);
                }

                if (rr->has_class_) {
                    rclass = pdns_logger_class2p(rr->class_);
                }

                if (rr->has_ttl) {
                    rttl = rr->ttl;
                }

                if (rr->has_rdata) {
                    if (rr->has_type && rr->type == 1 && rr->rdata.len == 4) {
                        inet_ntop(AF_INET, (const void *) rr->rdata.data, ip4, sizeof(ip4));
                        rdata = ip4;
                    } else if (rr->has_type && rr->type == 28 && rr->rdata.len == 16) {
                        inet_ntop(AF_INET6, (const void *) rr->rdata.data, ip6, sizeof(ip6));
                        rdata = ip6;
                    } else if (rr->has_type && ((rr->type == 2) || (rr->type == 5) || (rr->type == 6) || (rr->type == 15))) {
                        size_t copy_len = rr->rdata.len < sizeof(dnsname) - 1 ? rr->rdata.len : sizeof(dnsname) - 1;
                        memcpy(dnsname, rr->rdata.data, copy_len);
                        dnsname[copy_len] = '\0';
                        rdata = dnsname;
                    } else {
                        rdata = "[Not Supported]";
                    }
                }
                prepare_and_queue_statement(ts, from, msgid, qtype, qclass, qname,
                                           rcode, rcount, rname, rtype, rclass,
                                           rttl, rdata, policy);
            }
        } else {
            prepare_and_queue_statement(ts, from, msgid, qtype, qclass, qname,
                                       rcode, rcount, rname, rtype, rclass,
                                       rttl, rdata, policy);
        }
    } else {
        prepare_and_queue_statement(ts, from, msgid, qtype, qclass, qname,
                                   rcode, rcount, rname, rtype, rclass,
                                   rttl, rdata, policy);
    }

    return PDNS_OK;
}

pdns_logger_t sqlite_engine = {
    logsqlite_init,
    logsqlite_rotate,
    logsqlite_stop,
    logsqlite_log
};
