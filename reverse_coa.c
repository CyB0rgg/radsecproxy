/* Copyright (c) 2026, Nova Labs */
/* See LICENSE for licensing information. */

#include "reverse_coa.h"

#if defined(RADPROT_TLS) || defined(RADPROT_DTLS)

#include "coa.h"
#include "debug.h"
#include "hash.h"
#include "list.h"
#include "radmsg.h"
#include "util.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define REVERSE_COA_DEDUP_WINDOW 30
#define MAX_REVERSE_COA_FAILOVER 8

struct reverse_coa_regex_entry {
    char *pattern;
    regex_t regex;
    struct list *clients;
};

struct reverse_coa_route {
    uint32_t refcount;
    pthread_mutex_t refmutex;
    struct client *target;
};

struct reverse_coa_route *reverse_coa_route_new(struct client *target) {
    struct reverse_coa_route *route = malloc(sizeof(*route));
    if (!route)
        return NULL;
    route->refcount = 1;
    pthread_mutex_init(&route->refmutex, NULL);
    route->target = target;
    return route;
}

static void reverse_coa_route_ref(struct reverse_coa_route *route) {
    if (!route)
        return;
    pthread_mutex_lock(&route->refmutex);
    route->refcount++;
    pthread_mutex_unlock(&route->refmutex);
}

void reverse_coa_route_deref(struct reverse_coa_route *route) {
    if (!route)
        return;
    pthread_mutex_lock(&route->refmutex);
    uint32_t remaining = --route->refcount;
    pthread_mutex_unlock(&route->refmutex);
    if (remaining == 0) {
        pthread_mutex_destroy(&route->refmutex);
        free(route);
    }
}

static struct hash *realm_reverse_coa_clients;
static struct list *realm_reverse_coa_regex_list;
static struct list *reverse_coa_nas_routes;
static pthread_mutex_t realm_reverse_coa_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t oni_nonce;

/* dumps up to 16 bytes per line as hex+offset so the log can be
   pasted into wireshark "import from hex dump" (encap: radius) for decoding */
static void debug_hexdump(const char *tag, const uint8_t *buf, int len) {
    char line[3 * 16 + 1];
    int off, i, pos;

    for (off = 0; off < len; off += 16) {
        pos = 0;
        for (i = 0; i < 16 && off + i < len; i++)
            pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", buf[off + i]);
        if (pos > 0 && line[pos - 1] == ' ')
            line[pos - 1] = '\0';
        debug(DBG_DBG, "%s %04x: %s", tag, off, line);
    }
}

static void debug_dump_attrs(const char *tag, struct radmsg *msg) {
    struct list_node *node;
    struct tlv *attr;
    int idx = 0;

    debug(DBG_DBG, "%s: code=%d id=%d attrs:", tag, msg->code, msg->id);
    debug_hexdump(tag, msg->auth, 16);
    for (node = list_first(msg->attrs); node; node = list_next(node)) {
        attr = (struct tlv *)node->data;
        debug(DBG_DBG, "%s attr[%d] type=%u len=%u", tag, idx, attr->t, attr->l);
        debug_hexdump(tag, attr->v, attr->l);
        idx++;
    }
}

void init_reverse_coa(void) {
    if (!RAND_bytes((unsigned char *)&oni_nonce, sizeof(oni_nonce)))
        debugx(1, DBG_ERR, "init_reverse_coa: RAND_bytes failed");
    realm_reverse_coa_clients = hash_create();
    if (!realm_reverse_coa_clients)
        debugx(1, DBG_ERR, "malloc failed");
    realm_reverse_coa_regex_list = list_create();
    if (!realm_reverse_coa_regex_list)
        debugx(1, DBG_ERR, "malloc failed");
    reverse_coa_nas_routes = list_create();
    if (!reverse_coa_nas_routes)
        debugx(1, DBG_ERR, "malloc failed");
}

static const char *strip_regex_delimiters(const char *realm, char *buf, size_t bufsize) {
    const char *start = realm + 1;
    size_t len = strlen(start);
    if (len > 0 && start[len - 1] == '/')
        len--;
    if (len == 0)
        return NULL;
    if (len >= bufsize)
        len = bufsize - 1;
    memcpy(buf, start, len);
    buf[len] = '\0';
    return buf;
}

static struct reverse_coa_regex_entry *create_regex_entry(const char *pattern) {
    struct reverse_coa_regex_entry *re = NULL;
    int regex_compiled = 0;

    re = malloc(sizeof(*re));
    if (!re) {
        debug(DBG_ERR, "create_regex_entry: malloc failed");
        return NULL;
    }
    memset(re, 0, sizeof(*re));

    if (regcomp(&re->regex, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB)) {
        debug(DBG_ERR, "create_regex_entry: regcomp failed for pattern '%s'", pattern);
        goto cleanup;
    }
    regex_compiled = 1;

    re->pattern = stringcopy(pattern, 0);
    if (!re->pattern) {
        debug(DBG_ERR, "create_regex_entry: stringcopy failed");
        goto cleanup;
    }

    re->clients = list_create();
    if (!re->clients) {
        debug(DBG_ERR, "create_regex_entry: list_create failed");
        goto cleanup;
    }

    if (!list_push(realm_reverse_coa_regex_list, re)) {
        debug(DBG_ERR, "create_regex_entry: list_push failed");
        goto cleanup;
    }

    return re;

cleanup:
    if (re->clients)
        list_destroy(re->clients);
    free(re->pattern);
    if (regex_compiled)
        regfree(&re->regex);
    free(re);
    return NULL;
}

static struct reverse_coa_regex_entry *find_regex_entry(const char *pattern) {
    struct list_node *node;
    for (node = list_first(realm_reverse_coa_regex_list); node; node = list_next(node)) {
        struct reverse_coa_regex_entry *entry = (struct reverse_coa_regex_entry *)node->data;
        if (strcmp(entry->pattern, pattern) == 0)
            return entry;
    }
    return NULL;
}

static struct list *resolve_realm_list_for_register(const char *realm,
                                                    char *patbuf, size_t patbufsz,
                                                    struct reverse_coa_regex_entry **re_out) {
    *re_out = NULL;
    if (realm[0] == '/') {
        const char *pattern = strip_regex_delimiters(realm, patbuf, patbufsz);
        if (!pattern) {
            debug(DBG_ERR, "register_reverse_coa_client: empty regex pattern in reverseCoARealm, skipping");
            return NULL;
        }
        struct reverse_coa_regex_entry *re = find_regex_entry(pattern);
        if (!re) {
            re = create_regex_entry(pattern);
            if (!re)
                return NULL;
        }
        *re_out = re;
        return re->clients;
    }
    struct list *lst = hash_read(realm_reverse_coa_clients, realm, strlen(realm));
    if (!lst) {
        lst = list_create();
        if (!lst) {
            debug(DBG_ERR, "resolve_realm_list_for_register: malloc failed");
            return NULL;
        }
        if (!hash_insert(realm_reverse_coa_clients, realm, strlen(realm), lst)) {
            debug(DBG_ERR, "resolve_realm_list_for_register: hash insert failed");
            list_destroy(lst);
            return NULL;
        }
    }
    return lst;
}

static struct list *resolve_realm_list_for_unregister(const char *realm,
                                                      char *patbuf, size_t patbufsz,
                                                      struct reverse_coa_regex_entry **re_out) {
    *re_out = NULL;
    if (realm[0] == '/') {
        const char *pattern = strip_regex_delimiters(realm, patbuf, patbufsz);
        if (!pattern)
            return NULL;
        struct reverse_coa_regex_entry *re = find_regex_entry(pattern);
        if (!re)
            return NULL;
        *re_out = re;
        return re->clients;
    }
    return hash_read(realm_reverse_coa_clients, realm, strlen(realm));
}

void register_reverse_coa_client(struct client *client) {
    struct reverse_coa_route *route;
    int i;

    if (!client || !client->conf)
        return;

    if (!client->reverse_coa_rqs || !client->reverse_coa_route)
        return;

    route = client->reverse_coa_route;

    pthread_mutex_lock(&realm_reverse_coa_lock);

    reverse_coa_route_ref(route);
    if (!list_push(reverse_coa_nas_routes, route)) {
        reverse_coa_route_deref(route);
        debug(DBG_ERR, "register_reverse_coa_client: failed to add to global list");
    } else {
        debug(DBG_DBG, "register_reverse_coa_client: added client %s to global reverse-coa list",
              client->conf->name);
    }

    if (client->conf->reverse_coa_realms) {
        for (i = 0; client->conf->reverse_coa_realms[i]; i++) {
            char *realm = client->conf->reverse_coa_realms[i];
            char patbuf[256];
            struct reverse_coa_regex_entry *re = NULL;
            struct list *target_list = resolve_realm_list_for_register(realm, patbuf, sizeof(patbuf), &re);

            if (!target_list)
                continue;

            reverse_coa_route_ref(route);
            if (!list_push(target_list, route)) {
                reverse_coa_route_deref(route);
                debug(DBG_ERR, "register_reverse_coa_client: list push failed%s", re ? " for regex" : "");
            } else {
                debug(DBG_DBG, "register_reverse_coa_client: registered client %s for %s realm '%s'",
                      client->conf->name, re ? "regex" : "exact", re ? re->pattern : realm);
            }
        }
    }

    pthread_mutex_unlock(&realm_reverse_coa_lock);
}

void unregister_reverse_coa_client(struct client *client) {
    struct reverse_coa_route *route;
    int i;

    if (!client || !client->conf)
        return;

    if (!client->reverse_coa_rqs || !client->reverse_coa_route)
        return;

    route = client->reverse_coa_route;

    pthread_mutex_lock(&realm_reverse_coa_lock);

    {
        uint32_t before = list_count(reverse_coa_nas_routes);
        list_removedata(reverse_coa_nas_routes, route);
        uint32_t removed = before - list_count(reverse_coa_nas_routes);
        for (uint32_t r = 0; r < removed; r++)
            reverse_coa_route_deref(route);
    }

    if (client->conf->reverse_coa_realms) {
        for (i = 0; client->conf->reverse_coa_realms[i]; i++) {
            char *realm = client->conf->reverse_coa_realms[i];
            char patbuf[256];
            struct reverse_coa_regex_entry *re = NULL;
            struct list *target_list = resolve_realm_list_for_unregister(realm, patbuf, sizeof(patbuf), &re);

            if (!target_list)
                continue;

            uint32_t before = list_count(target_list);
            list_removedata(target_list, route);
            uint32_t removed = before - list_count(target_list);
            for (uint32_t r = 0; r < removed; r++) {
                reverse_coa_route_deref(route);
                debug(DBG_DBG, "unregister_reverse_coa_client: unregistered client %s from %s realm '%s'",
                      client->conf->name, re ? "regex" : "exact", re ? re->pattern : realm);
            }
            if (list_count(target_list) == 0) {
                if (re) {
                    list_removedata(realm_reverse_coa_regex_list, re);
                    list_destroy(target_list);
                    regfree(&re->regex);
                    free(re->pattern);
                    free(re);
                } else {
                    hash_extract(realm_reverse_coa_clients, realm, strlen(realm));
                    list_destroy(target_list);
                }
            }
        }
    }

    pthread_mutex_unlock(&realm_reverse_coa_lock);

    pthread_mutex_lock(&route->refmutex);
    route->target = NULL;
    pthread_mutex_unlock(&route->refmutex);
}

static void clear_rqout(struct rqout *rqout) {
    if (rqout->rq)
        freerq(rqout->rq);
    rqout->rq = NULL;
    memset(&rqout->expiry, 0, sizeof(struct timeval));
}

void free_reverse_coa_rqs(struct client *client) {
    if (!client->reverse_coa_rqs)
        return;
    for (int i = 0; i < MAX_REQUESTS; i++)
        clear_rqout(&client->reverse_coa_rqs[i]);
    free(client->reverse_coa_rqs);
    client->reverse_coa_rqs = NULL;
}

static void clear_dedup_slot(struct coa_dedup_slot *slot) {
    free(slot->replybuf);
    memset(slot, 0, sizeof(*slot));
}

static inline int slot_expired(const struct coa_dedup_slot *slot, time_t now) {
    return now >= slot->received + REVERSE_COA_DEDUP_WINDOW;
}

static int is_coa_duplicate(struct server *server, struct radmsg *msg) {
    struct coa_dedup_slot *slot;
    time_t now;
    uint8_t *replybuf = NULL;
    int replybuflen = 0;

    pthread_mutex_lock(&server->reverse_coa_lock);
    slot = &server->reverse_coa_seen[msg->id];
    if (!slot->occupied) {
        pthread_mutex_unlock(&server->reverse_coa_lock);
        return 0;
    }

    time(&now);
    if (slot_expired(slot, now)) {
        clear_dedup_slot(slot);
        pthread_mutex_unlock(&server->reverse_coa_lock);
        return 0;
    }

    if (memcmp(slot->auth, msg->auth, 16) != 0) {
        /* different auth means this is a new request reusing the id,
           not a retransmission - caller (record_coa_dedup) will overwrite the slot */
        pthread_mutex_unlock(&server->reverse_coa_lock);
        return 0;
    }

    if (slot->replybuf && slot->replybuflen > 0) {
        replybuf = malloc(slot->replybuflen);
        if (replybuf) {
            memcpy(replybuf, slot->replybuf, slot->replybuflen);
            replybuflen = slot->replybuflen;
        } else {
            debug(DBG_WARN, "is_coa_duplicate: malloc failed copying cached reply for id %d to %s, duplicate will be swallowed",
                  msg->id, server->conf->name);
        }
    }
    pthread_mutex_unlock(&server->reverse_coa_lock);

    if (replybuf) {
        debug(DBG_INFO, "is_coa_duplicate: resending cached response for id %d to %s",
              msg->id, server->conf->name);
        server->conf->pdef->clientradput(server, replybuf, replybuflen);
        free(replybuf);
    } else {
        debug(DBG_DBG, "is_coa_duplicate: retransmission for id %d from %s, response pending",
              msg->id, server->conf->name);
    }

    return 1;
}

static void expire_coa_dedup_entries(struct server *server) {
    time_t now;
    int cleaned = 0;
    int i;

    time(&now);

    if (now < server->last_dedup_cleanup + REVERSE_COA_DEDUP_WINDOW)
        return;

    pthread_mutex_lock(&server->reverse_coa_lock);
    for (i = 0; i < MAX_REQUESTS; i++) {
        struct coa_dedup_slot *slot = &server->reverse_coa_seen[i];
        if (slot->occupied && slot_expired(slot, now)) {
            clear_dedup_slot(slot);
            cleaned++;
        }
    }
    server->last_dedup_cleanup = now;
    pthread_mutex_unlock(&server->reverse_coa_lock);

    if (cleaned > 0)
        debug(DBG_DBG, "expire_coa_dedup_entries: purged %d stale entries for server %s",
              cleaned, server->conf->name);
}

static int match_nas_ext_operator(const struct client *client, const struct tlv *attr,
                                  const char **sublabel_out) {
    (void)sublabel_out;
    if (!client->conf->nas_identifier)
        return 0;
    size_t nas_id_len = strlen(client->conf->nas_identifier);
    return attr->l > 1 && attr->v[0] == RAD_Extended_Operator_NAS_Id &&
           attr->l - 1 == nas_id_len &&
           memcmp(attr->v + 1, client->conf->nas_identifier, nas_id_len) == 0;
}

static int match_nas_identifier_attr(const struct client *client, const struct tlv *attr,
                                     const char **sublabel_out) {
    (void)sublabel_out;
    if (!client->conf->nas_identifier)
        return 0;
    size_t nas_id_len = strlen(client->conf->nas_identifier);
    return attr->l == nas_id_len &&
           memcmp(attr->v, client->conf->nas_identifier, nas_id_len) == 0;
}

static int match_nas_ipv4(const struct client *client, const struct tlv *attr,
                          const char **sublabel_out) {
    struct in_addr nas_ipv4;
    if (attr->l != 4 || !client->addr)
        return 0;
    memcpy(&nas_ipv4, attr->v, 4);
    if (client->addr->sa_family == AF_INET) {
        struct sockaddr_in *ca = (struct sockaddr_in *)client->addr;
        return ca->sin_addr.s_addr == nas_ipv4.s_addr;
    }
    if (client->addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *ca6 = (struct sockaddr_in6 *)client->addr;
        if (IN6_IS_ADDR_V4MAPPED(&ca6->sin6_addr) &&
            memcmp(&ca6->sin6_addr.s6_addr[12], &nas_ipv4, 4) == 0) {
            *sublabel_out = " (v4-mapped)";
            return 1;
        }
    }
    return 0;
}

static int match_nas_ipv6(const struct client *client, const struct tlv *attr,
                          const char **sublabel_out) {
    (void)sublabel_out;
    if (attr->l != 16 || !client->addr || client->addr->sa_family != AF_INET6)
        return 0;
    struct sockaddr_in6 *ca = (struct sockaddr_in6 *)client->addr;
    return memcmp(&ca->sin6_addr, attr->v, 16) == 0;
}

struct nas_matcher {
    uint8_t attr_type;
    int (*matches)(const struct client *client, const struct tlv *attr, const char **sublabel_out);
    const char *label;
    uint8_t want_all; /* 1 = walk all attrs via radmsg_getalltype, 0 = first via radmsg_gettype */
};

static const struct nas_matcher nas_matchers[] = {
    {RAD_Attr_Extended_Type_1, match_nas_ext_operator, "operator-nas-identifier (241.8)", 1},
    {RAD_Attr_NAS_Identifier, match_nas_identifier_attr, "nas-identifier", 0},
    {RAD_Attr_NAS_IP_Address, match_nas_ipv4, "nas-ip-address", 0},
    {RAD_Attr_NAS_IPv6_Address, match_nas_ipv6, "nas-ipv6-address", 0},
};

static int match_nas_identifier(struct client *client, struct radmsg *msg) {
    for (size_t i = 0; i < sizeof(nas_matchers) / sizeof(nas_matchers[0]); i++) {
        const struct nas_matcher *m = &nas_matchers[i];
        const char *sublabel = "";
        int hit = 0;

        if (m->want_all) {
            struct list *attrs = radmsg_getalltype(msg, m->attr_type);
            if (attrs) {
                for (struct list_node *node = list_first(attrs); node && !hit; node = list_next(node))
                    hit = m->matches(client, (struct tlv *)node->data, &sublabel);
                list_free(attrs);
            }
        } else {
            struct tlv *attr = radmsg_gettype(msg, m->attr_type);
            if (attr)
                hit = m->matches(client, attr, &sublabel);
        }

        if (hit) {
            debug(DBG_DBG, "match_nas_identifier: matched via %s%s", m->label, sublabel);
            return 1;
        }
    }
    return 0;
}

/* Operator-NAS-Identifier (RFC 8559 section 3.4) naming one of our client
   connections: an opaque token carrying a per-process nonce and the client
   serial. The nonce keeps a token from a previous run from selecting an
   unrelated connection. */
#define ONI_PREFIX "rsp1:"
#define ONI_LEN (sizeof(ONI_PREFIX) - 1 + 8 + 1 + 8)

int reverse_coa_oni_format(uint32_t serial, char *buf, size_t bufsize) {
    int n = snprintf(buf, bufsize, ONI_PREFIX "%08x:%08x", oni_nonce, serial);
    return n == (int)ONI_LEN && (size_t)n < bufsize ? n : 0;
}

int reverse_coa_oni_parse(const struct tlv *attr, uint32_t *serial) {
    char buf[ONI_LEN + 1];
    unsigned int nonce, ser;

    if (!attr || attr->t != RAD_Attr_Extended_Type_1 || attr->l != ONI_LEN + 1 || attr->v[0] != RAD_Extended_Operator_NAS_Id)
        return 0;
    memcpy(buf, attr->v + 1, ONI_LEN);
    buf[ONI_LEN] = '\0';
    if (sscanf(buf, ONI_PREFIX "%8x:%8x", &nonce, &ser) != 2 || nonce != oni_nonce)
        return 0;
    *serial = ser;
    return 1;
}

/* RFC 8559 section 3.4: added by the visited network to Access-Request and
   Accounting-Request only, at most once, and only next to an Operator-Name */
int add_operator_nas_identifier(struct client *from, struct radmsg *msg) {
    char token[ONI_LEN + 1];
    struct tlv *attr;
    int len;

    if (!radmsg_gettype(msg, RAD_Attr_Operator_Name)) {
        debug(DBG_DBG, "add_operator_nas_identifier: no operator-name in %s (id %d) from %s, not adding operator-nas-identifier",
              radmsgtype2string(msg->code), msg->id, from->conf->name);
        return 1;
    }
    if (radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier)) {
        debug(DBG_DBG, "add_operator_nas_identifier: %s (id %d) from %s already carries an operator-nas-identifier, leaving it",
              radmsgtype2string(msg->code), msg->id, from->conf->name);
        return 1;
    }
    len = reverse_coa_oni_format(from->serial, token, sizeof(token));
    if (!len)
        return 0;
    attr = makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, len, token);
    if (!attr || !radmsg_add(msg, attr, 0)) {
        freetlv(attr);
        return 0;
    }
    debug(DBG_DBG, "add_operator_nas_identifier: added %s to %s (id %d) from client %s", token,
          radmsgtype2string(msg->code), msg->id, from->conf->name);
    return 1;
}

/* RFC 8559 section 4.2: the visited network removes Operator-Name and
   Operator-NAS-Identifier before the packet reaches the NAS */
void strip_operator_attrs(struct radmsg *msg) {
    struct list_node *n, *p = NULL;
    struct tlv *attr;

    n = list_first(msg->attrs);
    while (n) {
        attr = (struct tlv *)n->data;
        if (attr->t == RAD_Attr_Operator_Name ||
            (attr->t == RAD_Attr_Extended_Type_1 && attr->l > 0 && attr->v[0] == RAD_Extended_Operator_NAS_Id)) {
            list_removedata(msg->attrs, attr);
            freetlv(attr);
            n = p ? list_next(p) : list_first(msg->attrs);
        } else {
            p = n;
            n = list_next(n);
        }
    }
}

static void expire_reverse_coa_rqs(struct client *client) {
    struct timeval now;
    int i, cleaned = 0;

    if (!client->reverse_coa_rqs)
        return;

    gettimeofday(&now, NULL);
    for (i = 0; i < MAX_REQUESTS; i++) {
        struct rqout *rqout = &client->reverse_coa_rqs[i];
        if (rqout->rq && rqout->expiry.tv_sec > 0 && now.tv_sec > rqout->expiry.tv_sec) {
            debug(DBG_INFO, "expire_reverse_coa_rqs: expired request id %d for client %s",
                  i, client->conf->name);
            clear_rqout(rqout);
            cleaned++;
        }
    }
    if (cleaned > 0)
        debug(DBG_DBG, "expire_reverse_coa_rqs: cleaned %d expired requests for client %s",
              cleaned, client->conf->name);
}

static int send_reverse_coa_nak(struct server *server, struct radmsg *req, uint32_t error_cause,
                                uint8_t **out_buf, int *out_len) {
    struct radmsg *nak;
    uint8_t nakcode;
    uint8_t *buf = NULL;
    uint32_t ec_net;
    uint8_t ma_zeros[16] = {0};

    if (out_buf)
        *out_buf = NULL;
    if (out_len)
        *out_len = 0;

    nakcode = (req->code == RAD_CoA_Request) ? RAD_CoA_NAK : RAD_Disconnect_NAK;
    nak = radmsg_init(nakcode, req->id, req->auth);
    if (!nak) {
        debug(DBG_ERR, "send_reverse_coa_nak: radmsg_init failed");
        return 0;
    }

    ec_net = htonl(error_cause);
    if (!radmsg_add(nak, maketlv(RAD_Attr_Error_Cause, 4, (uint8_t *)&ec_net), 0)) {
        debug(DBG_ERR, "send_reverse_coa_nak: failed to add error-cause");
        radmsg_free(nak);
        return 0;
    }

    int ps_count = radmsg_copy_attrs(nak, req, RAD_Attr_Proxy_State);
    if (ps_count < 0)
        debug(DBG_WARN, "send_reverse_coa_nak: failed to copy proxy-state");
    else if (ps_count > 0)
        debug(DBG_DBG, "send_reverse_coa_nak: copied %d proxy-state attribute(s)", ps_count);

    if (!radmsg_add(nak, maketlv(RAD_Attr_Message_Authenticator, 16, ma_zeros), 0))
        debug(DBG_WARN, "send_reverse_coa_nak: failed to add message-authenticator");

    int radlen = radmsg2buf(nak, server->conf->secret, server->conf->secret_len, &buf);
    if (radlen <= 0) {
        debug(DBG_ERR, "send_reverse_coa_nak: radmsg2buf failed");
        radmsg_free(nak);
        return 0;
    }

    debug(DBG_DBG, "send_reverse_coa_nak: sending %s (id %d, error_cause=%u) to server %s",
          radmsgtype2string(nakcode), nak->id, error_cause, server->conf->name);

    server->conf->pdef->clientradput(server, buf, radlen);

    if (out_buf && out_len) {
        *out_buf = buf;
        *out_len = radlen;
    } else {
        free(buf);
    }
    radmsg_free(nak);
    return 1;
}

static int send_coa_to_client(struct server *from_server, struct request *origin, struct client *to_client, struct radmsg *msg, int final_hop) {
    struct request *rq;
    struct rqout *rqout;
    struct radmsg *copy;
    uint8_t newid;
    int attempts = 0;
    int replybuflen;

    if (!to_client->reverse_coa_rqs) {
        debug(DBG_WARN, "send_coa_to_client: client %s not configured for reverse coa",
              to_client->conf->name);
        return 0;
    }

    copy = radmsg_dup(msg);
    if (!copy) {
        debug(DBG_ERR, "send_coa_to_client: radmsg_dup failed");
        return 0;
    }
    if (final_hop)
        strip_operator_attrs(copy);

    rq = newrequest();
    if (!rq) {
        debug(DBG_ERR, "send_coa_to_client: newrequest failed");
        radmsg_free(copy);
        return 0;
    }

    pthread_mutex_lock(&to_client->lock);

    expire_reverse_coa_rqs(to_client);

    for (attempts = 0; attempts < MAX_REQUESTS; attempts++) {
        newid = to_client->reverse_coa_nextid++;
        rqout = &to_client->reverse_coa_rqs[newid];
        if (!rqout->rq)
            break;
    }

    if (attempts >= MAX_REQUESTS) {
        pthread_mutex_unlock(&to_client->lock);
        debug(DBG_WARN, "send_coa_to_client: no available ids for client %s", to_client->conf->name);
        freerq(rq);
        radmsg_free(copy);
        return 0;
    }

    rq->rqid = msg->id;
    memcpy(rq->rqauth, msg->auth, 16);
    rq->to = from_server;
    rq->origin = origin ? newrqref(origin) : NULL;
    rq->from = to_client;
    rq->udpsock = to_client->sock;
    rq->newid = newid;

    /* udp reverse coa must target the coa listener port, not the ephemeral src port
       of the last auth request. tls/dtls go through the existing tunnel and ignore to_override. */
    if (to_client->conf->type == RAD_UDP && to_client->addr) {
        rq->to_override = malloc(sizeof(struct sockaddr_storage));
        if (!rq->to_override) {
            pthread_mutex_unlock(&to_client->lock);
            debug(DBG_ERR, "send_coa_to_client: malloc failed for to_override");
            freerq(rq);
            radmsg_free(copy);
            return 0;
        }
        memset(rq->to_override, 0, sizeof(struct sockaddr_storage));
        memcpy(rq->to_override, to_client->addr, SOCKADDRP_SIZE(to_client->addr));
        port_set((struct sockaddr *)rq->to_override, (uint16_t)to_client->conf->coaport);
    }

    copy->id = newid;
    /* zero auth before radmsg2buf; _radsign hashes the buffer with auth bytes in place */
    memset(copy->auth, 0, 16);
    rq->msg = copy;

    /* pre-encode the buffer under the lock so sentauth is populated before
       rqout->rq is visible. this closes the race where a fast nas response arrives between
       the unlock and the sentauth write that previously happened after sendreply returned. */
    replybuflen = radmsg2buf(rq->msg, to_client->conf->secret, to_client->conf->secret_len, &rq->replybuf);
    if (replybuflen <= 0 || !rq->replybuf) {
        pthread_mutex_unlock(&to_client->lock);
        debug(DBG_ERR, "send_coa_to_client: radmsg2buf failed for client %s", to_client->conf->name);
        freerq(rq);
        return 0;
    }
    rq->replybuflen = replybuflen;

    rqout->rq = rq;
    gettimeofday(&rqout->expiry, NULL);
    rqout->expiry.tv_sec += to_client->conf->reverse_coa_timeout;
    memcpy(rqout->sentauth, rq->replybuf + 4, 16);

    pthread_mutex_unlock(&to_client->lock);

    debug(DBG_DBG, "send_coa_to_client: forwarding %s (orig id %d -> new id %d) to client %s",
          radmsgtype2string(copy->code), msg->id, newid, to_client->conf->name);

    sendreply(newrqref(rq));
    return 1;
}

static int try_send_to_realm_clients(struct server *server, struct request *origin, const char *realm, struct radmsg *msg) {
    struct reverse_coa_route *candidates[MAX_REVERSE_COA_FAILOVER];
    int count = 0;
    int preferred_idx = -1;
    int sent = 0;

    pthread_mutex_lock(&realm_reverse_coa_lock);
    struct list *clients = hash_read(realm_reverse_coa_clients, realm, strlen(realm));
    if (clients) {
        struct list_node *entry;
        for (entry = list_first(clients); entry && count < MAX_REVERSE_COA_FAILOVER; entry = list_next(entry)) {
            candidates[count] = (struct reverse_coa_route *)entry->data;
            reverse_coa_route_ref(candidates[count]);
            count++;
        }
    }
    if (count == 0) {
        debug(DBG_DBG, "try_send_to_realm_clients: no exact match for realm %s, trying regex patterns", realm);
        struct list_node *re_node;
        for (re_node = list_first(realm_reverse_coa_regex_list); re_node; re_node = list_next(re_node)) {
            struct reverse_coa_regex_entry *re = (struct reverse_coa_regex_entry *)re_node->data;
            if (!regexec(&re->regex, realm, 0, NULL, 0)) {
                struct list_node *cl_node;
                for (cl_node = list_first(re->clients); cl_node && count < MAX_REVERSE_COA_FAILOVER; cl_node = list_next(cl_node)) {
                    candidates[count] = (struct reverse_coa_route *)cl_node->data;
                    reverse_coa_route_ref(candidates[count]);
                    count++;
                }
                break;
            }
        }
    }
    pthread_mutex_unlock(&realm_reverse_coa_lock);

    if (count == 0)
        return 0;

    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&candidates[i]->refmutex);
        if (candidates[i]->target && match_nas_identifier(candidates[i]->target, msg))
            preferred_idx = i;
        pthread_mutex_unlock(&candidates[i]->refmutex);
        if (preferred_idx == i)
            break;
    }

    int start = (preferred_idx >= 0) ? preferred_idx : 0;
    pthread_mutex_lock(&candidates[start]->refmutex);
    if (candidates[start]->target) {
        debug(DBG_DBG, "try_send_to_realm_clients: trying %s client %s for realm %s",
              (preferred_idx >= 0) ? "preferred" : "first",
              candidates[start]->target->conf->name, realm);
        sent = send_coa_to_client(server, origin, candidates[start]->target, msg,
                                  preferred_idx >= 0 || candidates[start]->target->conf->type == RAD_UDP);
    }
    pthread_mutex_unlock(&candidates[start]->refmutex);

    if (!sent) {
        for (int i = 0; i < count && !sent; i++) {
            if (i == start)
                continue;
            pthread_mutex_lock(&candidates[i]->refmutex);
            if (candidates[i]->target) {
                debug(DBG_DBG, "try_send_to_realm_clients: trying alternate client %s (previous send failed locally) for realm %s",
                      candidates[i]->target->conf->name, realm);
                sent = send_coa_to_client(server, origin, candidates[i]->target, msg, candidates[i]->target->conf->type == RAD_UDP);
                if (sent)
                    debug(DBG_INFO, "try_send_to_realm_clients: send to alternate client %s succeeded",
                          candidates[i]->target->conf->name);
            }
            pthread_mutex_unlock(&candidates[i]->refmutex);
        }
    }

    for (int i = 0; i < count; i++)
        reverse_coa_route_deref(candidates[i]);

    return sent;
}

static void record_coa_dedup(struct server *server, uint8_t id, uint8_t *auth) {
    struct coa_dedup_slot *slot;

    pthread_mutex_lock(&server->reverse_coa_lock);
    slot = &server->reverse_coa_seen[id];
    if (slot->occupied && memcmp(slot->auth, auth, 16) != 0) {
        debug(DBG_DBG, "record_coa_dedup: slot %d for server %s reused (distinct auth, prior entry discarded)",
              id, server->conf->name);
    }
    clear_dedup_slot(slot);
    memcpy(slot->auth, auth, 16);
    time(&slot->received);
    slot->occupied = 1;
    pthread_mutex_unlock(&server->reverse_coa_lock);
}

static void cache_coa_dedup_reply(struct server *server, uint8_t id, uint8_t *auth,
                                  uint8_t *buf, int buflen) {
    struct coa_dedup_slot *slot;

    pthread_mutex_lock(&server->reverse_coa_lock);
    slot = &server->reverse_coa_seen[id];
    if (!slot->occupied || memcmp(slot->auth, auth, 16) != 0 || slot->replybuf) {
        pthread_mutex_unlock(&server->reverse_coa_lock);
        return;
    }
    slot->replybuf = malloc(buflen);
    if (!slot->replybuf) {
        debug(DBG_WARN, "cache_coa_dedup_reply: malloc failed for id %d to %s, retransmissions will trigger re-route instead of fast replay",
              id, server->conf->name);
        pthread_mutex_unlock(&server->reverse_coa_lock);
        return;
    }
    memcpy(slot->replybuf, buf, buflen);
    slot->replybuflen = buflen;
    pthread_mutex_unlock(&server->reverse_coa_lock);
}

/* stage 0: the connection this proxy named in Operator-NAS-Identifier when it
   forwarded the session's Access-Request (RFC 8559 section 3.4) */
static int try_send_to_affine_client(struct server *server, struct request *origin, struct radmsg *msg) {
    struct reverse_coa_route *route = NULL;
    struct list_node *node;
    uint32_t serial;
    int sent = 0;

    if (!reverse_coa_oni_parse(radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier), &serial))
        return 0;

    pthread_mutex_lock(&realm_reverse_coa_lock);
    for (node = list_first(reverse_coa_nas_routes); node && !route; node = list_next(node)) {
        struct reverse_coa_route *candidate = (struct reverse_coa_route *)node->data;
        pthread_mutex_lock(&candidate->refmutex);
        if (candidate->target && candidate->target->serial == serial)
            route = candidate;
        pthread_mutex_unlock(&candidate->refmutex);
    }
    if (route)
        reverse_coa_route_ref(route);
    pthread_mutex_unlock(&realm_reverse_coa_lock);

    if (!route) {
        debug(DBG_INFO, "try_send_to_affine_client: operator-nas-identifier names connection %u which is gone, trying realm and nas identity", serial);
        return 0;
    }

    pthread_mutex_lock(&route->refmutex);
    if (route->target) {
        debug(DBG_DBG, "try_send_to_affine_client: operator-nas-identifier matched client %s (connection %u)",
              route->target->conf->name, serial);
        sent = send_coa_to_client(server, origin, route->target, msg, 1);
    }
    pthread_mutex_unlock(&route->refmutex);
    reverse_coa_route_deref(route);
    return sent;
}

static int try_send_to_nas_client(struct server *server, struct request *origin, struct radmsg *msg) {
    struct reverse_coa_route *candidates[MAX_REVERSE_COA_FAILOVER];
    int count = 0;
    int sent = 0;

    pthread_mutex_lock(&realm_reverse_coa_lock);
    struct list_node *node;
    for (node = list_first(reverse_coa_nas_routes);
         node && count < MAX_REVERSE_COA_FAILOVER;
         node = list_next(node)) {
        candidates[count] = (struct reverse_coa_route *)node->data;
        reverse_coa_route_ref(candidates[count]);
        count++;
    }
    pthread_mutex_unlock(&realm_reverse_coa_lock);

    for (int i = 0; i < count && !sent; i++) {
        pthread_mutex_lock(&candidates[i]->refmutex);
        if (candidates[i]->target && match_nas_identifier(candidates[i]->target, msg)) {
            debug(DBG_DBG, "try_send_to_nas_client: trying client %s",
                  candidates[i]->target->conf->name);
            sent = send_coa_to_client(server, origin, candidates[i]->target, msg, 1);
        }
        pthread_mutex_unlock(&candidates[i]->refmutex);
    }

    for (int i = 0; i < count; i++)
        reverse_coa_route_deref(candidates[i]);

    if (!sent)
        debug(DBG_DBG, "try_send_to_nas_client: no NAS identity match found");
    return sent;
}

static int dispatch_reverse_coa(struct server *server, struct request *origin, struct radmsg *msg) {
    char realm_buf[256];
    char *realm = extract_operator_realm(msg, realm_buf, sizeof(realm_buf));

    debug(DBG_DBG, "dispatch_reverse_coa: looking for client for realm %s", realm ? realm : "(none)");

    /* stage 0: the connection named in Operator-NAS-Identifier, then the two
       stages of draft-ietf-radext-reverse-coa section 6: stage 1 - realm-based
       (intermediate proxy), stage 2 - NAS-identity (final proxy) */
    if (try_send_to_affine_client(server, origin, msg))
        return 1;
    if (realm && try_send_to_realm_clients(server, origin, realm, msg))
        return 1;
    if (try_send_to_nas_client(server, origin, msg))
        return 1;

    if (realm)
        debug(DBG_WARN, "dispatch_reverse_coa: no route for realm %s", realm);
    else
        debug(DBG_WARN, "dispatch_reverse_coa: no operator-name and no NAS identity match");
    return 0;
}

static void route_reverse_coa(struct server *server, struct radmsg *msg) {
    uint8_t *nakbuf = NULL;
    int naklen = 0;

    record_coa_dedup(server, msg->id, msg->auth);
    if (dispatch_reverse_coa(server, NULL, msg)) {
        radmsg_free(msg);
        return;
    }

    (void)send_reverse_coa_nak(server, msg, RAD_Err_Request_Not_Routable, &nakbuf, &naklen);
    if (nakbuf) {
        cache_coa_dedup_reply(server, msg->id, msg->auth, nakbuf, naklen);
        free(nakbuf);
    }
    radmsg_free(msg);
}

/* a CoA/Disconnect-Request received from a client (acceptCoA) that no coaServer
   takes: offer it to the reverse coa routes; the response comes back through
   forward_coa_response() and answers rq. 1 if dispatched, 0 if no route. */
int route_reverse_coa_from_client(struct request *rq) {
    if (!rq || !rq->msg || !rq->from)
        return 0;
    if (!dispatch_reverse_coa(NULL, rq, rq->msg))
        return 0;
    debug(DBG_INFO, "route_reverse_coa_from_client: %s (id %d) from client %s sent down a reverse coa route",
          radmsgtype2string(rq->msg->code), rq->msg->id, rq->from->conf->name);
    return 1;
}

static void handle_reverse_coa_request(struct server *server, uint8_t *buf, int len) {
    struct radmsg *msg;

    debug(DBG_DBG, "handle_reverse_coa_request: raw packet from %s (len=%d):",
          server->conf->name, len);
    debug_hexdump("coa raw", buf, len);

    msg = buf2radmsg(buf, len, server->conf->secret, server->conf->secret_len, NULL);
    if (!msg) {
        debug(DBG_INFO, "handle_reverse_coa_request: silently discarding invalid packet from %s",
              server->conf->name);
        return;
    }

    if (msg->authstate == RSP_RADMSG_MSGAUTH_INVALID || msg->authstate == RSP_RADMSG_INVALID) {
        debug(DBG_WARN, "handle_reverse_coa_request: message-authenticator invalid from %s, discarding",
              server->conf->name);
        radmsg_free(msg);
        return;
    }

    expire_coa_dedup_entries(server);

    if (is_coa_duplicate(server, msg)) {
        debug(DBG_DBG, "handle_reverse_coa_request: duplicate request "
                       "id %d from %s",
              msg->id, server->conf->name);
        radmsg_free(msg);
        return;
    }

    debug(DBG_INFO, "handle_reverse_coa_request: received %s (id %d) from server %s",
          radmsgtype2string(msg->code), msg->id, server->conf->name);
    debug_dump_attrs("coa parsed", msg);

    route_reverse_coa(server, msg);
}

int forward_coa_response(struct client *from, struct radmsg *msg) {
    struct rqout *rqout;
    struct server *to_server;
    uint8_t origid;
    uint8_t origauth[16];
    uint8_t *buf = NULL;
    struct radmsg *server_copy = NULL;
    struct timeval now;
    int radlen;
    int ret = 0;

    if (!from->reverse_coa_rqs) {
        debug(DBG_DBG, "forward_coa_response: client %s has no reverse coa tracking", from->conf->name);
        return 0;
    }

    pthread_mutex_lock(&from->lock);

    expire_reverse_coa_rqs(from);

    rqout = &from->reverse_coa_rqs[msg->id];
    if (!rqout->rq) {
        pthread_mutex_unlock(&from->lock);
        debug(DBG_DBG, "forward_coa_response: no pending request for id %d from client %s",
              msg->id, from->conf->name);
        return 0;
    }

    gettimeofday(&now, NULL);
    if (rqout->expiry.tv_sec > 0 && now.tv_sec > rqout->expiry.tv_sec) {
        debug(DBG_INFO, "forward_coa_response: request id %d expired, discarding response", msg->id);
        goto cleanup;
    }

    if (rqout->rq->origin) {
        struct request *origin = rqout->rq->origin;
        struct radmsg *reply;

        rqout->rq->origin = NULL;
        if (!origin->from) {
            debug(DBG_INFO, "forward_coa_response: client that sent request id %d is gone, dropping %s",
                  origin->rqid, radmsgtype2string(msg->code));
            freerq(origin);
            goto cleanup;
        }
        reply = radmsg_dup(msg);
        if (!reply) {
            debug(DBG_ERR, "forward_coa_response: radmsg_dup failed");
            freerq(origin);
            goto cleanup;
        }
        reply->id = origin->rqid;
        memcpy(reply->auth, origin->rqauth, 16);
        debug(DBG_DBG, "forward_coa_response: answering request id %d from client %s with %s",
              origin->rqid, origin->from->conf->name, radmsgtype2string(reply->code));
        radmsg_free(origin->msg);
        origin->msg = reply;
        /* sendreply takes over the reference held by the tracking request */
        if (sendreply(origin) < 1)
            debug(DBG_ERR, "forward_coa_response: answering request id %d failed", origin->rqid);
        ret = 1;
        goto cleanup;
    }

    to_server = rqout->rq->to;
    origid = rqout->rq->rqid;
    memcpy(origauth, rqout->rq->rqauth, 16);

    if (!to_server || !to_server->conf) {
        debug(DBG_WARN, "forward_coa_response: origin server no longer valid");
        goto cleanup;
    }

    server_copy = radmsg_dup(msg);
    if (!server_copy) {
        debug(DBG_ERR, "forward_coa_response: radmsg_dup failed");
        goto cleanup;
    }
    server_copy->id = origid;
    memcpy(server_copy->auth, origauth, 16);

    radlen = radmsg2buf(server_copy, to_server->conf->secret, to_server->conf->secret_len, &buf);
    if (radlen <= 0) {
        debug(DBG_ERR, "forward_coa_response: radmsg2buf failed");
        goto cleanup;
    }

    debug(DBG_DBG, "forward_coa_response: forwarding %s (id %d) to server %s",
          radmsgtype2string(server_copy->code), origid, to_server->conf->name);

    to_server->conf->pdef->clientradput(to_server, buf, radlen);
    cache_coa_dedup_reply(to_server, origid, origauth, buf, radlen);

    ret = 1;

cleanup:
    rqout->rq->msg = NULL;
    clear_rqout(rqout);
    pthread_mutex_unlock(&from->lock);
    radmsg_free(server_copy);
    free(buf);
    return ret;
}

void invalidate_reverse_coa_rqs_for_server(struct server *server, struct list *clconfs) {
    struct list_node *confentry, *cliententry;
    struct clsrvconf *conf;
    struct client *client;
    int i, cleaned = 0;

    for (confentry = list_first(clconfs); confentry; confentry = list_next(confentry)) {
        conf = (struct clsrvconf *)confentry->data;
        if (!conf || !conf->clients)
            continue;

        pthread_mutex_lock(conf->lock);
        for (cliententry = list_first(conf->clients); cliententry; cliententry = list_next(cliententry)) {
            client = (struct client *)cliententry->data;
            if (!client || !client->reverse_coa_rqs)
                continue;

            pthread_mutex_lock(&client->lock);
            for (i = 0; i < MAX_REQUESTS; i++) {
                struct rqout *rqout = &client->reverse_coa_rqs[i];
                if (rqout->rq && rqout->rq->to == server) {
                    debug(DBG_DBG, "invalidate_reverse_coa_rqs_for_server: clearing request id %d from client %s (server %s disconnecting)",
                          i, client->conf->name, server->conf->name);
                    clear_rqout(rqout);
                    cleaned++;
                }
            }
            pthread_mutex_unlock(&client->lock);
        }
        pthread_mutex_unlock(conf->lock);
    }

    if (cleaned > 0)
        debug(DBG_INFO, "invalidate_reverse_coa_rqs_for_server: cleared %d pending requests for server %s",
              cleaned, server->conf->name);
}

int lookup_reverse_coa_rqauth(struct client *from, uint8_t *buf, int buflen, uint8_t *out_auth) {
    uint8_t resp_id;
    struct rqout *rqout;

    if (buflen < 2 || !from->reverse_coa_rqs)
        return 0;
    if (!IS_COA_RESPONSE(buf[0]))
        return 0;

    resp_id = buf[1];
    pthread_mutex_lock(&from->lock);
    rqout = &from->reverse_coa_rqs[resp_id];
    if (rqout->rq) {
        memcpy(out_auth, rqout->sentauth, 16);
        pthread_mutex_unlock(&from->lock);
        return 1;
    }
    pthread_mutex_unlock(&from->lock);
    return 0;
}

void drain_coa_dedup(struct server *server) {
    int i;

    pthread_mutex_lock(&server->reverse_coa_lock);
    for (i = 0; i < MAX_REQUESTS; i++) {
        struct coa_dedup_slot *slot = &server->reverse_coa_seen[i];
        if (slot->occupied)
            clear_dedup_slot(slot);
    }
    pthread_mutex_unlock(&server->reverse_coa_lock);
}

int try_handle_reverse_coa_request(struct server *server, unsigned char *buf, int len) {
    uint8_t code = buf[0];

    if (IS_COA_REQUEST(code)) {
        if (!server->conf->accept_reverse_coa) {
            debug(DBG_INFO, "silently discarding reverse CoA from %s (not enabled)",
                  server->conf->name);
        } else {
            handle_reverse_coa_request(server, buf, len);
        }
        free(buf);
        return 1;
    }
    return 0;
}

#endif /* RADPROT_TLS || RADPROT_DTLS */
