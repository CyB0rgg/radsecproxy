/* Copyright (c) 2026, Nova Labs */
/* See LICENSE for licensing information. */

#include "../debug.h"
#include "../list.h"
#include "../radmsg.h"
#include "../radsecproxy.h"
#include "../reverse_coa.h"
#include "../udp.h"
#include "../util.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void removequeue(struct gqueue *q); /* not in a header */

int numtests = 0;

static uint8_t *secret = (uint8_t *)"testing123";
static int secretlen = 10;
static char *literalrealm[] = {"Example.COM", NULL};
static char *regexprealm[] = {"/\\.example\\.net$/", NULL};

/* the last packet sent to the originating server */
static uint8_t *sentbuf;
static int sentlen, sentcount;

void test_ok(int condition, char *msg) {
    if (!condition)
        printf("not ");
    printf("ok %d - %s\n", ++numtests, msg);
}

void test_eq(int expected, int actual, char *msg) {
    if (actual != expected)
        printf("not ");
    printf("ok %d - %s (expected %d, got %d)\n", ++numtests, msg, expected, actual);
}

static int stubradput(struct server *server, unsigned char *buf, int len) {
    free(sentbuf);
    sentbuf = malloc(len);
    memcpy(sentbuf, buf, len);
    sentlen = len;
    sentcount++;
    return 1;
}

static struct protodefs stubpdef = {.clientradput = stubradput};

/* a CoA-ACK with its response authenticator over rqauth, with a Proxy-State attribute when asked */
static int coaack(uint8_t *pkt, uint8_t id, int withattr, const uint8_t *rqauth) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int len = withattr ? 26 : 20;

    memset(pkt, 0, 26);
    pkt[0] = RAD_CoA_ACK;
    pkt[1] = id;
    pkt[3] = len;
    if (withattr) {
        pkt[20] = RAD_Attr_Proxy_State;
        pkt[21] = 6;
        memcpy(pkt + 22, "\xde\xad\xbe\xef", 4);
    }
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, pkt, 4);
    EVP_DigestUpdate(ctx, rqauth, 16);
    EVP_DigestUpdate(ctx, pkt + 20, len - 20);
    EVP_DigestUpdate(ctx, secret, secretlen);
    EVP_DigestFinal_ex(ctx, pkt + 4, NULL);
    EVP_MD_CTX_free(ctx);
    return len;
}

/* a udp client block with one entry, registered for reverse coa */
static struct client *newclient(char *name, char *nasid, char **realms, char *addr) {
    struct clsrvconf *conf = calloc(1, sizeof(struct clsrvconf));
    struct client *client = calloc(1, sizeof(struct client));
    struct sockaddr_in sin = {.sin_family = AF_INET};

    conf->name = name;
    conf->type = RAD_UDP;
    conf->secret = secret;
    conf->secret_len = secretlen;
    conf->nas_identifier = nasid;
    conf->reverse_coa_realms = realms;
    conf->coaport = 3799;
    conf->reverse_coa_timeout = 30;
    conf->lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(conf->lock, NULL);
    conf->clients = list_create();
    list_push(conf->clients, client);
    inet_pton(AF_INET, addr, &sin.sin_addr);
    client->conf = conf;
    client->addr = addr_copy((struct sockaddr *)&sin);
    pthread_mutex_init(&client->lock, NULL);
    client->replyq = newqueue();
    client->reverse_coa_route = reverse_coa_route_new(client);
    register_reverse_coa_client(client);
    return client;
}

static void freeclient(struct client *client) {
    unregister_reverse_coa_client(client);
    free_reverse_coa_rqs(client);
    reverse_coa_route_deref(client->reverse_coa_route);
    removequeue(client->replyq);
    pthread_mutex_destroy(&client->lock);
    free(client->addr);
    list_free(client->conf->clients);
    pthread_mutex_destroy(client->conf->lock);
    free(client->conf->lock);
    free(client->conf);
    free(client);
}

/* a server with acceptReverseCoA, answered through stubradput */
static struct server *newserver(char *name) {
    struct server *server = calloc(1, sizeof(struct server));

    server->conf = calloc(1, sizeof(struct clsrvconf));
    server->conf->name = name;
    server->conf->type = RAD_TLS;
    server->conf->secret = secret;
    server->conf->secret_len = secretlen;
    server->conf->pdef = &stubpdef;
    server->conf->accept_reverse_coa = 1;
    server->reverse_coa_seen = calloc(MAX_REQUESTS, sizeof(struct coa_dedup_slot));
    pthread_mutex_init(&server->reverse_coa_lock, NULL);
    return server;
}

static void freeserver(struct server *server) {
    drain_coa_dedup(server);
    free(server->reverse_coa_seen);
    pthread_mutex_destroy(&server->reverse_coa_lock);
    free(server->conf);
    free(server);
}

/* a request with Operator-Name and NAS-Identifier when given */
static struct radmsg *request(uint8_t code, uint8_t id, char *opname, char *nasid) {
    struct radmsg *msg = radmsg_init(code, id, NULL);

    if (opname)
        radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, strlen(opname), opname), 0);
    if (nasid)
        radmsg_add(msg, maketlv(RAD_Attr_NAS_Identifier, strlen(nasid), nasid), 0);
    return msg;
}

/* routes msg from server and frees it */
static int dispatch(struct server *server, struct radmsg *msg) {
    int result = _internal_dispatch_reverse_coa(server, NULL, msg);

    radmsg_free(msg);
    return result;
}

/* the request queued for the client, NULL if none */
static struct request *queued(struct client *client) {
    return (struct request *)list_shift(client->replyq->entries);
}

/* a session binding key: realm, attribute and value, a zero byte after each but the last */
static int keyis(char *key, int len, char *realm, uint8_t attr, char *value) {
    int rlen = strlen(realm), vlen = strlen(value);

    return len == rlen + 3 + vlen && !memcmp(key, realm, rlen + 1) && key[rlen + 1] == attr && !key[rlen + 2] && !memcmp(key + rlen + 3, value, vlen);
}

int main(int argc, char *argv[]) {
    uint8_t rqauth[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    struct client *nas, *proxy;
    struct server *server;

    debug_init("t_reverse_coa");
    init_reverse_coa();

    /* response authenticator */
    {
        uint8_t pkt[26], other[16];
        int len = coaack(pkt, 7, 0, rqauth);

        test_ok(radmsg_validate_response_auth(pkt, len, secret, secretlen, rqauth), "correct authenticator");
        memcpy(other, rqauth, 16);
        other[0] ^= 0xff;
        test_ok(!radmsg_validate_response_auth(pkt, len, secret, secretlen, other), "wrong request authenticator");
        test_ok(!radmsg_validate_response_auth(pkt, 19, secret, secretlen, rqauth), "short");
        memset(pkt + 20, 0xff, 6);
        test_ok(radmsg_validate_response_auth(pkt, 20, secret, secretlen, rqauth), "declared length used");
        test_ok(!radmsg_validate_response_auth(pkt, 26, secret, secretlen, rqauth), "trailing bytes fail");
        len = coaack(pkt, 8, 1, rqauth);
        test_ok(radmsg_validate_response_auth(pkt, len, secret, secretlen, rqauth), "with attribute");
    }

    /* pending response lookup */
    {
        struct client *client = newclient("udp", NULL, NULL, "192.0.2.100");
        struct sockaddr_in from = {.sin_family = AF_INET, .sin_port = htons(3799)};
        struct request dummy; /* not a real request, never freed */
        uint8_t pkt[26];
        int len = coaack(pkt, 7, 0, rqauth);

        inet_pton(AF_INET, "192.0.2.100", &from.sin_addr);
        memset(&dummy, 0, sizeof(dummy));
        client->sock = 42;
        client->reverse_coa_rqs = calloc(MAX_REQUESTS, sizeof(struct rqout));
        client->reverse_coa_rqs[7].rq = &dummy;
        memcpy(client->reverse_coa_rqs[7].sentauth, rqauth, 16); /* sentauth as send_coa_to_client stores it */
        test_ok(findreversecoaclient(client->conf, 42, (struct sockaddr *)&from, pkt, len) == client, "response matched");
        test_ok(!findreversecoaclient(client->conf, 99, (struct sockaddr *)&from, pkt, len), "wrong socket");
        from.sin_addr.s_addr ^= 1;
        test_ok(!findreversecoaclient(client->conf, 42, (struct sockaddr *)&from, pkt, len), "wrong source");
        from.sin_addr.s_addr ^= 1;
        client->reverse_coa_rqs[7].sentauth[0] ^= 0xff;
        test_ok(!findreversecoaclient(client->conf, 42, (struct sockaddr *)&from, pkt, len), "other request authenticator");
        client->reverse_coa_rqs[7].sentauth[0] ^= 0xff;
        pkt[1] = 8;
        test_ok(!findreversecoaclient(client->conf, 42, (struct sockaddr *)&from, pkt, len), "nothing pending for the id");
        client->reverse_coa_rqs[7].rq = NULL;
        freeclient(client);
    }

    /* token */
    {
        char token[REVERSE_COA_TOKEN_LEN + 1], token2[REVERSE_COA_TOKEN_LEN + 1], parsed[REVERSE_COA_TOKEN_LEN + 1];
        struct tlv *attr;

        test_ok(reverse_coa_newtoken(token) && strlen(token) == REVERSE_COA_TOKEN_LEN, "token length");
        test_ok(reverse_coa_newtoken(token2) && strcmp(token, token2) != 0, "tokens differ");
        attr = makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, token);
        test_ok(attr && attr->l == REVERSE_COA_TOKEN_LEN + 1 && attr->v[0] == 8, "token as attribute 241.8");
        test_ok(reverse_coa_token(attr, parsed) && !strcmp(parsed, token), "token parses");
        freetlv(attr);
        attr = makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, 9, (void *)"nas-1.lab");
        test_ok(!reverse_coa_token(attr, parsed), "foreign identifier rejected");
        freetlv(attr);
        test_ok(!reverse_coa_token(NULL, parsed), "missing attribute rejected");
    }

    /* operator-nas-identifier */
    {
        struct client *client = newclient("edge", NULL, NULL, "192.0.2.1");
        struct radmsg *msg = request(RAD_Access_Request, 1, NULL, NULL);
        struct tlv *attr;
        struct list *ext;
        char parsed[REVERSE_COA_TOKEN_LEN + 1];
        uint32_t code = 0;

        strcpy(client->token, "0123456789abcdef");
        radmsg_add(msg, maketlv(RAD_Attr_User_Name, 8, (void *)"user@abc"), 0);
        radmsg_add(msg, makeexttlv(RAD_ExtAttr_Original_Packet_Code, 4, &code), 0);
        test_ok(add_operator_nas_identifier(client, msg) && !radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier), "nothing added without operator-name");
        radmsg_add(msg, maketlv(RAD_Attr_Operator_Name, 12, (void *)"4EXAMPLE:XX"), 0);
        attr = add_operator_nas_identifier(client, msg) ? radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier) : NULL;
        test_ok(attr && reverse_coa_token(attr, parsed) && !strcmp(parsed, client->token), "added next to operator-name");
        add_operator_nas_identifier(client, msg);
        ext = radmsg_getalltype(msg, RAD_ExtAttr_Operator_NAS_Identifier.t);
        test_eq(2, ext ? (int)list_count(ext) : 0, "no second operator-nas-identifier");
        list_free(ext);
        strip_operator_attrs(msg);
        test_ok(!radmsg_gettype(msg, RAD_Attr_Operator_Name), "operator-name stripped");
        test_ok(!radmsg_getexttype(msg, RAD_ExtAttr_Operator_NAS_Identifier), "operator-nas-identifier stripped");
        test_ok(radmsg_getexttype(msg, RAD_ExtAttr_Original_Packet_Code) && radmsg_gettype(msg, RAD_Attr_User_Name), "other attributes kept");
        radmsg_free(msg);
        freeclient(client);
    }

    /* nas address */
    {
        struct radmsg *msg = request(RAD_Disconnect_Request, 1, NULL, NULL);
        struct sockaddr_storage ss;
        uint8_t v4[4] = {10, 0, 0, 69};
        uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

        test_ok(!reverse_coa_nas_addr(msg, &ss), "no address attribute");
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IPv6_Address, 16, v6), 0);
        test_ok(reverse_coa_nas_addr(msg, &ss) && ss.ss_family == AF_INET6 && !memcmp(&((struct sockaddr_in6 *)&ss)->sin6_addr, v6, 16), "nas-ipv6-address");
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, 4, v4), 0);
        test_ok(reverse_coa_nas_addr(msg, &ss) && ss.ss_family == AF_INET && !memcmp(&((struct sockaddr_in *)&ss)->sin_addr, v4, 4) && !((struct sockaddr_in *)&ss)->sin_port, "nas-ip-address preferred");
        radmsg_free(msg);
    }

    /* nas identity */
    {
        struct client *client = newclient("mapped", "nas-m", NULL, "192.0.2.102");
        struct sockaddr_in6 sin6 = {.sin6_family = AF_INET6};
        struct radmsg *msg = request(RAD_CoA_Request, 1, NULL, NULL);
        uint8_t v4[4] = {192, 0, 2, 102};

        inet_pton(AF_INET6, "::ffff:192.0.2.102", &sin6.sin6_addr);
        free(client->addr);
        client->addr = addr_copy((struct sockaddr *)&sin6);
        test_ok(!_internal_match_nas_identifier(client, msg), "not named");
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, 4, v4), 0);
        test_ok(_internal_match_nas_identifier(client, msg), "nas-ip-address on a v4-mapped client");
        radmsg_free(msg);
        msg = request(RAD_CoA_Request, 1, NULL, "nas-x");
        radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, 5, (void *)"nas-m"), 0);
        test_ok(_internal_match_nas_identifier(client, msg), "operator-nas-identifier");
        radmsg_free(msg);
        freeclient(client);
    }

    /* relayed message-authenticator */
    {
        struct radmsg *nak = radmsg_init(RAD_Disconnect_NAK, 5, rqauth), *back;
        uint8_t stale[16], *buf = NULL;
        int len;

        memset(stale, 0x5a, 16);
        radmsg_add(nak, maketlvlongint(RAD_Attr_Error_Cause, RAD_Err_Unsupported_Extension), 0);
        radmsg_add(nak, maketlv(RAD_Attr_Message_Authenticator, 16, stale), 0);
        len = radmsg2buf(nak, secret, secretlen, &buf);
        back = buf2radmsg(buf, len, secret, secretlen, rqauth);
        test_ok(back && (back->authstate == RSP_RADMSG_INVALID || back->authstate == RSP_RADMSG_MSGAUTH_INVALID), "stale msgauth fails");
        radmsg_free(back);
        free(buf);
        memcpy(nak->auth, rqauth, 16);
        ensuremsgauthfront(nak);
        len = radmsg2buf(nak, secret, secretlen, &buf);
        back = buf2radmsg(buf, len, secret, secretlen, rqauth);
        test_ok(back && back->authstate == RSP_RADMSG_MSGAUTH_VALID, "fresh msgauth verifies");
        radmsg_free(back);
        free(buf);
        radmsg_free(nak);
    }

    /* pending */
    {
        struct client *client = newclient("idle", NULL, NULL, "192.0.2.101");

        test_ok(!client_has_pending_reverse_coa(client), "nothing sent");
        client->reverse_coa_rqs = calloc(MAX_REQUESTS, sizeof(struct rqout));
        test_ok(!client_has_pending_reverse_coa(client), "nothing pending");
        client->reverse_coa_rqs[200].rq = newrequest();
        client->reverse_coa_rqs[200].expiry.tv_sec = time(NULL) + 30;
        client->reverse_coa_pending = 1;
        test_ok(client_has_pending_reverse_coa(client), "pending set");
        client->reverse_coa_rqs[200].expiry.tv_sec = time(NULL) - 30;
        test_ok(!client_has_pending_reverse_coa(client) && !client->reverse_coa_rqs[200].rq, "expired slot cleared");
        freeclient(client);
    }

    /* session binding keys */
    {
        struct radmsg *req = request(RAD_Accounting_Request, 9, "4EXAMPLE:XX", NULL);
        struct radmsg *rep = radmsg_init(RAD_Access_Accept, 9, NULL);
        char key[512];
        int len;

        radmsg_add(req, maketlv(RAD_Attr_Acct_Session_Id, 8, (void *)"80e00020"), 0);
        radmsg_add(rep, maketlv(RAD_Attr_CUI, 4, (void *)"cui1"), 0);
        len = sessionbindkey(req, NULL, RAD_Attr_Acct_Session_Id, key, sizeof(key));
        test_ok(keyis(key, len, "4EXAMPLE:XX", RAD_Attr_Acct_Session_Id, "80e00020"), "realm, attribute, value");
        len = sessionbindkey(req, rep, RAD_Attr_CUI, key, sizeof(key));
        test_ok(keyis(key, len, "4EXAMPLE:XX", RAD_Attr_CUI, "cui1"), "cui from the reply");
        test_ok(!sessionbindkey(req, NULL, RAD_Attr_CUI, key, sizeof(key)), "absent attribute no key");
        radmsg_free(req);
        req = request(RAD_Accounting_Request, 9, NULL, NULL);
        radmsg_add(req, maketlv(RAD_Attr_Acct_Session_Id, 8, (void *)"80e00020"), 0);
        len = sessionbindkey(req, NULL, RAD_Attr_Acct_Session_Id, key, sizeof(key));
        test_ok(keyis(key, len, "", RAD_Attr_Acct_Session_Id, "80e00020"), "empty realm without operator-name");
        radmsg_free(req);
        radmsg_free(rep);
    }

    server = newserver("hub");
    nas = newclient("nas", "nas-1", literalrealm, "192.0.2.10");
    proxy = newclient("proxy", NULL, NULL, "192.0.2.20");

    /* realm registry */
    {
        struct client *other = newclient("other", "nas-2", regexprealm, "192.0.2.30");
        struct request *rq;

        test_eq(0, dispatch(server, request(RAD_CoA_Request, 1, "1example.com", "nas-1")), "literal realm");
        rq = queued(nas);
        test_ok(rq != NULL, "case-insensitive match delivered");
        freerq(rq);
        test_eq(0, dispatch(server, request(RAD_CoA_Request, 2, "1ap.example.net", "nas-2")), "regexp realm");
        rq = queued(other);
        test_ok(rq != NULL, "regexp match delivered");
        freerq(rq);
        test_eq(RAD_Err_NAS_Identification_Mismatch, dispatch(server, request(RAD_CoA_Request, 3, "1example.com", "nas-2")), "nas not named 403");
        test_eq(RAD_Err_Request_Not_Routable, dispatch(server, request(RAD_CoA_Request, 4, "1example.org", "nas-1")), "unknown realm 502");
        test_ok(!queued(nas) && !queued(other), "nothing queued");
        unregister_reverse_coa_client(other);
        test_ok(!_internal_reverse_coa_route_target(other->reverse_coa_route), "unregister clears the target");
        test_eq(RAD_Err_Request_Not_Routable, dispatch(server, request(RAD_CoA_Request, 5, "1ap.example.net", "nas-2")), "unregistered realm 502");
        freeclient(other);
    }

    /* dispatch */
    {
        struct request *rq, *origin;
        struct radmsg *msg, *bind, *accept, *sent;
        uint8_t v4[4] = {192, 0, 2, 10};

        test_eq(0, dispatch(server, request(RAD_CoA_Request, 10, "1example.com", "nas-1")), "named nas");
        rq = queued(nas);
        sent = rq ? buf2radmsg(rq->replybuf, rq->replybuflen, secret, secretlen, NULL) : NULL;
        test_ok(sent && sent->authstate == RSP_RADMSG_MSGAUTH_VALID, "signed for the client");
        test_ok(sent && !radmsg_gettype(sent, RAD_Attr_Operator_Name) && !radmsg_getexttype(sent, RAD_ExtAttr_Operator_NAS_Identifier), "operator attributes removed");
        test_ok(sent && radmsg_gettype(sent, RAD_Attr_NAS_Identifier), "nas-identifier kept");
        test_ok(rq && rq->rqid == 10 && rq->to == server && sent && sent->id == rq->newid, "answers to the server");
        test_ok(rq && rq->to_override && ntohs(((struct sockaddr_in *)rq->to_override)->sin_port) == 3799, "sent to the coa port");
        radmsg_free(sent);
        freerq(rq);

        /* a plain rfc 5176 request names the nas by address */
        msg = request(RAD_CoA_Request, 11, NULL, NULL);
        radmsg_add(msg, maketlv(RAD_Attr_NAS_IP_Address, 4, v4), 0);
        test_eq(0, dispatch(server, msg), "nas-ip-address without operator-name");
        rq = queued(nas);
        test_ok(rq != NULL, "delivered by address");
        freerq(rq);

        /* operator-nas-identifier names the connection, next to operator-name only */
        strcpy(nas->token, "0123456789abcdef");
        msg = request(RAD_CoA_Request, 12, "1example.org", NULL);
        radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, nas->token), 0);
        test_eq(0, dispatch(server, msg), "token names the connection");
        rq = queued(nas);
        test_ok(rq != NULL, "delivered by token");
        freerq(rq);
        msg = request(RAD_CoA_Request, 13, NULL, NULL);
        radmsg_add(msg, makeexttlv(RAD_ExtAttr_Operator_NAS_Identifier, REVERSE_COA_TOKEN_LEN, nas->token), 0);
        test_eq(RAD_Err_Request_Not_Routable, dispatch(server, msg), "token without operator-name ignored");

        /* the session binding comes before the realm lookup */
        msg = request(RAD_Disconnect_Request, 14, "1example.com", NULL);
        radmsg_add(msg, maketlv(RAD_Attr_Acct_Session_Id, 2, (void *)"s1"), 0);
        test_eq(RAD_Err_NAS_Identification_Mismatch, _internal_dispatch_reverse_coa(server, NULL, msg), "unbound session 403");
        bind = request(RAD_Access_Request, 15, "1example.com", NULL);
        radmsg_add(bind, maketlv(RAD_Attr_Acct_Session_Id, 2, (void *)"s1"), 0);
        sessionbind(nas, bind, NULL);
        test_eq(0, _internal_dispatch_reverse_coa(server, NULL, msg), "bound by session");
        rq = queued(nas);
        test_ok(rq != NULL, "delivered by session");
        freerq(rq);
        bind->code = RAD_Accounting_Request;
        radmsg_add(bind, maketlvlongint(RAD_Attr_Acct_Status_Type, RAD_Acct_Status_Stop), 0);
        sessionbind(nas, bind, NULL);
        test_eq(RAD_Err_NAS_Identification_Mismatch, dispatch(server, msg), "stop unbinds");
        radmsg_free(bind);
        bind = request(RAD_Access_Request, 16, "1example.com", NULL);
        accept = radmsg_init(RAD_Access_Accept, 16, NULL);
        radmsg_add(accept, maketlv(RAD_Attr_CUI, 4, (void *)"cui1"), 0);
        sessionbind(nas, bind, accept);
        msg = request(RAD_Disconnect_Request, 17, "1example.com", NULL);
        radmsg_add(msg, maketlv(RAD_Attr_CUI, 4, (void *)"cui1"), 0);
        test_eq(0, dispatch(server, msg), "bound by cui");
        rq = queued(nas);
        test_ok(rq != NULL, "delivered by cui");
        freerq(rq);
        radmsg_free(bind);
        radmsg_free(accept);

        /* never back to the sender */
        origin = newrequest();
        origin->from = nas;
        origin->msg = request(RAD_CoA_Request, 18, "1example.com", "nas-1");
        test_eq(RAD_Err_Request_Not_Routable, route_reverse_coa_from_client(origin), "not back to the sender");
        test_ok(!queued(nas), "nothing queued for the sender");
        freerq(origin);
    }

    /* duplicates */
    {
        struct radmsg *msg = request(RAD_CoA_Request, 20, "1example.org", NULL), *nak;
        struct tlv *attr;
        uint8_t *buf, *copy;
        int len = radmsg2buf(msg, secret, secretlen, &buf);

        copy = malloc(len);
        memcpy(copy, buf, len);
        sentcount = 0;
        test_ok(try_handle_reverse_coa_request(server, copy, len), "request taken");
        nak = sentcount ? buf2radmsg(sentbuf, sentlen, secret, secretlen, msg->auth) : NULL;
        attr = nak ? radmsg_gettype(nak, RAD_Attr_Error_Cause) : NULL;
        test_ok(nak && nak->code == RAD_CoA_NAK && nak->id == 20 && nak->authstate == RSP_RADMSG_MSGAUTH_VALID, "nak signed for the server");
        test_ok(attr && tlv2longint(attr) == RAD_Err_Request_Not_Routable, "error-cause 502");
        radmsg_free(nak);
        test_ok(server->reverse_coa_seen[20].occupied && server->reverse_coa_seen[20].replybuf, "slot holds the reply");
        copy = malloc(len);
        memcpy(copy, buf, len);
        test_ok(try_handle_reverse_coa_request(server, copy, len) && sentcount == 2, "duplicate answered from the slot");
        test_eq(1, _internal_is_coa_duplicate(server, msg), "duplicate");
        msg->auth[0] ^= 0xff;
        test_eq(0, _internal_is_coa_duplicate(server, msg), "other authenticator is new");
        msg->auth[0] ^= 0xff;
        server->reverse_coa_seen[20].received -= 300;
        test_ok(!_internal_is_coa_duplicate(server, msg) && !server->reverse_coa_seen[20].occupied, "expired slot cleared");
        _internal_record_coa_dedup(server, 20, msg->auth);
        test_ok(server->reverse_coa_seen[20].occupied && !server->reverse_coa_seen[20].replybuf, "recorded without a reply");
        test_eq(1, _internal_is_coa_duplicate(server, msg), "duplicate while pending");
        free(buf);
        radmsg_free(msg);

        /* event-timestamp within the window */
        msg = request(RAD_CoA_Request, 21, "1example.org", NULL);
        radmsg_add(msg, maketlvlongint(RAD_Attr_Event_Timestamp, (uint32_t)time(NULL) - 3600), 0);
        len = radmsg2buf(msg, secret, secretlen, &buf);
        sentcount = 0;
        test_ok(try_handle_reverse_coa_request(server, buf, len) && !sentcount && !server->reverse_coa_seen[21].occupied, "stale event-timestamp dropped");
        radmsg_free(msg);
        msg = request(RAD_CoA_Request, 22, "1example.org", NULL);
        radmsg_add(msg, maketlvlongint(RAD_Attr_Event_Timestamp, (uint32_t)time(NULL)), 0);
        len = radmsg2buf(msg, secret, secretlen, &buf);
        test_ok(try_handle_reverse_coa_request(server, buf, len) && sentcount == 1, "current event-timestamp taken");
        radmsg_free(msg);
    }

    /* response pairing */
    {
        struct radmsg *msg = request(RAD_Disconnect_Request, 30, "1example.com", "nas-1"), *resp, *back;
        struct request *rq, *origin;
        uint8_t auth[16], id;

        memcpy(auth, msg->auth, 16);
        test_eq(0, dispatch(server, msg), "disconnect sent");
        rq = queued(nas);
        id = rq ? rq->newid : 0;
        freerq(rq);
        resp = radmsg_init(RAD_CoA_ACK, id, NULL);
        test_ok(!forward_coa_response(nas, resp) && nas->reverse_coa_rqs[id].rq, "coa-ack does not answer a disconnect");
        resp->code = RAD_Disconnect_ACK;
        sentcount = 0;
        test_ok(forward_coa_response(nas, resp) && !nas->reverse_coa_rqs[id].rq, "disconnect-ack answers");
        back = sentcount ? buf2radmsg(sentbuf, sentlen, secret, secretlen, auth) : NULL;
        test_ok(back && back->code == RAD_Disconnect_ACK && back->id == 30 && back->authstate == RSP_RADMSG_MSGAUTH_VALID, "relayed under the original id");
        test_ok(!forward_coa_response(nas, resp), "nothing pending for the id");
        radmsg_free(back);
        radmsg_free(resp);

        /* a request from a client is answered by the response */
        origin = newrequest();
        origin->from = proxy;
        origin->msg = request(RAD_Disconnect_Request, 31, "1example.com", "nas-1");
        test_eq(0, route_reverse_coa_from_client(origin), "client request routed");
        rq = queued(nas);
        id = rq ? rq->newid : 0;
        test_ok(rq && rq->origin == origin, "origin kept");
        freerq(rq);
        resp = radmsg_init(RAD_Disconnect_ACK, id, NULL);
        test_ok(forward_coa_response(nas, resp), "answered");
        rq = queued(proxy);
        test_ok(rq == origin && rq->replybuf[0] == RAD_Disconnect_ACK && rq->replybuf[1] == 31, "client request answered");
        freerq(rq);
        freerq(origin);
        radmsg_free(resp);
    }

    freeclient(proxy);
    freeclient(nas);
    freeserver(server);
    free(sentbuf);

    printf("1..%d\n", numtests);
    return 0;
}
