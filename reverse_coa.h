/* Copyright (c) 2026, Nova Labs */
/* Copyright (c) 2026, CyB0rgg */
/* See LICENSE for licensing information. */

#ifndef _REVERSE_COA_H
#define _REVERSE_COA_H

#include "radsecproxy.h"

void init_reverse_coa(void);
void register_reverse_coa_client(struct client *client);
void unregister_reverse_coa_client(struct client *client);
int forward_coa_response(struct client *from, struct radmsg *msg);
void invalidate_reverse_coa_rqs_for_server(struct server *server, struct list *clconfs);
void free_reverse_coa_rqs(struct client *client);
int lookup_reverse_coa_rqauth(struct client *from, uint8_t *buf, int buflen, uint8_t *out_auth);
int try_handle_reverse_coa_request(struct server *server, unsigned char *buf, int len);
void drain_coa_dedup(struct server *server);
struct reverse_coa_route *reverse_coa_route_new(struct client *target);
void reverse_coa_route_deref(struct reverse_coa_route *route);
int route_reverse_coa_from_client(struct request *rq);
int add_operator_nas_identifier(struct client *from, struct radmsg *msg);
int reverse_coa_newtoken(char *token);
int reverse_coa_token(const struct tlv *attr, char *token);
void strip_operator_attrs(struct radmsg *msg);
int reverse_coa_nas_addr(struct radmsg *msg, struct sockaddr_storage *out);
int client_has_pending_reverse_coa(struct client *client);
void sessionbind(struct client *client, struct radmsg *msg, struct radmsg *reply);
int sessionbindkey(struct radmsg *msg, struct radmsg *reply, uint8_t attr, char *buf, size_t bufsize);

/* for the tests */
int _internal_dispatch_reverse_coa(struct server *server, struct request *origin, struct radmsg *msg);
int _internal_is_coa_duplicate(struct server *server, struct radmsg *msg);
void _internal_record_coa_dedup(struct server *server, uint8_t id, uint8_t *auth);
int _internal_match_nas_identifier(struct client *client, struct radmsg *msg);
struct client *_internal_reverse_coa_route_target(struct reverse_coa_route *route);
void _internal_sessionbindset(struct reverse_coa_route *route, const char *key, uint32_t keylen);
void _internal_sessionbindclear(const char *key, uint32_t keylen);
int _internal_sessionbindfind(const char *key, uint32_t keylen);
uint32_t _internal_sessionbindcount(void);

#endif /* _REVERSE_COA_H */

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
