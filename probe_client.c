/* Probe what a given user can see on the fruit server.
 * Usage: probe_client <user> <password> */
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>
#include <stdio.h>
#include <stdlib.h>

static UA_Client *client;

static void
readColour(const UA_NodeId *obj) {
    UA_NodeId colour = UA_NODEID_NUMERIC(1, obj->identifier.numeric + 1);
    UA_Variant v; UA_Variant_init(&v);
    UA_StatusCode rv = UA_Client_readValueAttribute(client, colour, &v);
    if(rv == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v, &UA_TYPES[UA_TYPES_STRING])) {
        UA_String *s = (UA_String*)v.data;
        printf("colour=%.*s", (int)s->length, s->data);
    } else {
        printf("colour READ -> %s", UA_StatusCode_name(rv));
    }
    UA_Variant_clear(&v);
}

static void
browseNode(UA_UInt32 id, const char *label, int depth) {
    UA_BrowseRequest req; UA_BrowseRequest_init(&req);
    UA_BrowseDescription bd; UA_BrowseDescription_init(&bd);
    bd.nodeId = UA_NODEID_NUMERIC(id >= 1000 ? 1 : 0, id);
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    bd.includeSubtypes = true;
    bd.nodeClassMask = UA_NODECLASS_OBJECT;
    bd.resultMask = UA_BROWSERESULTMASK_ALL;
    req.nodesToBrowse = &bd; req.nodesToBrowseSize = 1;
    UA_BrowseResponse resp = UA_Client_Service_browse(client, req);
    UA_StatusCode st = resp.responseHeader.serviceResult;
    if(st == UA_STATUSCODE_GOOD && resp.resultsSize > 0)
        st = resp.results[0].statusCode;
    printf("%*sBrowse %s -> %s\n", depth*2, "", label, UA_StatusCode_name(st));
    if(st == UA_STATUSCODE_GOOD) {
        for(size_t i = 0; i < resp.results[0].referencesSize; i++) {
            UA_ReferenceDescription *r = &resp.results[0].references[i];
            if(r->nodeId.nodeId.namespaceIndex != 1) continue;
            UA_UInt32 cid = r->nodeId.nodeId.identifier.numeric;
            printf("%*s- listed: %-20.*s ", depth*2+2, "",
                   (int)r->displayName.text.length, r->displayName.text.data);
            if(cid >= 5000) {          /* variety */
                readColour(&r->nodeId.nodeId);
                printf("\n");
            } else {                   /* folder: recurse */
                printf("\n");
                char lbl[64];
                snprintf(lbl, sizeof(lbl), "%.*s", (int)r->displayName.text.length,
                         r->displayName.text.data);
                browseNode(cid, lbl, depth + 2);
            }
        }
    }
    UA_BrowseResponse_clear(&resp);
}

int main(int argc, char **argv) {
    if(argc < 3) { fprintf(stderr, "usage: %s user pw\n", argv[0]); return 1; }
    client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(cc);
    cc->logging->context = (void*)(uintptr_t)UA_LOGLEVEL_ERROR;
    cc->allowNonePolicyPassword = true; /* demo only */
    UA_StatusCode rv = UA_Client_connectUsername(client, "opc.tcp://localhost:4840",
                                                 argv[1], argv[2]);
    printf("=== user %s: connect %s ===\n", argv[1], UA_StatusCode_name(rv));
    if(rv != UA_STATUSCODE_GOOD) return 1;
    browseNode(UA_NS0ID_OBJECTSFOLDER, "Objects", 0);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}
