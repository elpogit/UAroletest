/* Fruit RBAC demo for open62541 master (1.6-dev), built with UA_ENABLE_RBAC.
 *
 * Browse hierarchy (what clients navigate):
 *   Objects/Fruits/Apples/<variety>
 *   Objects/Fruits/Oranges/<variety>
 *
 * Access hierarchy (a second, independent tree that decides who sees what):
 *   Objects/AccessGroups/Yellow  --Organizes-->  yellow varieties
 *   Objects/AccessGroups/Red     --Organizes-->  red(ish) varieties
 *   Objects/AccessGroups/Green   --Organizes-->  green varieties
 *
 * Roles:      YellowRole, RedRole, GreenRole (GreenRole mapped to nobody)
 * Users:      yellow    -> YellowRole
 *             yellowred -> YellowRole + RedRole
 *
 * Permissions are granted by walking the *access* tree with the library's
 * recursive flag, so the browse tree never has to mirror the access tree. */

#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include <stdlib.h>
#include <string.h>

#define NS 1
#define BR (UA_PERMISSIONTYPE_BROWSE | UA_PERMISSIONTYPE_READ)

typedef struct { const char *name; const char *colour; const char *group; } Variety;

static const Variety apples[] = {
    {"Golden Delicious",  "yellow",     "Yellow"},
    {"Opal",              "yellow",     "Yellow"},
    {"Yellow Transparent","pale yellow","Yellow"},
    {"Red Delicious",     "dark red",   "Red"},
    {"Gala",              "red-striped","Red"},
    {"Honeycrisp",        "red/yellow", "Red"},
    {"Pink Lady",         "pink-red",   "Red"},
    {"Granny Smith",      "green",      "Green"},
    {"Bramley",           "green",      "Green"},
};
static const Variety oranges[] = {
    {"Navel",             "orange",     "Yellow"}, /* demo choice: orange = yellow family */
    {"Valencia",          "orange",     "Yellow"},
    {"Moro (blood)",      "red",        "Red"},
    {"Tarocco (blood)",   "red-blush",  "Red"},
    {"Cara Cara",         "pink flesh", "Red"},
};

static UA_NodeId
addFolder(UA_Server *s, UA_NodeId parent, const char *name, UA_UInt32 id) {
    UA_ObjectAttributes a = UA_ObjectAttributes_default;
    a.displayName = UA_LOCALIZEDTEXT("en-US", (char*)(uintptr_t)name);
    UA_NodeId out = UA_NODEID_NUMERIC(NS, id);
    UA_Server_addObjectNode(s, out, parent,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                            UA_QUALIFIEDNAME(NS, (char*)(uintptr_t)name),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE),
                            a, NULL, NULL);
    return out;
}

static UA_NodeId
addVariety(UA_Server *s, UA_NodeId parent, const Variety *v, UA_UInt32 id) {
    UA_ObjectAttributes oa = UA_ObjectAttributes_default;
    oa.displayName = UA_LOCALIZEDTEXT("en-US", (char*)(uintptr_t)v->name);
    UA_NodeId obj = UA_NODEID_NUMERIC(NS, id);
    UA_Server_addObjectNode(s, obj, parent,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                            UA_QUALIFIEDNAME(NS, (char*)(uintptr_t)v->name),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                            oa, NULL, NULL);

    UA_VariableAttributes va = UA_VariableAttributes_default;
    UA_String c = UA_STRING((char*)(uintptr_t)v->colour);
    UA_Variant_setScalar(&va.value, &c, &UA_TYPES[UA_TYPES_STRING]);
    va.displayName = UA_LOCALIZEDTEXT("en-US", "Colour");
    UA_Server_addVariableNode(s, UA_NODEID_NUMERIC(NS, id + 1), obj,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
                              UA_QUALIFIEDNAME(NS, "Colour"),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
                              va, NULL, NULL);
    return obj;
}

/* Create a role and map one or more usernames to it */
static UA_NodeId
addRole(UA_Server *s, const char *roleName, size_t nUsers, const char **users) {
    UA_Role r;
    UA_Role_init(&r);
    r.roleName = UA_QUALIFIEDNAME(NS, (char*)(uintptr_t)roleName);
    UA_IdentityMappingRuleType rules[4];
    for(size_t i = 0; i < nUsers; i++) {
        UA_IdentityMappingRuleType_init(&rules[i]);
        rules[i].criteriaType = UA_IDENTITYCRITERIATYPE_USERNAME;
        rules[i].criteria = UA_STRING((char*)(uintptr_t)users[i]);
    }
    r.identityMappingRulesSize = nUsers;
    r.identityMappingRules = nUsers ? rules : NULL;
    UA_NodeId id = UA_NODEID_NULL;
    UA_StatusCode rv = UA_Server_addRole(s, &r, &id);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "addRole %s: %s",
                roleName, UA_StatusCode_name(rv));
    return id;
}

int main(void) {
    UA_ServerConfig config;
    memset(&config, 0, sizeof(config));
    UA_ServerConfig_setDefault(&config);
    config.allowNonePolicyPassword = true;   /* demo only: plaintext password */
    config.allPermissionsForAnonymous = false; /* strict: deny unless granted */

    UA_UsernamePasswordLogin logins[2] = {
        {UA_STRING_STATIC("yellow"),    UA_STRING_STATIC("yellow")},
        {UA_STRING_STATIC("yellowred"), UA_STRING_STATIC("yellowred")},
    };
    UA_AccessControl_default(&config, false /* no anonymous */, NULL, 2, logins);

    UA_Server *s = UA_Server_newWithConfig(&config);
    UA_Server_addNamespace(s, "urn:example:fruit");

    /* ns0 stays browsable/readable for any logged-in user */
    UA_RolePermission ns0[1] = {
        {UA_NODEID_NUMERIC(0, UA_NS0ID_WELLKNOWNROLE_AUTHENTICATEDUSER), BR}};
    UA_Server_setNamespaceDefaultRolePermissions(s, 0, 1, ns0);

    /* Roles */
    const char *yUsers[] = {"yellow", "yellowred"};
    const char *rUsers[] = {"yellowred"};
    UA_NodeId yellowRole = addRole(s, "YellowRole", 2, yUsers);
    UA_NodeId redRole    = addRole(s, "RedRole",    1, rUsers);
    UA_NodeId greenRole  = addRole(s, "GreenRole",  0, NULL);

    /* Browse tree */
    UA_NodeId objects = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeId fruits  = addFolder(s, objects, "Fruits", 1000);
    UA_NodeId appleF  = addFolder(s, fruits, "Apples", 1001);
    UA_NodeId orangeF = addFolder(s, fruits, "Oranges", 1002);

    /* Access tree */
    UA_NodeId acc     = addFolder(s, objects, "AccessGroups", 2000);
    UA_NodeId gYellow = addFolder(s, acc, "Yellow", 2001);
    UA_NodeId gRed    = addFolder(s, acc, "Red", 2002);
    UA_NodeId gGreen  = addFolder(s, acc, "Green", 2003);

    UA_UInt32 id = 5000;
    const Variety *lists[2] = {apples, oranges};
    size_t sizes[2] = {sizeof(apples)/sizeof(*apples), sizeof(oranges)/sizeof(*oranges)};
    UA_NodeId parents[2] = {appleF, orangeF};
    for(int l = 0; l < 2; l++) {
        for(size_t i = 0; i < sizes[l]; i++, id += 10) {
            const Variety *v = &lists[l][i];
            UA_NodeId n = addVariety(s, parents[l], v, id);
            UA_NodeId g = !strcmp(v->group, "Yellow") ? gYellow :
                          !strcmp(v->group, "Red") ? gRed : gGreen;
            /* Second parent: access group (non-browse-tree link) */
            UA_Server_addReference(s, g, UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                                   UA_EXPANDEDNODEID_NUMERIC(NS, n.identifier.numeric),
                                   true);
        }
    }

    /* ---- Policy: compile the access tree into per-node RolePermissions ---- */
    /* Group folders -> recursive grant (merge, so a node in two groups gets both) */
    UA_Server_addRolePermissions(s, gYellow, yellowRole, BR, false, true);
    UA_Server_addRolePermissions(s, gRed,    redRole,    BR, false, true);
    UA_Server_addRolePermissions(s, gGreen,  greenRole,  BR, false, true);
    /* Hide the access tree itself again */
    UA_Server_removeNodeRolePermissions(s, gYellow, false);
    UA_Server_removeNodeRolePermissions(s, gRed, false);
    UA_Server_removeNodeRolePermissions(s, gGreen, false);

    /* Structural folders of the browse tree: both roles may pass through */
    UA_NodeId structural[3] = {fruits, appleF, orangeF};
    for(int i = 0; i < 3; i++) {
        UA_Server_addRolePermissions(s, structural[i], yellowRole, BR, false, false);
        UA_Server_addRolePermissions(s, structural[i], redRole,    BR, false, false);
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Fruit server ready. Users: yellow/yellow, yellowred/yellowred");
    UA_Server_runUntilInterrupt(s);
    UA_Server_delete(s);
    return EXIT_SUCCESS;
}
