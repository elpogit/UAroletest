# Fruit RBAC PoC on open62541 1.6-dev — plan and findings

*Tapio Loponen · 25 Oct 2026 · open62541 master @ 2307912 (22 Oct 2026)*

## Bottom line

open62541's development branch (the 1.6 line; docs at open62541.org/doc/master) now ships **experimental Role-Based Access Control** per OPC UA Part 18, behind the CMake flag `UA_ENABLE_RBAC`. It gives you roles, username→role mapping, per-node RolePermissions, namespace defaults and **union-of-roles** semantics — enough for the yellow / yellowred demo.

What it does *not* have is a first-class "access-control hierarchy". Permissions are stored flat on each node; the `recursive` flag is a one-shot walk along hierarchical references at the moment you call it. The workable pattern is therefore to **model the access hierarchy as a second tree of nodes** and let `recursive` follow *that* tree, not the browse tree. A prototype doing exactly this is built and working (files alongside this plan).

One real gap: on stock master, browsing a folder still **lists** children the user has no Browse right on (names leak; contents are denied). A 10-line patch to `ua_services_view.c` fixes it and is worth proposing upstream.

## What the library offers (relevant APIs)

**Enable:** `-DUA_ENABLE_RBAC=ON -DUA_NAMESPACE_ZERO=FULL` (RBAC refuses to build without full ns0). CMake warns it is experimental / not for production.

**Authentication** — unchanged plugin model. `UA_AccessControl_default(&config, allowAnonymous, NULL, n, logins)` with a `UA_UsernamePasswordLogin[]` covers the two fixed demo users. With RBAC on, the default plugin's `allowBrowseNode`, `getUserAccessLevel`, `getUserRightsMask`, etc. all consult the effective RBAC permissions.

**Roles** (`server.h`, "Role Management"):
- `UA_Role` = roleId, roleName, `identityMappingRules[]`, optional application/endpoint restrictions.
- `UA_Server_addRole`, `UA_Server_updateRole`, `UA_Server_getRole(ById)`, `UA_Server_getRoles`, `UA_Server_removeRole`. Roles can also be preloaded via `config.roles` (then protected from removal).
- Identity mapping: `UA_IDENTITYCRITERIATYPE_USERNAME` with the username as criteria. The default plugin evaluates these automatically at ActivateSession; a session gets **every** role whose rule matches, plus the well-known Anonymous / AuthenticatedUser roles.
- Session roles can also be set by hand via session attribute `0:roles` (`UA_NodeId[]`) if you want custom mapping logic.

**Permissions** ("Node Role-Permission Management" / "Per-Role Node Permission Management"):
- `UA_Server_addRolePermissions(server, node, role, bits, overwriteExisting, recursive)` — merge or replace one role's bits on a node, optionally down the hierarchy.
- `UA_Server_setNodeRolePermissions(..., recursive, options)` — replace the whole set; `options` is "reserved for future use (e.g. to restrict the reference type for recursive traversal)".
- `UA_Server_removeNodeRolePermissions`, `UA_Server_removeRolePermissions`, `UA_Server_getNodeRolePermissions`.
- `UA_Server_setNamespaceDefaultRolePermissions(ns, ...)` — fallback when a node has no explicit set.
- `config.allPermissionsForAnonymous = false` makes unconfigured nodes deny-all (strict mode).

**Evaluation** (from `computeEffectivePermissions` in `ua_server_rbac.c`):
1. Node has explicit RolePermissions → use only those (namespace default ignored).
2. Else namespace default.
3. Else: all permissions if `allPermissionsForAnonymous`, otherwise none.
4. Effective bits = **OR over all of the session's roles**. This is what makes yellowred = YellowRole ∪ RedRole.

## Design for the demo

**Browse hierarchy** (what clients navigate):
```
Objects/Fruits/Apples/{Golden Delicious, Opal, Yellow Transparent,
                       Red Delicious, Gala, Honeycrisp, Pink Lady,
                       Granny Smith, Bramley}
Objects/Fruits/Oranges/{Navel, Valencia, Moro (blood), Tarocco (blood), Cara Cara}
each variety: Object + Colour property
```

**Access hierarchy** (independent; decides visibility):
```
Objects/AccessGroups/Yellow --Organizes--> yellow varieties (+ Navel, Valencia)
Objects/AccessGroups/Red    --Organizes--> red(ish) apples + blood/Cara Cara oranges
Objects/AccessGroups/Green  --Organizes--> Granny Smith, Bramley
```
A variety can sit in several groups (multiple Organizes parents) — `addRolePermissions` with merge gives it both roles.

**Roles and users**

| Role | Mapped users | Grants |
|---|---|---|
| YellowRole | yellow, yellowred | Browse+Read on AccessGroups/Yellow subtree |
| RedRole | yellowred | Browse+Read on AccessGroups/Red subtree |
| GreenRole | *(nobody)* | Browse+Read on AccessGroups/Green subtree |
| AuthenticatedUser | everyone logged in | Browse+Read on ns0 (namespace default) |

**Policy "compile" step** (runs once after the model is built):
1. `addRolePermissions(group, role, BROWSE|READ, merge, recursive=true)` for each access group → stamps the varieties and their Colour properties.
2. `removeNodeRolePermissions(group, recursive=false)` on the group folders themselves, so the access tree stays hidden.
3. Grant both roles Browse+Read on the structural folders Fruits / Apples / Oranges (non-recursive).
4. Strict mode + no namespace default for ns1 → anything not stamped is invisible.

Anonymous login is disabled.

## Prototype results

Built against master with RBAC on; probed with a small C client (`probe_client.c`).

| Variety group | yellow | yellowred | stock master: listed in parent? |
|---|---|---|---|
| Yellow apples + Navel/Valencia | read OK | read OK | yes |
| Red apples + blood oranges | **hidden** | read OK | yes, but read → BadUserAccessDenied |
| Green apples | **hidden** | **hidden** | yes, but read → BadUserAccessDenied |
| AccessGroups folder | browse denied | browse denied | yes (name only) |

With the browse patch applied, the "hidden" cells are truly absent from Browse results; without it the names still appear. TranslateBrowsePathsToNodeIds is already filtered on master.

## The browse-listing gap and the patch

`browseResolvedNode` checks `allowBrowseNode` on the node being browsed, but `browseReferencTargetCallback` adds every target to the result without checking it. Part 3 ties PermissionType.Browse to whether a Node is visible to the client, so this looks like a gap rather than intended behaviour. The patch (`browse-hide-forbidden-targets.patch`) adds the same `allowBrowseNode` check per target, skipping the admin session.

Before proposing upstream: run the RBAC test suites (`tests/server/check_server_rbac*.c`), check continuation-point behaviour with `maxReferences` small, and measure cost on large folders (one permission lookup per listed reference).

Alternative if patching core is off the table: a wrapping Nodestore plugin that filters references per session — much more work, and session identity is not passed to nodestore calls, so it is not a realistic option for a demo.

## Steps

**Phase 1 — reproduce (½ day)**
1. Clone master, `git submodule update --init`, build with `UA_ENABLE_RBAC=ON`, `UA_NAMESPACE_ZERO=FULL`.
2. Build and run `examples/access_control/server_rbac.c` once to sanity-check the RBAC build.
3. Build `fruit_server.c` and `probe_client.c` (compile lines below); run the probe for both users.

**Phase 2 — close the leak (½ day)**
4. Apply the browse patch; rebuild; confirm hidden varieties vanish from listings.
5. Run the existing RBAC test suites with `UA_BUILD_UNIT_TESTS=ON`; add a test case for target filtering.

**Phase 3 — harden the demo (1–2 days)**
6. Turn on an encrypted SecurityPolicy (Basic256Sha256 / Aes256-Sha256-RsaPss) and drop `allowNonePolicyPassword`.
7. Exercise with UaExpert as both users: Browse, Read, Subscribe on a hidden Colour node, TranslateBrowsePath, and Read of `UserRolePermissions`.
8. Check that Events from hidden nodes don't reach yellow (event filtering by source-node permission is not something I verified).

**Phase 4 — make the access tree live (optional)**
9. `recursive` is a snapshot. Add a global node constructor (`config.nodeLifecycle`) or re-run the compile step when varieties or Organizes links change. In strict mode a newly added, uncompiled node is invisible to everyone — fail-safe, but surprising.
10. Optionally use a custom non-hierarchical ReferenceType (e.g. `InAccessGroup`) for the access links so they never show up as browse children; this needs your own traversal instead of `recursive=true`, because `recursive` follows hierarchical references only and `options` to restrict the reference type is not implemented yet.

**Phase 5 — upstream**
11. Open an issue / PR on open62541 for the Browse target filtering, citing this reproduction.

## Risks and open questions

- **API stability.** RBAC is explicitly experimental; signatures may change before 1.6 is released. Pin a commit.
- **Orange oranges.** Your description says yellowred sees everything except green apples, so ordinary Navel/Valencia must belong to one of the two roles. The prototype puts them in YellowRole; moving them to RedRole or a fourth group is a one-line change.
- **ns0 exposure.** The namespace default gives every logged-in user Browse+Read on ns0 (Server object, diagnostics). Narrow it if that matters for the demo.
- **Docs vs. code.** The rendered master HTML truncates the Server page before the RBAC API section; the authoritative reference is `include/open62541/server.h` (lines ~2180–2260 and ~2684–3081 at this commit).

## Build and run

```
git clone https://github.com/open62541/open62541.git o6 && cd o6
git submodule update --init --depth 1
git apply ../browse-hide-forbidden-targets.patch     # optional, Phase 2
mkdir build && cd build
cmake .. -DUA_ENABLE_RBAC=ON -DUA_NAMESPACE_ZERO=FULL && make -j
cd ../..
O=$PWD/o6; F="-I$O/include -I$O/plugins/include -I$O/build/src_generated -I$O/arch -L$O/build/bin -lopen62541 -lm -lpthread"
gcc -std=c99 fruit_server.c $F -o fruit_server
gcc -std=c99 probe_client.c $F -o probe_client
./fruit_server &
./probe_client yellow yellow
./probe_client yellowred yellowred
```
