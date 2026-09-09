[<img src="https://shiro.apache.org/images/apache-shiro-logo.png" align="right" />](http://shiro.apache.org)

# CVE-2026-49268 — Analysis and Remediation of an LDAP Injection Authentication Bypass Vulnerability


| | |
|---|---|
| **Branch** | `1.13-CVE-2026-49268` |
| **Author** | Jinwoo Hwang (https://JinwooHwang.com) |

This branch (`1.13-CVE-2026-49268`) contains a comprehensive security remediation of an LDAP Injection Authentication Bypass Vulnerability in Apache Shiro 1.13 release. 


**Official NVD Description**

> A remote attacker can inject LDAP special characters into the Distinguished Name (DN) construction
> in DefaultLdapRealm class. User-supplied username input is directly concatenated into the LDAP DN 
> template without any escaping of RFC 2253 special characters. This allows an attacker to manipulate 
> the DN structure used for LDAP bind authentication, potentially bypassing authentication or 
> impersonating other users. This issue affects all Apache Shiro versions through 2.2.0, and 3.0.0-alpha-1 
> when using DefaultLdapRealm.

---

## 1. Vulnerability Overview

| Field | Value |
|---|---|
| **CVE** | CVE-2026-49268 — *Apache Shiro: LDAP DN Injection in DefaultLdapRealm* |
| **CWE ID** | CWE-90 — Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') |
| **CVSS v4.0** | **8.8 HIGH** — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/S:P/AU:Y/R:A/RE:L/U:Red` |
| **CVSS v3.1** | **9.1 CRITICAL** —  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Affected versions** | `org.apache.shiro:shiro-core` **0 through 2.2.0** inclusive; **3.0.0-alpha-0 through 3.0.0-alpha-1** inclusive |
| **Fixed upstream in** | 2.2.1 and 3.0.0-alpha-2 |
| **Reference** | https://lists.apache.org/thread/svszql3od8td7hn6conyj2oq70v53b5s |


---

## 2. Executive Summary

Apache Shiro can authenticate users against an LDAP directory. To do that, it turns a
submitted username into a *Distinguished Name* — the directory's address for that user's
entry — by dropping the username into a configured template, for example
`uid={0},ou=users,dc=mycompany,dc=com`.

In the affected versions the username is pasted into that template as raw text. A handful
of punctuation characters — most importantly the comma — are not ordinary text to a
directory server; they are the syntax that separates one part of an address from the next.
A username containing those characters therefore stops behaving like a value inside the
address and starts behaving like part of the address itself.

The practical consequence is that a person logging in can influence *which directory entry
Shiro tries to authenticate against*, rather than only supplying their own name. Instead of
being looked up in the container the deployment intended, the lookup can be redirected
elsewhere in the directory. Depending on how the directory is laid out and what it permits,
this can lead to authenticating as the wrong identity, or to authentication succeeding when
it should not.

**Risk profile.** What raises the risk: no prior access or credentials are required — the
input arrives at the login boundary, which is reachable by anyone who can reach the
application; and the affected class is the standard, documented way to wire Shiro to LDAP,
so this is not an exotic configuration. What lowers it: the deployment must actually use
`DefaultLdapRealm` (or `JndiLdapRealm`) **with a configured DN template**; deployments that
authenticate by other means, or that pass a full DN or a non-text credential such as a
certificate, are not affected. Whether a redirected lookup yields a usable authentication
also depends on the target directory's own layout and access rules, which vary by site.

A second, non-security consequence is worth noting for release planning: users whose
legitimate usernames contain a backslash or begin with `#` currently **cannot log in at
all**, because the address built for them is not a well-formed name and is rejected
outright. Other punctuation does not fail outright — it silently changes which entry the
address refers to, which is the security problem above. The same fix resolves both.

---

## 3. Root Cause Analysis

### 3.1 The defect

`core/src/main/java/org/apache/shiro/realm/ldap/DefaultLdapRealm.java`, `getUserDn(String)`,
lines 227–250 on the unfixed baseline:

```java
protected String getUserDn(String principal) throws IllegalArgumentException, IllegalStateException {
    if (!StringUtils.hasText(principal)) {
        throw new IllegalArgumentException("User principal cannot be null or empty for User DN construction.");
    }
    String prefix = getUserDnPrefix();
    String suffix = getUserDnSuffix();
    if (prefix == null && suffix == null) {
        log.debug("userDnTemplate property has not been configured, indicating the submitted "
                + "AuthenticationToken's principal is the same as the User DN.  Returning the method argument "
                + "as is.");
        return principal;
    }

    int prefixLength = prefix != null ? prefix.length() : 0;
    int suffixLength = suffix != null ? suffix.length() : 0;
    StringBuilder sb = new StringBuilder(prefixLength + principal.length() + suffixLength);
    if (prefixLength > 0) {
        sb.append(prefix);
    }
    sb.append(principal);            // <-- inserted verbatim
    if (suffixLength > 0) {
        sb.append(suffix);
    }
    return sb.toString();
}
```

The template is split once, at configuration time, around the `{0}` token
(`setUserDnTemplate`, lines 181–200), into a `prefix` and a `suffix`. At authentication time
the principal is concatenated between them. **No encoding is applied at any point.** There is
no escaping helper anywhere in `org/apache/shiro/realm/ldap/`.

### 3.2 The invariant that was assumed but never enforced

The surrounding code treats the result of `getUserDn` as a well-formed Distinguished Name —
it is handed straight to `LdapContextFactory.getLdapContext(...)` and from there to JNDI as a
bind DN. That is only sound if the substituted principal is a *single attribute value*.

String concatenation cannot enforce that. RFC 2253 (and RFC 4514) reserve
`,` `+` `"` `\` `<` `>` `;` `=`, a leading `#`, and leading/trailing whitespace as structural
syntax within a DN. When any of those appear in the principal they are read by the parser as
structure, not as content. The invariant — *"the principal occupies exactly one RDN value"* —
was assumed by every downstream consumer and enforced by none.

### 3.3 Execution flow, entry point to defect

```
  submitted credentials (username, password)
        │
        ▼
  DefaultLdapRealm.doGetAuthenticationInfo(AuthenticationToken)        [line 292]
        │
        ▼
  DefaultLdapRealm.getLdapPrincipal(AuthenticationToken)               [line 338]
        │   principal instanceof String ?
        │       ├── no  ──► return principal unchanged   ── NOT AFFECTED (e.g. X.509)
        │       └── yes ──┐
        ▼                 │
  DefaultLdapRealm.getUserDn(String)                                   [line 227]
        │   prefix == null && suffix == null ?
        │       ├── yes ──► return principal unchanged   ── NOT AFFECTED ("principal IS the DN")
        │       └── no  ──┐
        ▼                 │
  prefix + principal + suffix          ◄── DEFECT: unencoded concatenation  [line 246]
        │
        ▼
  LdapContextFactory.getLdapContext(userDn, credentials)
        │
        ▼
  JNDI bind against the directory using the constructed DN
```

### 3.4 Demonstrated effect

Template `uid={0},ou=users,dc=mycompany,dc=com`, principal `jsmith,ou=admins`:

| | Constructed DN | Parsed RDNs |
|---|---|---|
| Intended | `uid=jsmith\,ou\=admins,ou=users,dc=mycompany,dc=com` | 4 |
| Baseline (unfixed) | `uid=jsmith,ou=admins,ou=users,dc=mycompany,dc=com` | **5** |

The name gains a component. `ou=users` is no longer the container being addressed —
`ou=admins` is interposed. Verified by parsing with `javax.naming.ldap.LdapName`, which is
independent of any escaping implementation.

Measured behaviour of the baseline across the reserved set (JDK 8, `LdapName` parse):

| Principal | Baseline result | Effect |
|---|---|---|
| `jsmith,ou=admins` | parses, **5 RDNs** | **structure altered** — a container is interposed |
| `jsmith;ou=admins` | parses, **5 RDNs** | **structure altered** — `;` is an RDN separator under RFC 1779 |
| `jsmith+uid=admin` | parses, 4 RDNs | becomes a **multi-valued RDN**; `uid` gains a second value |
| `jsmith=admin` | parses, 4 RDNs | value corrupted |
| `quo"te`, `angle<br>ackets`, ` leadingSpace`, `trailingSpace ` | parse, 4 RDNs | value corrupted |
| `back\slash` | `IllegalArgumentException` | malformed — bind cannot be attempted |
| `#leadingNumberSign` | `IllegalArgumentException` | malformed — bind cannot be attempted |

Two characters alter the name's structure, not just its content: the comma, and the
semicolon — which RFC 1779 accepts as an alternative RDN separator. `+` introduces a second
attribute value into the same RDN. Only `\` and a leading `#` render the name unparseable.

### 3.5 Adjacent code that is correct, and why — blast radius

- **`userDnTemplate` unset.** `getUserDn` returns the principal untouched. This is the
  documented "the submitted principal *is* the DN" mode; the caller supplies a complete DN
  and owns its correctness. Not affected.
- **Non-`String` principals.** `getLdapPrincipal` only routes `String` principals into
  `getUserDn`; anything else (X.509 certificates, custom tokens) passes through. Not affected.
- **`setUserDnTemplate` validation** (lines 181–200) correctly rejects a null, blank, or
  `{0}`-less template. It validates the *operator-supplied* template, which was never the
  untrusted input — so it is correct code that simply does not address this defect.
- **`JndiLdapRealm`** extends `DefaultLdapRealm` and does not override `getUserDn`, so it
  inherits the defect. Confirmed by test (§6.1). In scope, and fixed by the same change.

### 3.6 Related path — ASSESSED, NOT AFFECTED

`AbstractLdapRealm.searchFilter` (line 89) carries a second `{0}` substitution, default
`(&(objectClass=*)(userPrincipalName={0}))`, used on the **authorization** path. It is **not affected**.

A sweep of every `search(` call, every `getLdapContext(` caller, and every LDAP-shaped
string literal across `core`, `support` and `web` main sources found exactly one use of
`searchFilter` — `ActiveDirectoryRealm.getRoleNamesForUser`, line 172:

```java
Object[] searchArguments = new Object[]{userPrincipalName};
NamingEnumeration answer = ldapContext.search(searchBase, searchFilter, searchArguments, searchCtls);
```

This is the **parameterized** `DirContext.search(String, String, Object[], SearchControls)`
overload. The username is passed as a filter *argument*, never concatenated into the filter
string. Per the JDK 8 `javax.naming.directory.DirContext` javadoc, verbatim:

> "When a string-valued filter argument is substituted for a variable, the filter is
> interpreted as if the string were given in place of the variable, with any characters
> having special significance within filters (such as `'*'`) having been escaped according
> to the rules of RFC 2254."

The JNDI provider performs the escaping. The historical record of this is in the field
declaration itself.

**Source: `core/src/main/java/org/apache/shiro/realm/ldap/AbstractLdapRealm.java`, lines 88–89**

```java
    //SHIRO-115 - prevent potential code injection:
    protected String searchFilter = "(&(objectClass=*)(userPrincipalName={0}))";
```

**Source: `core/src/main/java/org/apache/shiro/realm/activedirectory/ActiveDirectoryRealm.java`, lines 158–172**

```java
    protected Set<String> getRoleNamesForUser(String username, LdapContext ldapContext) throws NamingException {
        Set<String> roleNames;
        roleNames = new LinkedHashSet<String>();

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String userPrincipalName = username;
        if (principalSuffix != null && !userPrincipalName.toLowerCase(Locale.ROOT).endsWith(principalSuffix.toLowerCase(Locale.ROOT))) {
            userPrincipalName += principalSuffix;
        }

        Object[] searchArguments = new Object[]{userPrincipalName};

        NamingEnumeration answer = ldapContext.search(searchBase, searchFilter, searchArguments, searchCtls);
```

The username reaches the directory as `searchArguments[0]`, never as text spliced into
`searchFilter`. The `{0}` token in the filter is resolved by the JNDI provider, not by
Shiro.

`ActiveDirectoryRealm` line 108 passes the raw username to
`getLdapContext(username, password)`. That value becomes a single JNDI
`SECURITY_PRINCIPAL` environment entry; it is not substituted into a template and no DN is
constructed from it, so it is outside this defect's mechanism.

**Verified empirically against a live directory server.** The JNDI escaping was not taken
on trust: it was observed on the wire. An in-process LDAP server
(UnboundID `InMemoryDirectoryServer`) was instrumented with an
`InMemoryOperationInterceptor` that records the filter of every search request it receives,
and Shiro's default `searchFilter` was issued through the same parameterized JNDI call used
by `ActiveDirectoryRealm`, with a crafted argument:

```
filter template : (&(objectClass=*)(userPrincipalName={0}))
argument passed : *)(uid=jsmith
server received : (&(objectClass=*)(userPrincipalName=\2a\29\28uid=jsmith))
```

The `*`, `)` and `(` arrived at the server as `\2a`, `\29` and `\28` — escaped per
RFC 2254. The filter retains exactly two clauses; the argument could not add a third.

Control, the same template with the argument spliced in as raw text instead of passed as a
filter argument:

```
CONTROL, raw splice: (&(objectClass=*)(userPrincipalName=*)(uid=jsmith))
server received    : (&(objectClass=*)(userPrincipalName=*)(uid=jsmith))
```

The control reaches the server with its structure altered — a third clause added and the
`userPrincipalName` test reduced to a wildcard. The parameterized form does not. This
confirms, by observation rather than by contract, that the `searchFilter` path is not
affected.

---

## 4. Step-by-Step Reproduction Steps

Deterministic, from a clean checkout. Working directory is the repository root throughout.

### 4.1 Prerequisites

| Requirement | Value used |
|---|---|
| JDK | **8** — the branch sets `jdk.version` 1.8. Results below were produced with Zulu 1.8.0_432 (arm64). Point `JAVA_HOME` at a JDK 8 installation before running any command in this section: |
| Build | Apache Maven, network access required (parent POM `org.apache:apache:38`) |
| Baseline | `origin/1.13.x` |
| Configuration | `userDnTemplate = uid={0},ou=users,dc=mycompany,dc=com` |
| Directory server | **Not required for §4.3-§4.4** — the defect is in DN construction, before any network call, so those steps mock `LdapContextFactory`. §4.5 additionally reproduces the whole path against a **real** LDAP server over HTTP. |

Setting `JAVA_HOME` to a JDK 8 install:

```bash
# macOS
export JAVA_HOME=$(/usr/libexec/java_home -v 1.8)

# Linux (path varies by distribution and vendor)
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64

# Windows (cmd)
set JAVA_HOME=C:\Program Files\Zulu\zulu-8
```

Confirm with `mvn -v`, which reports the JDK Maven will use. The commands below assume this
is already set.

### 4.2 Obtain the unfixed baseline

```bash
git clone https://github.com/apache/shiro.git
cd shiro
git checkout -b repro origin/1.13.x
```

### 4.3 Observe the defect directly

This is the minimal trigger, independent of Shiro's build. Write `Repro.java` to a scratch
directory:

```java
import javax.naming.ldap.LdapName;

public class Repro {
    // reproduces DefaultLdapRealm.getUserDn line-for-line
    static String getUserDn(String prefix, String principal, String suffix) {
        StringBuilder sb = new StringBuilder(prefix.length() + principal.length() + suffix.length());
        sb.append(prefix);
        sb.append(principal);
        sb.append(suffix);
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String prefix = "uid=";
        String suffix = ",ou=users,dc=mycompany,dc=com";

        String benign = getUserDn(prefix, "jsmith", suffix);
        System.out.println("benign : " + benign + "  -> RDNs=" + new LdapName(benign).size());

        String crafted = getUserDn(prefix, "jsmith,ou=admins", suffix);
        System.out.println("crafted: " + crafted + "  -> RDNs=" + new LdapName(crafted).size());
    }
}
```

Run it:

```bash
javac Repro.java && java Repro
```

Observed output:

```
benign : uid=jsmith,ou=users,dc=mycompany,dc=com  -> RDNs=4
crafted: uid=jsmith,ou=admins,ou=users,dc=mycompany,dc=com  -> RDNs=5
```

The component count changes from 4 to 5. The submitted value has become name structure.

### 4.4 Reproduce through Shiro's own API

From the repository root on the unfixed baseline, apply the tests in §6.3 and run:

```bash
mvn -B clean verify
```

The build stops at `Apache Shiro :: Core` with the proving tests failing — see §6.1 for the
full captured output:

```
DefaultLdapRealmTest   Tests run: 16, Failures: 4, Errors: 0, Skipped: 0
JndiLdapRealmTest      Tests run: 16, Failures: 4, Errors: 0, Skipped: 0
```

### 4.5 End-to-end reproduction over HTTP against a live directory server

Reproduced through the **entire stack** — a real HTTP request, a real servlet container,
Shiro's own `FormAuthenticationFilter`, and a real LDAP server. Nothing is mocked at any
layer.

| Layer | Component |
|---|---|
| HTTP client | `HttpURLConnection`, raw form POST |
| Servlet container | Embedded Jetty 9.4.58.v20250814 |
| Security filter | `ShiroFilter` + `EnvironmentLoaderListener`, `authc` (`FormAuthenticationFilter`) |
| Realm | `DefaultLdapRealm`, `userDnTemplate = uid={0},ou=users,dc=mycompany,dc=com` |
| Directory | UnboundID `InMemoryDirectoryServer`, instrumented to record every bind DN |

**Directory fixture** — a nested privileged container, a common real-world layout:

```
dc=mycompany,dc=com
└── ou=users
    ├── uid=jsmith                     userPassword: userpass     (ordinary account)
    └── ou=admins
        └── uid=jsmith                 userPassword: adminpass    (privileged account)
```

#### 4.5.1 Affected build

**Request**

```http
POST /login HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded

username=jsmith%2Cou%3Dadmins&password=adminpass
```

**Response**

```http
HTTP/1.1 302 Found
Location: http://127.0.0.1/;jsessionid=node0qu3v2n612vy71alsuyir2bgzz1.node0
```

**Bind DN the directory received**

```
uid=jsmith,ou=admins,ou=users,dc=mycompany,dc=com
```

The 302 is `FormAuthenticationFilter`'s success redirect: the request **authenticated**.
The DN carries five components where the template defines four, and the entry reached is
the privileged one under `ou=admins`.

**Control — the same username with the ordinary account's password**

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=jsmith%2Cou%3Dadmins&password=userpass
```

```http
HTTP/1.1 200 OK
```

Rejected. This is what establishes impersonation rather than coincidence: the crafted
username authenticates with the **privileged account's** password and fails with the
ordinary user's, so the credentials being checked belong to a different directory entry
than the template addresses.

#### 4.5.2 Remediated build — identical requests

| Request | Affected | Remediated |
|---|---|---|
| `username=jsmith&password=userpass` | `302` authenticated | `302` authenticated |
| `username=jsmith%2Cou%3Dadmins&password=adminpass` | **`302` authenticated** | **`200` rejected** |
| `username=jsmith%2Cou%3Dadmins&password=userpass` | `200` rejected | `200` rejected |

Bind DN received by the directory for the crafted username:

```
affected   : uid=jsmith,ou=admins,ou=users,dc=mycompany,dc=com      (5 components)
remediated : uid=jsmith\,ou\=admins,ou=users,dc=mycompany,dc=com    (4 components)
```

Ordinary logins are unchanged — row 1 authenticates identically on both builds, with the
directory receiving `uid=jsmith,ou=users,dc=mycompany,dc=com`.

Both runs used the same harness and the same fixture; only `shiro-core` on the classpath
differed. The class actually loaded was confirmed with `-verbose:class` for each run.

---

## 5. Remediation Details & Remediation Code

### 5.1 Primary fix

Encode the principal as a single DN attribute value before substitution, using the JDK's
own RFC 2253 encoder, `javax.naming.ldap.Rdn.escapeValue`. This is the same mechanism the
JDK uses to build names, so its output is by construction consistent with the parser that
consumes it.

**File:** `core/src/main/java/org/apache/shiro/realm/ldap/DefaultLdapRealm.java`

```diff
@@ -35,6 +35,7 @@ import org.slf4j.LoggerFactory;
 import javax.naming.AuthenticationNotSupportedException;
 import javax.naming.NamingException;
 import javax.naming.ldap.LdapContext;
+import javax.naming.ldap.Rdn;
 
 /**
  * An LDAP {@link org.apache.shiro.realm.Realm Realm} implementation utilizing Sun's/Oracle's
@@ -239,11 +240,14 @@ public class DefaultLdapRealm extends AuthorizingRealm {
 
         int prefixLength = prefix != null ? prefix.length() : 0;
         int suffixLength = suffix != null ? suffix.length() : 0;
-        StringBuilder sb = new StringBuilder(prefixLength + principal.length() + suffixLength);
+        //the principal is a single attribute value within the resulting name, so it is encoded
+        //to keep any characters that are significant in a Distinguished Name within that value:
+        String value = Rdn.escapeValue(principal);
+        StringBuilder sb = new StringBuilder(prefixLength + value.length() + suffixLength);
         if (prefixLength > 0) {
             sb.append(prefix);
         }
-        sb.append(principal);
+        sb.append(value);
         if (suffixLength > 0) {
             sb.append(suffix);
         }
```

**What the hunk enforces.** `Rdn.escapeValue` backslash-escapes the RFC 2253 reserved set
(`\ , = + < > # ; "`) plus leading and trailing whitespace. After it, the substituted text
can only ever occupy one RDN value: the parser reads the escaped characters as content, so
the component count of the result is fixed by the template and cannot be influenced by the
principal. The `StringBuilder` capacity hint is updated to the encoded length — a sizing
detail, not a behavioural one.

**Placement.** The encoding sits *after* the early return for the unconfigured-template
case. That is deliberate: in that mode the caller supplies a complete DN and encoding it
would corrupt it. Both branches keep their existing contracts.

### 5.2 Behaviour change for legitimate callers

This fix **changes the DN string** produced for any principal containing a reserved
character. Three consequences worth stating plainly:

1. **Previously-broken logins now work.** Usernames containing a backslash or beginning
   with `#` produced a DN that was not a well-formed name, so no bind could be attempted at
   all. They now encode to a valid DN and will attempt a bind. Sites may see accounts begin
   authenticating that previously could not — a fix, but a visible change. Usernames
   containing `,`, `;`, `+` or `=` were not rejected before; they resolved to the wrong
   entry, and now resolve to the intended one.
2. **Bind DNs sent to the directory differ** for affected usernames. Directory-side logs,
   audit trails, and any log-scraping that matches on literal DN strings will see escaped
   forms (`uid=jsmith\,ou\=admins,...`). No configuration change is required.
3. **Deployments that relied on the old behaviour to construct multi-component DNs from the
   username field would break.** This is not a supported configuration — the template
   exists to define structure — but it is the one migration hazard, and it is the same
   behaviour the fix exists to remove.

`getUserDnTemplate()` is implemented as `getUserDn("{0}")`. `{` and `}` are not reserved in
RFC 2253, so the accessor's return value is unchanged. Confirmed by the pre-existing
`testUserDnTemplate`, which passes unmodified.

---

## 6. Verification & Testing

### 6.1 Before — baseline, unfixed

Branch `1.13-CVE-2026-49268`, JDK Zulu 1.8.0_432. Command as §4.4.

```
DefaultLdapRealmTest   Tests run: 16, Failures: 4, Errors: 0, Skipped: 0
JndiLdapRealmTest      Tests run: 16, Failures: 4, Errors: 0, Skipped: 0
```

Captured failure output — this is the evidence, and it is not recoverable once the fix is in
place:

```
testGetUserDnPreservesTemplateStructure:238
  User DN gained or lost components relative to the template:
  uid=jsmith,ou=admins,ou=users,dc=mycompany,dc=com
  expected:<4> but was:<5>

testGetUserDnPreservesTemplateStructureForReservedCharacters:262
  Component count changed for principal [jsmith,ou=admins]:
  uid=jsmith,ou=admins,ou=users,dc=mycompany,dc=com
  expected:<4> but was:<5>

testGetUserDnEncodesSubstitutedValue:280
  expected:<uid=jsmith[\,ou\]=admins,ou=users,dc=...>
   but was:<uid=jsmith[,ou]=admins,ou=users,dc=...>

testUserDnTemplateSubstitutionPreservesStructure:300
  Unexpected method call
    LdapContextFactory.getLdapContext("uid=jsmith,ou=admins,ou=users,dc=mycompany,dc=com", ...)
  expected:
    LdapContextFactory.getLdapContext("uid=jsmith\,ou\=admins,ou=users,dc=mycompany,dc=com", ...)
    expected: 1, actual: 0
```

`testGetUserDnLeavesOrdinaryPrincipalUnchanged` **passed on the baseline**, as intended — it
is a guard against over-correction, not a proving test.

### 6.2 After — with the fix applied

Same command, same JDK:

```
DefaultLdapRealmTest   Tests run: 16, Failures: 0, Errors: 0, Skipped: 0
JndiLdapRealmTest      Tests run: 16, Failures: 0, Errors: 0, Skipped: 0
```

All four proving tests now pass on both classes. Re-running §4.3 with the fix in place
yields `RDNs=4` for the crafted principal.

### 6.3 Tests added

**File:** `core/src/test/java/org/apache/shiro/realm/ldap/DefaultLdapRealmTest.java`
(+124 lines, 0 deletions). Because `JndiLdapRealmTest extends DefaultLdapRealmTest`, every
test below executes against **both** realms — 10 executions from 5 methods.

| Test | Asserts | Baseline |
|---|---|---|
| `testGetUserDnLeavesOrdinaryPrincipalUnchanged` | An ordinary principal yields the exact expected DN, 4 RDNs, value intact. Guards against over-escaping. | **passed** (guard) |
| `testGetUserDnPreservesTemplateStructure` | For `jsmith,ou=admins` the DN still has 4 components and the principal survives as one attribute value. | failed |
| `testGetUserDnPreservesTemplateStructureForReservedCharacters` | The same, across all 10 reserved-character principals; also fails the test if the DN is not a well-formed name. | failed |
| `testGetUserDnEncodesSubstitutedValue` | The substituted value is encoded such that it round-trips to the submitted principal. | failed |
| `testUserDnTemplateSubstitutionPreservesStructure` | End-to-end through `getAuthenticationInfo`: the DN handed to `LdapContextFactory` retains the template's structure. | failed |

**Design note.** The structural assertions parse the result with `javax.naming.ldap.LdapName`
and compare component counts and the round-tripped leaf value, rather than asserting an
expected escaped string. The tests therefore verify the actual required property and do not
presuppose `Rdn.escapeValue` as the implementation — an alternative correct encoder would
still pass.

Command:

```bash
mvn -B clean verify
```

### 6.4 Regression — full build

The full reactor build passes with **no flags and no skips**:

```
mvn -B clean verify
```

**BUILD SUCCESS — 907 tests, 0 failures, 0 errors, 3 skipped, across the full reactor.**
Every gate is active in this run: unit tests (surefire), integration tests (failsafe),
the Apache RAT licence audit, maven-enforcer, and japicmp.

| Gate | Result |
|---|---|
| Unit tests, full reactor | **907 run, 0 failures, 0 errors, 3 skipped** |
| `core` module alone | **321 run, 0 failures, 0 errors, 0 skipped** |
| LDAP tests (`DefaultLdapRealmTest` + `JndiLdapRealmTest`) | **32 run, 0 failures** |
| Integration tests (failsafe) | ran across the reactor, no failures |
| Apache RAT licence audit | Unapproved: 0, unknown: 0 |
| maven-enforcer | no violations |
| japicmp | no incompatibility reported |

The 3 skips are pre-existing `@Ignore`s in modules unrelated to this change; `core` — the
only module touched — skips nothing.

## References

- CVE record (MITRE API): `https://cveawg.mitre.org/api/cve/CVE-2026-49268`
- Upstream announcement: `https://lists.apache.org/thread/svszql3od8td7hn6conyj2oq70v53b5s`
- Apache Shiro security reports: `https://shiro.apache.org/security-reports.html`
- RFC 2253 / RFC 4514 — LDAP string representation of Distinguished Names
- RFC 4515 — LDAP search filter string representation

## Contact

Security Vulnerability Research and Remediation Author: Jinwoo Hwang ([https://JinwooHwang.com](https://jinwoohwang.com/))
