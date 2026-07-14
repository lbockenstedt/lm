# Microsoft Entra ID (Azure AD) SSO — setup

Lab Manager can authenticate users against **Microsoft Entra ID** (OIDC). One app
registration + certificate also powers the **Azure NSG** and **Cloud NAC** hooks,
so set it up once here.

Configure it in the WebUI at **Settings → Azure → SSO**.

> **MFA note:** LM does **not** verify MFA in the token. Entra omits the `amr`
> claim when MFA is satisfied from an existing session, so an in-token check
> falsely rejects valid logins. **Enforce MFA with a Conditional Access policy**
> (below) — that's where it belongs, and a user genuinely cannot sign in without
> it. LM trusts that a token it received means Entra let the user through.

---

## 1. Register the app

Entra admin center → **Identity → Applications → App registrations → New registration**.

- **Name:** e.g. `Lab Manager`.
- **Supported account types:** *Accounts in this organizational directory only* (single tenant).
- **Redirect URI:** platform **Web**, value `https://<your-hub>/auth/oidc/callback`.
- Register, then copy from the **Overview**:
  - **Application (client) ID**
  - **Directory (tenant) ID**

In LM (**Settings → Azure → SSO**): paste the tenant ID, client ID, and set the
**Redirect URI** to exactly the value above (it must match).

## 2. Certificate (client credential — not a secret)

LM authenticates to Entra with a **certificate**, not a client secret.

1. In LM **Settings → Azure → SSO → Generate certificate**. The card shows the
   public cert + its **thumbprint (x5t)**. Click **Download .cer**.
2. In Entra: App registration → **Certificates & secrets → Certificates → Upload
   certificate** → select the `.cer`.
3. Confirm the uploaded cert's thumbprint matches the one shown in LM.

The private key stays on the hub (`<data_dir>/oidc/`); it is never sent anywhere.

## 3. Microsoft Graph — application permissions

App registration → **API permissions → Add a permission → Microsoft Graph →
Application permissions**, add the ones you need, then **Grant admin consent**:

| Permission | Needed for |
|---|---|
| `Group.Read.All` | The group picker + resolving a user's group membership at login |
| `User.ReadWrite.All` | Cloud NAC — create / reset / delete accounts |
| `GroupMember.ReadWrite.All` | Cloud NAC — add provisioned users to a group |
| `AuditLog.Read.All` | Cloud NAC — idle-account sweep by sign-in activity (needs **Entra ID P1**) |

For login alone you only need `Group.Read.All`. Cloud NAC needs the other three.

## 4. (Recommended) Emit the groups claim

By default Entra does **not** put group memberships in the token. LM can fetch
them via `Group.Read.All`, but it's cleaner to emit them directly:

- App registration → **Token configuration → Add groups claim → Security groups →
  ID** → Save.

## 5. Map Entra groups → LM tenants / permissions

An Entra group grants LM access via a **permission group**:

- LM → **Settings → User Access → Permission Groups → New/Edit**.
- **Directory Group:** click **Pick from Entra** and choose the group (fills its
  object ID). Set the **Tenant Scope** and **Permissions** for that group.
- At login, a user's Entra group memberships are matched to these permission
  groups, granting the tied permissions + tenants (just-in-time; LM users are
  created on first successful login).

Optionally set an **Allowed group** in the SSO card to restrict login to members
of one group.

---

## 6. Enforce MFA with Conditional Access (P1)

MFA is enforced **in Entra**, not LM. A Conditional Access policy makes it
mandatory for the LM sign-in.

Entra admin center → **Protection → Conditional Access → Policies → New policy**:

1. **Name:** e.g. `Require MFA – Lab Manager`.
2. **Assignments → Users:** *Include* → **Select users and groups** → pick the
   group/users that should be forced to MFA. Under **Exclude**, add a
   **break-glass admin** account so you can't lock yourself out.
3. **Target resources → Include:** select the **Lab Manager** app (scopes MFA to
   LM), or **All resources** to require it everywhere.
4. **Grant → Grant access → Require multifactor authentication → Select**.
5. **Enable policy: On** (not *Report-only* — report-only evaluates but does **not**
   enforce), then **Create**.

**Prerequisites / notes**

- **Entra ID P1** is required for Conditional Access. No P1? Turn on **Security
  defaults** instead (Identity → Overview → Properties → *Manage security
  defaults* → Enabled) — enforces MFA tenant-wide, no group targeting.
- The user must have an **MFA method registered** (they're prompted to set one up
  on next sign-in if not).
- Tip: set the new policy to **Report-only** first to see who it would hit, then
  flip to **On**.

**Verify it's working:** Entra → **Sign-in logs** → your LM sign-in → the
**Conditional Access** tab should show the policy **Applied / Success**, and the
**Authentication requirement** column should read *Multifactor authentication*.
If it shows *Not applied*, fix the policy's **Target resources** (must include the
LM app or All resources) and confirm it's **On** and your account is in scope.

> A sign-in log entry that says *"MFA requirement satisfied by claim in the
> token"* means MFA was met from the existing session — that's normal and fully
> enforced; it's also why LM does not (and cannot reliably) re-check `amr`.

---

## 7. (Optional) Azure NSG hook — ARM role

The Azure NSG feature (**Settings → Azure → NSG**) uses the **same app cert** but
authenticates to **Azure Resource Manager**, which is RBAC (not Graph):

- On the **NSG** (or its resource group) → **Access control (IAM) → Add role
  assignment → Network Contributor → assign to the Lab Manager app**.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `could not load OIDC client private key` | Cert not generated — Settings → Azure → SSO → Generate certificate. |
| `token exchange failed: HTTP 401 — AADSTS700027` | Uploaded cert doesn't match the current key (regenerated after upload). Re-download `.cer` and re-upload; thumbprints must match. |
| Sign-in `50011` redirect mismatch | Redirect URI in the app must exactly equal the one in the SSO card. |
| Group picker `Authorization_RequestDenied` | Missing `Group.Read.All` (Application) + admin consent. |
| `Entra user is not a member of the allowed group` | No `groups` claim in the token — add it (step 4) or grant `Group.Read.All` so LM can fetch membership. |
| Login shows a GUID as the username | Cosmetic — LM keys users by the stable Entra `oid`; the header shows the name/email once present. |
