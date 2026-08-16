# Usage

## Create your vault

1. Open the app, click **Create account**.
2. Enter email + a strong master password (8+ chars). **This password is never
   stored** — losing it means your vault cannot be opened. There is no recovery.
3. You land in the vault. Your Master Encryption Key is derived on-device and
   kept only in your browser's local storage for this session.

## Save a secret

1. Tap the **+** button.
2. Title (e.g. "Gmail"), category (Login/Card/WiFi/Note/Other), username,
   password, website, notes. Mark favourite if you want it pinned on top.
3. **Save to vault**. The password is encrypted with AES-256-GCM before it ever
   leaves your browser.

## Generate a strong password

1. Tap **⚙** in the header (or the 🎲 button inside a new entry).
2. Set length (8–64) and character classes; optionally exclude ambiguous
   characters (`1 l I O 0`).
3. The generator shows the entropy estimate and a 0–4 strength score.
   **Use this password** fills it into the entry form.

## Find entries

- **Search** (🔍) filters by title / username / website.
- **Favourites** (⭐) toggles a favourites-only view. Favourited entries are
  always listed first.

## Audit log

The **🕘** button shows your recent activity: logins, entry creates/updates/
deletes, password generations, TOTP checks — with timestamps.

## Master password change

**🔑 Change master password** lets you rotate the password that protects the
vault. The verifier token is re-encrypted with the new key automatically.

## Auto-lock

The vault auto-locks after **5 minutes** of inactivity (timer in the header).
On lock the MEK is dropped from local storage — the vault list remains visible
but encrypted fields require a re-login. **Logout** (⎋) clears all local state.

## TOTP (developer / power-user flow)

`POST /api/totp/setup` returns a base32 secret + otpauth URI. Verify a 6-digit
code with `POST /api/totp/check` (`{"secret": "...", "code": "123456"}`).
