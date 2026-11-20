# pi-lockbox

[![CI](https://github.com/azmainadel/pi-lockbox/actions/workflows/ci.yml/badge.svg)](https://github.com/azmainadel/pi-lockbox/actions/workflows/ci.yml)

Give [pi](https://pi.dev) passwords, API keys, and database URLs without sending them to the model.

- **Secret requests.** When a task needs a credential, the agent calls `request_secret`. You type or paste the value into a masked card. The value goes into an owner-only file, and the model only receives the file's path, which its commands read with `"$(cat <file>)"`.
- **Paste guard.** If a message you send contains a database URL with a password, a known API key format, or a private key, pi asks before sending. You can store it and send a reference, send it as is, or go back and edit.
- **Redaction.** Stored values that show up anyway, such as in command output, error messages, or the model's own replies, are replaced with `[REDACTED: NAME]` before the model sees them and before they are saved to the session file.

Inspired by the secret request card in [T3 Code](https://github.com/pingdotgg/t3code/blob/main/docs/user/secrets.md).

## Install

```bash
pi install npm:pi-lockbox
```

Or from source:

```bash
pi install git:github.com/azmainadel/pi-lockbox
```

Then start pi again, or run `/reload`. The package has no runtime dependencies.

## Use

### When the agent needs a secret

Ask for a task that needs a credential, for example "run the pending migrations on staging". The agent opens a card:

```text
──────────────────────────────────────────────────────────
 🔒 Secret request
 Staging DATABASE_URL
 Needed to run prisma migrate deploy against staging.
 Get it: https://console.neon.tech

 › ••••••••••••••••••••••••••••

 Commands the agent runs can read this value for 24 hours.
 It never appears in the chat, the session file, or what the model sees.
 Enter save · Ctrl+R show · Esc decline
──────────────────────────────────────────────────────────
```

Press **Esc** to decline. The agent is told not to ask in chat instead.

### When you paste a secret by accident

```text
 ⚠ Your message looks like it contains a secret
   DATABASE_URL: postgres://admin:***@db.prod.internal:5432/app

 › 1. Store securely and send a reference
   2. Send as is
   3. Edit message
```

With option 1 the model receives the masked URL plus a file path, so it still knows the host and database. The transcript shows `postgres://admin:***@db.prod.internal:5432/app 🔒 DATABASE_URL`.

The guard looks for:

- URLs with a password, in any scheme: `postgres://user:pass@host`, `redis://:pass@host`, and so on.
- Tokens with a prefix that only credentials use, such as `sk-`, `sk_live_`, `ghp_`, `xoxb-`, `AKIA`, and JWTs.
- PEM private keys.
- Assignments such as `DB_PASSWORD=...` or `"api_key": "..."`, when the value looks like a real secret. `password = form.get("password")` and `TOKEN=${TOKEN}` are ignored.
- A message that is only one random-looking string, such as a password pasted as a reply. Words, identifiers, file names, paths, versions, hashes, UUIDs, and email addresses are left alone. The same string inside a sentence is not caught.

It matches formats and does not guess which service a key is for, since several services share prefixes (Stripe and Clerk both use `sk_live_`). A secret is stored under the variable name you assigned it to, such as `CLERK_WEBHOOK_SECRET`. Without one, it is stored as `SECRET`, then `SECRET_2`, and so on.

### /secrets

| Command | What it does |
| --- | --- |
| `/secrets` | List stored secrets: name, masked value, time left, and file path. |
| `/secrets add NAME` | Store a secret yourself, using the masked card. The agent is told the name and file path. |
| `/secrets rm NAME` | Delete one secret. |
| `/secrets clear` | Delete all stored secrets, after you confirm. |

## Where secrets live

Secrets are stored in `~/.pi/agent/secrets/`. The directory has mode `0700`, and each secret is a pair of `0600` files: the value, and metadata without the value. Each secret is deleted 24 hours after it was stored. Expired secrets are swept when a session starts and whenever the store is read.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PI_LOCKBOX_DIR` | `~/.pi/agent/secrets` | Where secrets are stored. |
| `PI_LOCKBOX_TTL_MS` | `86400000` (24 hours) | How long a secret lives. |

## Limits

pi-lockbox reduces leaks. It cannot rule them out:

- **The agent's commands can read the value.** That is how they use it. A command that prints it, or a model that runs `cat` on the file, would expose it. Redaction then replaces the exact value, its URL-encoded form, and a URL's password on its own. A value that is transformed further, for example base64-encoded or split across lines, is not caught.
- **Redaction needs the value to be at least 6 characters.** Shorter values would match ordinary text.
- **Tool calls run with the real value.** If the model writes a stored value into a command, pi runs that command as written and saves it to the session file unchanged, because rewriting it would break the command. The model still sees `[REDACTED: NAME]` in that call on later requests.
- **Detection uses patterns.** A secret in an unknown format is only caught when it is assigned to a name such as `PASSWORD` or `API_KEY`, or when it is the whole message. Use `/secrets add` for anything else, such as a password in the middle of a sentence.
- **"Send as is" sends it as is.** The value then reaches the model provider and the session file. Rotate it.
- **Secrets stay on this machine.** Each pi process reads the same directory, but nothing is synced.

## Develop

No npm install is needed. Tests use Node's built-in test runner:

```bash
npm test
```

For editor support and `npm run typecheck`, link the pi packages and Node types that ship with your pi install into `node_modules/` (development only; nothing is downloaded):

```bash
npm run link-types
npm run typecheck   # needs `tsc` on PATH
```

To try local changes in pi, install the clone itself: `pi install ~/Developer/pi-lockbox`.

## Releasing (maintainers)

```bash
npm version patch && git push --follow-tags   # CI stages the release
npm stage list pi-lockbox                       # find the stage ID
npm stage approve <stage-id>                    # approve with 2FA to go live
```

Publishes go through npm trusted publishing (OIDC), so no npm token is stored. The GitHub Action runs the tests and stages the release on `v*` tags.

## License

MIT
