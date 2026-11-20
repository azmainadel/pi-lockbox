# pi-lockbox

[![CI](https://github.com/azmainadel/pi-lockbox/actions/workflows/ci.yml/badge.svg)](https://github.com/azmainadel/pi-lockbox/actions/workflows/ci.yml)

**Give [pi](https://pi.dev) your passwords and API keys without giving them to the model.**

When pi needs a database URL or an API key, you type it into a locked box instead of the chat. The agent can still use it in its commands, but the model never sees it, and it stays out of your session history.

```text
 🔒 Secret request
 Staging DATABASE_URL
 Needed to run prisma migrate deploy against staging.

 › ••••••••••••••••••••••••••••

 Enter save · Ctrl+R show · Esc decline
```

## What you get

- **Ask instead of paste.** When a task needs a credential, pi asks for it in a masked prompt.
- **A safety net for slips.** Paste a key or a database URL into a message by mistake, and pi stops before sending it. One keypress locks it away, and the model gets a reference instead.
- **No leaks back.** If a stored secret shows up in command output or a reply, the model sees `[REDACTED: NAME]`.
- **Gone the next day.** Secrets live in files only you can read, and are deleted after 24 hours.

## Install

```bash
pi install npm:pi-lockbox
```

Restart pi or run `/reload`. There is nothing to configure.

## Commands

| Command | What it does |
| --- | --- |
| `/secrets` | See what's stored and when it expires |
| `/secrets add NAME` | Store a secret yourself |
| `/secrets rm NAME` | Delete one |
| `/secrets clear` | Delete all |

## Good to know

pi-lockbox cuts down leaks but can't rule them out. The agent's commands can read a stored value, since that's how they use it. The paste guard catches common formats like database URLs, API keys, and private keys, but not every possible password. If a secret does reach the model, rotate it.

Read [how it works](https://github.com/azmainadel/pi-lockbox/blob/main/docs/how-it-works.md) for the details, the full list of limits, and how to develop it.

Inspired by the secret requests in [T3 Code](https://github.com/pingdotgg/t3code).

## License

MIT
