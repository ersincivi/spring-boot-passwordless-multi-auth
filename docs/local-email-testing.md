# Local E-mail Testing with Mailpit

Every sign-in flow in this project sends an e-mail (magic link or OTP), so you
need a working mailbox even on a laptop with no mail account. That is what
[Mailpit](https://mailpit.axllent.org/) is for — it is already part of the
Docker setup and starts with `./start-dev.sh`.

## How it works

- The app is configured (dev profile) to send SMTP to `localhost:1025`.
- Mailpit accepts **everything** on that port — no authentication, no real
  delivery, nothing ever leaves your machine.
- Every message it catches appears instantly in a web inbox:

```
http://localhost:8025
```

## Typical loop

1. Request a magic link or OTP for `admin@example.com` (web form or API).
2. Open <http://localhost:8025> — the mail is already there.
3. Click the link (or copy the OTP) and finish the login.

The mail templates render exactly as they would in a real mailbox, so this is
also the fastest way to preview template changes in
`EmailService`.

## Notes

- Mailpit stores messages in memory — restarting the container empties the
  inbox. That is a feature for testing, not a bug.
- SMTP port `1025` and UI port `8025` are mapped in both
  `docker-compose.yml` and `docker-compose-full-stack.yml`.
- In the prod profile the app expects a real SMTP server via environment
  variables (`MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`) —
  Mailpit is wired up only for local development.
