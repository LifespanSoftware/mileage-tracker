# Handover

Where the project stands and what a new session needs to know. Written 24 November 2026, at version 1.2.1.
Read `ai_rules.md` as well: it holds the versioning rule. `README.md` covers how the app works and how to deploy it.

## State of the repository

- Everything is on `main`. There are no open pull requests and no unmerged work on any branch.
- `ccr-0d577575-2bf189` is the working branch Claude sessions have used. After a PR from it is merged it is restarted from `main`.
- `codex/monthly-report-cutoffs` and `codex/s3-report-archive` are old branches, fully merged. They can be deleted.
- `release-v1.0.0` has one commit not on `main` ("Finalize CHANGELOG for v1.0.0"). It only reworded the 1.0.0 changelog entry; nothing is lost by leaving it.
- Tags: only `v1.0.0` exists. `CHANGELOG.md` links 1.1.0, 1.2.0 and 1.2.1 to tags that have not been created, so those links are dead until they are.

## State of the live installation (24 November 2026)

Read through the Claude connector:

- Running 1.2.0. One user, 49 journeys, 9 fuel purchases.
- Backups: daily at 02:00 to S3, keeping 5. The last one (24 November 02:00) succeeded. The history lists two backups.
- "Forgot your password?" is off: `SMTP_HOST` is not set.
- One unresolved error: `Access Denied.` on the server, 23 November 15:01, once. It came from downloading a backup whose file was no longer in S3.
- One change request is waiting for approval in Settings → Claude connector: mark that error as resolved. It was filed by another Claude session. Nothing changes until an administrator approves or rejects it.

## What was done in this run of work

| PR | What |
| --- | --- |
| #6 | Receipt scanning fixed (it never started: bundling bug plus CDN files blocked by the security policy). Multiple vehicles. CSV export. Continuous integration. Two-step sign-in, password reset by email, activity log, rate limits kept in the database. |
| #7 | Journey import from CSV. Version 1.1.0. `ai_rules.md` versioning rule. |
| #8 | Claude connector with web sign-in, error log, changes that need approval, suggestions. "Backups to keep" on the Backups screen. Delete on backup history entries. Version 1.2.0. |
| #9 | "Backups to keep" also applies to the backup history, so entries from an earlier S3 location are cleared. |

## Working on it

**Rules**
- `ai_rules.md`: increase the version once on every day that changes are made, and only once. It lists every place the version appears.
- Add to `CHANGELOG.md` with each change. Update `README.md` when behaviour or settings change, and remove finished items from `ROADMAP.md`.
- The owner asks for a pull request and a merge explicitly. Don't open or merge one unasked.
- Lock files are not committed. `npm install` writes `package-lock.json`; delete it before committing.

**Running the tests**

```bash
cd client && npm install && npm test && npm run build
cd ../server && npm install --omit=optional
TEST_DATABASE_URL=postgresql://USER:PASS@127.0.0.1:5432/postgres npm test
cd ../e2e && TEST_DATABASE_URL=postgresql://USER:PASS@127.0.0.1:5432/postgres node run.mjs
```

- The database user must be allowed to create databases. Each API suite and the browser test get a fresh database and their own server (`server/test/harness.mjs`). `pg_dump` and `pg_restore` must be version 16.
- In a Claude cloud session the container is recycled between visits: reinstall the `node_modules`, start PostgreSQL (`service postgresql start`) and create a superuser for the tests again.
- Playwright is already installed in Claude cloud sessions; `e2e/app.test.mjs` loads it with `createRequire` so that works without `npm install` in `e2e/`. CI installs it itself.
- CI (`.github/workflows/ci.yml`) runs all three on every push and pull request.

**Things that will catch you out**
- **Bundling.** esbuild exposes a CommonJS package loaded with `await import()` only as `default`. That is what broke the receipt scanner. Import named exports statically, or use `.default`.
- **Security policy.** The server's Content-Security-Policy allows nothing from other origins. Anything the app needs at run time has to be copied into the build (see how `client/build.mjs` copies the scanner files).
- **Dialogs.** React passes a nested dialog's `close` event to its parent. `Sheet` in `client/src/ui.jsx` checks the event target for that reason.
- **Sync.** When adding a new kind of synced row, raise `DATA_VERSION` in `client/src/store.js` so devices fetch rows an older copy of the app skipped past. The server keeps a field it is not sent (see `vehicle_id` in the sync upserts) so older copies of the app don't wipe it.
- **Sign-in limit in tests.** Sign-in is limited to 20 attempts per address per 15 minutes, counted in the database. A test suite that signs in more often than that from one address will start failing with 429.
- **Two-step codes in tests.** A code can't be used twice. After turning two-step on with the code for one time step, sign in with the next step's code or a recovery code.
- **Restore.** A restore keeps the backup history, the activity log and "Backups to keep" as they were before it. It disconnects Claude and puts change requests, suggestions and the error log back to the time of the backup.

## Known gaps

Not yet tested against the real thing:
- Receipt scanning with a real phone photo (only a generated receipt image).
- Password reset emails through a real mail provider (only a test mail server).
- Deleting a backup whose S3 bucket or prefix has changed, against real S3.

Worth fixing:
- Downloading or restoring a backup whose file is missing from S3 shows the storage service's raw message (`Access Denied.`) and is logged as a server error. It should be a plain "that backup's file is no longer there".
- `README.md`'s Settings screenshot predates vehicles, two-step sign-in and the connector.
- Admins can only read the error log through the connector. There is no screen for it in the app.

Decisions made, in case they come up again:
- "Forgot your password?" emails the username, so it only works for accounts whose username is an email address.
- Authenticator secrets are stored unencrypted, so they are in every backup. Encrypting them with `JWT_SECRET` would lock everyone out if that secret changed.
- The connector cannot change anything directly. It files requests that an administrator approves in the app.
- Suggestions left through the connector are stored in the app, not written to the repository, because the app has no access to GitHub. A Claude session in the repository with the connector attached reads them with `list_suggestions`, adds them to `ROADMAP.md` and calls `mark_suggestion_added`.

`ROADMAP.md` has the backlog of features not yet built.

## Moving the repository to an organisation

GitHub redirects the old address after a transfer, so clones and links keep working, but these should be updated to the new owner:

- The repository address appears in `README.md` (feature request and issue links), `CHANGELOG.md` (the comparison links at the bottom), `ROADMAP.md` (feature request links) and `client/src/screens/More.jsx` (the GitHub link at the bottom of Settings).
- The deployment (Dokploy) pulls from the repository. Point it at the new address and reconnect its GitHub access for the organisation.
- Claude sessions reach the repository through the Claude GitHub App. Install it on the organisation and allow this repository, or new sessions won't be able to read or push.
- Check that GitHub Actions is enabled for the repository under the organisation's settings, or CI stops running.
- The Claude connector is part of the deployed app and is not affected by the move.
