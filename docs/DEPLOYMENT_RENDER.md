# Deployment Guide: GitHub → Render

This covers getting this repo onto GitHub and deployed on Render's free tier
as two services (backend API + static frontend). Every command below is
meant to be copy-pasted as-is.

---

## Part 1 — Push to GitHub

```bash
# 1. Unzip this project and cd into it
cd securemailscope

# 2. Initialize git (skip if already a repo)
git init
git branch -M main

# 3. Sanity-check .gitignore is doing its job BEFORE the first commit --
#    this must show NO .env files, NO node_modules/, NO *.db files, and
#    NO backend/uploads/<anything except .gitkeep>. If it does, stop and
#    fix .gitignore before committing -- once secrets/evidence data are in
#    git history, deleting the file later does not remove them from history.
git add -A
git status

# 4. First commit
git commit -m "Initial commit: SecureMailScope"

# 5. Create the GitHub repo (either via the website, or with the gh CLI):
gh repo create securemailscope --private --source=. --remote=origin
# -- OR, if you created the repo on github.com already --
git remote add origin https://github.com/<your-username>/securemailscope.git

# 6. Push
git push -u origin main
```

**Before you push, confirm no secrets are staged:**
```bash
git show --stat HEAD | grep -i "\.env$\|\.db$"
# should print nothing
```

If this is a fork of a repo that ever had a real .env or .db committed in
an earlier commit, `git log --all --full-history -- '*.env'` will show it —
that history needs scrubbing (`git filter-repo` or BFG Repo-Cleaner) before
this is safe to make public, since deleting the file in a new commit does
not remove it from history other people can still `git clone`.

---

## Part 2 — Deploy on Render

You have two options. **Option A (Blueprint) is recommended** — it reads
`render.yaml` at the repo root and creates both services in one step.

### Option A: Blueprint (recommended)

1. Go to [dashboard.render.com](https://dashboard.render.com) → **New** → **Blueprint**.
2. Connect your GitHub account if you haven't, then select the `securemailscope` repo.
3. Render reads `render.yaml` and shows you a preview of two services:
   - `securemailscope-backend` (Docker web service)
   - `securemailscope-frontend` (static site)
4. Click **Apply**. Render builds and deploys both. This takes a few
   minutes — the backend image build (installing `scapy`, `cryptography`,
   etc.) is the slow part.

   The frontend's build automatically points at the backend's URL
   (`VITE_API_BASE_URL` is resolved from the backend service's hostname
   via `render.yaml`'s `fromService`, re-checked on every Blueprint sync)
   — no manual step needed for that direction.
5. **One required manual step** (the other direction doesn't auto-wire:
   Render only shell-expands `${VAR}` inside `buildCommand`/`startCommand`,
   not inside a plain runtime env var's value, so the backend's
   `CORS_ORIGINS` can't reference the frontend's hostname the same way):
   - Open the **frontend** service → note its URL, e.g.
     `https://securemailscope-frontend.onrender.com`
   - Open the **backend** service → **Environment** → set `CORS_ORIGINS`
     to that frontend URL exactly (no trailing slash) → **Save Changes**
     (this triggers a redeploy).
6. Wait for the backend's redeploy to finish, then open the frontend URL.
   You should see the login page.
7. **Get your admin password**: Render dashboard → backend service →
   **Logs** → find the block that starts with `SecureMailScope: bootstrap
   admin account created` — it contains the one-time password for
   `admin@ntro.gov.in`, printed exactly once on first boot. Log in with it;
   you'll be forced to set a new password immediately.

### Option B: Manual (two services by hand)

If you'd rather not use the Blueprint, or want to customize service names:

**Backend:**
1. New → Web Service → connect the repo.
2. Runtime: **Docker**. Root directory: `backend`.
3. Plan: Free.
4. Add environment variables (Environment tab):
   | Key | Value |
   |---|---|
   | `ENVIRONMENT` | `production` |
   | `SECRET_KEY` | click "Generate" |
   | `DATABASE_URL` | `sqlite:///./uploads/securemailscope.db` |
   | `CORS_ORIGINS` | *(fill in after frontend exists — see step 5 above)* |
5. Add a **Disk**: mount path `/app/uploads`, size 1GB (so uploaded
   captures and the SQLite file survive redeploys).
6. Health check path: `/api/health`.
7. Deploy.

**Frontend:**
1. New → Static Site → connect the repo.
2. Root directory: `frontend`.
3. Build command: `npm install && npm run build`
4. Publish directory: `dist`
5. Add a **Redirect/Rewrite rule**: source `/*` → destination
   `/index.html` → type **Rewrite** (required for React Router — without
   this, refreshing any page other than `/` 404s).
6. Environment variable: `VITE_API_BASE_URL` = the backend URL from step
   above, with `/api` appended.
7. Deploy.

Then do the same cross-linking manual step as Option A step 5.

---

## Part 3 — Verifying the deployment actually works

Don't just trust that it deployed — check these three things:

1. **Health check**: `curl https://<your-backend>.onrender.com/api/health`
   → should return `{"status":"healthy"}`.
2. **CORS is actually locked down**, not silently wildcard:
   ```bash
   curl -i -H "Origin: https://evil.example.com" \
     https://<your-backend>.onrender.com/api/auth/login
   ```
   The response should NOT contain
   `access-control-allow-origin: https://evil.example.com` — if it does,
   `CORS_ORIGINS` isn't set correctly on the backend.
3. **Login works end-to-end**: open the frontend URL, log in with the
   bootstrap admin credentials from the backend logs (see step 7 above),
   confirm the dashboard loads. This proves `VITE_API_BASE_URL` is wired
   correctly — if it's wrong, login will hang or 404 in the browser
   console rather than failing loudly, since it usually means requests are
   silently going to the frontend's own origin instead of the backend.

## Common failure modes and what they mean

| Symptom | Cause |
|---|---|
| Backend won't start; log says `FATAL: SECRET_KEY must be set...` | `SECRET_KEY` env var missing/too short in production — this is intentional fail-safe behavior, not a bug. Set it. |
| Backend won't start; log says `FATAL: CORS_ORIGINS must be set...` | Same — set `CORS_ORIGINS` to your frontend's exact URL. |
| Frontend loads, but login spins forever / console shows CORS errors | Almost always `CORS_ORIGINS` on the backend — it's the one link that doesn't auto-wire (see Part 2, step 5). If you're using Option B (manual services) or overrode the Blueprint's build command, also check `VITE_API_BASE_URL`. |
| Refreshing `/cases/<id>` gives a Render 404 page | The `/* → /index.html` rewrite rule is missing on the static site. |
| Uploaded captures/DB disappear after a redeploy | No persistent disk attached to the backend service (SQLite lives on disk that Render's default web-service filesystem does NOT persist across deploys without an explicit Disk). |
| First login attempt says "invalid credentials" | You're probably using a guessed/old password — the real one-time password is only ever in the backend's boot logs (see Part 2, step 7); there's no fixed default. |
