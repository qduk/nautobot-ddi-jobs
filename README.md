# nautobot-ddi-jobs

Instructions for wiring up the **Nautobot DDI Jobs** app against an existing BIND9 DNS
server. By the end you will be able to:

- Generate BIND9 config/zone files from Nautobot data (**BIND9 Configuration Templating** job).
- Push live DNS record changes to BIND9 as you create/edit/delete records in Nautobot
  (**BIND9 Job Hook Receiver**).

---

## How it works (read this first)

There are **two** jobs, and they do different halves of one workflow:

| Job | Purpose | Mechanism |
|---|---|---|
| **BIND9 Configuration Templating** | **Provision zones.** Generates `named.conf`, `named.conf.options`, `named.conf.local`, and one `<zone>.zone` file per zone, as downloadable job artifacts. | Renders Jinja templates from Nautobot data. |
| **BIND9 Job Hook Receiver** | **Keep records live.** On every DNS record create/update/delete in Nautobot, pushes that single change to BIND9. | TSIG-authenticated dynamic update (RFC 2136). |

> **Critical:** the Job Hook Receiver can only modify records in zones BIND **already serves**.
> It cannot create a zone in BIND. A brand-new zone must first be provisioned in BIND's
> config (via the Templating job output, or manually) and BIND reloaded — *then* record
> changes for it will apply. Skipping this gives `REFUSED` errors.

Supported record types (both jobs): **A, AAAA, NS, CNAME, MX, TXT, PTR, SRV**.

---

## Prerequisites

- A running Nautobot 3.x instance.
- The [`nautobot-app-dns-models`](https://github.com/nautobot/nautobot-app-dns-models) app
  installed and enabled (provides the DNS Zone / record models).
- This repository, reachable as a Git repository Nautobot can sync.
- An existing BIND9 server meeting the requirements below.
- (Optional, for verification) the `dig` / `nsupdate` CLI tools.

### What your BIND9 server must provide

The Job Hook Receiver authenticates with a TSIG key and sends RFC 2136 dynamic updates, so
your BIND9 server must already have:

- A **TSIG key** (e.g. `hmac-sha256`). Note its **key name** and **secret** — you will put
  the same values into a Nautobot SecretsGroup.
- Each managed zone defined as `type master` with that key allowed to update it:
  ```
  zone "example.com" {
      type master;
      file "/etc/bind/zones/example.com.zone";
      allow-update { key "your-key-name"; };
  };
  ```
- The zone file directory writable by the `named` process (so journals can be written).
- The DNS service reachable from the Nautobot **worker** over TCP (default port 53).

---

## Step 1 — Load the jobs into Nautobot (Git repository)

The jobs are loaded as a **Git repository** providing the `extras.job` content type. The
`jobs/` package must sit at the repository root, and both the repo-root `__init__.py` and
`jobs/__init__.py` must be present (they make the package importable; `jobs/__init__.py`
registers the jobs with a **relative** import).

1. In Nautobot: **Extensibility → Git Repositories → Add**.
2. Set the remote URL / branch for this repository and, under **Provides**, check
   **Jobs**.
3. **Sync** the repository.
4. Confirm under **Jobs** you see, in the *Nautobot DDI Jobs* group:
   - **BIND9 Configuration Templating**
   - **BIND9 Job Hook Receiver** (hidden by default; visible via the API / job hook config)

---

## Step 2 — Create the BIND9 ExternalIntegration + secrets

The Job Hook Receiver reads the server address and TSIG key from a Nautobot
**ExternalIntegration** named `BIND9`.

### 2a. SecretsGroup

1. **Secrets → Secrets**: create two secrets holding your BIND9 TSIG **key name** and **key
   secret** (e.g. environment-variable or text-file backed).
2. **Secrets → Secret Groups**: create a group and attach:
   - Access type **Generic**, secret type **Username** → the **key name**
   - Access type **Generic**, secret type **Token** → the **key secret**

### 2b. ExternalIntegration

**Extensibility → External Integrations → Add**:

| Field | Value |
|---|---|
| Name | `BIND9` |
| Remote URL | `http://<your-bind9-host>:53` |
| Secrets Group | the group from 2a |

Notes on **Remote URL**:
- Only the **host** and **port** are used (the scheme is ignored by the job). Use `http://`
  because Nautobot's URL field rejects `dns://`.
- The host must be reachable from the Nautobot **worker** container/host. If Nautobot runs
  in Docker and BIND runs on the Docker host, use `host.docker.internal` rather than
  `127.0.0.1`.
- If no port is given, the job defaults to `53`.

> Override the integration name with the `BIND9_EXTERNAL_INTEGRATION` environment variable
> if you don't want to name it `BIND9`.

---

## Step 3 — Configure the Job Hook

This connects DNS record changes to the receiver.

1. **Extensibility → Job Hooks → Add**.
2. **Job**: *BIND9 Job Hook Receiver*.
3. **Content types**: add all record types you want synced — A, AAAA, NS, CNAME, MX, TXT,
   PTR, SRV records.
4. **Actions**: enable **Create**, **Update**, and **Delete**.
   - If **Delete** is unchecked, removing a record in Nautobot will **not** remove it from
     BIND.
5. Enable the hook.

---

## Step 4 — Create zones and records

Create your DNS zones and records in the Nautobot UI under **Apps → Nautobot DNS Models**
(create the DNS Zone first, then add records under it). As you create, edit, or delete
records, the Job Hook fires and pushes each change to BIND9.

> **Order matters for new zones.** Create the zone in Nautobot, make sure BIND is master
> for it (Step 5), *then* add records. Records pushed to a zone BIND doesn't serve
> return `REFUSED`.

---

## Step 5 — Generate config with the Templating job (for new zones)

When you add a brand-new zone, regenerate BIND's config so it becomes master for it:

1. Run **Jobs → BIND9 Configuration Templating**. Select specific zones or check
   *all zones*. Leave **Profile job execution** unchecked (it adds an unrelated `.pstats`
   profiling file to the job result).
2. Download the generated files from the Job Result page: `named.conf`,
   `named.conf.options`, `named.conf.local`, and one `<zone>.zone` per zone.
3. Deploy them to your BIND server's `/etc/bind/` and reload BIND (`rndc reload`). BIND is
   now master for the new zone(s).
4. From then on, record changes for those zones flow automatically via the Job Hook.

---

## Step 6 — Verify

Substitute your BIND9 host, port, and zone names:

```bash
# whole zone (forward)
dig @<your-bind9-host> <zone> AXFR +noall +answer

# a single forward record
dig @<your-bind9-host> <name>.<zone> A +short

# a single reverse record
dig @<your-bind9-host> -x <ip-address> +short
```

The **SOA serial** increments on every applied change — a quick way to confirm an update
landed. Diff an `AXFR` before/after a change to see exactly what the hook did.

---

## Reference

- Jobs: [`jobs/ddi.py`](jobs/ddi.py)
- Templates: [`jobs/bind9_templates/`](jobs/bind9_templates/)
- Helper scripts: [`populate_dns.py`](populate_dns.py), [`delete_dns.py`](delete_dns.py)
