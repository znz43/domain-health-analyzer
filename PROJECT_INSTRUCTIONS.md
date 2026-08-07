# Spamhaus Domain Analyzer - Project Status

## Goal

Build a Domain Health Analyzer based on Spamhaus Intelligence API.

Main idea:
- collect Spamhaus domain data;
- store snapshots;
- compare current snapshot with previous snapshot;
- explain score changes by dimensions and contexts.

---

# Current architecture
spamhaus-domain-analyzer/

app/

├── api/
│ └── spamhaus_client.py

├── collectors/

├── analyzers/

├── scoring/

├── history/
│ ├── snapshot.py
│ ├── loader.py
│ └── comparator.py

├── models/
│ ├── domain_report.py
│ └── domain_snapshot.py

├── utils/
│ ├── config.py
│ ├── logger.py
│ └── time.py

└── test_spamhaus.py


---

# Implemented

## Spamhaus API Client

File:


app/api/spamhaus_client.py


Implemented:

- authentication
- API requests
- domain dimensions
- domain contexts
- domain object


Available methods:

```python
login()

get()

get_domain()

get_domain_dimensions()

get_domain_contexts()

get_domain_report()
Spamhaus Dimensions

Spamhaus dimensions collected:

{
    "smtp": 0,
    "identity": 5,
    "infra": 15,
    "malware": -5,
    "human": 25
}

Meaning:

SMTP

Based on:

global email metadata
sending behavior
email traffic signals
Identity

Based on:

email authentication
encryption configuration
Infrastructure

Based on:

nameservers
hosting infrastructure
domain host
DROP/EDROP impact
Malware

Based on:

malware associations
malicious URLs
botnet infrastructure
abuse.ch intelligence
Human

Based on:

manual research
TTP investigations
Current Domain Test

Example:

optitidepages.org

Received dimensions:

{
    "smtp": 0,
    "identity": 5,
    "infra": 15,
    "malware": -5,
    "human": 25
}
Contexts

Spamhaus endpoint:

/api/intel/v2/byobject/domain/{domain}/contexts

Example response:

[
    {
        "context": "mailsample",
        "last-seen": 1785289301
    },
    {
        "context": "envelope-sender",
        "last-seen": 1784783886
    },
    {
        "context": "tlscert",
        "last-seen": 1783686166
    },
    {
        "context": "zrd",
        "last-seen": 1783685924
    }
]
Context normalization

Unix timestamps are converted before saving snapshots.

Example:

Before:

{
    "last-seen": 1785289301
}

After:

{
    "last_seen": "2026-07-29T..."
}

Utility:

app/utils/time.py

Function:

unix_to_iso()
Snapshot system

Snapshots are stored:

data/reports/

Format:

domain_YYYYMMDD_HHMMSS.json

Example:

optitidepages.org_20260729_144158.json

Purpose:

keep domain history;
compare changes over time.
Comparator

Already exists:

app/history/comparator.py

Current functionality:

Compare dimension scores:

Example:

{
    "smtp": {
        "previous": 0,
        "current": -5,
        "delta": -5
    }
}
Current context mapping (not finalized)

Working hypothesis only:

{
    "mailsample": "smtp",
    "envelope-sender": "smtp",

    "tlscert": "identity",

    "zrd": "infrastructure"
}

Do NOT treat as final until more Spamhaus examples are collected.

Next steps
1. Finish snapshot model

Add:

contexts
normalized timestamps
2. Collect more Spamhaus contexts

Test different domains.

3. Create context -> dimension mapping

Only after analyzing real API responses.

4. Add explanations

Example:

Identity score decreased:

Reason:
- new tlscert context detected
- TLS configuration changed
Important project rule

Do not invent scoring logic.

Source of truth:

Spamhaus Intelligence API documentation:

https://docs.spamhaus.com/sia/docs/source/10-API-Interface/310-Domains.html

First collect real signals.
Then build scoring explanations.

# Current Project State (2026-07-29)

## Completed

### Architecture

```
Spamhaus API
      │
      ▼
SpamhausClient
      │
      ▼
Normalizers
      │
      ▼
Collectors
      │
      ▼
DomainReport
      │
      ▼
History
      │
      ▼
Analyzer / Reporter
```

---

### Normalizers

Implemented:

```
app/
└── normalizers/
    ├── contexts.py
    ├── dimensions.py
    └── domain.py
```

Purpose:

- isolate Spamhaus API format;
- convert API responses into internal project model;
- all other modules work only with normalized data.

---

### DomainReport

Current snapshot structure:

```json
{
    "snapshot_id": "...",
    "timestamp": "...",

    "domain": "...",

    "smtp": {
        "score": -4
    },

    "identity": {
        "score": null
    },

    "infrastructure": {
        "score": -2.25
    },

    "malware": {
        "score": null
    },

    "human": {
        "score": -10
    },

    "overall_score": -16.25,

    "contexts": [
        {
            "context": "mailsample",
            "last_seen": "2026-07-29T01:41:41"
        }
    ]
}
```

---

### Infrastructure collector

Current collector returns project model only.

```python
{
    "nameservers": [],
    "a_records": [],
    "mx_records": [],
    "spf": None,
    "dkim": None,
    "dmarc": None
}
```

DNS implementation will be added later.

---

### Snapshot system

Snapshots are stored in:

```
data/reports/
```

Format:

```
domain_YYYYMMDD_HHMMSS.json
```

---

### Console Reporter

Next milestone:

```
app/
└── reporters/
    └── console.py
```

Target output:

```
Current Domain Test

Domain:
Total Score:

Dimensions

Contexts

Infrastructure

Snapshot saved.
```

---

## Important design rule

Everything outside `SpamhausClient` must use the project's internal model.

No module except `SpamhausClient` should depend directly on the raw Spamhaus API response.