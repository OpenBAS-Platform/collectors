# OpenAEV Splunk ES Collector

A collector module for fetching detection alerts from **Splunk Enterprise Security (ES)** and reconciling them against OpenAEV expectations.

**Note**: This collector assumes access to a working Splunk ES instance with alert-generating content, and requires the OpenAEV platform to be already configured. Expectation results are updated based on matching alert activity.

---

## Installation

Grab the repo and enter the collector directory:

```bash
git clone https://github.com/OpenBAS-Platform/collectors
cd ./collectors/splunk_es
```

Install dependencies via Poetry:

**Production**:

```bash
poetry install --extras prod
```

**Development** (also clone [pyoaev](OpenBAS-Platform/client-python) as instructed [here](../README.md#simultaneous-development-on-pyobas-and-a-collector)):

```bash
poetry install --extras dev
```

---

## Usage

Run the collector manually:

```bash'
poetry run python -m splunk_es.openaev_splunk_es
```

---

## Configuration

Configure via YAML or environment variables. Here’s what you’re wiring up:

| Config Parameter      | Docker env var        | Default     | Required | Description                                                |
|-----------------------|-----------------------|-------------|----------|------------------------------------------------------------|
| `openbas.url`         | `OPENBAS_URL`         |             | Yes      | URL of the OpenAEV backend                                 |
| `openbas.token`       | `OPENBAS_TOKEN`       |             | Yes      | OpenAEV authentication token                               |
| `collector.id`        | `COLLECTOR_ID`        |             | Yes      | Unique identifier for this collector instance              |
| `collector.name`      | `COLLECTOR_NAME`      | `Splunk ES` | No       | Display name for the collector in UI                       |
| `collector.period`    | `COLLECTOR_PERIOD`    | `60`        | No       | Collection run frequency (seconds)                         |
| `collector.log_level` | `COLLECTOR_LOG_LEVEL` | `error`     | No       | Logging level (e.g., debug, info, warning, error)          |
| `splunk.base_url`     | `SPLUNK_BASE_URL`     |             | Yes      | Base URL for the Splunk Management API (usually port 8089) |
| `splunk.username`     | `SPLUNK_USERNAME`     |             | Yes      | Splunk API username                                        |
| `splunk.password`     | `SPLUNK_PASSWORD`     | `           | Yes      | Splunk API password                                        |
| `splunk.index`        | `SPLUNK_INDEX`        |             | No       | Splunk Index if any                                        |


---

## Behavior

This collector syncs with OpenAEV to fetch pending expectations, queries Splunk ES for detection alerts, and updates OpenAEV accordingly. It operates in batched cycles.

### Process Flow (mermaid)

```mermaid
flowchart TD
    A[Collector run on OpenAEV] --> B[Wait for expectations via PyOAEV]
    B --> C[Expectations received]
    C --> D{Loop over expectations}

    D -->|Not useful| E[Expire expectation to skip - BadSignatureType, BadDetectionType]
    D -->|Useful but not executed| F[Ignore until executed]
        F --> D
    D -->|Useful & Executed| G[Add to processing in batch]

    G --> H[Craft global SPL query for batch expectations]
    H --> I[Call Splunk ES API with the SPL]
    I --> J[Iterate over alerts to format them as intended]
    J --> K{Match alert to expectation via PyOAEV]
    K -->|Alert found| L[Update expectation state to 'Detected' ]
    K -->|Alert not found| M[Update expectation state to 'Not Detected' ]

    L --> N{Check if last batch}
        M --> N
    N -->|Not last batch| P[Loop back to next batch]
    P --> D
    N -->|Last Batch| O[Wait for next run]
    O --> A
```

Each expectation goes through a validation → filtering → batching → SPL query → result matching → state update pipeline.
No alert? It’s `Not Detected`. Hit an alert? You got a `Detected`. Simple rules.

---

## Development

Run the test suite:

```bash
cd collectors/splunk_es
poetry run python -m unittest
```

---

## Notes

* Splunk credentials must have read access to the `alerts` index or equivalent.
* Expectation parsing and signature validation is powered by **PyOAEV**.
* Large batches will be split into multiple SPL queries if needed.

---