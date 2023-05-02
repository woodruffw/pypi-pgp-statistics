# pypi-pgp-statistics

**NOTE**: The data in this repository comes from [PyPI's BigQuery dataset],
and was generated on 2023-03-26. See
[Updating the files](#updating-the-files) for steps for rebuilding
it.

[PyPI's BigQuery dataset]: https://warehouse.pypa.io/api-reference/bigquery-datasets.html

## Updating the files

**NOTE**: These steps are provided on a best-effort basis. They may
become outdated or broken over time.

### Setup

Create a virtual environment with the dependencies needed:

```
python -m venv --upgrade-deps env
./env/bin/python -m pip install -r requirements.txt
```

### `inputs/dists-with-signatures.csv`

Run the following BigQuery query (tweak the timestamp,
if you'd like):

```sql
SELECT name, version, filename, python_version
FROM `bigquery-public-data.pypi.distribution_metadata`
WHERE has_signature
AND upload_time > TIMESTAMP("2020-03-27 00:00:00")
```

### `outputs/dists-by-keyid.json`

```bash
./env/bin/python dists-by-keyid.py \
    < inputs/dists-with-signatures.csv \
    > outputs/dists-by-keyid.json
```

### `outputs/all-dist-keys.jsonl`

```bash
./env/bin/python all-dist-keys.py \
    <(some jq magic here)
    > outputs/all-dist-keys.jsonl
```

### `outputs/key-audit.jsonl`

```bash
./env/bin/python key-audit.py \
    < outputs/all-dist-keys.jsonl
    > outputs/key-audit.jsonl
```
