# Threat feeds

Every `.txt` and `.csv` file here is loaded at start-up.

* `*.txt` - one IP, CIDR range or domain per line; `#` starts a comment.
  The file name is used as the reason shown in alerts.
* `*.csv` - columns `indicator,description`.

A listed domain also matches its subdomains. `sample_blocklist.csv` only
contains documentation addresses (RFC 5737) and reserved `.test` domains
used by the lab simulator - replace it with feeds you trust, for example
abuse.ch Feodo Tracker / URLhaus exports or your MISP instance.
