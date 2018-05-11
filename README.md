Scan files and directories with multiple rules files, without cross-file rule name collision!

Files containing rules can be provided on the command-line, as a list in one or more text
files, as a directory containing (just) rules files, or in a config dir.  Each option
(-d -f -l) can be provided multiple times.

Default output is space-separated RULE NAME, RULE FILE, and MATCH FILE.  Use CSV option
for comma-separated values.

## Installation
```bash
pip install .
```

## Usage
~~~~
usage: yara-multi-rules.py [-h] [-d SIGDIRS] [-f SIGFILES] [-l LISTFILES] [-v]
                           [--csv] [-m] [--quiet] [--init]
                           [--config-dir CONFIGDIR] [--fail-on-warnings]
                           FILE [FILE ...]

positional arguments:
  FILE                  file(s) to scan

optional arguments:
  -h, --help            show this help message and exit
  -d SIGDIRS            Directory containing rules
  -f SIGFILES           rule file (allowed multiple times for list)
  -l LISTFILES          file containing path to rule files, one per line
  -v                    verbose output
  --csv                 output in CSV format
  -m                    only show matches
  --quiet, -q           only display match/none, no informational messages
  --init                Create a blank config (default: ~/.yara/)
  --config-dir CONFIGDIR
                        Use/create configuration in given directory.
  --fail-on-warnings    Error on warnings during rule compilation
~~~~


## Copyright

Copyright (c) 2018, The MITRE Corporation. All rights reserved.

Approved for Public Release; Distribution Unlimited. Case Number 18-0989
