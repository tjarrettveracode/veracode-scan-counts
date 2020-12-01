# Veracode Scan Counts

Identify applications with one or more static scans in an incomplete state.

## Setup

Clone this repository:

    git clone https://github.com/tjarrettveracode/veracode-scan-counts

Install dependencies:

    cd veracode-scan-counts
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python vcscancounts.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python vcscancounts.py (arguments)

Arguments supported include:

* --appid, -a  (opt): application guid to check for static scans in an incomplete state.
* --all, -l (opt): If set, checks all applications.

## NOTES

1. This script checks all applications and their sandboxes so may take a long time to run.
1. All values are logged to vcscancounts.log.
