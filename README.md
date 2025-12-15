# Scan the Internet with YARA!

# Introduction
A single Python 3.11+ script to scan the records within [Web ARChive (WARC)](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1-annotated/ "Web ARChive (WARC)") format files with [YARA-X](https://github.com/VirusTotal/yara-x "YARA-X").

The idea is to use YARA-X to scan a large repository of WARC files. For example, the monthly crawl of ~2.3 billion pages from the [Common Crawl](https://commoncrawl.org/get-started "Common Crawl") project.

The WARC format is the raw data from a web crawl and contains HTTP headers and body (payload). In addition, the WARC stores metadata about the crawl itself. The Appendix of this README contains an example of a single WARC record. 

This script extracts the HTTP payload for each individual WARC record and scans it with the profile YARA-X rules. It script returns the which record matched, the content of the match itself, a superset of the match itself (to allow more easily to anlayze the result), and the offset of the record within the WARC file (to allow for quick extraction of the full record). 

# Example Use
Clone this repo and install the needed libraries
``` bash
git clone https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC.git
cd YARA-X-Scan-Web-ARChive-WARC/
pip install -r requirements.txt
```

Run the script against the included sample WARC using the included sample YARA-X rules
```bash
python3 ./yara_scan_warc.py --warc-directory example/ --output matches.json --rules ./example/rules.yara
```

The output is saved to `matches.json`. For example:

```json
{"warc_file_name": "askkemp.com.warc.gz",
"warc_file_path": "example/askkemp.com.warc.gz",
"warc_record_offset": 287,
"warc_record_target_uri": "https://askkemp.com/",
"warc_record_id": "<urn:uuid:7121073b-2242-518b-b601-52f70490b3fc>",
"warc_record_content_type": "application/http; msgtype=response",
"yara_rule_identifier": "example_askkemp_1",
"yara_rule_namespace": "default", "yara_rule_tags": [],
"yara_rule_metadata": {"description": "Example - Find specific names on a page"},
"yara_rule_matching_content": ["Lisa Thompson"],
"yara_rule_matching_content_superset": ["op&w=688&q=80\" alt=\"Lisa Thompson\">\r\n                ", "dium text-gray-900\">Lisa Thompson</p>\r\n              "]}
```
Extract the full payload from the WARC by using the `warc_file_path` and `warc_record_offset` from the `matches.json` file. This uses the warcio library which got installed earlier with `pip install -r requirements.txt`.
```bash
warcio extract --payload example/askkemp.com.warc.gz 287
```

# Prerequisites
To use this repository, you'll need WARC files and YARA-X signatures. 

## Get WARC Files
Option 1: Install the Webrecorder Chrome extension which allows for creation of WARC files as your browse the internet. Go to a site like urlscan.io and visit suspicious and malicious websites. Export the WARCs from Webrecorder and scan them with this script.

Option 2: The [Common Crawl](https://commoncrawl.org/get-started "Common Crawl") project stores the crawl data using the Web ARChive (WARC) Format. This is a MASSIVE monthly ~80TB dataset. Use a tool like their [cc-downloader](https://github.com/commoncrawl/cc-downloader "cc-downloader") to get the files locally. For example:

```bash
cc-downloader download-paths CC-MAIN-2025-47  warc /data/commoncrawl/
cc-downloader download -t 1 /data/commoncrawl/warc.paths.gz /data/commoncrawl/
```

## YARA-X Rules
Option 1: The best option is to build your own rules based on what you are looking for.

Option 2: Below is a link to public YARA rules that can get you started with using this script. These YARA rules WILL need to be validated if they work on YARA-X. Also note that many of these rules are meant to be scanned against files on the webserver and NOT the page being compiled/rendered and served which is how the WARC sees it. i.e., there will be lots (if not 100%) of false positives.

* 100s of webshell rules at https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/examples/yara.rules

# Built with
* Python 3.12

# Appendix
For example, the below is a simple example of a record within a WARC:

``` text
WARC/1.1
WARC-Record-ID: <urn:uuid:7121073b-2242-518b-b601-52f70490b3fc>
WARC-Page-ID: fznravko0qoxj03y1vay4l
WARC-JSON-Metadata: {"cert":{"issuer":"WE1","ctc":"1"},"pixelRatio":1.5,"storage":"{\"local\":[],\"session\":[]}"}
WARC-Target-URI: https://askkemp.com/
WARC-Date: 2025-12-15T10:08:57.012Z
WARC-Type: response
Content-Type: application/http; msgtype=response
WARC-Payload-Digest: sha256:9769c817828f0580984b3fd3a626153ab57138fae85a0dee1b81d656e0f6bbb9
WARC-Block-Digest: sha256:ac2be71a883b4fdf2362e1ae5750768d63c44b89ded9336dbe4e7291b13de0c1
Content-Length: 15535

HTTP/1.1 200 OK
access-control-allow-origin: *
alt-svc: h3=":443"; ma=86400
cache-control: public, max-age=0, must-revalidate
cf-cache-status: DYNAMIC
cf-ray: 9ae524843c4a1ad7-FRA
content-type: text/html; charset=utf-8
date: Mon, 15 Dec 2025 10:08:57 GMT
nel: {"report_to":"cf-nel","success_fraction":0.0,"max_age":604800}
priority: u=0,i
referrer-policy: strict-origin-when-cross-origin
report-to: {"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/"}]}
server: cloudflare
server-timing: cfExtPri
vary: accept-encoding
x-content-type-options: nosniff
x-orig-content-encoding: br

<!DOCTYPE html>
<html lang="en">
<head>
...
```