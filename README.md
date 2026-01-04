# Scan the Internet with YARA!

# Introduction
Use Python to scan the records within [Web ARChive (WARC)](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1-annotated/ "Web ARChive (WARC)") format files with [YARA-X](https://github.com/VirusTotal/yara-x "YARA-X").

The idea is to use YARA-X to scan a large repository of WARC files. For example, the monthly crawl of ~2.3 billion pages from the [Common Crawl](https://commoncrawl.org/get-started "Common Crawl") project.

The WARC format is the raw data from a web crawl and contains HTTP headers and body (payload). In addition, the WARC stores metadata about the crawl itself. The Appendix of this README contains an example of a single WARC record. 

This Python script extracts the HTTP payload for each individual WARC record and scans it with the YARA-X rules. Matches are returned with details of which WARC record matched, the content of the match itself, a superset of the match itself (to allow more easily to anlayze the result), and the offset of the record within the WARC file (to allow for quick extraction of the full record). 

Each of the below scripts are independent and have different usage scenerarios:

* [yara_scan_warc.py](example_scenarios/simple_demonstration/yara_scan_warc.py) - Scan a local directory of WARC files with YARA-X. See [Simple Usage](https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC/tree/main?tab=readme-ov-file#scenario-1-generate-warc-with-webrecorder-chrome-extension).
* [mass_web_crawl_warc.py](example_scenarios/scenario_2_wario_capture_http_library/mass_web_crawl_warc.py) - Demonstration of how to self-scan the internet to create your own WARC files. See [Scenario 3](https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC/tree/main?tab=readme-ov-file#scenario-3-download-locally-warcs-from-common-crawl-recommended-only-for-testing).
* [mass_scan_commoncrawl_ec2.py](example_scenarios/scenario_4_AWS_mass_scan/mass_scan_commoncrawl_ec2.py) - Scan the entire Common Crawl ~88TB archive with YARA-X. Multiprocess and tested with 128vCPUs. See [Scenario 4](https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC/tree/main?tab=readme-ov-file#scenerio-4-use-aws-to-mass-scan-warcs-from-common-crawl-recommended).
* [download_WARC_matches.py](example_scenarios/scenario_4_AWS_mass_scan/download_WARC_matches.py) - Given the output from `mass_scan_commoncrawl_ec2.py`, will download the appropriate record from the WARC and save it to disk. See [Scenario 4](https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC/tree/main?tab=readme-ov-file#scenerio-4-use-aws-to-mass-scan-warcs-from-common-crawl-recommended).

# Simple Usage
Clone this repo and install the needed libraries.
``` bash
git clone https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC.git
cd YARA-X-Scan-Web-ARChive-WARC/
pip install -r requirements.txt
```
Run the script against the included sample WARC using the included sample YARA-X rules.
```bash
cd example_scenarios/simple_demonstration/
python3 ./yara_scan_warc.py --warc-directory example/ --output matches.json --rules ./rules.yara
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
Extract the full payload from the WARC by using the `warc_file_path` and `warc_record_offset` from the `matches.json` file. This uses the warcio library which was installed earlier with `pip install -r requirements.txt`.
```bash
warcio extract --payload example/askkemp.com.warc.gz 287
```

# Advanced Usage Scenarios 
The prerequisites to use this repository are WARC files and YARA-X signatures. 

## Prerequisite: Create YARA-X Rules
**Option 1**: The best option is to build your own rules based on what you are looking for in the HTTP payload.

**Option 2**: Below is a link to public YARA rules that can get you started with using this script. These YARA rules WILL need to be validated if they are compatible with YARA-X. Also note that many of these rules are meant to be scanned against files on the webserver and NOT the page being compiled/rendered and served which is how the WARC sees it. i.e., there will be lots (if not 100%) of false positives.

* 100s of webshell rules at https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/examples/yara.rules
* 100s of webshell rules at https://raw.githubusercontent.com/Neo23x0/signature-base/50f14d7d1def5ee1032158af658a5c0b82fe50c9/yara/thor-webshells.yar

## Scenario 1: Generate WARC with Webrecorder Chrome Extension

In this scenario, you use a web browser to generate WARC files.
1. Install the Webrecorder Chrome extension which allows for creation of WARC files as your browse the internet.
2. Go to a site like urlscan.io and visit suspicious and malicious websites with your web browser.
2. Export the WARCs from Webrecorder and scan them with the script [yara_scan_warc.py](example_scenarios/simple_demonstration/yara_scan_warc.py) just like shown in the simple demonstration section above

## Scenario 2: Rapidly Generate WARCs with warcio capture_http library
The wario capture_http library is awesome because you can feed it a list of URLs and it will process them all and save them into a single WARC.

1. The script [mass_web_crawl_warc.py](example_scenarios/scenario_2_wario_capture_http_library/mass_web_crawl_warc.py) demonstrates how to crawl several URLs and save their output to `WARC-Example-Crawl.warc.gz`.
2. Scan `WARC-Example-Crawl.warc.gz` with the script yara_scan_warc.py just like shown in the simple demonstration section above

## Scenario 3: Download locally WARCs from Common Crawl (recommended only for testing)
The [Common Crawl](https://commoncrawl.org/get-started "Common Crawl") project stores the crawl data using the Web ARChive (WARC) Format. This is a MASSIVE monthly ~80TB dataset. You will need a lot of storage for this method and you'll need fast access to the storage for the scan to complete in a reasonable amount of time. 

Use [cc-downloader](https://github.com/commoncrawl/cc-downloader "cc-downloader") to get the files locally. For example, download 2 files at a time to local disk:

```bash
cc-downloader download-paths CC-MAIN-2025-47  warc /data/commoncrawl/
cc-downloader download -t 2 /data/commoncrawl/warc.paths.gz /data/commoncrawl/
```

Once you have the files downloaded, scan them with `yara_scan_warc.py`. Note that this script is single threaded so only one WARC is scanned at a time. For MUCH faster WARC processing, see scenerio 4 which uses a different script.

``` bash
git clone https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC.git
cd YARA-X-Scan-Web-ARChive-WARC/
pip install -r requirements.txt
python3 ./yara_scan_warc.py --warc-directory /data/commoncrawl/ --output matches.json --rules ./example/rules.yara
```

## Scenerio 4: Use AWS to Mass Scan WARCs from Common Crawl (recommended)
The [Common Crawl](https://commoncrawl.org/get-started "Common Crawl") project stores the crawl data using the Web ARChive (WARC) Format. Instead of downloading all ~80TB of the files locally, you can use AWS to access the data within the Common Crawl S3 bucket for free ([see the conditions of the AWS Open Data](https://registry.opendata.aws/commoncrawl/)). In other words, the cost to you is running the EC2 node while the access to the CommonCrawl S3 bucket and its transfers are at no cost.

The script [mass_scan_commoncrawl_ec2.py](example_scenarios/scenario_4_AWS_mass_scan/mass_scan_commoncrawl_ec2.py) provides the following features:
* Multi-processing (tested up to 128 vCPUs)
* Uses temporary files. It will download the WARC, process it, and then delete it.
* Keeps track of what files have been already processed. It simply saves it into file `processed_warc_files.txt`. When the script is ran it will resume where it left off.
* A status progress bar
* YARA-X matches are written to disk in file `yara_matches.json` and include:
  * S3 key name of WARC record with match including offset of the record
  * Metadata of the matching YARA-X rule
  * Content of the match and a superset of the match

The script [download_WARC_matches.py](example_scenarios/scenario_4_AWS_mass_scan/download_WARC_matches.py), given the `yara_matches.json` output from `mass_scan_commoncrawl_ec2.py` will:
* Download and extracts to disk the payload from the specific WARC record ID that had a YARA-X match
* Downloads just subset of the Common Crawl WARC (i.e., only a few MB of the original 1GB WARCfile is downloaded and saved)
* Metadata from the HTTP headers from the WARC is put into json which cites the on-disk location of the payload

### AWS EC2 Instance
The best way to scan through all the data is to use an large EC2 located at region `us-east-1` with a lot of cores, a fast network connection, and high IOPs SSD. For example, a c6gn.16xlarge (64vCPU, 128GB RAM, 100 Gigabit network) EC2 node with a 80GB io2 root volume at 60,000 IOPS SSD can scan the entire ~80TB of files in about 28 hours. Or a c6a.32xlarge (128vCPU, 256GB RAM, 50 Gigabit network) EC2 node with a 160GB io2 root volume at 32,000 IOPS SSD can scan the entire ~80TB of files in about 14 hours.

**Important note 1**: To access the CommonCrawl S3 bucket, you must [use an authenticated account](https://commoncrawl.org/blog/introducing-cloudfront-access-to-common-crawl-data) (i.e. not anonymous). There are two ways to do this:
* Option 1: In the Python script, for the Boto3 S3 client, provide aws_access_key_id and aws_secret_access_key
* Option 2: Add an IAM role to the EC2 instance. Create a new IAM role that allows EC2 to call S3 with `AmazonS3ReadOnlyAccess` then apply that role to the EC2 node. 

**Important note 2**: You need at least 1GB of free space for vCPU core because each CommonCrawl download is 1GB in size. For example, you'll have 128GB of temporary files on the EC2 node at a time when running with 128vCPUs (1 Common Crawl WARC per vCPU). Make sure the EBS volume is correctly sized. 

### Install the needed tools on AMI AWS Linux 2023
```bash
sudo dnf --releasever=latest update
sudo dnf -y install python3.13 python3.13-pip htop git
```

### Get this repo and install the requirements
```bash
git clone https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC.git
cd YARA-X-Scan-Web-ARChive-WARC/
sudo pip3.13 install -r requirements.txt
cd example_scenarios/scenario_4_AWS_mass_scan/
```

### Mass scan AWS
The script is configured to download and scan the the Common Crawl CC-MAIN-2025-51. This can be changed by editing the configuration of the script to the crawl you desire.
```bash
[ec2-user@x scenario_4_AWS_mass_scan]$ python3.13 mass_scan_commoncrawl_ec2.py
INFO:root:Will use 102 CPU cores for processing
INFO:botocore.credentials:Found credentials from IAM Role: EC2_readonly_S3
INFO:root:Processed WARC files tracked in file: processed_warc_files.txt
INFO:root:Number of already processed WARC files to skip: 0
INFO:root:Loaded YARA-X rules from: rules.yara
INFO:root:Scan output results filename: yara_matches.json
INFO:root:Using temporary directory: cc_tmp_e4a8u270
INFO:root:Total WARC files available: 100000
INFO:root:WARC files needing processing: 100000
Processed WARC Files:   0%|                                                                          | 127/100000 [00:56<8:14:22,  3.37it/s]
```

Watch the YARA-X scan matches in realtime!
```bash
$ tail -f yara_matches.json | jq .
```

### Download the Payload Matches
Given the `yara_matches.json` output from `mass_scan_commoncrawl_ec2.py`, the script [download_WARC_matches.py](example_scenarios/scenario_4_AWS_mass_scan/download_WARC_matches.py) with download the payload and save it to disk. This script only downloads the WARC record match itself without having to download the entire 1GB WARC.

```bash
[ec2-user@x scenario_4_AWS_mass_scan]$ python3.13download_WARC_matches.py

INFO:botocore.credentials:Found credentials from IAM Role: EC2_readonly_S3
INFO:root:Loaded YARA-X match results from: yara_matches.json
INFO:root:Downloading matched WARC payload to directory: downloads
INFO:root:Outputting downloaded records to: payload_records.json
Extracted WARC Files:   3%|█▉                                       | 88/2909 [00:28<16:51,  2.79it/s]
```

The output file `payload_records.json` contains metadata about the payload including the WARC record ID, HTTP headers, and payload location on disk
```bash
[ec2-user@x scenario_4_AWS_mass_scan]$ payload_records.json | jq -c '[.warc_record_id, .payload_file]'
["<urn:uuid:a0cf36e7-f80b-462e-8fb9-f2a01292a931>","downloads/urn_uuid_a0cf36e7-f80b-462e-8fb9-f2a01292a931.bin"]
["<urn:uuid:f808f41a-d9cf-4e39-a0c2-1387256116e9>","downloads/urn_uuid_f808f41a-d9cf-4e39-a0c2-1387256116e9.bin"]
["<urn:uuid:e897765f-037b-4af2-9c80-eda4786e6010>","downloads/urn_uuid_e897765f-037b-4af2-9c80-eda4786e6010.bin"]
["<urn:uuid:18623f8c-26d5-495b-b57f-89a23d8d9bc6>","downloads/urn_uuid_18623f8c-26d5-495b-b57f-89a23d8d9bc6.bin"]
```

Open the payload from the WARC
```bash
[ec2-user@x scenario_4_AWS_mass_scan]$ cat downloads/urn_uuid_a0cf36e7-f80b-462e-8fb9-f2a01292a931.bin
```

# Built with
* Python 3.13

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
