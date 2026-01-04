#!/usr/bin/env python3
# Built in Python 3.13
# https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC
__author__ = "Kemp Langhorne"
__copyright__ = "Copyright (C) 2026 AskKemp.com"
__license__ = "gpl-3.0"
import gzip
import tempfile
from pathlib import Path
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from warcio.archiveiterator import ArchiveIterator
import yara_x
import json
import logging
import tqdm
import os
from concurrent.futures import ProcessPoolExecutor, as_completed

#
# CONFIGURE ME
#
BUCKET = "commoncrawl"
WARC_PATHS_KEY = "crawl-data/CC-MAIN-2025-51/warc.paths.gz" # See https://commoncrawl.org/the-data/get-started/ for list of available WARC paths files
YARA_RULES_FILENAME = Path("rules.yara")
OUTPUT_RESULTS_FILENAME = Path("yara_matches.json")
WARC_STATE_TRACKER = Path("processed_warc_files.txt") # to track already processed WARC files
total_cpus = os.cpu_count() or 1
CPU_COUNT_TO_USE = total_cpus if total_cpus == 1 else max(1, int(total_cpus * 0.8)) # only use 80% of CPU cores to leave some overhead

# logging setup
logging.basicConfig(level=logging.INFO)

logging.info(f"Will use {CPU_COUNT_TO_USE} CPU cores for processing")

# Validate YARA rules file exists
if not YARA_RULES_FILENAME.exists():
    logging.critical(f"YARA rules file not found: {YARA_RULES_FILENAME}\n\
    the file contains the signatures and must exist. Exiting!")
    exit(1)

# Validate access to bucket
# Also provides client to download warc.paths.gz
s3 = boto3.client(
        "s3",
        region_name="us-east-1" # Common Crawl sits on US-East-1 (Northern Virginia) AWS Region. See https://commoncrawl.org/get-started
    )
try:
    s3.head_object(Bucket=BUCKET, Key=WARC_PATHS_KEY)
except NoCredentialsError:
    logging.critical("S3 Common Crawl bucket access validation failed.\n\
    --> Access to data from the Amazon cloud using the S3 API will be restricted to authenticated AWS users.\n\
    --> See https://commoncrawl.org/blog/introducing-cloudfront-access-to-common-crawl-data\n\
    --> IAM role on EC2 must allow S3 read access to commoncrawl bucket\n\
    Exiting.\n")
    exit(1)

# Create list of already processed WARC files to skip them
logging.info(f"Processed WARC files tracked in file: {WARC_STATE_TRACKER}")
if not WARC_STATE_TRACKER.exists():
    WARC_STATE_TRACKER.parent.mkdir(parents=True, exist_ok=True)
    WARC_STATE_TRACKER.touch()
warc_processed_files = set()
with WARC_STATE_TRACKER.open('r', encoding='utf-8') as f:
    processed_keys = {line.strip() for line in f if line.strip()}
    warc_processed_files.update(processed_keys)
    logging.info(f"Number of already processed WARC files to skip: {len(warc_processed_files)}")

def download_file(s3, bucket: str, key: str, dest_path: Path):
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    logging.debug(f"Downloading s3://{bucket}/{key} -> {dest_path}")
    try:
        s3.download_file(bucket, key, str(dest_path))
    except ClientError as e:
        raise RuntimeError(f"Failed to download s3://{bucket}/{key}: {e}")

def parse_warc_paths_gz(warc_paths_gz: Path):
    """ Generator to give a filename per line from warc.paths.gz """
    with gzip.open(warc_paths_gz, mode="rt", encoding="utf-8") as fh:
        for line in fh:
            path = line.strip()
            if not path:
                logging.critical("ERROR: Something really wrong with warc.paths.gz")
                exit(1)
            yield path

def process_warc_key(key: str, bucket: str, out_dir: Path)  -> tuple[str, list[dict]]:
    '''
    Download and scan a single WARC from Common Crawl.

    The WARC referenced by the S3 `key` is downloaded into `out_dir`,
    each response record is scanned with YARA-X, match details are collected,
    and the temporary file is deleted before returning results.

    Args:
        key (str | Path): S3 object key for the WARC file.
        bucket (str): S3 bucket name (typically 'commoncrawl').
        out_dir (Path): Local temporary directory root used for downloads.

    Returns:
        tuple[str, list[dict]]: (finished_key, match_items) where:
            - finished_key: the S3 key that was processed
            - match_items: dict with WARC and YARA-X match metadata
    '''

    # Create local S3 client per process (separate connection for concurrency)
    s3_local = boto3.client(
        "s3",
        region_name="us-east-1"
    )

    # Yara-x setup per process
    # I believe this is needed to allow concurrency to function correctly
    compiler = yara_x.Compiler()
    compiler.add_source(f'include "{YARA_RULES_FILENAME}"') # Loads all rules from this single file
    rules = compiler.build()
    yara_scanner = yara_x.Scanner(rules)
    yara_scanner.set_timeout(60)
    yara_scanner.max_matches_per_pattern(1000)

    # Temp directory creation
    dest_path = out_dir / key
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    # Download WARC to temp directory
    s3_local.download_file(bucket, key, str(dest_path))
    
    # Collect results in-memory (which may be a bad idea if in EC2 node with limited RAM)
    results: list[dict] = []

    # Open one warc file at a time and scan it with yara
    try:
        logging.debug(f"Scanning file: {dest_path.name}")
        with open(dest_path, 'rb') as stream:
            it = ArchiveIterator(stream, check_digests=True)
            for record in it:
                rec_offset = it.offset # Get the byte offset of the current record which is needed to quickly extract it later
                #record_type = record.rec_type
                warc_headers = record.rec_headers
                record_id = warc_headers.get_header('WARC-Record-ID')
                target_uri = warc_headers.get_header('WARC-Target-URI')
                content_type = warc_headers.get_header('Content-Type')
                #date = warc_headers.get_header('WARC-Date')

                # Read the payload of the warc record
                # https://github.com/webrecorder/warcio/blob/6775fb9ea3505db144a145c5a8b3ba1dfb822ac1/warcio/extractor.py#L27
                # From https://github.com/webrecorder/warcio/blob/master/README.rst: 
                # A special ArcWarcRecord.content_stream() function provides a stream that automatically decompresses and de-chunks the HTTP payload, if it is compressed and/or transfer-encoding chunked.
                content = record.content_stream().read() 
                if record.rec_type == 'response': # response: HTTP response received from server
                    
                    # Scan warc record content with YARA-X rules
                    result = yara_scanner.scan(content)  # ScanResults object
                    
                    # Details for each matching rule
                    for rule in result.matching_rules:
                        temp_dict = {}
                        temp_dict['warc_file_name'] = dest_path.name
                        temp_dict['warc_file_path'] = str(key)
                        temp_dict['warc_record_offset'] = rec_offset
                        temp_dict['warc_record_target_uri'] = target_uri
                        temp_dict['warc_record_id'] = record_id
                        temp_dict['warc_record_content_type'] = content_type

                        temp_dict['yara_rule_identifier'] = rule.identifier
                        #temp_dict['yara_rule_namespace'] = rule.namespace
                        #temp_dict['yara_rule_tags'] = list(rule.tags)
                        temp_dict['yara_rule_metadata'] = dict(rule.metadata)

                        # Specific YARA pattern matches
                        for pattern in rule.patterns: # Matching Patterns
                            match_count = len(list(pattern.matches))
                            if match_count == 0: # No matches for this pattern
                                continue
                            matched_content_set = set()
                            matched_content_superset_set = set()
                            for i, match in enumerate(pattern.matches): # Details for each match of this pattern

                                # Extract and show the matched content to help future analysis
                                matched_content = content[match.offset:match.offset + match.length] # exactly what matched

                                # To make future analysis even easier, show some context around the match
                                start = max(0, match.offset - 20)
                                end = min(len(content), match.offset + match.length + 20)
                                matched_content_superset = content[start:end]

                                if len(matched_content) > 100:
                                    matched_preview = matched_content[:100] + b"(truncated at 100 bytes)"
                                else:
                                    matched_preview = matched_content
                                    
                                try:
                                    matched_text = matched_preview.decode('utf-8', errors='replace')
                                    matched_content_set.add(matched_text)
                                except:
                                    matched_content_set.add(matched_preview) # bytes

                                if len(matched_content_superset) > 100:
                                    matched_preview = matched_content_superset[:100] + b"(truncated at 100 bytes)"
                                else:
                                    matched_preview = matched_content_superset
                                    
                                try:
                                    matched_text = matched_preview.decode('utf-8', errors='replace')
                                    matched_content_superset_set.add(matched_text)
                                except:
                                    matched_content_superset_set.add(matched_preview) # bytes
                        
                            temp_dict['yara_rule_matching_content'] = list(matched_content_set)
                            temp_dict['yara_rule_matching_content_superset'] = list(matched_content_superset_set)

                        logging.debug(temp_dict) # to watch it real-time
                        results.append(temp_dict)

    except Exception as e:
        logging.critical(f"Error processing {key}: {e}")
    finally:
        # Delete
        dest_path.unlink()
    
    return (key, results)

def main():

    # Yara-x setup
    logging.info(f"Loaded YARA-X rules from: {YARA_RULES_FILENAME}")

    # output stdout statement
    logging.info(f"Scan output results filename: {OUTPUT_RESULTS_FILENAME}")
    if OUTPUT_RESULTS_FILENAME.exists():
        logging.warning(f"Scan output results file already exists and will be appended to.")

    # Prepare temp file directory
    tmp_root = Path(tempfile.mkdtemp(dir=Path.cwd(), prefix="cc_tmp_")) # /tmp does NOT have enough space on AWS EC2 so need to save under current working directory which is hopefully mounted at / 
    out_dir = tmp_root / "commoncrawl" # e.g. /tmp/commoncrawl
    logging.info(f"Using temporary directory: {tmp_root}")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Download warc.paths.gz to temp directory
    warc_paths_gz_local = out_dir / "warc.paths.gz"
    logging.debug(f"Downloading s3://{BUCKET}/{WARC_PATHS_KEY} -> {warc_paths_gz_local}")
    download_file(s3, BUCKET, WARC_PATHS_KEY, warc_paths_gz_local)

    # Get total number of items within warc.paths.gz for progress tracking
    with gzip.open(warc_paths_gz_local, mode="rt", encoding="utf-8") as f:
        total_warc_files = sum(1 for _ in f)
    logging.info(f"Total WARC files available: {total_warc_files}")

    # Build list of keys to process, skipping already processed
    keys_to_process = []
    for key in parse_warc_paths_gz(warc_paths_gz_local):
        if key in warc_processed_files:
            continue
        keys_to_process.append(key)
    logging.info(f"WARC files needing processing: {len(keys_to_process)}")

    # Iterate and download each WARC to temp directory based on contents of warc.paths.gz (multiprocess)
    warc_pbar = tqdm.tqdm(total=total_warc_files, initial=len(warc_processed_files)) # on screen progress bar
    warc_pbar.set_description("Processed WARC Files")

    # Process in parallel
    # Good luck!
    max_workers = CPU_COUNT_TO_USE
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_warc_key, key, BUCKET, out_dir) for key in keys_to_process]
        for fut in as_completed(futures):
            try:
                finished_key, results = fut.result()

                # Write worker results to json
                # Concern that leaving all Yara-x results in memory in the EC2 node may exhaust RAM
                # Hopefully this method works well
                with OUTPUT_RESULTS_FILENAME.open('a', encoding='utf-8') as out_f: # notice append mode
                    for item in results:
                        out_f.write(json.dumps(item, ensure_ascii=False) + "\n")

                # Track processed WARC file by adding completed filename to tracker file
                with WARC_STATE_TRACKER.open('a', encoding='utf-8') as tracker:
                    tracker.write(f"{finished_key}\n")

                # Add one to the progress bar
                warc_pbar.update(1)

            except Exception as e:
                logging.critical(f"Worker failed: {e}")
                exit(1)             

    logging.info(f"Finished!")

if __name__ == "__main__":
    main()
