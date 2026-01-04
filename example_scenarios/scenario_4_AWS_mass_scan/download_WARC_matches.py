#!/usr/bin/env python3
# Built in Python 3.13
# https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC
__author__ = "Kemp Langhorne"
__copyright__ = "Copyright (C) 2026 AskKemp.com"
__license__ = "gpl-3.0"
import gzip
from pathlib import Path
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from warcio.archiveiterator import ArchiveIterator
import json
import logging
import tqdm
import os
import io

#
# CONFIGURE ME
#
BUCKET = "commoncrawl"
WARC_PATHS_KEY = "crawl-data/CC-MAIN-2025-51/warc.paths.gz" # JUST FOR TESTING S3 Boto3 connection
OUTPUT_RESULTS_FILENAME = Path("payload_records.json")
MATCHES_INPUT_NDJSON_FILENAME = Path("yara_matches.json")
DOWNLOADS_DIR = Path("downloads")
S3_CHUNK_LENGTH_BYTES = 20 * 1024 * 1024  # 20 MB and a guess of how big a record to get from S3 as a chunch to ensure we get the requested WARC record

# logging setup
logging.basicConfig(level=logging.INFO)

# S3 client setup plus access validation
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

def write_payload(payload_bytes: bytes, record_id: str) -> Path:
    """Write payload bytes to downloads/<uuid>.bin and return the path."""
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    # write safe record id (strip angle brackets)
    safe_id = record_id.strip().replace("<", "").replace(">", "").replace(":", "_")
    out_path = DOWNLOADS_DIR / f"{safe_id}.bin"
    with open(out_path, "wb") as f:
        f.write(payload_bytes)
    return out_path

def process_matches(yara_match_results_file: Path, output_results_file:Path):
    """
    Process YARA-X NDJSON match results, fetch matched WARC records via ranged S3 GET,
    decompress the corresponding GZIP chunk, extract payloads, and emit a newline-delimited
    JSON (NDJSON) summary for each matched record.

    Args:
            yara_match_results_file (Path): Path to the NDJSON file of YARA-X match results.
                    This file is the output of mass_scan_commoncrawl_ec2.py
            output_results_file (Path): Path to the NDJSON file to write extracted record
                    metadata and payload file locations.
    Returns:
            None
    Writes:
            - NDJSON to output_results_file with one JSON object per successfully extracted record.
            - Payload bytes to a file determined by write_payload(...).
    Notes:
            - S3_CHUNK_LENGTH_BYTES must be large enough to include the full compressed GZIP member
              that contains the desired WARC record to avoid EOFError (gzip decompression error).
    """
    if not yara_match_results_file.exists():
        raise FileNotFoundError(f"Input JSON not found: {yara_match_results_file}")

    # Get total number of items within matches for progress tracking
    with open(yara_match_results_file, mode="rt", encoding="utf-8") as f:
        total_matches = sum(1 for _ in f)

    # Iterate and download each WARC
    warc_pbar = tqdm.tqdm(total=total_matches, initial=0) # on screen progress bar
    warc_pbar.set_description("Extracted WARC Files")    

    with open(output_results_file, "w", encoding="utf-8") as out_f:
        with open(yara_match_results_file, mode="rt", encoding="utf-8") as in_f:
            for line in in_f:
                item = json.loads(line)

                rec_id = item.get("warc_record_id")
                warc_path = item.get("warc_file_path")
                s3_key = warc_path # e.g. crawl-data/CC-MAIN-2025-51/segments/1764871306713.64/warc/CC-MAIN-20251204191828-20251204221828-00007.warc.gz
                start_offset = item.get("warc_record_offset")
                end_offset = start_offset + S3_CHUNK_LENGTH_BYTES - 1
                s3_range = f"bytes={start_offset}-{end_offset}"
                              
                logging.debug(f"S3 GET {BUCKET}/{s3_key} Range {s3_range}")
                try:
                    resp = s3.get_object(Bucket=BUCKET, Key=s3_key, Range=s3_range)
                    chunk_body = resp["Body"].read()
                except ClientError as e:
                    logging.critical(f"S3 get_object failed for {s3_key} with range {s3_range}: {e}")
                    exit(1)

                # Wrap the chunk that came from S3 body as bytes in a file-like for gzip
                gz_stream = io.BytesIO(chunk_body)

                # Decompress the GZIP chunk and iterate WARC records within
                try:
                    with gzip.GzipFile(fileobj=gz_stream, mode="rb") as decompressed:
                        for record in ArchiveIterator(decompressed):
                            gz_rec_id = record.rec_headers.get_header("WARC-Record-ID")

                            if gz_rec_id == rec_id: # does the record from the chunk in the GZ match the record we want from the YARA-X match
                                target_uri = record.rec_headers.get_header("WARC-Target-URI")
                                http_headers = None
                                if getattr(record, "http_headers", None) is not None:
                                    http_headers = record.http_headers
                                payload = record.content_stream().read()
                                payload_path = write_payload(payload, gz_rec_id)
            
                                out_f.write(json.dumps({
                                    "warc_file_path": warc_path,
                                    "warc_record_id": gz_rec_id,
                                    "warc_record_target_uri": target_uri,
                                    "http_headers": http_headers.to_str(),
                                    "payload_file": str(payload_path), # where the payload bytes were written
                                }) + "\n")
                            break
                except EOFError:
                    logging.critical(f"Gzip decompression failed likely because the WARC Record ID is NOT found in the provided chunk from S3. Increase the range size in S3_CHUNK_LENGTH_BYTES and try again.")
                    exit(1)
                except Exception as e:
                    logging.critical(f"Something failed: {e}")
                    exit(1)
                warc_pbar.update(1)


if __name__ == "__main__":
    logging.info(f"Loaded YARA-X match results from: {MATCHES_INPUT_NDJSON_FILENAME.resolve()}")
    logging.info(f"Downloading matched WARC payload to directory: {DOWNLOADS_DIR.resolve()}")
    logging.info(f"Outputting downloaded records to: {OUTPUT_RESULTS_FILENAME.resolve()}")

    process_matches(MATCHES_INPUT_NDJSON_FILENAME, OUTPUT_RESULTS_FILENAME)

    logging.info(f"Finished!")

