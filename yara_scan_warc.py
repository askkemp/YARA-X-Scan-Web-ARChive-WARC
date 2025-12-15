#!/usr/bin/env python3
# Built in Python 3.12
# https://github.com/askkemp/YARA-X-Scan-Web-ARChive-WARC
__author__ = "Kemp Langhorne"
__copyright__ = "Copyright (C) 2025 AskKemp.com"
__license__ = "gpl-3.0"

from warcio.archiveiterator import ArchiveIterator
import yara_x
from pathlib import Path
import json
import logging
from tqdm import tqdm
import argparse

# logging setup
logging.basicConfig(level=logging.WARNING)

def process(warc_directory: Path, output_results_filename: Path, yara_scanner: yara_x.Scanner) -> None:
    '''
    Process WARC files in the specified directory, scanning each record with YARA-X rules, and saving matches to an NDJSON file.
    Args:
        warc_directory (Path): Base directory containing WARC files.
        output_results_filename (Path): Output NDJSON file for YARA matches.
        yara_scanner (yara_x.Scanner): Pre-configured YARA-X scanner object.
    Returns:
        None
    '''

    # Collect all .warc.gz files recursively under any 'warc' subdirectory
    warc_files = sorted(warc_directory.glob('**/*.warc.gz'))
    total_warc_files = len(warc_files)
    logging.info(f"Found {total_warc_files} WARC files to scan in: {warc_directory}")
    
    logging.info(f"Writing YARA matches to: {output_results_filename}")
    with output_results_filename.open('w', encoding='utf-8') as out_f: # Yara matches output file
        for warc_file in tqdm(warc_files, desc="Processing WARC files"): # Progress bar for total number of warc files found
            logging.debug(f"Scanning file: {warc_file.name}")
            try:
                # Open one warc file at a time and scan it with yara
                with open(warc_file, 'rb') as stream:
                    it = ArchiveIterator(stream, check_digests=True)
                    for record in it:
                        rec_offset = it.offset # Get the byte offset of the current record which is needed to quickly extract it later
                        record_type = record.rec_type
                        warc_headers = record.rec_headers
                        record_id = warc_headers.get_header('WARC-Record-ID')
                        target_uri = warc_headers.get_header('WARC-Target-URI')
                        content_type = warc_headers.get_header('Content-Type')
                        date = warc_headers.get_header('WARC-Date')
    
                        # Read the payload of the warc record
                        # https://github.com/webrecorder/warcio/blob/6775fb9ea3505db144a145c5a8b3ba1dfb822ac1/warcio/extractor.py#L27
                        # From https://github.com/webrecorder/warcio/blob/master/README.rst: A special ArcWarcRecord.content_stream() function provides a stream that automatically decompresses and de-chunks the HTTP payload, if it is compressed and/or transfer-encoding chunked.
                        content = record.content_stream().read() 
                        if record.rec_type == 'response': # response: HTTP response received from server
                            
                            # Scan warc record content with YARA-X rules
                            result = yara_scanner.scan(content)  # ScanResults object
                            
                            # Create detailed information for each matching rule and save as JSON lines
                            for rule in result.matching_rules:
                                temp_dict = {}
                                temp_dict['warc_file_name'] = warc_file.name
                                temp_dict['warc_file_path'] = str(warc_file)
                                temp_dict['warc_record_offset'] = rec_offset
                                temp_dict['warc_record_target_uri'] = target_uri
                                temp_dict['warc_record_id'] = record_id
                                temp_dict['warc_record_content_type'] = content_type
    
                                temp_dict['yara_rule_identifier'] = rule.identifier
                                temp_dict['yara_rule_namespace'] = rule.namespace
                                temp_dict['yara_rule_tags'] = list(rule.tags)
                                temp_dict['yara_rule_metadata'] = dict(rule.metadata)
    
                                # Collect specific YARA pattern matches
                                for pattern in rule.patterns: # Matching Patterns
                                    match_count = len(list(pattern.matches))
                                    if match_count == 0: # No matches for this pattern
                                        continue
                                    matched_content_set = set()
                                    matched_content_superset_set = set()
                                    for i, match in enumerate(pattern.matches): # Details for each match of this pattern
    
                                        # Extract and show the matched content to help future analysis
                                        matched_content = content[match.offset:match.offset + match.length] # exaxctly what matched
    
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
                                out_f.write(json.dumps(temp_dict, ensure_ascii=False) + "\n")
    
            except Exception as e:
                logging.critical(f"Error processing {warc_file}: {e}")
    

def main () -> None:
    parser = argparse.ArgumentParser(
        description="Scan records within Web ARChive (WARC) files with YARA-X and save matches to NDJSON."
    )
    parser.add_argument(
        "--warc-directory",
        type=Path,
        required=True,
        help="Base directory and it will recursively search for WARC files with extension *.warc.gz",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("yara_matches.ndjson"),
        help="Output NDJSON file for YARA matches results.",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        required=True,
        help="Path to YARA-X rules file (single file).",
    )
    args = parser.parse_args()


    # Yara-x setup
    compiler = yara_x.Compiler()
    compiler.add_source(f'include "{args.rules}"') # Loads all rules from this single file
    rules = compiler.build()
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(60)
    scanner.max_matches_per_pattern(1000)

    # Kick it off
    process(args.warc_directory, args.output, scanner)
    
if __name__ == '__main__':
    main()