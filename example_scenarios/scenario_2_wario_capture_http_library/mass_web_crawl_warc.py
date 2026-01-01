from warcio.capture_http import capture_http
import requests  # requests must be imported after capture_http
from typing import List
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#
# CONFIGURE ME
#
WARC_CAPTURE_FILENAME = 'WARC-Example-Crawl.warc.gz' # All URLs requested will be captured into this WARC file
url_download_list = [
    'http://google.com',
    'http://cnn.com',
    'http://yahoo.com',
    'http://facebook.com',
    'http://amazon.com',
    'http://wikipedia.org',
    'http://reddit.com',
    'http://ebay.com',
    'http://bing.com',
    'http://msn.com',
]

print(f'Total URLs to crawl: {len(url_download_list)}')

with capture_http(WARC_CAPTURE_FILENAME):
    for url in url_download_list:
        print(f'Crawling {url}')
        try:
            requests.get(url, verify=False, timeout=1)
        except requests.exceptions.ConnectTimeout:
            print(f'ConnectTimeout for {url}')
        except requests.exceptions.ConnectionError:
            print(f'ConnectionError for {url}')
        except Exception as e:
            print(f'Error for {url}: {e}')
