
LOG_FILENAME = "DNS.log"

GQ_PROD_SERVER = 'gcs-gq.gc.guardicore.com'

SCENRAIO_ID = "ui_update_dns_2"

DNS_BLOCK_NAMES = {'CNC': 'CNC servers', 'MALWARE': 'Malware domains', 'PHISHING': 'Phishing sites'}

DNS_FEED_BUCKET_NAME = "d75f5b5c60ea492485593d7819e7c0b0"

ENV_UPDATE_CONFIGURATION_FILE = "/root/DNSLists/config.yaml"

GC_INTERNAL_HEADERS = {'Gc-Caller-Type': 'internal'}

DNS_LISTS_FILE_PATH = '/root/DNSLists/DNSListsFromBucket/'

DNS_LISTS_FILE_NAME = 'etp_threat_intel_dns_feedetp_threat_intel_top_domains-2023-03-06.csv'


API_GET_DNS_LISTS_PATH = "/api/v4.0/dns_security"
API_BULK_DELETE_DNS_LISTS_PATH = "/api/v4.0/dns_security/bulk"
API_CREATE_DNS_LIST_PATH = "/api/v4.0/dns_security/bulk"
API_UPDATE_DNS_LIST_PATH = "/api/v4.0/dns_security/bulk"  # add list id at the end




