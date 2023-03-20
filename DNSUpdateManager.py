import csv
import logging
import os

import requests
import urllib3

from datetime import datetime
from google.cloud import storage
from Lib.consts import DNS_FEED_BUCKET_NAME, DNS_BLOCK_NAMES, \
    API_BULK_DELETE_DNS_LISTS_PATH, API_GET_DNS_LISTS_PATH, API_CREATE_DNS_LIST_PATH, \
    API_UPDATE_DNS_LIST_PATH, GOOGLE_APPLICATION_CREDENTIALS, DNS_LISTS_FILE_PATH

urllib3.disable_warnings()

logger = logging.getLogger()


def validate_ip(s):
    if s.find("_") != -1:
        return True
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True


def clean_domain_name(name: str):
    return name[:1] + name[1:].lower() if name != 'CNC' else name


class DNSUpdateManager:
    def __init__(self):
        self.block_list_data = self.get_dns_feed_data_from_gcp_bucket()
        self.env_id = ""
        self.bearer_token = ""
        self.env_url = ""
        self.domain_amount = 0

    def get_domain_lists_from_env(self):
        headers = self.get_headers_with_token()
        logger.info("Getting lists from env")
        full_url = self.env_url + API_GET_DNS_LISTS_PATH  # urljoin(f"{self.env_url}", API_GET_DNS_LISTS_PATH)
        response = requests.get(url=full_url, headers=headers, verify=False).json()
        lists = []
        #  check if the lists from env are the relevant lists (cnc / phishing / malware)
        for l in response['objects']:
            if l['name'] in (DNS_BLOCK_NAMES.keys()):
                lists.append(l)
        logger.info(f"Fetched {len(response['objects'])} lists")
        return lists

    def get_token_from_mongo_placeholder(self):
        return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NzgxOTAzMzAsImlhdCI6MTY3ODEwMzkzMCwibmJmIjoxNjc4MTAzOTMwLCJpZGVudGl0eSI6ImFkbWluIiwicmFuZCI6IjY1Y2UxNmI4LWU2ZDctNGIwMy04NGE0LWM3MDY3NDJkOTg0YiJ9.A2UOPHqfASA04cFFlimgcDbSuODmeL-8TQlAUfAHnIQ"  # todo500

    def get_headers_with_token(self):
        return {"Content-Type": "application/json",
                "Authorization": f"Bearer {self.bearer_token}"}

    def run_dns_operation(self, env_id, domain_amount, env_url):
        self.env_id = env_id
        self.domain_amount = domain_amount
        self.bearer_token = self.get_token_from_mongo_placeholder()
        self.env_url = env_url

        domain_lists_from_env = self.get_domain_lists_from_env()
        if self.domain_amount:
            domains_to_update = self.create_lists_to_update()
            if domain_lists_from_env:
                self.update_dns_lists(domains_to_update, domain_lists_from_env)
            else:
                self.create_dns_lists(domains_to_update)
        else:
            if domain_lists_from_env:
                self.delete_domains_lists(domain_lists_from_env)
            else:
                logger.info(f"No DNS lists to delete in env: {self.env_id}")
        logger.info(f"finished DNS operation for env: {self.env_id}")
        return

    def create_dns_lists(self, domains_to_update):
        logger.info("Creating Domain lists")
        data = {"create_list": []}
        for name in DNS_BLOCK_NAMES.keys():
            data["create_list"].append(
                {
                    "name": clean_domain_name(name),
                    "type": "CUSTOM_BLOCKLIST",
                    "domains": domains_to_update[name]
                }
            )
        headers = self.get_headers_with_token()
        full_url = self.env_url + API_CREATE_DNS_LIST_PATH  # urljoin(self.env_url, API_CREATE_DNS_LIST_PATH)
        response = requests.post(full_url, headers=headers, json=data, verify=False).json()

        if any(r['error'] is not None for r in response['results']):
            raise RuntimeError(response)
        logger.info(f"Status: added {len(response['results'])} DNS lists")
        return

    def update_dns_lists(self, domains_to_update, domain_lists_from_env):
        logger.info(f"Updating Domain Lists")
        data = {"edit_list": []}
        for l in domain_lists_from_env:
            data['edit_list'].append(
                {
                    "id": l['id'],
                    "name": clean_domain_name(l['name']),
                    "domains": domains_to_update[l['name']],
                    "enabled": True
                }
            )

        headers = self.get_headers_with_token()
        full_url = self.env_url + API_UPDATE_DNS_LIST_PATH
        response = requests.patch(full_url, headers=headers, json=data, verify=False).json()
        try:
            if len(response['failed']) or len(response['missing']):
                logger.error("Failed to update DNS lists")
                raise RuntimeError(response)
            logger.info(
                f"Status: Succeeded: {len(response['succeeded'])}, Failed:{len(response['failed'])}, Missing: {len(response['missing'])}")
        except Exception as e:
            raise RuntimeError(e)
        return

    def create_lists_to_update(self):
        third = int(self.domain_amount) / 3
        phishing_count, cnc_count, malware_count = third, third, third
        reached_phishing_limit, reached_cnc_limit, reached_malware_limit = False, False, False
        phishing_domain_amount = len(self.block_list_data['PHISHING'])
        cnc_domain_amount = len(self.block_list_data['CNC'])
        malware_domain_amount = len(self.block_list_data['MALWARE'])

        if phishing_domain_amount < phishing_count:
            diff = phishing_count - phishing_domain_amount
            phishing_count = phishing_domain_amount  # if the phishing domains to update are less than the amount that was requested - then update the maximum amount, and add the remains to cnc and malware
            cnc_count += diff / 2
            malware_count += diff / 2
            reached_phishing_limit = True
        if cnc_domain_amount < cnc_count:
            diff = cnc_count - cnc_domain_amount
            cnc_count = cnc_domain_amount  # if the phishing domains to update are less than the amount that was requested - then update the maximum amount, and add the remains to cnc and malware
            if reached_phishing_limit:
                malware_count += diff
            else:
                phishing_count += diff / 2
                malware_count += diff / 2
            reached_cnc_limit = True
        if malware_domain_amount < malware_count:
            diff = malware_count - malware_domain_amount
            malware_count = malware_domain_amount  # if the phishing domains to update are less than the amount that was requested - then update the maximum amount, and add the remains to cnc and malware
            if reached_phishing_limit:
                if not reached_cnc_limit:
                    cnc_count += diff
            elif reached_cnc_limit:
                phishing_count += diff
            else:
                phishing_count += diff / 2
                cnc_count += diff / 2
            reached_malware_limit = True

        if reached_malware_limit or reached_cnc_limit or reached_malware_limit:
            logger.warning("Not enough available DNS lists")
            logger.warning(
                f"Wanted DNS amount: {self.domain_amount}. Available domains: Phishing: {phishing_count}, CNC: {cnc_count}, Malware: {malware_count}")

        block_lists_to_update = {key: [] for key in DNS_BLOCK_NAMES.keys()}
        for domain in self.block_list_data['PHISHING']:
            block_lists_to_update['PHISHING'].append(domain)
            phishing_count -= 1
            if phishing_count <= 0:
                break
        for domain in self.block_list_data['CNC']:
            block_lists_to_update['CNC'].append(domain)
            cnc_count -= 1
            if cnc_count <= 0:
                break
        for domain in self.block_list_data['MALWARE']:
            block_lists_to_update['MALWARE'].append(domain)
            malware_count -= 1
            if malware_count <= 0:
                break

        return block_lists_to_update

    def get_dns_feed_data_from_gcp_bucket(self):
        # blocks_list_data = {key: [] for key in DNS_BLOCK_NAMES.keys()}
        # with open(DNS_LISTS_FILE_PATH + DNS_LISTS_FILE_NAME, 'r', newline='') as file:
        #     reader = csv.reader(file)
        #     devnull = next(reader)  # first row is column names
        #     for i in reader:
        #         if not i:
        #             continue
        #             #  i[4] is the domain "list"/"category" (phishing, cnc, malware)
        #             #  i[0] is the full domain address
        #         blocks_list_data[i[4]].append(i[0].rstrip("."))
        # return blocks_list_data

        logger.info("Getting all dns feed details from gcp bucket")
        if not os.path.exists(GOOGLE_APPLICATION_CREDENTIALS):
            raise RuntimeError("Not found gcp bucket file credentials %s" % GOOGLE_APPLICATION_CREDENTIALS)
        try:
            storage_client = storage.Client.from_service_account_json(GOOGLE_APPLICATION_CREDENTIALS)
            bucket = storage_client.get_bucket(DNS_FEED_BUCKET_NAME)
        except Exception as e:
            raise RuntimeError("Failed to connect to dns feed bucket")

        blocks_list_data = {key: [] for key in DNS_BLOCK_NAMES.keys()}

        blob = list(storage_client.list_blobs(DNS_FEED_BUCKET_NAME))[-1]  # getting the last item => most updated file

        logger.info("Found dns feed file - %s" % blob)
        cur_date = datetime.now().strftime("%d_%m_%Y")
        local_file_name = os.path.join(DNS_LISTS_FILE_PATH, DNS_FEED_BUCKET_NAME + cur_date)

        blob.download_to_filename(local_file_name)

        with open(local_file_name, 'r', newline='') as f:
            reader = csv.reader(f)
            devnull = next(reader)
            for line in reader:
                if not line:
                    continue
                    #  i[4] is the domain "list"/"category" (phishing, cnc, malware)
                    #  i[0] is the full domain address
                blocks_list_data[line[4]].append(line[0].rstrip("."))

        for category in blocks_list_data.keys():
            logger.info("Collected %s items for %s " % (len(blocks_list_data), category))

        return blocks_list_data

    def delete_domains_lists(self, dns_objects_from_env):
        logger.info(f"Deleting existing DNS lists on env: {self.env_id}")
        ids_to_delete = [obj['id'] for obj in dns_objects_from_env]
        params = {'ids': ','.join(ids_to_delete)}
        headers = self.get_headers_with_token()
        full_url = self.env_url + API_BULK_DELETE_DNS_LISTS_PATH
        response = requests.delete(url=full_url, headers=headers, params=params, verify=False).json()
        try:
            if len(response['failed']) or len(response['missing']):
                logger.error("Failed to delete DNS lists")
                raise RuntimeError(response)
            logger.info(
                f"Delete operation status: Succeeded: {len(response['succeeded'])}, Failed:{len(response['failed'])}, Missing: {len(response['missing'])}")
        except Exception as e:
            raise RuntimeError(e)
        return
