import logging
import os
import sys
import yaml

from datetime import datetime
from pathlib import Path
from Lib.consts import LOG_FILENAME, ENV_UPDATE_CONFIGURATION_FILE

# Initiating the logger:
# When initiating the logger as done here, it allows global logging capabilities
from DNSUpdateManager import DNSUpdateManager
# from google.cloud import storage

format_str = '%(asctime)s [%(process)d:%(thread)d:%(levelname)s] %(module)s.%(funcName)s.%(lineno)d: %(message)s'
datetime_str = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")

temp_output_path = os.path.join(os.getcwd(), datetime_str)
Path(temp_output_path).mkdir(parents=True, exist_ok=True)
log_output_path = os.path.join(temp_output_path, LOG_FILENAME)

formatter = logging.Formatter(format_str)
stdout_handler = logging.StreamHandler(sys.stdout)
logger = logging.getLogger()
logging.basicConfig(
    filename=log_output_path,
    level=logging.DEBUG,
    format=format_str)
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)


def get_parsed_config(conf_file_path):
    with open(f"{conf_file_path}") as config_file:
        parsed_config_file = yaml.safe_load(config_file)
    return parsed_config_file


if __name__ == "__main__":

    logger.info(f"<---------- Initiating script ---------->")
    config = get_parsed_config(ENV_UPDATE_CONFIGURATION_FILE)
    logger.info(f"Envs data: {config}")

    update_manager = DNSUpdateManager()

    for line in config['envs']:
        env_id, domain_amount, env_url = line.split(',')
        logger.info(f"--- Initiating operation on env: {env_id}, domain_amount: {domain_amount} ---")
        update_manager.run_dns_operation(env_id, int(domain_amount), env_url)
        # except Exception as e:
        #     logger.error(e)
        logger.info(f">---------- Script done ----------<")

