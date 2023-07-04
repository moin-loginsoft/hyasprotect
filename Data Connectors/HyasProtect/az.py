# import datetime
import logging
from datetime import datetime, timedelta, timezone
from json import dumps
from os import environ

import requests

import azure.functions as func

from .state_manager import StateManager
from .utils import save_to_sentinel

customer_id = environ.get("WorkspaceID")
shared_key = environ.get("WorkspaceKey")
HYAS_API_KEY = environ.get("ApiKey")
connection_string = environ.get("AzureWebJobsStorage")
FetchBlockedDomains = environ.get("FetchBlockedDomains")
FetchSuspiciousDomains = environ.get("FetchSuspiciousDomains")
FetchMaliciousDomains = environ.get("FetchMaliciousDomains")
FetchPermittedDomains = environ.get("FetchPermittedDomains")
LAST_X_DAYS = 0
PAGE_SIZE = 1000
OUTPUT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
INPUT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
START = environ.get("Start")
END = environ.get("End")
INVALID_HYAS_API_KEY_MSG = "Invalid HYAS API KEY."


logAnalyticsUri = (
    "https://"
    + customer_id
    + ".ods.opinsights.azure.com"
    + "/api/logs"
    + "?api-version=2016-04-01"
)


state = StateManager(connection_string)


def get_from_and_to_date(date_format: str = INPUT_DATE_FORMAT):
    """
    Returns the 'from' and 'to' dates as formatted strings based on the given date_format.

    Args:
        date_format (str): Optional. The format string for the output dates. Default is INPUT_DATE_FORMAT.

    Returns:
        tuple: A tuple containing the 'from' and 'to' dates as formatted strings.
    """

    current_date_time = datetime.utcnow().replace(second=0, microsecond=0)
    last_run_date_time = state.get()
    logging.debug(last_run_date_time)
    if last_run_date_time is not None:
        from_date_time = datetime.strptime(last_run_date_time, date_format)
    else:
        from_date_time = current_date_time - timedelta(days=LAST_X_DAYS)

    return format(from_date_time, date_format), format(current_date_time, date_format)


def call_hyas_protect_api():
    """
    Calls the HYAS Protect API to fetch logs based on specified filters and saves them to Sentinel.

    Returns:
        None
    """

    url = "https://api.hyas.com/dns-log-report/v2/logs"
    (
        from_datetime,
        to_datetime,
    ) = get_from_and_to_date()
    from_date = datetime.strptime(from_datetime, INPUT_DATE_FORMAT).strftime(
        OUTPUT_DATE_FORMAT
    )
    to_date = datetime.strptime(to_datetime, INPUT_DATE_FORMAT).strftime(
        OUTPUT_DATE_FORMAT
    )
    # Optional: Provide any required headers or parameters
    headers = {"Content-Type": "application/json", "X-API-Key": HYAS_API_KEY}

    query_data = {
        "id": "datetime",
        "isRange": True,
        "rangeValue": {
            "start": START or from_date,
            "end": END or to_date,
            "timeType": "range",
        },
    }

    applied_filters = [query_data]
    if FetchBlockedDomains == "Yes":
        blocked_query = {"id": "reputation", "value": "blocked"}
        applied_filters.append(blocked_query)

    if FetchSuspiciousDomains == "Yes":
        blocked_query = {"id": "reputation", "value": "suspicious"}
        applied_filters.append(blocked_query)

    if FetchMaliciousDomains == "Yes":
        blocked_query = {"id": "reputation", "value": "malicious"}
        applied_filters.append(blocked_query)

    if FetchPermittedDomains == "Yes":
        blocked_query = {"id": "reputation", "value": "permitted"}
        applied_filters.append(blocked_query)
    data = {"applied_filters": applied_filters}
    total_count = 1
    page_size = PAGE_SIZE  # 1000 records per api call
    page_number = 0
    records_fetched = 0
    while records_fetched < total_count:
        # Prepare the paging parameters
        paging_params = {
            "order": "desc",
            "page_number": page_number,
            "page_size": page_size,
            "page_type": "standard",
            "sort": "datetime",
        }
        data["paging"] = paging_params

        # Make the API call
        response = requests.post(url, headers=headers, data=dumps(data), timeout=300)
        if response.status_code in range(200, 299):
            result = response.json()
            logs = result["logs"]
            records_fetched += len(logs)
            page_number += 1
            total_count = result["total_count"]
            sentinel_logs = [make_hyas_dict(log) for log in logs]
            sentinel_resp = save_to_sentinel(
                logAnalyticsUri, customer_id, shared_key, dumps(sentinel_logs)
            )
            if sentinel_resp is not None:
                logging.info(
                    f"Logs from {from_date} to {to_date} with filter {str(data)} saved in sentinel successfully."
                )
                state.post(to_datetime)
        else:
            # Print the error message if the request was unsuccessful
            if response.status_code == 403:
                logging.error(INVALID_HYAS_API_KEY_MSG)
                raise Exception(INVALID_HYAS_API_KEY_MSG)
            logging.info(response.content)
            logging.info(
                f"Unable to fetch logs from HyasProtect API. Response code: {response.status_code}"
            )
            break
        if records_fetched >= total_count:
            break


def make_hyas_dict(data: dict):
    """
    Converts a dictionary representing HYAS Protect log data into a standardized format.

    Args:
        data (dict): The dictionary containing the HYAS Protect log data.

    Returns:
        dict: The converted log data in a standardized format.
    """

    return {
        "Domain": data.get("domain"),
        "FQDN": ",".join(data.get("markup", {}).get("fqdn", {})),
        "Domain Category": ",".join(data.get("domain_category", [])),
        "FQDN Nameserver": ",".join(data.get("markup", {}).get("nameserver", {})),
        "NS IP": data.get("nameserver_ip", {}),
        "ARecord IP": data.get("a_record", {}),
        "Registrar": data.get("registrar"),
        "Device Name": data.get("devicename"),
        "Process Name": data.get("processname"),
        "Deployment mode": data.get("resolver_mode"),
        "DomainTLD": data.get("domain_tld"),
        "Domain Age (days)": data.get("domain_age"),
        "Tags": ",".join(data.get("tags", [])),
        "Query Type": data.get("query_type"),
        "Response Code": data.get("response_code"),
        "TTL (sec)": data.get("ttl"),
        "Nameserver": data.get("nameserver"),
        "NS TLD": data.get("nameserver_tld"),
        "AAAA Record IP": data.get("aaaa_record"),
        "CName FQDN": ",".join(data.get("markup", {}).get("cname", {})),
        "CName": ",".join(data.get("c_name", [])),
        "verdict": data.get("verdict"),
        "verdictSource": data.get("verdictSource"),
        "verdictStatus": data.get("verdictStatus"),
        "datetime": data.get("datetime"),
    }


def main(mytimer: func.TimerRequest) -> None:
    """
    The main function for the timer trigger.

    Args:
        mytimer (func.TimerRequest): The TimerRequest object containing information about the timer trigger.

    Returns:
        None
    """
    utc_timestamp = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
    if mytimer.past_due:
        logging.info("The timer is past due!")
        return
    call_hyas_protect_api()

    logging.info("Python timer trigger function ran at %s", utc_timestamp)
