"""
py-rllib v1.0.0
author: Mislav Sever

TitaniumCloud
A Python library for the ReversingLabs TitaniumCloud REST API-s.

Copyright (c) ReversingLabs International GmbH. 2016-2019

This unpublished material is proprietary to ReversingLabs International GmbH.. All rights reserved.
Reproduction or distribution, in whole or in part, is forbidden except by express written permission of ReversingLabs International GmbH.
"""

import sys
import hashlib
import requests


class FileReputation:
    SINGLE_QUERY_ENDPOINT = "/api/databrowser/malware_presence/query/{hash_type}/{hash_value}?" \
                            "extended={extended_results}&show_hashes={show_hashes_in_results}&format={format}"
    BULK_QUERY_ENDPOINT = "/api/databrowser/malware_presence/bulk_query/{format}?" \
                          "extended={extended_results}&show_hashes={show_hashes_in_results}"

    def __init__(self, host, username, password, verify=True):
        self.host = host
        self.username = username
        self.password = password
        self.verify = verify

    def _get_credentials(self):
        """Returns a credentials tuple.
            :return: credentials tuple
            :rtype: tuple
        """
        return self.username, self.password

    def get_file_reputation(self, hash_input, extended_results=True, show_hashes_in_results=True, response_format="json"):
        """Accepts a hash string or a list of hash strings and returns a response.
        Hash strings in a passed list must all be of the same hashing algorithm.
            :param hash_input: string or list of strings
            :type hash_input: str or list[str]
            :param extended_results: show extended results
            :type extended_results: bool or str
            :param show_hashes_in_results: show all sample hashes in results
            :type show_hashes_in_results: bool or str
            :param response_format: json or xml
            :type response_format: str
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        helper = HelperMethods()
        extended_results = helper.format_boolean(extended_results)
        show_hashes_in_results = helper.format_boolean(show_hashes_in_results)
        if response_format not in ("xml", "json"):
            raise ValueError("Only string 'xml' or 'json' are allowed as parameters for the response_format parameter.")
        if isinstance(hash_input, str):
            endpoint = self.SINGLE_QUERY_ENDPOINT.format(
                hash_type=helper.get_hashing_algorithm(hash_input),
                hash_value=hash_input,
                extended_results=extended_results,
                show_hashes_in_results=show_hashes_in_results,
                format=response_format
            )
            response = requests.get(
                url=helper.format_url(self.host) + endpoint,
                auth=self._get_credentials(),
                verify=self.verify
            )
        elif isinstance(hash_input, list):
            endpoint = self.BULK_QUERY_ENDPOINT.format(
                format=response_format,
                extended_results=extended_results,
                show_hashes_in_results=show_hashes_in_results
            )
            post_json = {"rl": {"query": {"hash_type": helper.get_hashing_algorithm(hash_input[0]), "hashes": hash_input}}}
            response = requests.post(
                url=helper.format_url(self.host) + endpoint,
                auth=self._get_credentials(),
                json=post_json,
                verify=self.verify
            )
        else:
            raise TypeError("Only hash string or list of hash strings are allowed as the hash_input parameter.")
        if response.status_code in (401, 403):
            raise Exception("An authentication error occurred: Please check your credential data.")
        return response


class AVScanners:
    SINGLE_QUERY_ENDPOINT = "/api/xref/v2/query/{hash_type}/{hash_value}?format={format}&history={history}"
    BULK_QUERY_ENDPOINT = "/api/xref/v2/bulk_query/{format}?history={history}"

    def __init__(self, host, username, password, verify=True):
        self.host = host
        self.username = username
        self.password = password
        self.verify = verify

    def _get_credentials(self):
        """Returns a credentials tuple.
            :return: credentials tuple
            :rtype: tuple
        """
        return self.username, self.password

    def get_scan_results(self, hash_input, response_format="json", historical_results=False):
        """Accepts a hash string or a list of hash strings and returns a response.
        Hash strings in a passed list must all be of the same hashing algorithm.
            :param hash_input: string or list of strings
            :type hash_input: str or list[str]
            :param response_format: json or xml
            :type response_format: str
            :param historical_results: return historical results
            :type historical_results: bool or str
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        helper = HelperMethods()
        historical_results = helper.format_boolean(historical_results)
        if response_format not in ("xml", "json"):
            raise ValueError("Only 'xml' and 'json' are allowed as parameters for the response_format.")
        if isinstance(hash_input, str):
            endpoint = self.SINGLE_QUERY_ENDPOINT.format(
                hash_type=helper.get_hashing_algorithm(hash_input),
                hash_value=hash_input,
                format=response_format,
                history=historical_results
            )
            response = requests.get(
                url=helper.format_url(self.host) + endpoint,
                auth=self._get_credentials(),
                verify=self.verify
            )
        elif isinstance(hash_input, list):
            endpoint = self.BULK_QUERY_ENDPOINT.format(
                format=response_format,
                history=historical_results
            )
            post_json = {"rl": {"query": {"hash_type": helper.get_hashing_algorithm(hash_input[0]), "hashes": hash_input}}}
            response = requests.post(
                url=helper.format_url(self.host) + endpoint,
                auth=self._get_credentials(),
                json=post_json,
                verify=self.verify
            )
        else:
            raise TypeError("Only hash string or list of hash strings are allowed as the hash_input parameter.")
        if response.status_code in (401, 403):
            raise Exception("An authentication error occurred. Please check your credential data.")
        return response


class FileAnalysis:
    SINGLE_QUERY_ENDPOINT = "/api/databrowser/rldata/query/{hash_type}/{hash_value}?format={format}"
    BULK_QUERY_ENDPOINT = "/api/databrowser/rldata/bulk_query/{format}"

    def __init__(self, host, username, password, verify=True):
        self.host = host
        self.username = username
        self.password = password
        self.verify = verify

    def _get_credentials(self):
        """Returns a credentials tuple.
            :return: credentials tuple
            :rtype: tuple
        """
        return self.username, self.password

    def get_analysis_results(self, hash_input, response_format="json"):
        """Accepts a hash string or a list of hash strings and returns a response.
        Hash strings in a passed list must all be of the same hashing algorithm.
            :param hash_input: string or list of strings
            :type hash_input: str or list[str]
            :param response_format: json or xml
            :type response_format: str
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        helper = HelperMethods()
        if response_format not in ("xml", "json"):
            raise ValueError("Only string 'xml' or 'json' are allowed as parameters for the response_format parameter.")
        if isinstance(hash_input, str):
            endpoint = self.SINGLE_QUERY_ENDPOINT.format(
                hash_type=helper.get_hashing_algorithm(hash_input),
                hash_value=hash_input,
                format=response_format
            )
            response = requests.get(
                url=helper.format_url(self.host) + endpoint,
                auth=self._get_credentials(),
                verify=self.verify
            )
        elif isinstance(hash_input, list):
            endpoint = self.BULK_QUERY_ENDPOINT.format(
                format=response_format
            )
            post_json = {"rl": {"query": {"hash_type": helper.get_hashing_algorithm(hash_input[0]), "hashes": hash_input}}}
            response = requests.post(
                url=helper.format_url(self.host) + endpoint,
                auth=self._get_credentials(),
                json=post_json,
                verify=self.verify
            )
        else:
            raise TypeError("Only hash string or list of hash strings are allowed as the hash_input parameter.")
        if response.status_code in (401, 403):
            raise Exception("An authentication error occurred: Please check your credential data.")
        if response.status_code == 404:
            raise Exception("No reference was found for this hash.")
        return response


class RHAFunctionalSimilarity:
    SINGLE_QUERY_ENDPOINT = "/api/group_by_rha1/v1/query/{rha1_type}/{hash_value}?format={format}&" \
                            "limit={result_limit}&extended={extended_results}&classification={classification}"

    def __init__(self, host, username, password, verify=True):
        self.host = host
        self.username = username
        self.password = password
        self.verify = verify

    def _get_credentials(self):
        """Returns a credentials tuple.
            :return: credentials tuple
            :rtype: tuple
        """
        return self.username, self.password

    def get_similar_hashes(self, hash_input, response_format="json",
                           extended_results=True, result_limit=1000, classification="malicious"):
        """Accepts a hash string and returns a response.
            :param hash_input: sha1 hash string
            :type hash_input: str
            :param response_format: json or xml
            :type response_format: str
            :param extended_results: show extended response
            :type extended_results: bool
            :param result_limit: limit the number of result entries
            :type result_limit: int
            :param classification: show only results of certain classification
            :type classification: str
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        helper = HelperMethods()
        rldata = FileAnalysis(self.host, self.username, self.password, self.verify)
        file_type = helper.get_file_type(rldata, hash_input)
        rha1_type = helper.determine_rha1_type(file_type)
        if response_format not in ("xml", "json"):
            raise ValueError("Only string 'xml' or 'json' are allowed as parameters for the response_format parameter.")
        if not isinstance(hash_input, str):
            raise TypeError("Only single hash string is allowed as the hash_input parameter.")
        if helper.get_hashing_algorithm(hash_input) != "sha1":
            raise ValueError("Only SHA-1 hashes are allowed as input values.")
        extended_results = helper.format_boolean(extended_results)
        endpoint = self.SINGLE_QUERY_ENDPOINT.format(
            rha1_type=rha1_type,
            hash_value=hash_input,
            extended_results=extended_results,
            format=response_format,
            result_limit=result_limit,
            classification=classification
        )
        response = requests.get(
            url=helper.format_url(self.host) + endpoint,
            auth=self._get_credentials(),
            verify=self.verify
        )
        if response.status_code in (401, 403):
            raise Exception("An authentication error occurred: Please check your credential data.")
        return response


class RHA1Analytics:
    SINGLE_QUERY_ENDPOINT = "/api/rha1/analytics/v1/query/{rha1_type}/{sha1}" \
                            "?format={format}&extended={extended_results}"
    BULK_QUERY_ENDPOINT = "/api/rha1/analytics/v1/query/{post_format}"

    def __init__(self, host, username, password, verify=True):
        self.host = host
        self.username = username
        self.password = password
        self.verify = verify

    def _get_credentials(self):
        """Returns a credentials tuple.
            :return: credentials tuple
            :rtype: tuple
        """
        return self.username, self.password

    def get_rha1_analytics(self, hash_input, response_format="json", extended_results=True):
        """Accepts a SHA-1 hash string and returns a response.
            :param hash_input: sha1 hash string or list of sha1 strings
            :type hash_input: str or list[str]
            :param response_format: json or xml
            :type response_format: str
            :param extended_results: show extended response
            :type extended_results: bool
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        helper = HelperMethods()
        if isinstance(hash_input, str):
            sample_hash = hash_input
        elif isinstance(hash_input, list):
            sample_hash = hash_input[0]
        else:
            raise TypeError("Only hash string or list of hash strings are allowed as the hash_input parameter.")
        rldata = FileAnalysis(self.host, self.username, self.password, self.verify)
        file_type = helper.get_file_type(rldata, sample_hash)
        rha1_type = helper.determine_rha1_type(file_type)
        if response_format not in ("xml", "json"):
            raise ValueError("Only string 'xml' or 'json' are allowed as parameters for the response_format parameter.")
        if helper.get_hashing_algorithm(sample_hash) != "sha1":
            raise ValueError("Only SHA-1 hashes are allowed as input values.")
        extended_results = helper.format_boolean(extended_results)
        if isinstance(hash_input, str):
            endpoint = self.SINGLE_QUERY_ENDPOINT.format(
                rha1_type=rha1_type,
                sha1=hash_input,
                extended_results=extended_results,
                format=response_format
            )
            response = requests.get(
                url=helper.format_url(self.host) + endpoint,
                auth=self._get_credentials(),
                verify=self.verify
            )
        elif isinstance(hash_input, list):
            endpoint = self.BULK_QUERY_ENDPOINT.format(
                post_format=response_format
            )
            post_json = {"rl": {"query": {"rha1_type": rha1_type, "response_format": response_format,
                                "extended": extended_results, "hashes": hash_input}}}
            response = requests.post(
                url=helper.format_url(self.host) + endpoint,
                auth=self._get_credentials(),
                json=post_json,
                verify=self.verify
            )
        else:
            raise TypeError("Only hash string or list of hash strings are allowed as the hash_input parameter.")
        if response.status_code in (401, 403):
            raise Exception("An authentication error occurred: Please check your credential data.")
        if response.status_code == 404:
            raise Exception("No reference was found for this hash.")
        return response


class URIStatistics:
    SINGLE_QUERY_ENDPOINT = "/api/uri/statistics/uri_state/sha1/{sha1}?format={format}"

    def __init__(self, host, username, password, verify=True):
        self.host = host
        self.username = username
        self.password = password
        self.verify = verify

    def _get_credentials(self):
        """Returns a credentials tuple.
            :return: credentials tuple
            :rtype: tuple
        """
        return self.username, self.password

    def get_uri_statistics(self, uri_input, response_format="json"):
        """Accepts an email address, URL, DNS name or IPv4 string and returns a response.
            :param uri_input: email address, URL, DNS name or IPv4 string
            :type uri_input: str
            :param response_format: json or xml
            :type response_format: str
            :return: :class:`Response <Response>` object
            :rtype: requests.Response
        """
        if response_format not in ("xml", "json"):
            raise ValueError("Only string 'xml' or 'json' are allowed as parameters for the response_format parameter.")
        if not isinstance(uri_input, str):
            raise TypeError("Only a single email address, URL, DNS name or IPv4 string is allowed "
                            "as the uri_input parameter.")
        helper = HelperMethods()
        hash_string = helper.calculate_hash(
            data_input=uri_input,
            hashing_algorithm="sha1"
        )
        endpoint = self.SINGLE_QUERY_ENDPOINT.format(
            sha1=hash_string,
            format=response_format
        )
        response = requests.get(
            url=helper.format_url(self.host) + endpoint,
            auth=self._get_credentials(),
            verify=self.verify
        )
        if response.status_code in (401, 403):
            raise Exception("An authentication error occurred: Please check your credential data.")
        if response.status_code == 404:
            raise Exception("No reference was found for this URI.")
        return response


class AdvancedSearch:
    SEARCH_ENDPOINT = "/api/search/v1/query"

    def __init__(self, host, username, password, verify=True):
        self.host = host
        self.username = username
        self.password = password
        self.verify = verify

    def _get_credentials(self):
        """Returns a credentials tuple.
            :return: credentials tuple
            :rtype: tuple
        """
        return self.username, self.password

    def search(self, query):
        """Advanced search"""
        endpoint = self.QUERY_ENDPOINT
        response = requests.post(
            url=HelperMethods.format_url(self.host) + endpoint,
            auth=self._get_credentials(),
            verify=self.verify,
            json=query
        )
        response.raise_for_status()
        return response.json()


class HelperMethods(object):
    @staticmethod
    def format_url(host):
        """Returns a formatted host URL including the protocol statement.
            :param host: URL string
            :type host: str
            :returns: formatted URL string
            :rtype: str
        """
        if host.startswith("http://"):
            raise ValueError("Unsupported protocol definition: TitaniumCloud services can only be used over HTTPS.")
        elif host.startswith("https://"):
            pass
        else:
            host = "https://{host}".format(host=host)
        return host

    @staticmethod
    def get_hashing_algorithm(hash_input):
        """Checks if a string is a valid hash (hexadecimal).
        Returns a hashing algorithm type depending on the accepted hash string.
            :param hash_input: hash string
            :type hash_input: str
            :returns: hashing algorithm string or raises an exception
            :rtype: str
        """
        algorithms = {
            32: "md5",
            40: "sha1",
            64: "sha256"
        }
        algorithm = algorithms.get(len(hash_input))
        if algorithm is not None:
            try:
                int(hash_input, 16)
                return algorithm
            except ValueError:
                raise ValueError("The given input string does not correspond to a valid hexadecimal value.")
        else:
            raise ValueError("The length of the input string does not match any of the supported hashing algorithms: "
                             "Use only MD5, SHA-1 or SHA-256")

    @staticmethod
    def format_boolean(statement):
        """Returns a statement string formatted from a boolean expression.
            :param statement: boolean statement
            :type statement: bool
            :returns: formatted statement string
            :rtype: str
        """
        if isinstance(statement, bool):
            statement = "true" if statement is True else "false"
        elif isinstance(statement, str):
            if statement not in ("true", "false"):
                raise ValueError("Only 'true' or 'false' are accepted as string parameters for the requested query.")
        else:
            raise TypeError("Wrong data type for query parameter: "
                            "Only boolean True or False and string 'true' or 'false' are accepted as parameters for "
                            "the requested query.")
        return statement

    @staticmethod
    def get_file_type(rldata, sample_hash):
        """Returns a TitaniumCore classified file type.
            :param rldata: FileAnalysis API object
            :type rldata: ticloud.FileAnalysis
            :param sample_hash: hash string
            :type sample_hash: str
            :returns: file type string
            :rtype: str
        """
        rldata_response = rldata.get_analysis_results(sample_hash).json()
        try:
            file_type = rldata_response["rl"]["sample"]["analysis"]["entries"][0]["tc_report"]["info"]["file"]["file_type"]
        except KeyError:
            raise KeyError("There is no file type definition in the File Analysis API response for the provided sample."
                           " Can not return file type.")
        return file_type

    def determine_rha1_type(self, file_type):
        """Returns an RHA1 type string.
            :param file_type: file type string
            :type file_type: str
            :returns: RHA1 type string
            :rtype: str
        """
        file_type_map = {
            "PE": "pe01",
            "PE+": "pe01",
            "PE16": "pe01",
            "PE32": "pe01",
            "PE32+": "pe01",
            "MachO32 Big": "macho01",
            "MachO32 Little": "macho01",
            "MachO64 Big": "macho01",
            "MachO64 Little": "macho01",
            "ELF32 Big": "elf01",
            "ELF32 Little": "elf01",
            "ELF64 Big": "elf01",
            "ELF64 Little": "elf01"
        }
        rha1_type = file_type_map.get(file_type)
        if rha1_type is None:
            allowed_files = self.stringify_keys(file_type_map)
            raise ValueError("The provided hash belongs to a file type that can not be used in this context: "
                             "Only the following file types can be used: "
                             "{allowed_files}".format(allowed_files=allowed_files))
        return rha1_type

    def update_hash_object(self, input_source, hash_object):
        """Accepts a string or an opened file in 'rb' mode and a created hashlib hash object and
        returns an updated hashlib hash object.
            :param input_source: open file in "rb" mode or string
            :type input_source: str or file or BinaryIO
            :param hash_object: hash object
            :type hash_object: _hashlib.HASH
            :returns: updated hash object
            :rtype: _hashlib.HASH
        """
        if self.is_file(input_source):
            hash_object.update(input_source.read())
        elif isinstance(input_source, str):
            if sys.version_info[0] == 3:
                input_source = input_source.encode("utf-8")
            hash_object.update(input_source)
        else:
            raise TypeError("This is not a valid source type: Only string and file opened in 'rb' mode "
                            "are accepted as input source parameters")
        return hash_object

    def calculate_hash(self, data_input, hashing_algorithm):
        """Returns a calculated hash string of a selected hashing algorithm type for a file or string.
            :param data_input: open file in "rb" mode or string
            :type data_input: str or file or BinaryIO
            :param hashing_algorithm: selected hashing algorithm
            :type hashing_algorithm: str
            :returns: hash string
            :rtype: str
        """
        algorithms = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256()
        }
        hash_object = algorithms.get(hashing_algorithm)
        if hash_object is None:
            allowed = self.stringify_keys(algorithms)
            raise KeyError("Unsupported hashing algorithm specification. "
                           "Only {allowed} can be used.".format(allowed=allowed))
        hash_object = self.update_hash_object(data_input, hash_object)
        return hash_object.hexdigest()

    @staticmethod
    def stringify_keys(dictionary):
        """Returns a comma-separated string of dictionary keys.
            :param dictionary: open file in "rb" mode or string
            :type dictionary: dict
            :returns: dictionary keys string
            :rtype: str
        """
        resulting_string = ""
        counter = 1
        for k in dictionary:
            if counter < len(dictionary):
                resulting_string = resulting_string + k + ", "
            else:
                resulting_string = resulting_string + k
            counter += 1
        return resulting_string

    @staticmethod
    def is_file(input_value):
        """Returns a correct file handle instance check depending on the major Python version.
            :param input_value: a file handle type object for Python 2.x or Python 3.x
            :type input_value: file handle
            :returns: boolean statement or raises exception
            :rtype: bool
        """
        if sys.version_info[0] == 2:
            return isinstance(input_value, file)
        elif sys.version_info[0] == 3:
            return hasattr(input_value, "read")
        else:
            raise Exception("The version of Python in use is not compatible with this module. The py-rllib module "
                            "works with Python versions 2.x and 3.x")
