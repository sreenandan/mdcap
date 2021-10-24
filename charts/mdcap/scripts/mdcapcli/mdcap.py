#!/usr/bin/env python3

__author__      = "Ravikumar Alluboyina"
__email__       = "ravi@robin.io"
__copyright__   = "Copyright 2019, Robin.io"

import os
import types
import sys
import requests
import json
import click
import csv
import logging
import time
import tarfile
import base64
import tempfile
import html
import yaml
import re
import ssl
from datetime import datetime
import urllib.parse
from pprint import pprint
from pprint import pformat
from tabulate import tabulate
from jinja2 import Environment, FileSystemLoader
from click_aliases import ClickAliasedGroup
import jinja2schema
from subprocess import call, Popen
from collections import namedtuple
import aiohttp
import asyncio
import subprocess
# import paramiko
import errno
import math
import csv

from urllib3.exceptions import InsecureRequestWarning


common_options = [
    click.option('--urlinfo', is_flag=True, help="Display curl command associated with command")
]

common_set_options = [
    click.option('--set', type=str, multiple=True, help="Set key value pair to add or override the element configuration in values file. Example: --set os.root_password=robin321 --set network.bootinterface.ip=1.2.3.4"),
    click.option('--setadd', type=str, multiple=True, help="Set key value pair to append an array in the element configuration in values file. Example: --set-add os.dns=dns1 --set-add os.dns=dns2")
]

SET = set

# logging. basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


class TaskState(object):
    SUBMITTED = "submitted"
    INPROGRESS = "inprogress"
    SUCCESS = "success"
    FAILED = "failed"

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Server context
sc = None

class ServerContext(object):

    MDCAP_CLI_VERSION = os.environ.get("MDCAP_CLI_VERSION", "dev")
    MDCAP_CONFIG_PATH = f"{os.environ['HOME']}/.mdcap.config"
    MDCAP_API_VERSION = "v1"
    MDCAP_EDITOR = os.environ.get('EDITOR','vi')
    __instance = None

    def __new__(cls):
        if ServerContext.__instance is None:
            obj = object.__new__(cls)
            obj.contexts = {}
            obj.default = {}
            obj._load_contexts()
            ServerContext.__instance = obj
        return ServerContext.__instance

    def __init__(self):
        pass

    def _load_contexts(self):

        # load the contexts
        if os.path.exists(ServerContext.MDCAP_CONFIG_PATH):
            LOG.debug("Reading mdcap.config for context")
            with open(ServerContext.MDCAP_CONFIG_PATH) as fh:
                self.contexts = json.loads(fh.read())

    def _load_default_context(self):
        # Pick up default context
        for name, ctx in self.contexts.items():
            if ctx.get('default', False):
                self.default = ctx

        if not self.default:
            raise Exception("No default server context found. Set the default server context using 'mdcap sc makedefault ...'")

        LOG.debug("Using context:")
        LOG.debug(f"{json.dumps(self.default)}")

    def _dump(self):
        with open(ServerContext.MDCAP_CONFIG_PATH, "w") as fh:
            fh.write(json.dumps(self.contexts, indent=4))

    def del_context(self, name, url=None, default=False, token=None):
        if name not in self.contexts:
            raise Exception(f"Server context '{name}' not found")

        # If the user is trying to delete the default context, let him do it
        # we will handle this in the get_default_context.
        del self.contexts[name]
        self._dump()


    def set_context(self, name, url=None, default=False, token=None):
        ctx = self.contexts.get(name, {})
        LOG.debug(ctx)

        if not ctx and not url:
            raise Exception(f"Server context '{name}' not found")

        if url:
            # Register a new context
            url = url.rstrip('/')
            LOG.debug(url)
            ctx['name'] =  name
            ctx['mdcap_base_url'] = url
            ctx['mdcap_engine_url'] = f"{url}/engine/api/{ServerContext.MDCAP_API_VERSION}"
                        # check are we running inside pod, if yes, we talk to the 
            # services locally and not through the loadbalancer.
            internal = os.environ.get("POD_NAME", False)
            if internal:
                ctx['mdcap_engine_url'] = f"{url}/api/{ServerContext.MDCAP_API_VERSION}"
                ctx['mdcap_log_url'] = f"{os.environ.get('MDCAP_LOG_URL')}"
            else:
                ctx['mdcap_engine_url'] = f"{url}/engine/api/{ServerContext.MDCAP_API_VERSION}"
                ctx['mdcap_log_url'] = f"{url}/log/api/{ServerContext.MDCAP_API_VERSION}"
            ctx['mdcap_cli_version'] = ServerContext.MDCAP_CLI_VERSION
            ctx['mdcap_api_version'] = ServerContext.MDCAP_API_VERSION
            ctx['mdcap_editor'] = ServerContext.MDCAP_EDITOR

        if token:
            ctx['token'] = token

        if default:
            # Reset the default flag
            for _, _ctx in self.contexts.items():
                _ctx['default'] = False

            # Set this context as default
            ctx['default'] = True
            self.default = ctx

        # TBD -- Verify the URL
        self.contexts[name] = ctx

        if len(self.contexts) == 1:
            # If there is only one context, mark it as default.
            ctx['default'] = True

        self._dump()

    def set_creds(self, token, role):
        self._load_default_context()
        self.default['token'] = token
        self.default['role'] = role
        self._dump()

    def _default(self):
        if not self.default:
            self._load_default_context()
        return self.default

    def engine(self):
        return self._default()['mdcap_engine_url']

    def editor(self):
        return self._default()['mdcap_editor']

    def logstore(self):
        return self._default()['mdcap_log_url']

    def artifactory(self):
        return self._default()['mdcap_artifactory_url']

    def eventserver(self):
        return self._default()['mdcap_eventserver_url']

    def token(self):
        _tkn = self._default()['token']
        if not _tkn:
            raise Exception("Token not found")
        return _tkn

    def role(self):
        _role = self._default()['role']
        return _role

    def get_context(self, name):
        return self.contexts.get(name)


def is_uid(uid):
    if len(uid) != 36 or len(uid.split('-')) != 5:
        return False
    else:
        return True

def check_uid(uid):
    if not is_uid(uid):
        print("Error: Provide the UUID and not the name")
        sys.exit(1)

def get_hdrs():
    hdrs = {}
    try:
        hdrs['authorization'] = sc.token()
        hdrs['role'] = sc.role()
    except Exception:
        click.secho("Login in to MDCAP using 'mdcap login'", fg="red")
        sys.exit(1)

    return hdrs

def get_meta(**kwargs):
    hdrs = get_hdrs()
    try:
        url = "{}/metadata".format(sc.engine())
        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()
        pprint(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Error getting metadata ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func
    return _add_options

def get_inventory(batchid, poolid):
    hdrs = get_hdrs()
    res = requests.get('{}/inventory/{}/{}'.format(sc.engine(), batchid, poolid), verify=False, headers=hdrs)
    pprint(res.json())

def print_nested(val, indent=-4, nl=False):
    if type(val) == dict:
        indent += 4
        if nl:
            # dictionary within dictionary is not nesting correctly, so adding tihs print
            print()
        for k in val:
            print('{}{}'.format(indent * ' ', k), end=':')
            print_nested(val[k], indent, nl=True)
    else:
        print(" {}".format(val))


def parse_time(time_str):
    vals = time_str.split(':')
    total_time = 0
    for v in vals:
        try:
            if v[-1] == 'd':
                total_time += int(v[:-1]) * 86400
            elif v[-1] == 'h':
                total_time += int(v[:-1]) * 3600
            elif v[-1] == 'm':
                total_time += int(v[:-1]) * 60
            elif v[-1] == 's':
                total_time += int(v[:-1]) * 1
            else:
                raise Exception("Time format is Ad:Bh:Cm:Ds or any subset (remove :'s that aren't needed)")

        except:
            raise Exception("Time format is Ad:Bh:Cm:Ds or any subset (remove :'s that aren't needed)")
    return total_time


def parse_labels(labels, ret_dict=False):
    labellist = []
    kvpairs = {}
    if labels:
        for t in labels:
            t = t.replace("=", ":")
            try:
                keyval_list = t.split(",")
                for k in keyval_list:
                    keyval = k.split(":")
                    kvpairs[keyval[0]] = keyval[1]
                    labellist.append("labels={}:{}".format(keyval[0], keyval[1]))
            except Exception as e:
                print(e)
                raise Exception("label format is: key1:val1,key2:val2,... OR key1=val1,key2=val2,...")
    if ret_dict:
        return kvpairs
    return labellist


def convert_bytes_to_readable(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("b", "kb", "mb", "gb", "tb", "pb")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return f"{s} {size_name[i]}"


def convert_readable_to_bytes(size):
    try:
        value = int(size)
        return value
    except:
        regex = re.compile(r'(\d+(?:\.\d+)?)\s*([kmgtp]?b)', re.IGNORECASE)

        order = ['b', 'kb', 'mb', 'gb', 'tb', 'pb']

        for value, unit in regex.findall(size):
            return int(float(value) * (1024**order.index(unit.lower())))

def replace_value_dict(adict, key, value):
    for k in adict.keys():
        if k == key:
            adict[k] = value
        elif isinstance(adict[k], dict):
            replace_value_dict(adict[k], key, value)
        elif isinstance(adict[k], list):
            for item in adict[k]:
                if isinstance(item, dict):
                    replace_value_dict(item, key, value)


def compute_curl_command(request_obj, headers={}, data=None, ignore_response=False):

    curl_cmd = "curl -i -k -X {0}".format(request_obj.request.method)
    data_str = None
    if data:
        if isinstance(data, dict):
            data_str = json.dumps(data)
        elif not isinstance(data, types.GeneratorType):
            data_str = str(data)
        if data_str:
            redact_keys = {'password'}
            if any([key in data for key in redact_keys]):
                try:
                    json_request_body = json.loads(data_str)
                except ValueError:
                    pass
                else:
                    for key in redact_keys.intersection(set(json_request_body.keys())):
                        replace_value_dict(json_request_body, key, "<REDACTED>")
                    curl_cmd += " -d '{0}'".format(json.dumps(json_request_body).replace("'", '"'))
            else:
                curl_cmd += " -d '{0}'".format(data_str.replace("'", '"'))

    header_str = ""
    for k, v in headers.items():
        if type(v) == bytes:
            header_str += " -H {}".format('"{}: {}"'.format(k, v.decode('utf-8')))
        elif type(v) == str:
            header_str += " -H {}".format('"{}: {}"'.format(k, v))

    if header_str:
        curl_cmd += header_str

    curl_cmd += " {0}\n".format(request_obj.request.url)

    print()
    print("    CURL cmd :")
    print("        {}".format(curl_cmd))
    if not ignore_response:
        print("    HTTP code :")
        print("        {}".format(request_obj.status_code))
        print("    HTTP response :")
        json_request_response = json.loads(request_obj.text)
        mask_sensitive_data(json_request_response)
        print("        {}".format(str(json.dumps(json_request_response))))


def find_args(*args):
    fl = []
    for param in args:
        if type(param) == type([]):
            fl += find_args(*param)
        else:
            fl.append(param)
    return fl

def parameter_string(*args):
    final_str = ""
    q_args = find_args(*args)
    if q_args:
        final_str = "?" + "&".join([arg for arg in q_args if arg])
    if final_str:
        final_str += "&total=True"
    else:
        final_str += "?total=True"
    return final_str


def offset_limit_from_range(index):
    limit = None
    offset = None
    if index:
        split_values = index.split(":")
        try:
            offset = int(split_values[0])
        except ValueError:
            raise Exception("Starting index specified is not an integer.")
        if len(split_values) == 2:
            try:
                end = int(split_values[1])
            except ValueError:
                raise Exception("End index specified is not an integer.")
            limit = end - offset
            limit = "limit={}".format(limit)
            offset = "offset={}".format(offset)
    return limit, offset


def handle_error(exception, action_msg=None):
    if type(exception) == requests.exceptions.ConnectionError:
        click.secho("Failed to establish a connection with the MDCAP engine.", fg="red")
    elif type(exception) == requests.exceptions.HTTPError:
        click.secho("{}\n{}".format(action_msg if action_msg else "", exception.response.content.decode('utf-8')), fg="red")
    else:
        click.secho("{}\nError: {}".format(action_msg if action_msg else "", exception.args[0]), fg="red")
    sys.exit(1)

def open_in_editor(uid, content="", otype="element", param=None, edit_fmt="json", accept_no_changes=False, merge_config={}):
    try:
        if uid:
            def get_value(keys, obj):
                tmp = obj
                for key in keys.split("."):
                    tmp = tmp[key]
                return tmp
            r = None
            hdrs = get_hdrs()
            r = requests.get(f"{sc.engine()}/{otype}/{uid}", verify=False, headers=hdrs)
            r.raise_for_status()
            cfg = r.json()
            if edit_fmt == "json":
                if param:
                    cfg = get_value(param, cfg)
                if merge_config:
                    cfg = merge_dict(cfg, merge_config)
                content = json.dumps(cfg, indent=4)
            elif edit_fmt == "yaml":
                if param:
                    cfg = get_value(param, cfg)
                if not merge_config:
                    cfg = merge_dict(cfg, merge_config)
                content = yaml.dump(cfg, indent=4)
            elif not edit_fmt:
                content = cfg
            if not content:
                print(f"No data found for {param} of {otype} with uid {uid}")
                return ""
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information about element with uid {}. ".format(uid))
    with tempfile.NamedTemporaryFile(suffix=".tmp") as t:
        t.write(bytes(content, 'UTF-8'))
        t.flush()
        rc = call([sc.editor(), t.name])
        with open(t.name,'rb') as f:
            mcontent = f.read()
        if accept_no_changes or content.strip() != mcontent.decode("utf-8").strip():
            if edit_fmt == "json":
                return json.loads(mcontent)
            elif edit_fmt == "yaml":
                return yaml.load(mcontent, Loader=yaml.FullLoader)
            return mcontent
        print("No changes found")
        return None

def create_dict_fromkeys(setvalues, setaddvalues):
    result = {}
    for value in setvalues:
        tks = value.split("=")
        tmp = result
        lk = None
        ptmp = tmp
        for key in tks[0].split("."):
            ptmp = tmp
            if key not in tmp:
                tmp[key] = {}
            tmp = tmp[key]
            lk = key
        if lk:
            ptmp[lk] = tks[1]

    for value in setaddvalues:
        tks = value.split("=")
        tmp = result
        lk = None
        ptmp = tmp
        initialized = False
        for key in tks[0].split("."):
            ptmp = tmp
            if key not in tmp:
                tmp[key] = {}
                initialized = True
            tmp = tmp[key]
            lk = key
        if lk:
            if lk not in ptmp or initialized:
                ptmp[lk] = []
            elif type(ptmp[lk]).__name__ != 'list':
                raise Exception(f"--setadd tks cannot be added to {ptmp[lk]} {type(ptmp[lk])} {list}")
            ptmp[lk].append(tks[1])

    return result

def merge_dict(d1,d2, overwrite=False):
    if type(d2) != dict or not d1:
        if d2 or d2 is not None:
            if overwrite and d2:
                return d2
            if d1:
                return d1
            return d2
        return d1
    d1.update({k:merge_dict(d1.get(k), v, overwrite=overwrite) for k,v in d2.items() if v is not None})
    return d1

def print_explanation(key, explain_dict):
    if explain_dict is None or not explain_dict:
        return
    if explain_dict.get('explain'):
        if key:
            print("{}:".format(key))
        for explain in explain_dict['explain']:
            print(explain)
        print("")
    for k in explain_dict:
        if k != 'explain':
            print_explanation(key + "/" + k, explain_dict[k])

def print_schema_documentaton(doc, fmt='json'):
    print("-------------------------------------------------------------------------------------------------------------------")
    if 'summary' in doc['documentation']:
        print('Summary')
        for summary in doc['documentation'].get('summary', ['-']):
            print("    {}".format(summary))
    if 'example' in doc['documentation']:
        print("Example")
        if fmt == 'json':
            print(json.dumps(doc['documentation']['example'], indent=4))
        else:
            print(yaml.dump(doc['documentation']['example'], indent=4))
    print("-------------------------------------------------------------------------------------------------------------------")
    print_explanation("", doc['sampleconfig'])
    if 'notes' in doc['documentation']:
        print('Note:')
        for note in doc['documentation'].get('notes', ['-']):
            print("    {}".format(note))

def generate_element_template(kind, apiversion, filename=None, print_doc=False, fmt='json', include_non_mandatory=False):
    try:
        r = None
        data_input = {}
        data_input['template'] = True
        data_input['kind'] = kind
        data_input['apiVersion'] = apiversion if apiversion else "mdcap.robin.io/v1"
        if print_doc:
            data_input['template_type'] = 2
        elif include_non_mandatory:
            data_input['template_type'] = 1
        hdrs = get_hdrs()
        r = requests.put("{}/elementschema/".format(sc.engine()), data=json.dumps(data_input), verify=False, headers=hdrs)
        r.raise_for_status()
        if print_doc:
            print_schema_documentaton(r.json(), fmt=fmt)
        else:
            if filename:
                with open(filename, 'w') as outfile:
                    if fmt == 'json':
                        json.dump(r.json()['sampleconfig'], outfile, indent=4)
                    elif fmt == 'yaml':
                        yaml.dump(r.json()['sampleconfig'], outfile, indent=4)
            else:
                return r.json()['sampleconfig']
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate schema.")

def get_alias_element_type(kind):
    if kind == 'network_function':
        return 'nf'
    if kind == 'NETWORK_FUNCTION':
        return 'NF'
    if kind == 'robincluster':
        return 'rc'
    if kind == 'ROBINCLUSTER':
        return 'RC'
    if kind == 'network_service':
        return 'ns'
    if kind == 'NETWORK_SERVICE':
        return 'NS'
    return kind

def showfile(url):
    r = requests.get(url, verify=False)
    r.raise_for_status()
    with tempfile.NamedTemporaryFile(suffix=".tmp") as t:
        t.write(bytes(r.content))
        t.flush()
        call([sc.editor(), '-R', t.name])

def common_validate(element_uid, schema_uid, kind, apiversion, data_input):
    payload = {}
    payload["kind"] = kind
    payload["apiversion"] = apiversion if apiversion else "mdcap.robin.io/v1"
    payload["element_config"] = data_input
    payload["element_uid"] = element_uid
    if schema_uid:
        payload["schema_uid"] = schema_uid

    url = "{}/elementschema/validate".format(sc.engine())
    res = requests.put(url, data=json.dumps(payload), verify=False, headers=get_hdrs())

    return res

# returns (scheme, user, password, ip, path, params, query, fragment)
def parse_url(url):
    parsedUrl = namedtuple("parsedUrl", ["scheme", "user", "password", "ip", "path", "params", "query", "fragment"])
    res = None
    if url:
        # scheme://netloc/path;parameters?query#fragment
        result = urllib.parse.urlparse(url)
        netloc = result.netloc.split("@")
        #netloc should be ["user:pass", "[ip]:""]
        if len(netloc) > 1:
            username = netloc[0].split(":")[0]
            password = netloc[0].split(":")[1]
            ip = netloc[1].rstrip(":")
            res = parsedUrl(result.scheme, username, password, ip, result.path, result.params, result.query, result.fragment)
        else:
            ip = netloc.rstrip(":")
            # no user, pass in the url
            res = parsedUrl(result.scheme, None, None, ip, result.path, result.params, result.query, result.fragment)
    return res

def printProgress(transferred, toBeTransferred):
    print ("Downloaded: {}/{}".format(transferred, toBeTransferred))

def md5sum(filename):
    if not os.path.exists(filename):
        raise Exception(f"File {filename} not exists to check md5sum")
    md5, err, status = run_command("md5sum {}".format(filename))
    if status:
        raise Exception("Could not determine checksum, error: {}".format(err))
    return md5.split(" ")[0]

# md5checksum ??
def download_file_sshclient(user, password, ip, remotepath):
    localpath = '/tmp/' + os.path.basename(remotepath)
    sshclient = paramiko.SSHClient()
    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshclient.connect(ip, username=user, password=password, timeout=30)
    sftpclient = sshclient.open_sftp()
    #sftpclient.get(remotepath, localpath, callback=printProgress)
    sftpclient.get(remotepath, localpath)
    sftpclient.close()
    #print("file download complete for: {}:{}".format(ip,remotepath))
    return localpath

def download_file(url, force=False):
    localpath = '/tmp/' + os.path.basename(url)
    if not force and os.path.isfile(localpath):
        print("The file is already present on playground at: {}, please remove it or use --force to overwrite.".format(localpath))

    if os.path.isfile(url):
        #its not a url but a local file on the same host.
        return url
    elif url.startswith("scp"):
        parsedurl = parse_url(url)
        LOG.info("Downloading file: {} from host: {}, please wait".format(parsedurl.path, parsedurl.ip))
        if parsedurl:
            return download_file_sshclient(parsedurl.user,
                                    parsedurl.password,
                                    parsedurl.ip,
                                    parsedurl.path)
    elif url.startswith("https") or url.startswith("http"):
        LOG.info("Downloading file from sc.engine(): {}".format(url))
        with open(localpath, "wb") as wfd:
            r = requests.get(url, stream=True, allow_redirects=True)
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=8192):
                wfd.write(chunk)
        return localpath
    else:
        print("unknown protocol in sc.engine()")
    return None

# upload a file to robin artifactory
async def upload_file(url, filename):
    try:
        #headers = {'Authorization': os.environ.get('MDCAP_CDN_TOKEN', '')}
        with open(filename, 'rb') as fh:
            print("Uploading file to : {}".format(url))
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.put(url, data={"filename": fh}) as response:
                    response.raise_for_status()
                    print("File Upload Complete")
                    return True
    except Exception as e:
        print(f"Could not upload at {url} due to {e}")
        return False

# delete a file from robin artifactory
async def delete_file(url, filename):
    try:
        #headers = {'Authorization': os.environ.get('MDCAP_CDN_TOKEN', '')}
        with open(filename, 'rb') as fh:
            print("Delete file: {}".format(filename))
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.delete(url, data={"filename": fh}) as response:
                    response.raise_for_status()
                    print("File Delete Complete")
                    return True
    except Exception as e:
        print(f"Could not upload at {url} due to {e}")
        return False

# file : local file path
# type    : the artifact type
# name      : name to register with the DB
# artifactorynetloc: optional, network location "ip:port" for the artifactoy
def upload_to_robin_artifactory(url, file, type, name, artifactorynetloc=None):
    return asyncio.get_event_loop().run_until_complete(upload_file(url, file))

# localpath : local file path
# type    : the artifact type
# name      : name to register with the DB
# version   : artifact file version
# artifactorynetloc: optional, network location "ip:port" for the artifactoy
# def delete_from_robin_artifactory(artifactoryurl):
#     upload_res = False
#     if artifactoryurl:
#         upload_res = asyncio.get_event_loop().run_until_complete(delete_file(url, localpath))
#     else:
#         print("please check the issue and try again")
#     return upload_res

def elem_format(elem, keys=[]):
    if type(elem) == type([]):
        for e in elem:
            yield from elem_format(e, keys)
    else:
        elem.update(elem.pop('metadata', {}))
        elem.update(elem.pop('status', {}))
        if keys:
            yield {key:elem[key] for key in keys}
        else:
            yield elem

@click.group(cls=ClickAliasedGroup)
def cli():
    global sc
    sc = ServerContext()

def run_command(cmd):
    # Make sure everything passed in is a string
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _out, _err = proc.communicate()
    out = _out.decode('utf-8') if _out else ''
    err = _err.decode('utf-8') if _err else ''
    status = proc.returncode
    return out, err, status


def read_csv_file(filepath, columndelimiter=',', rowdelimiter='\n'):
    if os.path.isfile(filepath):
        records = []
        with open(filepath, encoding='utf-8') as filepath:
            try:
                csvreader = csv.reader(filepath, delimiter=columndelimiter, quotechar=rowdelimiter)
                col_names = []
                for line in csvreader:
                    if not col_names:
                        for col in line:
                            col_names.append(col)
                    else:
                        col_index = 0
                        entry = {}
                        for col in line:
                            if "." in col_names[col_index]:
                                tokens = col_names[col_index].split(".")
                                tmp = entry
                                lasttoken = None
                                for token in tokens:
                                    if lasttoken:
                                        tmp = tmp[lasttoken]
                                    if token not in tmp:
                                        tmp[token] = {}
                                    lasttoken = token
                                tmp[lasttoken] = col
                            else:
                                entry[col_names[col_index]] = col
                            col_index+=1
                        records.append(entry)
            except Exception:
                raise Exception("File {} is not a properly formatted JSON and thus cannot be converted.".format(filepath))
        return records
    raise Exception("Path {} is not a file.".format(filepath))

def read_json_file(filepath):
    if os.path.isfile(filepath):
        with open(filepath) as json_file:
            try:
                return json.load(json_file)
            except Exception:
                raise Exception("File {} is not a properly formatted JSON and thus cannot be converted.".format(filepath))
    else:
        raise Exception("Path {} is not a file.".format(filepath))


def read_yaml_file(filepath):
    if os.path.isfile(filepath):
        with open(filepath) as yaml_file:
            try:
                return yaml.load(yaml_file, Loader=yaml.FullLoader)
            except Exception:
                raise Exception("File {} is not a properly formatted YAML and thus cannot be converted.".format(filepath))
    else:
        raise Exception("Path {} is not a file.".format(filepath))


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            exc.message = 'Failed to create dir ' + path
            raise exc

def generate_new_elem(kind):
    import textwrap
    blueprint = '''\
                from sanic import Blueprint
                from sanic.response import json, text
                from lib.element import list_elements, get_element
                from lib.utils.utils import parse_args
                from elements.newelem.models import NEWELEMElement
                from elements.models import GenerateWorkflow
                from blueprints.utils.utils import get_auth_headers, get_parameters
                from sanic_openapi import doc
                from sanic_openapi.doc import RouteField
                from sanic.exceptions import ServerError
                from lib.jsonvalidator.schema_matcher import validate_element_schema_wrapper
                from lib.task import trigger_workflow
                from elements.newelem.lib import NEWELEM

                bp_version1 = Blueprint('newelem')

                @bp_version1.get('/')
                @doc.route(
                    summary="Fetches all NEWELEMs",
                    description="NEWELEMs fetched depends on user role and privileges",
                    consumes_content_type=["application/json"],
                    produces_content_type=["application/json"],
                    consumes=get_auth_headers(),
                    response=[
                        [200, RouteField([NEWELEMElement], "body", True, "List of NEWELEM objects")],
                        [401, RouteField({"code": int}, "", "", "User is not authorized to fetch NEWELEMs")],
                        [500, RouteField({"code": int, "error": str}, "", "", "Internal server error")]
                    ],
                    operation="get_all_newelems"
                )
                async def get(request):
                    args = parse_args(request)
                    rows = await list_elements(request.app.db, request.ctx.uid, request.ctx.roles[0], kind=NEWELEM._KIND, limit=args['limit'], offset=args['offset'], total_count=args['total'], labels=args['labels'], match=args.get('match'))
                    return json(rows)

                @bp_version1.get('/<uid>')
                @doc.route(
                    summary="Fetches a NEWELEM with UID",
                    description="NEWELEM describes ssh configuration required for access",
                    consumes_content_type=["application/json"],
                    produces_content_type=["application/json"],
                    consumes=get_auth_headers(),
                    response=[
                        [200, RouteField(NEWELEMElement, "body", True, "NEWELEMElement object")],
                        [401, RouteField({"code": int}, "", "", "User is not authorized to retrieve a NEWELEM with UID")],
                        [403, RouteField({"code": int}, "", "", "User does not have access to the specified NEWELEM")],
                        [404, RouteField({"code": int}, "", "", "Specified NEWELEM not found")],
                        [500, RouteField({"code": int, "error": str}, "", "", "Internal server error")]
                    ],
                    operation="get_newelem"
                )
                async def info(request, uid):
                    evaluate = True if request.args and request.args.get("evaluate", "false").lower() == "true" else False
                    elem = await get_element(request.app.db, request.ctx.uid, request.ctx.roles[0], uid, access_control=False, kind=NEWELEM._KIND, evaluate=evaluate)
                    return json(elem.todict())

                @bp_version1.post('/')
                @doc.route(
                    summary="Register a new NEWELEM",
                    description="Once NEWELEM element is registered, its available for life cycle management",
                    consumes_content_type=["application/json"],
                    produces_content_type=["application/json"],
                    consumes=get_parameters([
                        RouteField({'newelem': NEWELEMElement}, location="body", description="Payload which describes NEWELEM")
                    ]),
                    response=[
                        [200, RouteField({"type": str, "name": str, "id": str, "msg": str}, "body", True, "NEWELEM registration message")],
                        [401, RouteField({"code": int}, "", "", "User is not authorized to register a NEWELEM")],
                        [400, RouteField({"code": int}, "", "", "Invalid API payload sent to register for NEWELEM")],
                        [409, RouteField({"code": int}, "", "", "NEWELEM with the given name already exists")],
                        [403, RouteField({"code": int}, "", "", "Insufficient privileges to register a NEWELEM")],
                        [500, RouteField({"code": int, "error": str}, "", "", "Internal server error")]
                    ],
                    operation="register_newelem"
                )
                @validate_element_schema_wrapper(NEWELEM._KIND)
                async def add(request):
                    payload = request.json
                    _id, name = await NEWELEM.add(request.app.db, request.ctx.uid, request.ctx.roles[0], payload, access_control=False)
                    return json({"kind": NEWELEM._KIND, "name": name, "id": _id, "msg": "Successfully registered NEWELEM {} with id {}".format(name, _id)})


                @bp_version1.delete('/<uid>')
                @doc.route(
                    summary="Unregister a NEWELEM with UID",
                    description="Once a NEWELEM is unregistered, its no longer available in the system for life cycle management.",
                    consumes_content_type=["application/json"],
                    produces_content_type=["application/json"],
                    consumes=get_auth_headers(),
                    response=[
                        [200, RouteField(str, "body", True, "NEWELEM unregistration message")],
                        [401, RouteField({"code": int}, "", "", "User is not authorized to unregister the NEWELEM")],
                        [404, RouteField({"code": int}, "", "", "Specified NEWELEM not found")],
                        [403, RouteField({"code": int}, "", "", "Insufficient privileges to unregister a NEWELEM")],
                        [500, RouteField({"code": int, "error": str}, "", "", "Internal server error")]
                    ],
                    operation="unregister_newelem"
                )
                async def delete(request, uid):
                    await NEWELEM.delete(request.app.db, request.ctx.uid, request.ctx.roles[0], uid, access_control=False)
                    return text(f"Successfully unregistered NEWELEM '{uid}'")

                @bp_version1.put('/<uid>')
                @doc.route(
                    summary="Update NEWELEM",
                    description="Various attributes of NEWELEM can be updated.",
                    consumes_content_type=["application/json"],
                    produces_content_type=["application/json"],
                    consumes=get_parameters([
                        RouteField({'newelem': NEWELEMElement}, location="body", description="Payload which describes updated NEWELEM")
                    ]),
                    response=[
                        [200, RouteField(str, "body", True, "NEWELEM update message")],
                        [401, RouteField({"code": int}, "", "", "User is not authorized to update NEWELEM")],
                        [404, RouteField({"code": int}, "", "", "Specified NEWELEM not found")],
                        [403, RouteField({"code": int}, "", "", "Insufficient privileges to update a NEWELEM")],
                        [500, RouteField({"code": int, "error": str}, "", "", "Internal server error")]
                    ],
                    operation="update_newelem"
                )
                @validate_element_schema_wrapper(NEWELEM._KIND, modify=True)
                @trigger_workflow(NEWELEM._KIND)
                async def update(request, uid):
                    payload = request.json
                    _id = await NEWELEM.update(request.app.db, request.ctx.uid, request.ctx.roles[0], uid, payload, access_control=False, perm_check=False)
                    return json({"msg": f"Successfully updated NEWELEM with id '{_id}'", "kind": NEWELEM._KIND, "id": _id})

                @bp_version1.put('/')
                @doc.route(
                    summary="Generate workflow for NEWELEM",
                    description="There are 2 types of workflows: static and dynamic. Static workflow is designed by the user on MDCAP dashboard. "
                                "Dynamic workflow is automatically generated by MDCAP.",
                    consumes_content_type=["application/json"],
                    produces_content_type=["application/json"],
                    consumes=get_parameters([
                        RouteField({'generate_wf': GenerateWorkflow}, location="body", description="Payload which describes generation of dynamic workflow for NEWELEM")
                    ]),
                    response=[
                        [200, RouteField({"workflow": dict}, "body", True, "Workflow represented as a directed acyclic graph.")],
                        [401, RouteField({"code": int}, "", "", "User is not authorized to generate workflow for NEWELEM")],
                        [400, RouteField({"code": int}, "", "", "Invalid API payload sent to generate workflow for NEWELEM")],
                        [404, RouteField({"code": int}, "", "", "Specified NEWELEM not found")],
                        [403, RouteField({"code": int}, "", "", "Insufficient privileges to generate a workflow for a NEWELEM")],
                        [500, RouteField({"code": int, "error": str}, "", "", "Internal server error")]
                    ],
                    operation="gen_wf_newelem"
                )
                async def generate_wf(request):
                    payload = request.json
                    for key in ['name', 'wf_name']:
                        if key not in payload:
                            raise ServerError("Key {} missing in payload.".format(key), status_code=400)
                    wf_name = payload['wf_name']
                    uids = payload['uids']
                    wf = await NEWELEM.generate_workflow(request.app.db, request.ctx.uid, request.ctx.roles[0], wf_name, uids)
                    return json(wf)
                '''
    libpy = '''\
            from elements.base import BaseElement
            # from lib.element import get_element, del_element, add_element_v2, update_element_v2
            # from lib.workflow import get_workflow
            # from lib.dynamic import get_dynamic_workflow
            # from lib.utils.utils import update_dictionary
            # from sanic.exceptions import ServerError

            class NEWELEM(BaseElement):
                SUPPORTED_WF_TYPES = []
                _KIND = 'NEWELEM'

                # @classmethod
                # async def add(cls, db, user_uid, role, elem, access_control=True):
                #     try:
                #         name = elem['metadata']['name']
                #         await cls.validate_spec(db, elem['spec'])
                #         uid = await add_element_v2(db, user_uid, role, elem, access_control=access_control)
                #     except ServerError as s:
                #         raise ServerError(f"Failed to add {cls._KIND}: {s.args[0]}", status_code = s.status_code)
                #     except Exception as ex:
                #         raise ServerError(f"Failed to add {cls._KIND}: {ex.args[0]}")

                #     return uid, name

                # @classmethod
                # async def update(cls, db, user_uid, role, uid, elem, access_control=True, perm_check=True):

                #     original_elem = await get_element(db, user_uid, role, elem_uid=uid, access_control=access_control, kind=cls._KIND)
                #     elem['spec'] = update_dictionary(original_elem.spec, elem.get('spec', {}))
                #     await cls.validate_spec(db, elem['spec'])

                #     try:
                #         uid = await update_element_v2(db, user_uid, role,
                #                 original_elem.uid, elem, access_control=False,
                #                 perm_check=perm_check,
                #                 original_elem=original_elem.todict())
                #     except Exception as ex:
                #         raise ServerError(f"Failed to update {cls._KIND}: {ex.args[0]}")

                #     return uid

                # @classmethod
                # async def delete(cls, db, user_uid, role_uid, uid, cascade=False, access_control=True):
                #     try:
                #         elem = await get_element(db, user_uid, role_uid, elem_uid=uid, kind=cls._KIND, access_control=access_control)
                #         if not elem:
                #             raise ServerError(f"{cls._KIND} with UID '{uid}' not found", status_code=404)

                #         await del_element(db, user_uid, role_uid, uid=uid, kind=cls._KIND, access_control=False)
                #     except ServerError:
                #         raise
                #     except Exception as ex:
                #         raise ServerError(f'Failed to delete {cls._KIND}: {ex.args[0]}')


                # @classmethod
                # async def generate_workflow(cls, db, user_uid, role_uid, wf_name, uids, access_control=True, update_payload=None, cached_db_elements=None):
                #     wf = await get_workflow(db, role_uid, name=wf_name, access_control=access_control)
                #     if cls._KIND not in wf.todict()['kinds']:
                #         raise ServerError("Workflow {} does not support the specified element's type".format(wf_name), status_code=400)
                #     if not update_payload:
                #         return await get_dynamic_workflow(db, user_uid, role_uid, wf, uids, cached_db_elements=cached_db_elements)
                #     if not isinstance(update_payload, list):
                #         update_payload = [update_payload]
                #     return await get_dynamic_workflow(db, user_uid, role_uid, wf, uids, user_payloads=update_payload, cached_db_elements=cached_db_elements)

                # @classmethod
                # async def validate_spec(cls, db, spec):
                #     pass

                # @classmethod
                # async def expand_config(cls, db, user_uid, role, uid, access_control=True, evaluate=False, return_elem=False):

                #     elem = await get_element(db, user_uid, role, elem_uid=uid, kind=cls._KIND, access_control=access_control, evaluate=evaluate)
                #     new_spec = elem.spec
                #     if return_elem:
                #         return elem
                #     return new_spec
            '''

    clipy = '''\
            from mdcapcli.cli_utils import cli, ClickAliasedGroup, click, \\
                add_options, common_options, get_hdrs, read_json_file, requests, \\
                sm, handle_error, compute_curl_command, json, open_in_editor, \\
                yaml, parse_labels, parameter_string, tabulate, \\
                offset_limit_from_range, os, tempfile, common_validate, ssl, \\
                print_nested, elem_format


            @cli.group(cls=ClickAliasedGroup)
            def newelem():
                """NEWELEM Management"""
                pass

            @newelem.command(aliases=['register'])
            @click.argument('config', type=click.File('r'))
            @add_options(common_options)
            def add(config, **kwargs):
                """Register a NEWELEM element"""
                try:
                    r = None
                    hdrs = get_hdrs()
                    data = json.load(config)
                    r = requests.post(f"{sc.engine()}/newelem", json=data, verify=False, headers=hdrs)
                    r.raise_for_status()
                    print(r.json()['msg'])
                except Exception as ex:
                    handle_error(ex)
                finally:
                    if kwargs.get('urlinfo') and r:
                        compute_curl_command(r, headers=hdrs, data=data)

            @newelem.command()
            @click.argument('uid', type=str)
            @add_options(common_options)
            def delete(uid, **kwargs):
                """Delete a NEWELEM element"""
                try:
                    r = None
                    hdrs = get_hdrs()
                    r = requests.delete(f"{sc.engine()}/newelem/{uid}", verify=False, headers=hdrs)
                    r.raise_for_status()
                    print(r.text)
                except Exception as ex:
                    handle_error(ex)
                finally:
                    if kwargs.get('urlinfo') and r:
                        compute_curl_command(r, headers=hdrs)

            @newelem.command()
            @click.option("--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
            @click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
            @click.option('-m', '--match', type=str, help="Partial filter match")
            @click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
            @add_options(common_options)
            def list(index, labels, match, output, **kwargs):
                """List all NEWELEM elements"""
                try:
                    r = None
                    hdrs = get_hdrs()
                    limit, offset = offset_limit_from_range(index)
                    labellist = parse_labels(labels)
                    query_params = [limit, offset, labellist]
                    if match:
                        query_params.append(f"match={match}")
                    limit_url = parameter_string(query_params)
                    r = requests.get("{}/newelem{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
                    r.raise_for_status()

                    if output == 'yaml':
                        print(yaml.dump(r.json(), indent=4))
                        return

                    if output == 'json':
                        print(json.dumps(r.json(), indent=4))
                        return
                    results = r.json()
                    if not results['items']:
                        print("No results found")
                        return
                    else:
                        print(tabulate(elem_format(results['items']), headers="keys"))
                        footer = '\\n--------------------------------------------\\n'
                        footer += "Displaying {}/{} elements from offset {}\\n".format(results['count'], results['limit'], results['offset'])
                        footer += '--------------------------------------------\\n'
                        print(footer)
                except Exception as ex:
                    handle_error(ex, action_msg="Failed to list newelems. ")
                finally:
                    if kwargs.get('urlinfo') and r:
                        compute_curl_command(r, headers=hdrs)

            @newelem.command()
            @click.argument('uid', type=str)
            @click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the NEWELEM config")
            @click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
            @add_options(common_options)
            def info(uid, output, evaluate, **kwargs):
                """Get information on a particular NEWELEM element"""
                try:
                    r = None
                    hdrs = get_hdrs()
                    evaluate_str = "?evaluate=true" if evaluate else ""
                    r = requests.get(f"{sc.engine()}/newelem/{uid}{evaluate_str}", verify=False, headers=hdrs)
                    r.raise_for_status()

                    if output == 'yaml':
                        print(yaml.dump(r.json(), indent=4))
                        return

                    if output == 'json':
                        print(json.dumps(r.json(), indent=4))
                        return
                    result = r.json()
                    if not result:
                        print("newelem '{}' does not exist".format(uid))
                    else:
                        #hdrs = ['uid', 'type', 'name', 'description']
                        print("Name: {}".format(result['metadata']['name']))
                        print("UUID: {}".format(result['metadata']['uid']))
                        print("Description: {}".format(result['metadata']['description'] if result['metadata']['description'] else "-"))
                        print()
                        if result['spec']:
                            print()
                            print("Additional Config:")
                            print_nested(result['spec'], indent=0)
                except Exception as ex:
                    handle_error(ex, action_msg="Failed to display information for newelem '{}'. ".format(uid))
                finally:
                    if kwargs.get('urlinfo') and r:
                        compute_curl_command(r, headers=hdrs)

            @newelem.command()
            @click.argument('uid', type=str)
            @click.option('--config', help="Path to file containing config details")
            @click.option('--ignore-wf', is_flag=True, help="Don't trigger workflow for this config update", default=False)
            @click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
            @add_options(common_options)
            def update(uid, config, output, ignore_wf, **kwargs):
                """Update a NEWELEM element"""
                try:
                    r = None
                    hdrs = get_hdrs()
                    if config:
                        data = read_json_file(config)
                    else:
                        data = open_in_editor(uid, edit_fmt=output)
                        if not data:
                            return

                    r = requests.put(f"{sc.engine()}/newelem/{uid}?ignorewf={str(ignore_wf)}", json=data, verify=False, headers=hdrs)
                    r.raise_for_status()
                    print(r.text)
                except Exception as ex:
                    handle_error(ex)
                finally:
                    if kwargs.get('urlinfo') and r:
                        compute_curl_command(r, headers=hdrs, data=data)

            @newelem.command()
            @click.option('--uid', type=str, help="UID of NEWELEM to be modified")
            @click.option("--schema-uid", type=str, help="Validate the configuration using this schema uid")
            @click.option('--config', help="Path to file containing config details")
            @click.option('--apiversion', help="API Version against to validate", default="mdcap.robin.io/v1")
            @click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
            @add_options(common_options)
            def validate(uid, schema_uid, config, apiversion, output, **kwargs):
                """Validates new or modified NEWELEM element configuration"""
                try:
                    r = None
                    hdrs = get_hdrs()
                    if config:
                        data = read_json_file(config)
                    else:
                        data = open_in_editor(uid, edit_fmt=output)
                        if not data:
                            return

                    r = common_validate(uid, schema_uid, "newelem", apiversion, data)
                    r.raise_for_status()
                    print(r.json())

                except Exception as ex:
                    handle_error(ex)
                finally:
                    if kwargs.get('urlinfo') and r:
                        compute_curl_command(r, headers=hdrs, data=data)

            @newelem.command()
            @click.argument('name', type=str)
            @click.argument('workflow', type=str)
            @click.option("--output-file", help="Output file to dump generated workflow to")
            @add_options(common_options)
            def generate(name, workflow, output_file, **kwargs):
                """Generate a config file for a dynamic workflow of a NEWELEM"""
                try:
                    r = None
                    hdrs = get_hdrs()
                    data = {
                        'name': name,
                        'wf_name': workflow
                    }
                    r = requests.put(f"{sc.engine()}/newelem", json=data, headers=hdrs, verify=False)
                    r.raise_for_status()
                    if output_file:
                        with open(output_file, 'w') as outfile:
                            json.dump(r.json(), outfile)
                    else:
                        print(json.dumps(r.json(), indent=4))
                except Exception as ex:
                    handle_error(ex, action_msg="Failed to generate workflow {} for NEWELEM {}. ".format(workflow, name))
                finally:
                    if kwargs.get('urlinfo') and r:
                        compute_curl_command(r, headers=hdrs, data=data)


            @newelem.command(name="import")
            @click.argument('filename', type=str)
            @add_options(common_options)
            def import_newelems(filename, **kwargs):
                """Import NEWELEMs from a file"""
                if not os.path.exists(filename):
                    raise Exception("No file found at specified location: {}".format(filename))
                with open(filename, 'r') as fh:
                    newelems = json.load(fh)
                    print(f"Importing {len(newelems)} newelems...")
                    for newelem in newelems:
                        try:
                            r, hdrs = None, get_hdrs()
                            data = newelem
                            r = requests.post(f"{sc.engine()}/newelem", json=data, verify=False, headers=hdrs)
                            r.raise_for_status()
                            print(r.json()['msg'])
                        except Exception as ex:
                            handle_error(ex)
                        finally:
                            if kwargs.get('urlinfo') and r:
                                compute_curl_command(r, headers=hdrs, data=data)

            '''

    models_py = '''\
                from elements.models import *

                class NEWELEMElement:
                    pass
                '''

    schema_py = '''\
                {
                    "name": "NEWELEM_schema"
                }
                '''
    kind = kind.lower()
    mkdir_p(kind)
    with open(f"{kind}/blueprint.py", "w+") as f:
        f.write(textwrap.dedent(blueprint.replace('NEWELEM', kind.upper()).replace('newelem', kind)))
    with open(f"{kind}/lib.py", "w+") as f:
        f.write(textwrap.dedent(libpy.replace('NEWELEM', kind.upper()).replace('newelem', kind)))
    with open(f"{kind}/cli.py", "w+") as f:
        f.write(textwrap.dedent(clipy.replace('NEWELEM', kind.upper()).replace('newelem', kind)))
    with open(f"{kind}/schema.json", "w+") as f:
        f.write(textwrap.dedent(schema_py.replace('NEWELEM', kind.upper()).replace('newelem', kind)))
    with open(f"{kind}/models.py", "w+") as f:
        f.write(textwrap.dedent(models_py.replace('NEWELEM', kind.upper()).replace('newelem', kind)))
    print(f"Element {kind} scaffolding has been created. Edit as required and then tar the folder to add the element to MDCAP")

def cprint(message, c1, c2, flag=False):
    if c2 == sys.maxsize:
        message = "{} UNLIMITED".format(message)
        print(click.style(message))
        return

    if flag:
        message = "{} {}/{}".format(message, mem_val(c1, output_units="G", strict_output=True), mem_val(c2, output_units="G", strict_output=True))
    else:
        message = "{} {}/{}".format(message, c1, c2)
    if c1 < c2:
        print(click.style(message))
    elif c1 == c2:
        print(click.style(message, fg='yellow'))
    else:
        print(click.style(message, fg='white', bg='red'))

def mem_val(size, output_units=None, strict_output=False, precision=None):
    s = human_readable(size, type="MEM", output_units=output_units, strict_output=strict_output, precision=precision)
    return s.replace('bytes', 'B')

def drive_val(size, output_units=None, strict_output=False):
    s = human_readable(size, output_units=output_units, strict_output=strict_output)
    return s.replace('bytes', 'B')

def human_readable(size, type='MEM', input_units='bytes', output_units=None, precision=None, strict_output=False):
    """
    Format a disk/file/memory size value (converted to bytes) into a 'human' readable
    format. Note that unless output_units is specified, the formatted value will be the
    largest granularity unit level (e.g., 8.64 TB vs 8641.77 GB). When the output value is
    'bytes', the formatted value will be a whole number. For formatted values that are
    KB and above, the value will have a default precision of two digits. You can pass in a
    custom precision number to override.
    """
    if size == 0:
        return "-"

    negative = False
    if size < 0:
        negative = True
        size *= -1

    suffix_table_storage = [('bytes', 0), ('K', 0), ('M', 0), ('G', 0), ('T', 0), ('P', 0)]
    suffix_table_memory = [('bytes', 0), ('K', 0), ('M', 0), ('G', 0), ('T', 0), ('P', 0)]

    def suffix_table_index(units):
        for s in suffix_table_storage:
            if units[0].upper() == s[0].upper():
                return suffix_table_storage.index(s)
        for s in suffix_table_memory:
            if units.upper() == s[0].upper():
                return suffix_table_memory.index(s)
        raise Exception('Invalid unit type: \'{0}\''.format(units))

    default_precision = 0
    suffix = 'bytes'

    if type.upper() in ('MEM', 'MEMORY'):
        units = 1024.0
        suffix_table = suffix_table_memory
    elif type.upper() in ('DRIVE', 'DISK', 'FILE'):
        units = 1000.0
        suffix_table = suffix_table_storage
    else:
        raise Exception('Invalid type: \'{0}\''.format(type))

    # normalize size to bytes
    if input_units == 'bytes':
        size_bytes = size
    else:
        suffix_index = suffix_table_index(input_units)
        unit_size = units ** suffix_index
        size_bytes = size * unit_size

    # check to see if there is any output constraint
    output_suffix = None
    if output_units:
        suffix_index = suffix_table_index(output_units)
        output_suffix = suffix_table[suffix_index][0]

    num = float(size_bytes)
    for suffix, default_precision in suffix_table:
        strict = False if strict_output else (num < units)
        if (output_suffix == suffix) or strict:
            break
        num /= units

    # Use default precision if not provided
    if not precision:
        if num < 1 and strict_output:
            precision = 2
        else:
            precision = default_precision

    if precision == 0:
        formatted_size = "%d" % num
    else:
        formatted_size = str(round(num, ndigits=precision))

    if negative:
        formatted_size = "-{}".format(formatted_size)

    return "%s%s" % (formatted_size, suffix)

class LicenseState(object):

    EXPIRED = "EXPIRED"
    VIOLATED = "VIOLATED"
    NOT_ACTIVATED = "NOT ACTIVATED"
    EXPIRED_WITH_GRACE = "EXPIRED_WITH_GRACE"
    GOOD = "OK"
    EXPIRED_FORCEFULLY = "FORCEFULLY EXPIRED"

def mask_sensitive_data(message, mask_keys=['password', 'root_password', 'robin_password']):
    from collections import deque
    if not isinstance(message, dict):
        return
    q = deque()
    q.append(message)
    while len(q) > 0:
        node = q.popleft()
        for key in node:
            if key.lower() in mask_keys:
                if isinstance(node[key], str) and not node[key].startswith("vault@"):
                    node[key] = "******"
                elif isinstance(node[key], dict):
                    for k, v in node[key].items():
                        if isinstance(node[key][k], str):
                            node[key][k] = "******"
            elif isinstance(node[key], dict):
                q.append(node[key])
    return

_URLPATH_POLICY_TEMPLATE = 'policytemplate'
_URLPATH_POLICY = 'policy'

def _login(userid, password, keycloak, timeout):
    """Login into MDCAP"""
    if keycloak:
        CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
        SERVER = os.getenv("KEYCLOAK_SERVER")
        REDIRECT_URI = os.getenv("KEYCLOAK_REDIRECT_URI")
        REALM = os.getenv("KEYCLOAK_REALM")

        err = False
        for mkey in ["KEYCLOAK_SERVER", "KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID", "KEYCLOAK_REDIRECT_URI"]:
            if not os.getenv(mkey):
                err = True
                click.secho(f"ERROR: Environment variable '{mkey}' not defined", fg="red")
        if err:
            exit(1)
        if SERVER[-1] != '/':
            SERVER += '/'
        try:
            provider = f"{SERVER}auth/realms/{REALM}"
            payload = {
                    "response_type": "code",
                    "client_id": CLIENT_ID,
                    "scope": "openid",
                    "redirect_uri": REDIRECT_URI,
            }
            payload_str = "&".join("%s=%s" % (k,v) for k,v in payload.items())
            resp = requests.get(
                url = provider + "/protocol/openid-connect/auth",
                params = payload_str,
                allow_redirects=False,
                verify=False
            )
            resp.raise_for_status()
            cookie = resp.headers['Set-Cookie']
            cookie = '; '.join(c.split(';')[0] for c in cookie.split(', '))
            page = resp.text
            form_action = html.unescape(re.search('<form\s+.*?\s+action="(.*?)"', page, re.DOTALL).group(1))
            resp = requests.post(
                url=form_action,
                data={
                    "username": userid,
                    "password": password,
                },
                headers={"Cookie": cookie},
                allow_redirects=False,
                verify=False
            )
            resp.raise_for_status()
            redirect = resp.headers['Location']
            query = urllib.parse.urlparse(redirect).query
            redirect_params = urllib.parse.parse_qs(query)
            auth_code = redirect_params['code'][0]
            data = {'auth_code': auth_code}
        except Exception:
            print("Keycloak login failed")
            exit(1)
    else:
        data = {'userid': userid, 'password': password}
    try:
        if timeout:
            data['timeout'] = timeout
        resp = requests.post(f"{sc.engine()}/login", json=data, verify=False)
        resp.raise_for_status()
        r = resp.json()
        print("Login successful! MDCAP is all yours.")
        sc.set_creds(r['token'], r['roleuid'])
    except Exception as ex:
        handle_error(ex)
        if "expired" in ex.response.content.decode('utf-8'):
            print("Use: mdcap change-password <username>")
        exit(1)
    try:
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/login", verify=False, headers=hdrs)
        r.raise_for_status()
        resp = r.json()
        print(f"Username: {resp['username']}")
        cur_role = [(r[0], r[1]) for r in resp['roleinfo'] if r[0] == resp['current_role']]
        if len(cur_role):
            print(f"Current Role: {cur_role[0][1]}, uid: {cur_role[0][0]}")
        else:
            print("No role assigned to this user. Please ask admin to assign a role.")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to access information about self.")


@cli.group(cls=ClickAliasedGroup, aliases=['sc'])
def server_context():
    """Manage server contexts"""
    pass

@server_context.command(name="set")
@click.argument("name", type=str)
@click.argument("mdcap-url", type=str)
@click.option('-u', '--userid', type=str)
@click.option('-p', '--password', hide_input=True)
@click.option('-k', '--keycloak', is_flag=True)
@click.option('-t', '--timeout', type=int, help="Timeout of issued token, in seconds")
@click.option('-d', '--default', is_flag=True, type=bool, default=False, help="Make this the default connection context")
def set(name, mdcap_url, userid, password, keycloak, timeout, default):
    """Add or update a new MDCAP server connection context"""
    try:
        ServerContext().set_context(name.lower(), url=mdcap_url, default=default)
        if (userid and password) or keycloak:
            _login(userid, password, keycloak, timeout)
    except Exception as ex:
        handle_error(ex)

@server_context.command(name="list")
@click.option('-o', '--format', type=click.Choice(['json', 'yaml']))
def lst(format):
    """List all the registered MDCAP server connection contexts"""
    try:
        if format == 'json':
            print(json.dumps(ServerContext().contexts, indent=4))
        elif format == 'yaml':
            print(yaml.dump(ServerContext().contexts, indent=4))
        else:
            hdrs = ["Name", "Endpoint", "Default"]
            vals = []
            for name, ctx in ServerContext().contexts.items():
                vals.append((name, ctx['mdcap_base_url'], ctx.get('default', False)))
            print(tabulate(vals, headers=hdrs))
    except Exception as ex:
        handle_error(ex)

@server_context.command(name="makedefault")
@click.argument('name')
def makedefault(name):
    """Set a default server context"""
    try:
        ServerContext().set_context(name.lower(), default=True)
    except Exception as ex:
        handle_error(ex)

@server_context.command(name="remove")
@click.argument('name')
def remove(name):
    """Remove a server context from the list"""
    try:
        ServerContext().del_context(name.lower(), default=True)
    except Exception as ex:
        handle_error(ex)

@cli.command(name="change-password")
@click.argument("userid", type=str)
@click.option('-o', '--old-password', prompt=True, hide_input=True, required=True)
@click.option('-n', '--new-password', prompt=True, hide_input=True, required=True)
@click.option('-e', '--expiry', type=str, help="Expiry of the new password. Format: Ad:Bh:Cm:Ds. A is #days, B is #hours, C is #minutes, D is #seconds")
def change_password(userid, old_password, new_password, expiry, **kwargs):
    """Change user password"""
    try:
        r = None
        data = {}
        data['opcode'] = 'change-password'
        data['userid'] = userid
        data['new_password'] = new_password
        data['old_password'] = old_password
        if expiry:
            data['expiry'] = parse_time(expiry)
        r = requests.post(f"{sc.engine()}/login/reset", json=data, verify=False)
        r.raise_for_status()
        resp = r.json()
        print(resp['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, data=data)

@cli.command()
@click.argument("userid", type=str)
@click.option('-p', '--password', prompt=True, hide_input=True, required=True)
@click.option('-k', '--keycloak', is_flag=True)
@click.option('-t', '--timeout', type=int, help="Timeout of issued token, in seconds")
def login(userid, password, keycloak, timeout):
    """Login into MDCAP"""
    _login(userid, password, keycloak, timeout)


@cli.command(name="login-auth-code")
@click.argument("authcode", type=str, required=True)
def login_authcode(authcode):
    """Login via Keycloak Auth Code"""
    data = {'auth_code': authcode}
    try:
        resp = requests.post(f"{sc.engine()}/login", json=data, verify=False)
        resp.raise_for_status()
        r = resp.json()
        print("Login successful! MDCAP is all yours.")
        config = {}
        sc.set_creds(r['token'], r['roleuid'])
    except Exception as ex:
        handle_error(ex)

@cli.group(cls=ClickAliasedGroup)
def audit():
    """User-Audit Information"""
    pass

@audit.command()
@click.option("-u", "--userid", type=str, help="User UID to audit")
@click.option("-s", "--sort", type=str, help="'asc' for First-In First-Out or 'desc' Last-In First-Out")
@click.option("-i", "--resid", type=str, help="Resource ID to audit. For ex. element UID, batchid, wf_tracker, poolid, etc.")
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@add_options(common_options)
def list(userid, sort, resid, index, **kwargs):
    '''Print the User-Audit information on the console'''
    try:
        resp = None
        hdrs = get_hdrs()
        url = f"{sc.engine()}/audit"
            
        if userid or resid or sort or index:
            url += "?"
            args_list = []
            if userid:
                args_list.append(f"userid={userid}")
            if resid:
                args_list.append(f"res_id={resid}")
            if sort:
                args_list.append(f"ordering={sort}")
            if index:
                limit, offset = offset_limit_from_range(index)
                if limit is not None:
                    args_list.append(limit)
                if offset is not None:
                    args_list.append(offset)
            url += '&'.join(args_list)

        resp = requests.get(url, verify=False, headers=hdrs)
        resp.raise_for_status()
        r_list = resp.json() # [[],[],..]
        if not r_list:
            print("No records found!")
            return
        # Convert timestamps to human-readable format
        for r in r_list:
            r[-1] = time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(int(r[-1])))
        # print(f"r_list: {r_list} \n r_list_type:{type(r_list)}")

        # if not output: # print to console
        headers = ['User ID', 'Action', 'Resource ID', 'Action Time']
        print(tabulate(r_list, headers=headers, tablefmt='presto'))

    except Exception as ex:
        handle_error(ex, action_msg="Error Obtaining User-Audit Information")
    finally:
        if kwargs.get('urlinfo') and resp:
            compute_curl_command(resp, headers=hdrs, ignore_response=True)

@audit.command()
@click.option("-u", "--userid", type=str, help="User UID to audit")
@click.option("-s", "--sort", type=str, help="'asc' for First-In First-Out or 'desc' Last-In First-Out")
@click.option("-o", "--output", required=True, type=click.Choice(['json', 'csv']), help="Output file format")
@click.option("-i", "--resid", type=str, help="Resource ID to audit. For ex. element UID, batchid, wf_tracker, poolid, etc.")
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@add_options(common_options)
def save(userid, sort, output, resid, index, **kwargs):
    '''Save the User-Audit information to a file'''
    try:
        resp = None
        hdrs = get_hdrs()
        url = f"{sc.engine()}/audit"

        if userid or resid or sort or index:
            url += "?"
            args_list = []
            if userid:
                args_list.append(f"userid={userid}")
            if resid:
                args_list.append(f"res_id={resid}")
            if sort:
                args_list.append(f"ordering={sort}")
            if index:
                limit, offset = offset_limit_from_range(index)
                if limit is not None:
                    args_list.append(limit)
                if offset is not None:
                    args_list.append(offset)
            url += '&'.join(args_list)
        
        resp = requests.get(url, verify=False, headers=hdrs)
        resp.raise_for_status()
        r_list = resp.json() # [[],[],..]
        if not r_list:
            print("No records found!")
            return
        # Convert timestamps to human-readable format
        for r in r_list:
            r[-1] = time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(int(r[-1])))

        if output == 'csv':
            csv_columns=['userid', 'action', 'res_id', 'action_time']
            if userid:
                csv_file = f"/tmp/{userid}_audit_{int(time.time())}.csv"
            else:
                csv_file = f"/tmp/audit_{int(time.time())}.csv"
            try:
                with open(csv_file, 'w') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(csv_columns)
                    writer.writerows(r_list)
                print(f"Saved csv file at {csv_file}")
            except Exception as e:
                handle_error(e, action_msg="CSV I/O Error")

        elif output == 'json':
            mapped_list = []
            r_keys = ['userid', 'action', 'res_id', 'action_time']
            for r in r_list:
                r_dict = {r_keys[i]: r[i] for i in range(len(r_keys))}
                mapped_list.append(r_dict)
            if userid:
                json_file = f"/tmp/{userid}_audit_{int(time.time())}.json"
            else:
                json_file = f"/tmp/audit_{int(time.time())}.json"
            try:
                with open(json_file, "w") as jsonfile:
                    json.dump(mapped_list, jsonfile, ensure_ascii=False, indent=4)
                print(f"Saved json file at {json_file}")
            except Exception as e:
                handle_error(e, action_msg="JSON I/O Error")
        else:
            print("Unknown format given for audit info")
            
    except Exception as ex:
        handle_error(ex, action_msg="Error Obtaining User-Audit Information")
    finally:
        if kwargs.get('urlinfo') and resp:
            compute_curl_command(resp, headers=hdrs, ignore_response=True)

@cli.command()
def logout():
    """Logout out of MDCAP"""
    sc.set_creds(None, None)

@cli.command()
@add_options(common_options)
def version(**kwargs):
    """Display MDCAP version information"""
    try:
        r = None
        r = requests.get(f"{sc.engine()}/version", verify=False)
        r.raise_for_status()
        results = r.json()
        if not results.get('version'):
            raise Exception("Version not returned from server.")
        else:
            print(f"MDCAP Version: {results['version']}")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to retrieve version. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r)

@cli.command(name="use-role")
@click.argument("uid", type=str, required=True)
@add_options(common_options)
def use_role(uid, **kwargs):
    """Use particular role"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/login", verify=False, headers=hdrs)
        r.raise_for_status()
        resp = r.json()
        new_role = [(r[0], r[1]) for r in resp['roleinfo'] if r[0] == uid]
        if not len(new_role):
            print(f"{uid} not in your list of allowed roles. Please use a valid role uid")
            return
    except Exception as ex:
        handle_error(ex, action_msg="Unable to retrieve user information")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)
        return

    try:
        config = {}
        r = requests.get(f"{sc.engine()}/login/role/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        resp = r.json()
        sc.set_creds(resp['token'], resp['roleuid'])
        print(f"Role is now: {resp['roleuid']}")
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to update current role. Check {sc.MDCAP_CONFIG_PATH}. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@cli.command()
@add_options(common_options)
def whoami(**kwargs):
    """Find Out Info About Logged in User"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/login", verify=False, headers=hdrs)
        r.raise_for_status()
        resp = r.json()
        fname = resp['fname']
        lname = resp['lname']
        username = resp['username']
        current_role = resp['current_role']
        if fname:
            pprint(f"First Name: {fname}")
        if lname:
            pprint(f"Last Name: {lname}")
        pprint(f"Username: {username}")
        cur_role = [(r[0], r[1]) for r in resp['roleinfo'] if r[0] == current_role]
        if len(cur_role):
            pprint(f"Current Role: {cur_role[0][1]}, uid: {cur_role[0][0]}")
        else:
            pprint(f"Current Role: {current_role}")
        print(tabulate(resp['roleinfo'], headers=['role id', 'rolename', 'privileges']))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to access information about self. Check if Logged in. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


# @cli.group(cls=ClickAliasedGroup)
# def job():
#     """Job Management"""
#     pass

@cli.group(cls=ClickAliasedGroup)
def task():
    """Task Management"""
    pass

@cli.group(cls=ClickAliasedGroup)
def batch():
    """Batch Management"""
    pass

@cli.group(cls=ClickAliasedGroup)
def worker():
    """Worker Management"""
    pass

@cli.group(cls=ClickAliasedGroup, aliases=['wp'])
def workerprofile():
    """Worker Profile Management"""
    pass

@cli.group(cls=ClickAliasedGroup)
def trigger():
    """System Trigger Management"""
    pass

@cli.group(cls=ClickAliasedGroup, aliases=['pl'])
def prioritylane():
    """Priority Lane Management"""
    pass

def add_dummy_script():

    try:
        hdrs = get_hdrs()
        data = {
            'name': "robin_placeholder",
            'version': "mdcap.robin.io/v1",
            'script': "dummy.sh",
            'operator': "shell",
            'etypes': ['VM', 'SWITCH', 'BM', 'VRAN', 'ROBINCLUSTER', 'GC', 'NFP'],
            'description': "Placeholder script for workflow execution",
            'fanout': 10
        }

        r = requests.post(f"{sc.engine()}/fn", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
    except Exception as e:
        print("Dummy script addition failed: {}".format(e))

# @task.command(aliases=['execute', 'run'])
# @click.option('-w', '--workflow', type=str, help="Name/UID of the workflow to execute")
# @click.option('-f', '--function', type=str, help="Name/UID of the function to execute")
# @click.option('-p', '--runtime-params-file', type=str, help="Runtime parameters needed for workflow execution")
# @click.option('--set', type=str, multiple=True, help="Set envs for function execution")
# @click.option('-e', '--element-uid', type=str, help="Element uid to execute workflow with. Valid only for dynamic workflows")
# @click.option('-n', '--notification_urls', type=str, help="Notification URLs specified in json string or in a file")
# @add_options(common_options)
# def add(workflow, function, runtime_params_file, set, element_uid, notification_urls, **kwargs):
#     """Execute a function/workflow on a single element"""
#     try:
#         if function and workflow:
#             print("Please specify either function or workflow to execute")
#             return
#         if not function and not workflow:
#             print("Please specify either function or workflow to execute")
#             return
#         r = None
#         hdrs = get_hdrs()
#         if runtime_params_file:
#             config = read_json_file(runtime_params_file)
#         else:
#             config = create_dict_fromkeys(set, [])

#         data = {
#             'env': config,
#             'element_uid': element_uid
#         }
#         if function:
#             data['function'] = function
#         elif workflow:
#             data['workflow'] = workflow
#         if notification_urls:
#             if os.path.isfile(notification_urls):
#                 data['notification_urls'] = read_json_file(notification_urls)
#             else:
#                 try:
#                     data['notification_urls'] = json.loads(notification_urls)
#                 except Exception:
#                     print("Argument: notification_urls is not valid json string")

#         r = requests.post(f"{sc.engine()}/task", json=data, verify=False, headers=hdrs)
#         r.raise_for_status()
#         res = r.json()
#         click.secho("TaskID: ", nl=False, fg="green")
#         click.secho(res['taskid'])
#     except Exception as ex:
#         handle_error(ex, action_msg="Failed to add task. ")
#     finally:
#         if kwargs.get('urlinfo') and r:
#             compute_curl_command(r, headers=hdrs, data=data)

@task.command()
@click.argument('taskid', type=str)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(taskid, output, **kwargs):
    """Get task info"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/task/{taskid}", verify=False, headers=hdrs)
        r.raise_for_status()
        r = r.json()

        if output == 'yaml':
            print(yaml.dump(r, indent=4))
            return
        if output == 'json':
            print(json.dumps(r, indent=4))
            return
        print("Name                 : {}".format(r['name']))
        print("TaskID               : {}".format(r['taskid']))
        print("Status               : {}".format(r['status']))
        print("Start Time           : {}".format(r['start_time']))
        if r['start_time'] and r['end_time']:
            print("Duration             : {}".format(r['end_time'] - r['start_time']))
        else:
            print("Duration             : -")
        if r['errmsg']:
            print("Error                : {}".format(r['errmsg']))
        if r['fn_uid']:
            print("Function UID         : {}".format(r['fn_uid']))
        if r['wf_uid']:
            print("Workflow UID         : {}".format(r['wf_uid']))
        print("Element UID          : {}".format(r['element_uid']))
        if r['batchid']:
            # single worker for fn execution
            print("Worker:              : {}".format(f"dcapworker{r['batchid'][0:6]}"))
        else:
            # multiple workers for wf execution, one for each node in wf
            print("Worker(s)            :\n")
            _, batches = _get_workflow_nodes(r['config'], display_wf_stages=False, add_elements=True)
            workers = []
            for batch in batches:
                tw = []
                tw.append(batch[0])
                for item in batch[1].keys():
                    tw.append(f"dcapworker{item[0:6]}")
                workers.append(tw)
            print(tabulate(workers, ["WF Node ID", "Worker"]))


    except Exception as ex:
        handle_error(ex, action_msg="Failed to retrieve status for task with id: {}. ".format(taskid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@task.command()
@click.argument('taskid', type=str)
@add_options(common_options)
def terminate(taskid, **kwargs):
    """Terminate a task"""

    print("Task terminate is not supported")
    # print("Task termination is best effort and it depends on the JOB status when the API was issued, this will abruptly terminate the workflow.")
    # ip = input("Are you sure you want to continue [y/n] ? ")
    # if ip.lower() in ['y', 'yes']:
    #     try:
    #         r = None
    #         hdrs = get_hdrs()
    #         data = {
    #             "action": "terminate"
    #         }
    #         r = requests.put(f"{sc.engine()}/task/{taskid}", json=data, verify=False, headers=hdrs)
    #         r.raise_for_status()
    #         print(f"Task: {taskid} has been terminated, Please confirm that task has been terminated with task list command.")
    #     except Exception as ex:
    #         handle_error(ex)
    #     finally:
    #         if kwargs.get('urlinfo') and r:
    #             compute_curl_command(r, headers=hdrs, data=data)

@task.command()
@click.argument('taskid', type=str)
@click.argument('action', type=click.Choice(['run_from_failed', 'run_all', 'run_only_failed', 'ignore_failed']))
@click.option("--json", 'output_json', default=False, help="Option to display output in JSON", is_flag=True)
@add_options(common_options)
def resume(taskid, action, output_json, **kwargs):
    """Resume a task"""

    print("Task resume is not supported")
    # try:
    #     r = None
    #     hdrs = get_hdrs()
    #     data = {
    #         'action': "resume",
    #         'resume_operation': action
    #     }
    #     r = requests.put(f"{sc.engine()}/task/{taskid}", json=data, headers=hdrs, verify=False)
    #     r.raise_for_status()
    #     resp = r.json()
    #     if output_json:
    #         print(json.dumps(resp, indent=4))
    #         return
    #     print(resp['msg'])
    # except Exception as ex:
    #     handle_error(ex)
    # finally:
    #     if kwargs.get('urlinfo') and r:
    #         compute_curl_command(r, headers=hdrs, data=data)


# @task.command()
# @click.argument('taskid', type=str)
# @add_options(common_options)
# def delete(taskid, **kwargs):
#     """Delete a task"""
#     try:
#         r = None
#         hdrs = get_hdrs()
#         r = requests.delete(f"{sc.engine()}/task/{taskid}", verify=False, headers=hdrs)
#         r.raise_for_status()
#         print(r.text)
#     except Exception as ex:
#         handle_error(ex, action_msg="Failed to delete task with id: {}. ".format(taskid))
#     finally:
#         if kwargs.get('urlinfo') and r:
#             compute_curl_command(r, headers=hdrs)

@task.command()
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(output, **kwargs):
    '''List all tasks'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/task", verify=False, headers=hdrs)
        r.raise_for_status()
        results = r.json()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        if not results['items']:
            print("No results found")
        else:
            for item in results['items']:
                item['taskid'] = item['taskid']
                if item["end_time"]:
                    item["duration"] = item["end_time"] - item["start_time"]
                else:
                    item["duration"] = '-'
                item.pop("end_time", None)
                item.pop("batchid", None)
                item["start_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item['start_time']))
            print(tabulate(results['items'], headers="keys"))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list tasks. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@task.command()
@click.argument('taskid', type=str)
@click.option('-w', '--worker', is_flag=True, help="See worker logs")
@click.option('-e', '--element', is_flag=True, help="See element logs")
@click.option('--stream', '-f', is_flag=True, help="Stream logs", default=False)
def logs(taskid, worker, element, stream):
    '''Stream task logs'''
    def _get_task_execution_info(config):
        _, batches = _get_workflow_nodes(config, display_wf_stages=False, add_elements=True)
        r = requests.get(f"{sc.engine()}/element/{task['element_uid']}", verify=False, headers=get_hdrs())
        r.raise_for_status()
        _element = r.json()
        inner_elements = []
        if _element['kind'] == 'ROBINCLUSTER':
            inner_elements = []
            for k, v in _element['spec']['infra'].items():
                inner_elements.append(v['elem_uid'])
        for batch in batches:
            batch[2] = [value for value in inner_elements if value in batch[2]]
        print(f"Please use below information to track logs for element: {task['element_uid']}")

        batch_logs = []
        hdrs = ["WF Node id", "Worker logs", "Element logs"]
        for batch in batches:
            worker_logs, element_logs = "", ""
            for item in batch[1].keys():
                worker_logs = worker_logs + f"mdcap batch logs {item} -w 1\n"
                # for element logs, pick correct element
                if batch[2]:
                    for element in batch[2]:
                        element_logs = element_logs + f"mdcap batch logs {item} -e {element}\n"
                else:
                    element_logs = element_logs + f"mdcap batch logs {item} -e {task['element_uid']}\n"
            batch_logs.append([batch[0], worker_logs, element_logs])
        print(tabulate(batch_logs, hdrs))

    try:
        # get task info
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/task/{taskid}", verify=False, headers=hdrs)
        r.raise_for_status()
        task = r.json()
        if not worker and not element:
            print("Please choose worker logs or element logs")
            return
        batchid = task['batchid']
        if worker:
            if not batchid:
                _get_task_execution_info(task['config'])
            else:
                if stream:
                    r = requests.get(f"{sc.logstore()}/stream/{batchid}/worker/worker1.log", stream=True, verify=False)
                else:
                    r = requests.get(f"{sc.logstore()}/{batchid}/worker/worker1.log", verify=False)
                r.raise_for_status()
                if stream:
                    for line in r.iter_lines():
                        # filter out keep-alive new lines
                        if line:
                            decoded_line = line.decode('utf-8')
                            print(decoded_line)
                else:
                    print(r.content.decode('utf-8'))
        elif element:
            # task can either be function or workflow
            if task['fn_uid']:
                poolid = 1
                r = requests.get(f"{sc.logstore()}/stream/{batchid}/{poolid}", stream=False, verify=False)
                r.raise_for_status()
                log_files = r.text.split(',')
                # batch mode
                if f"pool{poolid}.log" in log_files:
                    if stream:
                        r = requests.get(f"{sc.logstore()}/stream/{batchid}/{poolid}/pool{poolid}.log", stream=True, verify=False)
                    else:
                        r = requests.get(f"{sc.logstore()}/{batchid}/{poolid}/pool{poolid}.log", verify=False)
                # unit mode
                else:
                    if stream:
                        r = requests.get(f"{sc.logstore()}/stream/{batchid}/{poolid}/{task['element_uid']}.log", stream=True, verify=False)
                    else:
                        r = requests.get(f"{sc.logstore()}/{batchid}/{poolid}/{task['element_uid']}.log", verify=False)
                r.raise_for_status()
                if stream:
                    for line in r.iter_lines():
                        # filter out keep-alive new lines
                        if line:
                            decoded_line = line.decode('utf-8')
                            print(decoded_line)
                else:
                    print(r.content.decode('utf-8'))
            elif task['wf_uid']:
                _get_task_execution_info(task['config'])
    except Exception as ex:
        handle_error(ex)

@cli.group(cls=ClickAliasedGroup, aliases=['wf'])
def workflow():
    '''Workflow Management'''
    pass

@workflow.command(aliases=['register'])
@click.argument('jsonfile', type=click.File('r'))
@click.option('-t', "--type", type=click.Choice(['dynamic', 'static']), default='dynamic')
@add_options(common_options)
def add(jsonfile, type, **kwargs):
    '''Register a workflow'''
    try:
        r = None
        hdrs = get_hdrs()
        payload = json.loads(jsonfile.read())
        payload['type'] = type
        url = "{}/workflow".format(sc.engine())
        res = requests.post(url, json=payload, verify=False, headers=hdrs)
        res.raise_for_status()
        print(res.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add workflow. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=payload)

@workflow.command()
@click.argument('uid', type=str)
@click.option('-c', '--config', help="Path to file containing config details")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, output, **kwargs):
    '''Update a dynamic workflow'''
    try:
        res = None
        hdrs = get_hdrs()
        data = {}
        if config:
            data['input'] = read_json_file(config)
        else:
            mod = open_in_editor(uid, otype="workflow", param="input", edit_fmt=output)
            if not mod:
                return
            data['input'] = mod

        url = "{}/workflow/{}".format(sc.engine(), uid)
        res = requests.put(url, json=data, verify=False, headers=hdrs)
        res.raise_for_status()
        print(res.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to update workflow. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs, data=data)

@workflow.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    '''Delete a workflow'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/workflow/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete workflow with uid {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@workflow.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option('-m', '--match', type=str, help="Partial filter match on uid, name")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, match, output, **kwargs):
    '''List all workflows'''

    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        q_params = [limit, offset]
        if match:
            q_params.append("match={}".format(match))
        limit_url = parameter_string(q_params)
        r = requests.get("{}/workflow{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            rows = []
            hdrs = ['uid', 'name', "type", "element types"]
            for _r in results['items']:
                row = [_r[hdr] for hdr in hdrs[:-1]]
                row.append(", ".join(_r['kinds']) if _r['kinds'] else "N/A")
                rows.append(row)
            print(tabulate(rows, headers=hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list workflows. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@workflow.command()
@click.argument('uid', type=str)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, **kwargs):
    '''Retrieve workflow configuration'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/workflow/{uid}", headers=hdrs, verify=False)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        print(json.dumps(r.json(), indent=4))
        return r.json()
    except Exception as ex:
        handle_error(ex, action_msg="Failed to fetch workflow with uid {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@workflow.command()
@click.argument('uid', type=str)
@add_options(common_options)
def export(uid, **kwargs):
    '''Export a workflow'''
    try:
        r = None
        hdrs = get_hdrs()
        data = { 'action': "export",
                 'uid': uid
               }
        r = requests.put(f"{sc.engine()}/workflow", headers=hdrs, json=data, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to export workflow with uid {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@workflow.command(name="import")
@click.argument("location", type=str)
def import_wf(location):
    '''Import a workflow'''
    hdrs = get_hdrs()
    try:
        if not os.path.exists(location):
            raise Exception("No file found at specified location: {}".format(location))
        files = {}
        tar = tarfile.open(location)
        for member in tar.getmembers():
            files[member.name.split("/")[-1]] = (member.name.split("/")[-1], tar.extractfile(member.name))
        r = requests.post(f"{sc.engine()}/workflow?action=import", headers=hdrs, files=files, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to import workflow from tarball located at {}. Error: ".format(location))

@workflow.command(name='gentpl')
@click.option("-t", "--type", type=click.Choice(["simple", "dependencies", "detailed"]), default="simple")
@click.option("-m", "--mode", type=click.Choice(["static", "dynamic"]), default="dynamic")
def gentpl(type, mode):
    '''Provides sample dynamic workflow registration template'''
    if mode == 'static' and type == 'simple':
        print(
            json.dumps(
                {
                    "name": "<wfname>",
                    "nodes": [
                        {
                            "id": 1,
                            "x": -400,
                            "y": 50,
                            "name": "<name>",
                            "fn_uid": "<fn_uid>",
                            "fn_envs": "",
                            "fn_description": "<fn description>",
                            "fn_reserved_envs": "UPDATE_PAYLOAD,ACCESS_TOKEN",
                            "fn_mode": 1
                        }
                    ],
                    "links": []
                }
            )
        )
        return

    if mode == 'static' and type == 'dependencies':
        print(
            json.dumps(
                {
                    "name": "<wfname>",
                    "nodes": [
                        {
                            "id": 1,
                            "x": -400,
                            "y": 50,
                            "name": "<name>",
                            "fn_uid": "<fn_uid>",
                            "fn_envs": "",
                            "fn_description": "<fn description>",
                            "fn_reserved_envs": "UPDATE_PAYLOAD,ACCESS_TOKEN",
                            "fn_mode": 1
                        },
                        {
                            "id": 2,
                            "x": -200,
                            "y": 50,
                            "name": "<name>",
                            "fn_uid": "<fn_uid>",
                            "fn_envs": "",
                            "fn_description": "<fn description>",
                            "fn_reserved_envs": "UPDATE_PAYLOAD,ACCESS_TOKEN",
                            "fn_mode": 1
                        }
                    ],
                    "links": [{"id":1,"from":1,"to":2,"path":"success"}]
                }
            , indent=4)
        )
        return

    if mode == 'static' and type == 'dependencies':
        print("Detailed not supported for static wfs")
        return

    if type == 'simple':
        print(
            json.dumps(
                {
                    "name": "<wfname>",
                    "kind": "<element-kind>",
                    "fns": {
                        "<wfnode-name>": {
                            "function": "<fn_uid>"
                        }
                    }
                },
                indent=4
            )
        )
    elif type == 'dependencies':
        print(
            json.dumps(
                {
                    "name": "<wfname>",
                    "kind": "<element-kind>",
                    "fns": {
                        "<wfnode1-name>": {
                            "function": "<fn_uid>"
                        },
                        "<wfnode2-name>": {
                            "function": "<fn_uid>",
                            "depends": [
                                "<wfnode1-name>"
                            ]
                        },
                        "<wfnode3-name>": {
                            "function": "<fn_uid>",
                            "depends": [
                                "<wfnode1-name>"
                            ]
                        },
                        "<wfnode4-name>": {
                            "function": "<fn_uid>",
                            "depends": [
                                "<wfnode2-name>",
                                "<wfnode3-name>"
                            ]
                        }
                    }
                },
                indent=4
            )
        )
    else:
        print("You can also pass jinja macros to select element uids in a composite element as shown below.")
        print("For a live example, please look at mdcap workflow info <robin-ha-install-uuid>")
        print(
            json.dumps(
                {
                    "name": "<wfname>",
                    "kind": "<element-kind>",
                    "fns": {
                        "<wfnode1-name>": {
                            "function": "<fn_uid>",
                            "elements": "<jinjamacro-resolves-element-uid>"
                        },
                        "<wfnode2-name>": {
                            "function": "<fn_uid>",
                            "depends": [
                                "<wfnode1-name>"
                            ],
                            "elements": "<jinjamacro-resolves-element-uid>"
                        },
                        "<wfnode3-name>": {
                            "function": "<fn_uid>",
                            "depends": [
                                "<wfnode1-name>"
                            ],
                            "elements": "<jinjamacro-resolves-element-uid>"
                        },
                        "<wfnode4-name>": {
                            "function": "<fn_uid>",
                            "depends": [
                                "<wfnode2-name>",
                                "<wfnode3-name>"
                            ]
                        }
                    }
                },
                indent=4
            )
        )

@cli.group(cls=ClickAliasedGroup, aliases=['profile'])
def bmprofile():
    """BM Profile Management"""
    pass

@bmprofile.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-t", "--tags", type=str, multiple=True, help="Filter by tags used to idenftify bm profiles. Format: class:sku2,location:tokyo...")
@click.option('-ot', "--ostype", type=str, help="Filter profile objects using ostype.")
@click.option('-k', "--keys", type=str, multiple=True, help="Filter profile objects using keys (separated by --keysdelimiter) present in the profile json.")
@click.option('-d', '--keysdelimiter', help="User can provide more than one keys (in --keys) separated by this delimiter")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, tags, ostype, keys, keysdelimiter, output, **kwargs):
    """List BM Profiles"""
    try:
        r = None
        limit, offset = offset_limit_from_range(index)
        taglist = parse_labels(tags)
        search = ""
        delimiter = keysdelimiter if keysdelimiter else ","
        if keys:
            search = "keys={}".format(delimiter.join(keys))
        delimiter = "keysdelimiter={}".format(delimiter)
        ostypeparam = ""
        if ostype:
            ostypeparam= f"ostype={ostype}"

        query_params = [limit, offset, taglist, search, delimiter, ostypeparam]
        limit_url = parameter_string(query_params)

        hdrs = get_hdrs()
        r = requests.get("{}/bmprofile{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            data = []
            headers = ["uid", "name", "description", "ostype", "kickstarter url", "tags"]
            for item in results['items']:
                tags = []
                if item['tags']:
                    for key, val in item['tags'].items():
                        tags.append(f"{key}:{val}")
                data.append([
                    item['uid'],
                    item['name'],
                    item['description'],
                    item['ostype'],
                    item['config_url'],
                    ",".join(tags)
                ])

            print(tabulate(data, headers))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list profiles. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@bmprofile.command()
@click.argument('uid', type=str)
@click.option("--profile/--no-profile", default=False, help="Get only the Profile JSON which can be dumped to a file.")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, profile, **kwargs):
    """Get information about a particular BM Profile"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/bmprofile/{uid}", headers=hdrs, verify=False)
        r.raise_for_status()
        data = r.json()
        if output == 'yaml':
            print(yaml.dump(data['profile'], indent=4))
            return

        if output == 'json':
            print(json.dumps(data['profile'], indent=4))
            return

        if profile:
            print(json.dumps(data['profile'], indent=4))
            return
        tags = []
        if data['tags']:
            for key, val in data['tags'].items():
                tags.append(f"{key}:{val}")
        print("UID            : {}".format(data['uid']))
        print("Name           : {}".format(data['name']))
        print("Description    : {}".format(data['description']))
        print("OS tpe         : {}".format(data['ostype']))
        print("Kickstart URL  : {}".format(data['config_url']))
        print("(Config URL)")
        print("Tags           : {}".format(",".join(tags)))
        print("Profile        : ")
        print(json.dumps(data['profile'], indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for Baremetal Profile with uid {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@bmprofile.command()
@click.argument('name', type=str)
@click.option('-d', '--description', help="Description of Profile.")
@click.option('-k', '--ks', help="Kickstart file that is located in external artifactory")
@click.option('-i', '--iso', help="ISO file that is located in external artifactory")
@click.option('-a', '--artifact-uuid', help="Kickstarter artifact UUID of kickstart url")
@click.option('--keys', is_flag=True, default=False, help="Print the variables of the chosen artifact or kickstart")
@click.option('-f', '--force', help="Force to upload ISO and kickstarter file even if it is already present in artifactory")
@click.option('-ot', '--ostype', help="OS type of kickstarter file provided through --ks or ISO file provided through --iso")
@click.option('--override', is_flag=True, help="MDCAP will skip to validate ostype against qualified operating systems")
@click.option('--set', type=str, multiple=True, help="Override the default values of BM profile")
@click.option('--setadd', type=str, multiple=True, help="Set key value pair to append an array in the element configuration in values file. Example: --set-add os.dns=dns1 --set-add os.dns=dns2")
@click.option("-t", "--tags", type=str, multiple=True, help="Filter by tags used to idenftify bm profiles. Format: class:sku2,location:tokyo...")
@click.option('-r', '--dry-run', is_flag=True, default=False, help="Show the required values from kickstarter file, don't add bare metal profile")
@add_options(common_options)
def add(name, description, ks, iso, artifact_uuid, keys, force, ostype, override, set, setadd, tags, dry_run, **kwargs):
    """Add a BM Profile using artifact-uuid or using a URL of the kickstart file os ISO (auto upload in case of external artifactory) in artifactory"""
    def send_req(url, get=None, put=None, post=None, verify=False, headers=None, data={}, allow_redirects=False, kwargs={}):
        if not headers:
            headers = get_hdrs()
        r = None
        try:
            if get:
                r = requests.get(url, verify=verify, headers=headers)
            elif put:
                r = requests.put(url, json=data, allow_redirects=allow_redirects, verify=verify, headers=headers)
            elif post:
                r = requests.post(url, json=data, allow_redirects=allow_redirects, verify=verify, headers=headers)
            return r
        finally:
            if kwargs.get('urlinfo') and r:
                compute_curl_command(r, headers=headers, data=data)
    try:
        if (ks or iso) and artifact_uuid:
            print("Cannot provide kickstart (ks) or iso along with artifact uid at the same time")
            return
        if (ks or iso) and not ostype:
            print("OS type must be provided")
            return
        if artifact_uuid and ostype:
            print("Ignoring --ostype. OS type is not required when artifact_uuid is given")

        r = send_req(f"{sc.engine()}/bmprofile?name={name}", get=True, kwargs=kwargs)
        if r.status_code == 200:
            print(f"BM profile with name {name} already exists")
            return
        if r.status_code != 404:
            r.raise_for_status()

        if artifact_uuid:
            r = send_req(f"{sc.engine()}/artifact/{artifact_uuid}", get=True, kwargs=kwargs)
            r.raise_for_status()

        def check_in_artifactory_upload(file, type, force, dryrun, ostype, override):
            # Commenting it now - now  the bmprofile add will only register and wont upload
            # ksbasefn = os.path.basename(file)
            # will remove after a few months once we look good
            # Check if the artifact present using md5sum
            # curr_md5sum = md5sum(file)
            # q_params = []
            # q_params.append("checksum={}".format(curr_md5sum))
            # limit_url = parameter_string(q_params)
            # r = send_req("{}/artifact{}".format(sc.engine(), limit_url), get=True, kwargs=kwargs)
            # r.raise_for_status()
            # results = r.json()
            # artifact_exists = results['items'] and len(results['items'])
            # if artifact_exists:
            #     if not force:
            #         print(f"File {results['items'][0]['url']} exists already in artifactory, skipping upload {file}")
            #         return results['items'][0]['url']
            #     else:
            #         print(f"File {results['items'][0]['url']} exists already in artifactory, forcing upload {file}")
            # Check if the artifact present using name
            # q_params = []
            # q_params.append("name={}".format(ksbasefn))
            # limit_url = parameter_string(q_params)
            # r = send_req("{}/artifact{}".format(sc.engine(), limit_url), get=True, kwargs=kwargs)
            # r.raise_for_status()
            # results = r.json()
            # if results['items'] and len(results['items']):
            #     print(f'Artifact with a name {file} exists')
            #     return False
            # if dryrun:
            #     print("Artifact cannot be uploaded as part of dry-run")
            #     return None

            q_params = []
            q_params.append("url={}".format(file))
            limit_url = parameter_string(q_params)
            r = send_req("{}/artifact{}".format(sc.engine(), limit_url), get=True, kwargs=kwargs)
            r.raise_for_status()
            results = r.json()
            if results['items'] and len(results['items']):
                print(f'Artifact with a URL {file} already registered')
                return False
            if dryrun:
                print(f"Dry-run can register {file}; register and then try dry-run")
                return None

            # Upload preparation
            # data = {
            #     'filename': ksbasefn,
            #     'name': ksbasefn,
            #     'type': type
            # }
            # r = send_req(f"{sc.engine()}/artifact", put=True, data=data, allow_redirects=True, kwargs=kwargs)
            # r.raise_for_status()
            # url = r.json()['redirect_url']
            # upload to artifactory
            # if not upload_to_robin_artifactory(url, file, type, name):
            #     raise Exception("File upload failed. Please check artifactory logs")

            # register the artifact
            # md5, err, status = run_command("md5sum {}".format(file))
            # if status:
            #     raise Exception("Could not determine checksum, error: {}".format(err))
            # else:
            #     md5 = md5.split(" ")[0]
            data = {
                'name': name,
                'type': type,
                'internal' : False, # Change it true when we upload
                'url' : file, # change it back ksbasefn when we need upload + registration; also add md5sum
                'ostype': ostype,
                'override': override,
                'description': "Auto registering during bmprofile creation"
            }
            r = send_req(f"{sc.engine()}/artifact", post=True, data=data, kwargs=kwargs)
            r.raise_for_status()
            return r.json()

        ks_artifact_uuid = artifact_uuid
        if not keys:
            if ks and ks.startswith('http'):
                ks_artifact = check_in_artifactory_upload(ks, 'ks', force, dry_run, ostype, override)
                if not ks_artifact:
                    return
                ks_artifact_uuid = ks_artifact['uid']
            elif ks:
                print(f"File {ks} located in http location can be registered")
                return
            if iso and iso.startswith('http'):
                iso_artifact = check_in_artifactory_upload(iso, 'iso', force, dry_run, ostype, override)
                if not iso_artifact:
                    return
            elif iso:
                print(f"File {iso} located in http location can be registered")
                return

        data = {}
        data['name'] = name
        data['description'] = description if description else ""
        data['tags'] = parse_labels(tags, ret_dict=True) if tags else {}
        payload = {}
        if set or setadd:
            result = create_dict_fromkeys(set, setadd)
            payload = merge_dict(payload, result)

        data['profile'] = payload
        if ostype:
            data['ostype'] = ostype

        q_params = []
        if ks_artifact_uuid:
            q_params.append("artifact_uid={}".format(ks_artifact_uuid))
        else:
            print("Valid artifact_uid is mandatory for registering a BM profile")
            return

        if keys:
            q_params.append("keys=true")
            param_url = parameter_string(q_params)
            r = send_req(f"{sc.engine()}/bmprofile{param_url}", post=True, data=data, kwargs=kwargs)
            r.raise_for_status()
        elif dry_run:
            q_params.append("dryrun=true")
            param_url = parameter_string(q_params)
            r = send_req(f"{sc.engine()}/bmprofile{param_url}", post=True, data=data, kwargs=kwargs)
            r.raise_for_status()
        else:
            data['artifact_uid'] = ks_artifact_uuid
            r = send_req(f"{sc.engine()}/bmprofile", post=True, data=data, kwargs=kwargs)
            r.raise_for_status()

        if not dry_run:
            if not keys:
                print(r.json()['msg'])
            else:
                for k,v in r.json().items():
                    print("{}: {}".format(k, v))
        else:
            print("BM Profile would look like:")
            pprint(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add Baremetal Profile")

@bmprofile.command()
@click.argument('uid', type=str)
@click.argument('newprofile_uid', type=str)
@add_options(common_options)
def validate(uid, newprofile_uid, **kwargs):
    """Check if new profile can replace this profile"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/bmprofile/{uid}?conformancecheck={newprofile_uid}", headers=hdrs, verify=False)
        r.raise_for_status()
        payload = r.json()
        print(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Failed to validate the BMProfiles")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=payload)

@bmprofile.command()
@click.argument('uid', type=str)
@click.option('-d', '--description', help="Description of Profile.")
@click.option("-t", "--tags", type=str, multiple=True, help="Filter by tags used to idenftify bm profiles. Format: class:sku2,location:tokyo")
@add_options(common_options)
def update(uid, description, tags, **kwargs):
    """Update the description and/or the tags of a BM Profile"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        if description or description == "":
            data['description'] = description if description else ""

        if tags or tags == "\"\"":
            data['tags'] = parse_labels(tags, ret_dict=True) if tags else {},

        if not data:
            print("Nothing to update - provide tags and/or description")
            return

        r = requests.post(f"{sc.engine()}/bmprofile", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to update Baremetal Profile {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@bmprofile.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a BM Profile"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/bmprofile/{uid}", headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete Baremetal Profile with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

# Artifact Management  CLI Commandset
@cli.group(cls=ClickAliasedGroup)
def artifact():
    """Artifact Management in Robin artifactory"""
    pass

@artifact.command()
@click.argument('file', type=str)
@click.argument('name', type=str)
@click.argument('type', type=str)
@click.option('-ot', '--ostype', type=str, help="Provide os type if it is ks or iso file")
@click.option('--desc', "-d", type=str, help="description about the file")
@add_options(common_options)
def upload(file, name, type, ostype, desc, **kwargs):
    """Upload artifact from local file system to the Robin Artifactory\n
        FILE         : file path\n
        NAME         : artifact name\n
        TYPE         : artifact type, choose one of below types\n
                           - iso  : for OS\n
                           - ks   : for kickstart file\n
                           - bin  : for binary file\n
                           - ar   : for archive\n
                           - conf : for config file\n
        --ostype     : OS type for OS and ks types. List of supported OS types\n
                           - check 'mdcap artifact list --list-supported-os' to view supported OS
    """
    try:
        req = None
        r = None
        hdrs = get_hdrs()
        if not os.path.isfile(file):
            raise Exception(f"File not found: {file}")

        if type.lower() in ['ks', 'iso'] and not ostype:
            print("--ostype is mandatory for ks and iso types")
            return

        md5, err, status = run_command("md5sum {}".format(file))
        if status:
            raise Exception("Could not determine checksum, error: {}".format(err))
        else:
            md5sum = md5.split(" ")[0]

        put_data = {
            'filename': os.path.basename(file),
            'name': name,
            'type': type,
            'ostype': ostype
        }

        req = requests.put(f"{sc.engine()}/artifact", json=put_data, allow_redirects=True, verify=False, headers=hdrs)
        req.raise_for_status()
        url = req.json()['redirect_url']

        # upload to artifactory
        if not upload_to_robin_artifactory(url, file, type, name):
            raise Exception("File upload failed. Please check artifactory logs")

        # register the artifact
        data = {
            'name': name,
            'type': type,
            'internal' : True,
            'url' : url,
            'checksum': md5sum,
            'description': desc
        }
        if ostype:
            data['ostype'] = ostype
        r = requests.post(f"{sc.engine()}/artifact", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to register artifact {}. ".format(name))
    finally:
        if kwargs.get('urlinfo'):
            if req:
                compute_curl_command(req, headers=hdrs, data=put_data)
            if r:
                compute_curl_command(r, headers=hdrs, data=data)

@artifact.command()
@click.argument('url', type=str)
@click.argument('name', type=str)
@click.argument('type', type=str)
@click.option('-ot', '--ostype', type=str, help="Provide os type if it is ks or iso file")
@click.option('-o', '--override', is_flag=True, help="MDCAP will skip to validate ostype against qualified operating systems")
@click.option('--desc', '-d', type=str, help="description about the artifact")
@add_options(common_options)
def register(url, name, type, ostype, override, desc, **kwargs):
    """Register artifact with MDCAP (for external managed artifactory)\n
        ARTIFACT_URL : URL of artifact\n
        NAME         : artifact name\n
        TYPE         : artifact type, choose one of below types\n
                           - iso  : for OS\n
                           - ks   : for kickstart file\n
                           - bin  : for binary file\n
                           - ar   : for archive\n
                           - conf : for config file\n
        DESC         : description about artifact\n
        --ostype     : OS type for OS and ks types. List of supported OS types\n
                           - check 'mdcap artifact list --list-supported-os' to view supported OS\n
                           - for marinerv1, the URL specified needs to end in config (config-dir that has all config files)\n
                           - use --override to register an unsupported/non-qualified artifact.\n
        --override   : If this option is not given, MDCAP will fail if ostype is not in its list-supported-os\n
    """
    try:
        r = None
        hdrs = get_hdrs()
        if type.lower() in ['ks', 'iso'] and not ostype:
            print("--ostype is mandatory for ks and iso types")
            return

        data = {
            'name': name,
            'type': type,
            'url' : url,
            'internal' : False,
            'description': desc,
            'override': override
        }
        if ostype:
            data['ostype'] = ostype
        r = requests.post(f"{sc.engine()}/artifact", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to register artifact {}. ".format(url))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@artifact.command()
@click.option('-r', "--range", 'index', type=str, help="display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("--type", '-t', type=str, help="filter artifacts based on type. valid values iso|ks|bin|ar")
@click.option("--ostype", '-ot', type=str, help="filter artifacts based on os types.")
@click.option("--name", '-n',type=str, help="filter artifacts based on name")
@click.option("--url", '-u',type=str, help="filter artifacts based on a substring in url")
@click.option("--checksum", '-c',type=str, help="filter artifacts based on file checksum")
@click.option("--list-supported-os", is_flag=True, default=False, help="List supported operating system versions")
@add_options(common_options)
def list(index, type, ostype, name, url, checksum, list_supported_os, **kwargs):
    """List artifacts"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        q_params = [limit, offset]
        if type:
            q_params.append("type={}".format(type))
        if ostype:
            q_params.append("ostype={}".format(ostype))
        if name:
            q_params.append("name={}".format(name))
        if url:
            q_params.append("url={}".format(url))
        if checksum:
            q_params.append("checksum={}".format(checksum))
        #The below param append must be the last check
        if list_supported_os:
            if len(q_params) > 2:
                print("List supported OS cannot be mixed with type,ostype,name,url,checksum")
                return
            q_params.append(f"listsupportedos={list_supported_os}")
        limit_url = parameter_string(q_params)
        r = requests.get("{}/artifact{}".format(sc.engine(), limit_url), verify=False, headers=hdrs)
        r.raise_for_status()
        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            print(tabulate(results['items'], headers="keys"))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list Artifacts.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@artifact.command()
@click.argument('uid', type=str)
@add_options(common_options)
def info(uid, **kwargs):
    """Get information about an artifact"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/artifact/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        result = r.json()
        print("UUID             : {}".format(result['uid']))
        print("Name             : {}".format(result['name']))
        print("Type             : {}".format(result['type']))
        print("OS type          : {}".format(result['ostype']))
        print("URL              : {}".format(result['url']))
        print("Description      : {}".format(result.get('description', '-')))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for Artifactory with uid {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@artifact.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete an artifact from Robin Artifactory and unregister the artifact"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/artifact/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        result = r.json()

        url = result['url']
        if result['internal']:
            requests.delete(f"{url}", verify=False, headers=hdrs)
            r.raise_for_status()

        r = requests.delete(f"{sc.engine()}/artifact/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print("Successfully deleted artifact from Artifactory, unregistration complete")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete Artifact with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@cli.group(cls=ClickAliasedGroup, aliases=['fn'])
def func():
    """Function Management"""
    pass

@func.command(aliases=['register'])
@click.argument('name', type=str)
@click.argument('version', type=str)
@click.argument('operator', type=str)
@click.option('--cmd', '-c', type=str, help="Command to be run as part of the Function.")
@click.option('--script', '-s', type=str, help="Script to be run as part of the Function.")
@click.option('--desc', '-d', type=str, help="Description of the Function.")
@click.option('--envs', type=str, help="Comma seperated list of environment variables needed by the specified script.")
@click.option('--fanout', '-n', type=int, help="Fanout factor to be used with this function")
@click.option('--action', '-a', type=str, help="Action type: mutable or default")
@click.option('--tar', type=bool, help="Files to be placed in execution environmnet of entry")
@click.option('--kinds', '-e', '-k', required=True, multiple=True, help="Valid element kinds for this function")
@click.option('--upload', is_flag=True, help="upload the script while adding, without script present error is thrown")
@click.option('--mode', '-m', required=True, default="unit",
              type=click.Choice(['unit', 'batch'], case_sensitive=False),
              help="Valid function modes ('unit', 'batch')")
@click.option('--mem_size', '-ms', required=False, type=int,
              help="Memory size for required worker in bytes")
@click.option('--cpu', '-cpu', required=False, type=float,
              help="Number of cpus required for worker")
@click.option('--timeout', '-t', required=False, type=int,
              help="Timeout for the function to exit, for 1 element")
@click.option('--runtime', '-r', required=False, type=str,
              help="Executor image which this function will use")
@add_options(common_options)
def add(name, version, operator, cmd, script, kinds, desc,
        envs, fanout, action, tar, upload, mode, mem_size, cpu,
        timeout, runtime, **kwargs):
    """Add a function"""

    try:
        r = None
        hdrs = get_hdrs()
        tar = 1 if tar else 0
        if not timeout:
            timeout = 0
        data = {
            'name': name,
            'version': version,
            'operator': operator,
            'etypes': kinds,
            'description': desc,
            'envs': envs if envs else "",
            'fanout': fanout,
            'action': action if action else 'default',
            'tar': tar,
            'mode': 0 if mode.lower() == 'unit' else 1,
            'mem_size': mem_size,
            'cpu': cpu,
            'timeout': timeout,
            'runtime': runtime
        }
        if script:
            data['script'] = script.split('/')[-1]
        if cmd:
            data['cmd'] = cmd

        if not cmd and not script:
            raise Exception("CMD or SCRIPT are required")
        elif cmd and script:
            raise Exception("Only one of CMD or SCRIPT can be specified.")
        else:
            if upload:
                print("Trying to upload script {}".format(script))
                try:
                    files = {'file': (script.split('/')[-1], open(script, 'rb'))}
                    r = requests.post(f"{sc.engine()}/fn/upload", files=files, headers=hdrs, verify=False)
                    r.raise_for_status()
                except Exception as e:
                    handle_error(e, action_msg=f"Failed to upload file: {script}")
                    return
                else:
                    print("Upload complete !")

        r = requests.post(f"{sc.engine()}/fn", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        # if "not fetch" in ex:
        #     click.secho("Try adding --upload", fg="red")
        handle_error(ex, action_msg="Failed to add function {}. ".format(name))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@func.command()
@click.argument('uid', type=str)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, **kwargs):
    """Get information for a particular function"""

    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/fn/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for function with uid {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@func.command()
@click.argument('uid', type=str)
@click.option("-o", "--output", help="Filename to store envs")
@add_options(common_options)
def getenv(uid, output, **kwargs):
    """Get envs for a particular function"""

    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/fn/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        envs = r.json().get('envs', None)
        data = {}
        if envs:
            for item in envs.split(","):
                data[item.strip()] = ""

        if output:
            try:
                if data:
                    with open(output, "w") as fh:
                        fh.write(json.dumps(data, indent=4))
                    print(f"Function envs are saved to {output}")
                else:
                    print(f"There are no envs registered with function: {uid}")
            except Exception as ex:
                print(f"Failed to save envs to file: {output}, error: {ex}")
        else:
            print(json.dumps(data, indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get envs for function with uid {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@func.command()
@click.argument('uid', type=str)
@add_options(common_options)
def source(uid, **kwargs):
    """Retrieve function script"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/fn/{uid}?artifact=true", verify=False, headers=hdrs)
        if r.ok:
            path = f'/tmp/rorc-fn-{uid}'
            with open(path, "wb") as fh:
                fh.write(r.content)
            print(f"Dumped the function to '{path}'")
        else:
            raise Exception(f"Failed to download function. {r.text}")
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@func.command()
@click.argument('uids', type=str)
@click.argument('filename', type=str)
@add_options(common_options)
def export(uids, filename, **kwargs):
    """Export function(s)"""
    try:
        r = None
        hdrs = get_hdrs()
        ls_uids = uids.split(",")
        params = {
            'uids': ls_uids,
            'filename': filename
        }
        r = requests.put(f"{sc.engine()}/fn", params=params, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to export functions with uid(s): {} ".format(uids))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@func.command(name="import")
@click.argument("location", type=str)
@add_options(common_options)
def import_fn(location, **kwargs):
    """Import function(s)"""
    try:
        r = None
        hdrs = get_hdrs()
        if not os.path.exists(location):
            raise Exception("No file found at specified location: {}".format(location))
        files = {}
        tar = tarfile.open(location)
        for member in tar.getmembers():
            files[member.name.split("/")[-1]] = (member.name.split("/")[-1], tar.extractfile(member.name))
        r = requests.post(f"{sc.engine()}/fn/import", files=files, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to import functions from tarball located at {}. Error: ".format(location))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@func.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a function"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/fn/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete function with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@func.command()
@click.option('-k', "--kind", type=str, help="Option to filter Functions based on the kinds they operate on.")
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option('-m', '--match', type=str, help="Partial filter match on uid, name, source")
@click.option("-v", "--verbose", is_flag=True)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(kind, index, match, verbose, output, **kwargs):
    """List all functions"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        q_params = [limit, offset]
        if match:
            q_params.append("match={}".format(match))
        if kind:
            q_params.append("etype={}".format(kind))
        limit_url = parameter_string(q_params)
        url = "{}/fn{}".format(sc.engine(), limit_url)

        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
            return
        if verbose:
            for item in results['items']:
                item['hash'] = item['hash'][0:6]
            #hdrs = ['uuid', 'name', 'version', 'operator', 'cmd', 'source', 'etypes', 'desc', 'ENV variables', 'reserved ENV variables', 'fanout']
            print(tabulate(results['items'], headers="keys"))
        else:
            table_hdrs = ['uid', 'name', 'version', 'operator', 'mode', 'source', 'types', 'fanout', 'mem_size', 'cpu', 'timeout', 'runtime', 'action']
            vals = []
            for item in results['items']:
                vals.append([item['uid'],
                            item['name'],
                            item['version'],
                            item['operator'],
                            item['mode'],
                            item['source'],
                            item['types'],
                            item['fanout'],
                            item['mem_size'],
                            item['cpu'],
                            item['timeout'],
                            item['runtime'],
                            item['action']])
            print(tabulate(vals, headers=table_hdrs))

    except Exception as ex:
        handle_error(ex, action_msg="Failed to list functions. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


# @func.command()
# @click.argument("file", type=str)
# @add_options(common_options)
# def upload(file, **kwargs):
#     """Upload a function script"""
#     try:
#         r = None
#         hdrs = get_hdrs()
#         files = {'file': (file, open(file, 'rb'))}
#         r = requests.post(f"{sc.engine()}/fn/upload", headers=hdrs, files=files, verify=False)
#         r.raise_for_status()
#         print("Upload complete !")
#     except Exception as ex:
#         handle_error(ex, action_msg="Failed to upload file: {}. ".format(file))
#     finally:
#         if kwargs.get('urlinfo') and r:
#             compute_curl_command(r, headers=hdrs)

@func.command()
@click.argument("uid", type=str)
@click.argument("key", type=click.Choice(['script', 'operator', 'runtime', 'mode',
                        'envs', 'fanout', 'mem_size', 'cpu', 'timeout']))
@click.argument("value", type=str)
@click.option("-v", "--version", type=str, help="new version of the function")
@click.option("-uwf", "--update_wfs", is_flag=True, help="Update all existing workflows with this function")
@add_options(common_options)
def update(uid, key, value, version, update_wfs, **kwargs):
    """Update a function script already registered \n
        UID: uid of the already registered fn \n
        KEY: Param of fn to update \n
        VALUE: Value or fn param \n
        script: str (path/to/script) \n
        operator: shell|ssh \n
        runtime: str (docker img) \n
        mode: 1|0  (batch|unit) \n
        envs: comma separated str \n
        fanout: int \n
        mem_size: int (mb) \n
        cpu: float \n
        timeout: int (seconds)"""
    try:
        r = None
        hdrs = get_hdrs()
        errmsg = None
        r = requests.get(f"{sc.engine()}/fn/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        fn_conf = r.json()
        payload = {}
        if key == 'script':
            errmsg = "Failed to upload new script for fn: {}. ".format(uid)
            script = value
            files = {}
            with open(script, 'rb') as f:
                files[fn_conf['uid']] = (os.path.basename(script), f.read())
            r = requests.post(f"{sc.engine()}/fn/upload?update=true", headers=hdrs, files=files, verify=False)
            r.raise_for_status()
            print("Upload complete, script is updated.")
        else:
            fn_conf[key] = value
            payload = {
                "config": {
                    key: value
                }
            }
            r = requests.put(f"{sc.engine()}/fn/{uid}", headers=hdrs, data=json.dumps(payload), verify=False)
            r.raise_for_status()
            print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg=errmsg if errmsg else "Failed to update fn: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=payload)

@cli.group(cls=ClickAliasedGroup)
def config():
    """Config Management"""
    pass

@config.command()
@add_options(common_options)
def list(**kwargs):
    '''List controller configuration'''
    get_meta(**kwargs)

@config.command()
@click.argument('key', type=str)
@click.argument('value', type=str)
@add_options(common_options)
def set(key, value, **kwargs):
    '''Update controller configuration key'''
    try:
        res, data = None, {'key': key, 'value': value}
        hdrs = get_hdrs()
        url = "{}/metadata".format(sc.engine())
        res = requests.put(url, json=data, verify=False, headers=hdrs)
        res.raise_for_status()
        print(res.text)
    except Exception as ex:
        handle_error(ex, action_msg="Error setting metadata ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs, data=data)

# @config.command()
# @click.argument('key', type=str)
# @click.argument('value', type=str)
# @add_options(common_options)
# def addmetadata(key, value, **kwargs):
#     '''Add a custom metadata key'''
#     try:
#         res, data = None, {'key': key, 'value': value}
#         hdrs = get_hdrs()
#         url = "{}/metadata".format(sc.engine())
#         res = requests.post(url, json=data, verify=False, headers=hdrs)
#         res.raise_for_status()
#         print(res.text)
#     except Exception as ex:
#         handle_error(ex, action_msg="Error setting metadata ")
#     finally:
#         if kwargs.get('urlinfo') and res:
#             compute_curl_command(res, headers=hdrs, data=data)

@cli.group(cls=ClickAliasedGroup)
def env():
    """Engine Internal ENV Management"""
    pass

@env.command()
def list(**kwargs):
    '''List internal ENV'''
    try:
        res = None
        hdrs = get_hdrs()
        url = "{}/env".format(sc.engine())
        res = requests.get(url, verify=False, headers=hdrs)
        res.raise_for_status()
        print(tabulate(res.json().items(), headers=["KEY", "VALUE"]))
    except Exception as ex:
        handle_error(ex, action_msg="Error setting internal env and hot-reload engine instances")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)

"""
MDCAP Helm release doesn't support env updates. Please do
1. kubectl edit cm -n <> mdcap-engine-env
2. kubectl annotate pod -n <> <engine.pod> key=value

@env.command()
@click.argument('key', type=str)
@click.argument('value', type=str)
def update(key, value, **kwargs):
    '''Update ENV'''
    try:
        res = None
        hdrs = get_hdrs()
        url = "{}/env".format(sc.engine())
        data = {"key": key, "value": value}
        res = requests.put(url, verify=False, headers=hdrs, json=data)
        res.raise_for_status()
        print(res.text)
    except Exception as ex:
        handle_error(ex, action_msg="Error updating internal ENV variables")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs, data=data)
"""

@trigger.command()
@add_options(common_options)
def list(**kwargs):
    '''List currently active System triggers'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/triggers", verify=False, headers=hdrs)
        r.raise_for_status()
        results = r.json()
        if not results:
            print("No active triggers found")
        else:
            table = []
            tbl_hdrs = ['type', 'objid', 'event', 'tracker', 'start_time', 'assignee']
            for item in results:
                table.append([item['type'], item['objid'], item['event'], item['counter'], datetime.fromtimestamp(int(item['inprogress'])) if item['inprogress'] else '-', item['assignee']])
            print(tabulate(table, headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list triggers. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@prioritylane.command(aliases=['register'])
@click.argument("name", type=str)
@click.argument("description", type=str)
@click.argument("priority", type=int)
@click.argument("initial_num_workers", type=int)
@click.argument("max_workers", type=int)
@click.argument("burst", type=int)
#@click.argument("worker_steal_percent", type=int)
#@click.argument("worker_steal_mode", type=click.Choice(['forceful', 'graceful']))
@click.argument("pause", type=click.Choice(['true', 'false']))
@add_options(common_options)
def add(name, description, priority, initial_num_workers, max_workers, burst, pause, **kwargs):
    '''Register a new Priority Lane'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            "name": name,
            "description": description,
            "config": {
                "priority": priority,
                "initial_num_workers": initial_num_workers,
                "max_workers": max_workers,
                "burst": burst,
                #"worker_steal_percent": worker_steal_percent,
                #"worker_steal_mode": worker_steal_mode,
                "pause": True if pause == 'true' else False
            }
        }
        r = requests.post(f"{sc.engine()}/prioritylane", verify=False, json=data, headers=hdrs)
        r.raise_for_status()
        results = r.json()
        print(f"Priority lane {name} with {results['id']} has been registered")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to register priority lane. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@prioritylane.command()
def gentpl():
    '''Provides sample priority lane template'''
    print(
        json.dumps(
            {
                "burst": 2,
                "initial_num_workers": 5,
                "max_workers": 40,
                "pause": True,
                "priority": 20
            },
            indent=4
        )
    )

@prioritylane.command()
@click.argument("uid", type=str)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, **kwargs):
    '''Info on Priority Lane'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/prioritylane/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        pl = r.json()
        pl.pop('uid')
        print(json.dumps(pl, indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get information on priority lane. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@prioritylane.command()
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(output, **kwargs):
    '''List all priority lanes'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/prioritylane", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        results = r.json()
        if not results:
            print("No priority lanes found, please add them before executing batch/workflow")
        else:
            table=[]
            tbl_hdrs = ['UID', 'Name', 'Description', 'Priority', 'Initial #Workers', 'Max workers', 'Burst workers', 'Pausing allowed']
            for item in results:
                table.append([item['uid'], item['name'], item['description'], item['config']['priority'], item['config']['initial_num_workers'],
                              item['config']['max_workers'], item['config']['burst'], item['config']['pause']])
            print(tabulate(table, headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list priority lanes. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@prioritylane.command()
@click.argument("uid", type=str)
@click.option("-c", "--config", type=str, help="Priority lane config file")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, output, **kwargs):
    '''Update a priority lane'''
    try:
        r = None
        hdrs = get_hdrs()
        if not config:
            mod = open_in_editor(uid, otype="prioritylane", param="config", edit_fmt=output)
            if not mod:
                return
        else:
            mod = read_json_file(config)
        r = requests.put(f"{sc.engine()}/prioritylane/{uid}", json=mod, verify=False, headers=hdrs)
        r.raise_for_status()
        print(f"Priority Lane with uid: {uid} has been updated")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to update Priority lane with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=mod)

@prioritylane.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a prioritylane"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/prioritylane/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete Priority lane with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@worker.command()
@click.argument('name', type=str)
@click.option("-i", "--id", is_flag=True, help="Interpret name as id")
@click.option("-u", "--unassign", is_flag=True, help="Unassign the batch")
@click.option("-t", "--toggle-status", is_flag=True, help="Toggle the status of a worker")
@add_options(common_options)
def update(name, unassign, toggle_status, id, **kwargs):
    ''' Update worker information '''
    try:
        hdrs = get_hdrs()
        parameters = []
        if id:
            parameters.append("id=true")
        if unassign:
            parameters.append("unassign=true")
        if toggle_status:
            parameters.append("togglestatus=true")
        limit_url = parameter_string(parameters) if parameters else ''
        r = requests.put(f"{sc.engine()}/worker/{name}{limit_url}", verify=False, headers=hdrs)
        r.raise_for_status()
        results = r.json()
        print(results)
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to update persistent worker {name}")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@worker.command()
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(output, **kwargs):
    '''List all workers'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/worker", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        results = r.json()
        if not results:
            print("No persistent workers found")
        else:
            table=[]

            tbl_hdrs = ['ID', 'Name', 'State', 'Profile', 'Batchid']
            for item in results:
                st = "UP" if item['state'] == 1 else "DOWN"
                table.append([item['id'], item['name'], st, item['profile'], item['batchid']])

            print(tabulate(table, headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list persistent workers. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@worker.command(hidden=True)
@add_options(common_options)
def deleteall(**kwargs):
    '''Delete all workers'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/worker", verify=False, headers=hdrs)
        r.raise_for_status()
        # results = r.json()
        print("Deleted all persistent workers")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete persistent workers. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@workerprofile.command("add")
@click.argument("img", type=str)
@click.option("--mem", "-m", type=str, default='0b')
@click.option("--cpu", "-c", type=int, default=1)
@click.option("--max-workers", "-w", type=int, default=1, help="Max worker count")
@add_options(common_options)
def add_wp(img, mem, cpu, max_workers, **kwargs):
    '''Register a new Persistent Worker profile'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            "img": img,
            "max_worker_cnt": max_workers,
            "mem": convert_readable_to_bytes(mem),
            "cpu": cpu,
        }
        r = requests.post(f"{sc.engine()}/taskprofile", verify=False, json=data, headers=hdrs)
        r.raise_for_status()
        results = r.json()
        print(f"Worker profile {results['id']} has been registered")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to register worker profile. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@workerprofile.command("list")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list_wp(output, **kwargs):
    '''List all workers'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/taskprofile", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        results = r.json()
        if not results:
            print("No persistent worker profiles found")
        else:
            table=[]
            tbl_hdrs = ['uid', 'img', 'cpu', 'mem', 'max_wrks', 'deployed_wrks', 'desired_wrks', 'disabled', 'activejob', 'lastjob', 'lasterr', 'mtime']
            for item in results:
                table.append([item['uid'], item['img'],
                              item['cpu'], convert_bytes_to_readable(item['mem']),
                              item['max_worker_cnt'],
                              item['total_worker_cnt'],
                              item['desired_worker_cnt'],
                              item['disabled'],
                              item['activejob'],
                              item['lastjob'],
                              item['lasterr'],
                              datetime.fromtimestamp(int(item['mtime']))])

            print(tabulate(table, headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list persistent workers. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@workerprofile.command()
@click.argument("uid", type=str)
@add_options(common_options)
def disable(uid, **kwargs):
    '''Halt worker management'''
    try:
        r = None
        hdrs = get_hdrs()
        data = { 'disabled': True }
        r = requests.put(f"{sc.engine()}/taskprofile/{uid}",
                         json=data,
                         verify=False, headers=hdrs)
        r.raise_for_status()
        print(f"Worker profile with uid: {uid} has been updated")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to disable worker profile with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@workerprofile.command()
@click.argument("uid", type=str)
@add_options(common_options)
def enable(uid, **kwargs):
    '''Resume worker management'''
    try:
        r = None
        hdrs = get_hdrs()
        data = { 'disabled': False }
        r = requests.put(f"{sc.engine()}/taskprofile/{uid}",
                         json=data,
                         verify=False, headers=hdrs)
        r.raise_for_status()
        print(f"Worker profile with uid: {uid} has been updated")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to enable worker profile with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@workerprofile.command()
@click.argument("uid", type=str)
@click.option("--max_worker_cnt", "-w", type=int, help="Maximum worker count")
@click.option("--desired_worker_cnt", "-d", type=int, help="Desired worker count")
@add_options(common_options)
def update(uid, max_worker_cnt, desired_worker_cnt, **kwargs):
    '''Update a persistent worker profile'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        if desired_worker_cnt is not None:
            if desired_worker_cnt < 0:
                print(f"Invalid desired count: {desired_worker_cnt}")
                return
            else:
                data['desired_worker_cnt'] = desired_worker_cnt

        if max_worker_cnt is not None:
            if max_worker_cnt < 0:
                print(f"Invalid desired count: {max_worker_cnt}")
                return
            else:
                data['max_worker_cnt'] = max_worker_cnt
    
        data = {
            'desired_worker_cnt': desired_worker_cnt,
            'max_worker_cnt': max_worker_cnt
        }
        r = requests.put(f"{sc.engine()}/taskprofile/{uid}",
                         json=data,
                         verify=False, headers=hdrs)
        r.raise_for_status()
        print(f"Worker profile with uid: {uid} has been updated")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to update worker profile with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@workerprofile.command()
@add_options(common_options)
def reconcile(**kwargs):
    '''Reconcile desired worker counts for all workerprofiles'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.put(f"{sc.engine()}/taskprofile/reconcile", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Failed to reconcile worker counts. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@workerprofile.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a worker profile"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/taskprofile/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete workerprofile with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@workerprofile.command()
@click.argument('jobid', type=str)
@add_options(common_options)
def logs(jobid, **kwargs):
    """Get logs for a jobid"""
    try:
        res = None
        hdrs = get_hdrs()
        res = requests.get(f"{sc.engine()}/taskprofile/logs/{jobid}", headers=hdrs, verify=False)
        res.raise_for_status()
        fname = f"/tmp/{jobid}_logs.tar.gz"
        with open(fname, 'wb') as f:
            for chunk in res.iter_content(chunk_size=512):
                f.write(chunk)
        print(f"Dumped job logs to {fname}")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to fetch job logs")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)


@batch.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("--full/--no-full", default=True, help="Option to display full Batch ID.")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option("--archived", is_flag=True, help="Display the batches which have already been archived")
@click.option("-b", "--before", type=str, help="Select batches completed before time supplied. Format: Ad:Bh:Cm:Ds. A is #days, B is #hours, C is #minutes, D is #seconds")
@click.option("-a", "--after", type=str, help="Select batches started after time supplied. Format: Ad:Bh:Cm:Ds. A is #days, B is #hours, C is #minutes, D is #seconds")
@click.option("--hide-bow", is_flag=True, help="Hide bow sub batches in the result.")
@add_options(common_options)
def list(index, full, output, archived, before, after, hide_bow, **kwargs):
    '''List all batches and status'''
    try:
        req = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        parameters = [limit, offset]
        if archived:
            parameters.append("archived=True")
        if after:
            parameters.append(f"after={parse_time(after)}")
        if before:
            parameters.append(f"before={parse_time(before)}")
        if hide_bow:
            parameters.append("root_task=true")
        limit_url = parameter_string(parameters)
        req = requests.get("{}/batch{}".format(sc.engine(), limit_url), verify=False, headers=hdrs)
        req.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(req.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(req.json(), indent=4))
            return
        results = req.json()
        if not results:
            print("No results found")
        else:
            tbl_hdrs = ['CustomID', 'BatchID', 'Name', 'Profile', '#Pools', 'Workers\n(active/\nassigned/\ntotal)', 'Fanout', 'Priority\nlane', 'Status', 'Submitted\nTime', 'Start\nTime', 'Exec\nTime', 'Wait\nTime', 'Total\nTime', 'Error']
            output = []
            footer = "Note: above list displays 1000 entries, use -r <startindex>:<endindex> to list desired range"
            for r in results[::-1]:
                row = []
                row.append(r['customid'])
                if not full:
                    r['batchid'] = str(r['batchid'])[0:6]
                row.append(r['batchid'])
                row.append(r['name'])
                row.append(r['tprofile'][0:8] if r.get('tprofile', '') else '')
                row.append("{}/{}".format(r['npools_done'], r['npools']))
                worker_str = f"{r.get('assigned_workers', '-')}/{r.get('max_assigned_workers', '-')}/{r.get('total_workers', '-')}"
                if worker_str == "None/None/None":
                    worker_str = "Waiting for Profile"
                row.append(worker_str)
                row.append(r['fanout'])
                row.append(r['prioritylane'])
                row.append(r['status'])
                row.append(datetime.fromtimestamp(int(r['submitted_time'])))
                row.append(datetime.fromtimestamp(int(r['st_time'])) if r['st_time'] else '-')
                if r['end_time']:
                    if r['st_time']:
                        row.append("{}s".format(r['duration']))
                    else:
                        row.append("-")
                else:
                    if r['st_time']:
                        footer = "* - Indicates batches are still in progress"
                        row.append("{}s*".format(r['duration']))
                    else:
                        row.append("N/A")
                if r['st_time']:
                    row.append("{}s".format(r['wait_time']))
                else:
                    if r['end_time']:
                        row.append("{}s".format(r['total_time']))
                    else:
                        footer = "* - Indicates batches are still in progress"
                        row.append("{}s*".format(r['wait_time']))

                if r['end_time']:
                    row.append("{}s".format(r['total_time']))
                else:
                    row.append("{}s*".format(r['total_time']))
#                row.append(r['jobid'])
                row.append(r['errmsg'])
                output.append(row)

            print(tabulate(output, headers=tbl_hdrs))
            if footer:
                print("\n{}".format(footer))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list batches. ")
    finally:
        if kwargs.get('urlinfo') and req:
            compute_curl_command(req, headers=hdrs)

def _get_workflow_nodes(result, display_wf_stages=True, add_elements=True):
    global SET
    def get_start_nodes(len_nodes, links):
        n_list = [i+1 for i in range(len_nodes)]
        for link in links:
            try:
               n_list.pop(n_list.index(int(link['to'])))
            except ValueError:
               pass
        return n_list

    nodes = result.get('workflow_nodes', result.get('nodes'))
    links = result.get('workflow_links', result.get('links'))
    stg_nodes = {}
    stg_list = []
    count = 0
    if links:
        start_node_ids = get_start_nodes(len(nodes), links)
        #links[0]['from']
        stg_list.extend(start_node_ids)
    while stg_list != []:
        while stg_list != []:
            node = stg_list.pop(0)
            if not stg_nodes.get(count):
                stg_nodes[count] = [node]
            else:
                stg_nodes[count].append(node)
        new_stg_list = []
        for node in SET(stg_nodes[count]):
            for lnk in links:
                if lnk['from'] == node:
                    new_stg_list.append(lnk['to'])
        stg_list = new_stg_list
        count += 1
    completed_nodes = {}
    batch_ids = []
    for node in nodes:
        item = []
        if node['config']['trigger_pools']:
            completed_nodes[node['id']] = TaskState.INPROGRESS
        elif node['config']['total_pools'] == len(node['config']['completed_pools']) \
                and not node['config']['failed_pools']:
            completed_nodes[node['id']] = TaskState.SUCCESS
        elif node['config']['failed_pools']:
            completed_nodes[node['id']] = TaskState.FAILED
        elif node['config']['submitted_pools']:
            completed_nodes[node['id']] = TaskState.INPROGRESS
        else:
            completed_nodes[node['id']] = TaskState.SUBMITTED
        item.extend([node['id'], node['config']['batch_ids']])
        if add_elements:
            item.append(node['elements'])
        batch_ids.append(item)
    if display_wf_stages:
        hdrs = ['Stage', 'Node', 'Status']
        items = []
        for key, val in stg_nodes.items():
            for n in val:
                item = [key, n, completed_nodes[n] if n in completed_nodes else TaskState.FAILED]
                items.append(item)
        if items:
            click.secho("Workflow Stages    :")
            click.secho("")
            print(tabulate(items, headers=hdrs))
    hdrs = ['Node', 'Batch ids', 'Elements'] if add_elements else ['Node', 'Batch ids']
    return hdrs, batch_ids

@batch.command()
@click.argument('batchid', type=str)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(batchid, output, **kwargs):
    """Get information about a particular batch"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/batch/{batchid}", verify=False, headers=hdrs)
        r.raise_for_status()
        result = r.json()
        if not result:
            print("No results found")
            return
        if output == 'yaml':
            print(yaml.dump(result, indent=4))
            return
        if output == 'json':
            print(json.dumps(result, indent=4))
            return

        duration = result['end_time']-result['st_time'] if result['end_time'] and result['st_time'] else '-'
        print(f"Batch ID           : {batchid}")
        print(f"Custom ID          : {result['customid']}")
        print(f"Name               : {result['name']}")
        print(f"Function UID       : {result['fn_uid']}")
        print(f"Status             : {result['status']}")
        print(f"JOB ID(s)          : {result['jobid']}")
        print(f"Fanout             : {result['fanout']}")
        print(f"Priority Lane      : {result['prioritylane']}")
        print(f"Pools Status       : {result['npools_done']}/{result['npools']} complete")
        print(f"Number of Elements : {len(result['tasks'])}")
        # print(f"Number of Workers  : {result['nworkers']}")
        print(f"Total duration (seconds) : {duration}")
        print(f"Workflowid         : {result.get('workflowid', '')}")
        print(f"Root Task          : {result.get('root_task', '')}")
        if result.get('workflow_nodes'):
            click.secho("")
            click.secho("")
            hdrs, batch_ids = _get_workflow_nodes(result, add_elements=False)
            print(tabulate(batch_ids, headers=hdrs))
            return

        hdrs = ['Pool ID', 'Element UID', 'Start Time', 'Duration', 'Worker ID', 'Status', 'Error']
        tasks = []
        pool_exec, min_st_time, max_end_time = 0, 0, 0
        # sort tasks based on poolid
        result['tasks'] = sorted(result['tasks'], key=lambda i: i['poolid'])
        poolid=0
        for task in result['tasks']:
            duration = ''
            if task['end_time'] and task['st_time']:
                duration = task['end_time'] - task['st_time']
                if poolid != task['poolid']:
                    pool_exec += duration
                    if task['end_time'] > max_end_time:
                        max_end_time = task['end_time']
                    poolid = task['poolid']
            start_time = '-'
            if task['st_time']:
                start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(task['st_time']))
                if min_st_time == 0:
                    min_st_time = task['st_time']
                elif task['st_time'] < min_st_time:
                    min_st_time = task['st_time']
            try:
                worker_id = result['blockmap'][task['poolid']-1]
            except Exception:
                worker_id = '-'
            if result['status'] in ['pausing', 'paused'] and task['status'] == 'submitted':
                status = result['status']
            else:
                status = task['status']
            tasks.append([task['poolid'], task['element_uid'], start_time, duration, worker_id, status, task['errmsg']])

        print(f"Pool execution (seconds) : {pool_exec}")
        # Pool management calculation wont work like this when things execute in parallel, commenting this for now
        #print("Pool mgmt (seconds)      : {}".format(max_end_time-min_st_time-pool_exec if max_end_time else '-'))
        print("\nTasks: \n")
        print(tabulate(tasks, headers=hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list detailed information on batches. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)
"""
@batch.command()
@click.argument('batchid', type=str)
@click.argument('fanout', type=int)
def set_fanout(batchid, fanout, **kwargs):
    '''Set a new fanout for a batch'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.put(f"{sc.engine()}/batch/{batchid}/set-fanout?fanout={fanout}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to set fanout for batch: {batchid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)
"""
@batch.command()
@click.argument('batchid', type=str)
def cancel(batchid, **kwargs):
    '''cancel batch operation'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.put(f"{sc.engine()}/batch/{batchid}/cancel", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to cancel batch: {batchid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@batch.command()
@click.argument('batchid', type=str)
def pause(batchid, **kwargs):
    '''Pause batch operation'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.put(f"{sc.engine()}/batch/{batchid}/pause", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to pause batch: {batchid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@batch.command()
@click.argument('batchid', type=str)
def resume(batchid, **kwargs):
    '''Resume batch operation'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.put(f"{sc.engine()}/batch/{batchid}/resume", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to pause batch: {batchid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@batch.command(aliases=['speedup'])
@click.argument('batchid', type=str)
@click.argument('count', type=int)
def add_workers(batchid, count, **kwargs):
    '''Add more workers for a batch to speed up execution'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'count': count,
            'opcode': 'add',
        }
        r = requests.put(f"{sc.engine()}/batch/{batchid}/transform", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        result = r.json()
        print(result['msg'])
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to add workers for batchid: {batchid}, error: {ex}")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@batch.command(aliases=['slowdown'])
@click.argument('batchid', type=str)
@click.argument('count', type=int)
def remove_workers(batchid, count, **kwargs):
    '''Remove workers from a batch to slow down execution'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'count': count,
            'opcode': 'del',
        }
        r = requests.put(f"{sc.engine()}/batch/{batchid}/transform", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        result = r.json()
        print(result['msg'])
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to remove workers for batchid: {batchid}, error: {ex}")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@batch.command()
def stats(**kwargs):
    """Retrieve batch statistics"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/batch/stats", verify=False, headers=hdrs)
        r.raise_for_status()
        results = r.json()
        pprint(results)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get stats on batches")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@batch.command()
@click.argument('batchid', type=str)
@click.option('--poolid', '-p', type=int, help="Optional poolid to rerun batch")
@click.option('--allpools', '-a', is_flag=True, help="Rerun all pools in the batch(not just failed ones)", default=False)
@click.option('--fanout', '-s', type=int, help="Fan out value for batch rerun.")
def rerun(batchid, poolid, allpools, fanout, **kwargs):
    '''Rerun the batch'''
    try:
        r = None
        hdrs = get_hdrs()
        url = f"{sc.engine()}/batch/{batchid}/rerun"
        q = []
        if poolid:
            q.append(f"poolid={poolid}")
        if allpools:
            q.append(f"allpools={allpools}")
        if fanout:
            q.append(f"fanout={fanout}")

        if q:
            url += f"?{'&'.join(q)}"

        r = requests.put(url, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, "Failed to rerun batch. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@batch.command()
@click.argument('jsonfile', type=str, required=False)
def run_bow(jsonfile, **kwargs):
    '''Execute a bow'''
    try:
        res = None
        hdrs = get_hdrs()
        payload = read_json_file(jsonfile)
        url = "{}/batch/bow".format(sc.engine())
        res = requests.post(url, json=payload, verify=False, headers=hdrs)
        res.raise_for_status()
        r = res.json()
        print(r)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add batch. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs, data=payload)

@batch.command()
@click.option("-o", "--output", type=click.Choice(['wide', 'json']))
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("--archived", is_flag=True, help="Display the BoWs which have already been archived")
@click.option("-b", "--before", type=str, help="Select batches completed before time supplied. Format: Ad:Bh:Cm:Ds. A is #days, B is #hours, C is #minutes, D is #seconds")
@click.option("-a", "--after", type=str, help="Select batches started after time supplied. Format: Ad:Bh:Cm:Ds. A is #days, B is #hours, C is #minutes, D is #seconds")
def list_bows(output, index, archived, before, after, **kwargs):
    '''List bows'''
    try:
        res = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        parameters = [limit, offset]
        if archived:
            parameters.append("archived=True")
        if after:
            parameters.append(f"after={parse_time(after)}")
        if before:
            parameters.append(f"before={parse_time(before)}")
        limit_url = parameter_string(parameters)
        url = "{}/batch/bow{}".format(sc.engine(), limit_url)
        res = requests.get(url, verify=False, headers=hdrs)
        res.raise_for_status()
        r = res.json()
        if output == 'json':
            print(json.dumps(r, indent=4))
            return
        elif output == 'wide':
            tbl_hdrs = ['uid', 'name', 'wf_uid', 'ctime', 'etime', 'batches', 'nodestates', 'status', 'overall_status']
        else:
            tbl_hdrs = ['uid', 'name', 'wf_uid', 'ctime', 'etime', 'nodestates', 'overall_status']
        data = []
        for item in r['items']:
            # data.append([item['uid'], item['wf_uid'], datetime.fromtimestamp(int(item['ctime'])), '\n'.join(item['batches']), item['nodestates'], {nodeid: f"{item['status'][nodeid]['success']}/{item['status'][nodeid]['failed']}/{item['status'][nodeid]['total']}" for nodeid in item['status'].keys()}, item['overall_status']])
            if output == 'wide':
                data.append([item['uid'], item['name'], item['wf_uid'], datetime.fromtimestamp(int(item['ctime'])), datetime.fromtimestamp(int(item['etime'])) if item['etime'] else '-', '\n'.join(item['batches']), item['nodestates'], item['status'], item['overall_status']])
            else:
                data.append([item['uid'], item['name'], item['wf_uid'], datetime.fromtimestamp(int(item['ctime'])), datetime.fromtimestamp(int(item['etime'])) if item['etime'] else '-', item['nodestates'], item['overall_status']])
        print(tabulate(data, headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add batch. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)

@batch.command()
@click.argument('wf_tracker', type=str)
@click.option("-e", "--element", type=str)
@click.option("-g", "--graph", is_flag=True)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option("-v", "--verbose", is_flag=True)
def info_bow(wf_tracker, element, graph, output, verbose, **kwargs):
    '''Info bows'''
    try:
        res = None
        hdrs = get_hdrs()
        options = ""
        if graph:
            options = "?graph=true"
        url = "{}/batch/bow/{}{}".format(sc.engine(), wf_tracker, options)
        res = requests.get(url, verify=False, headers=hdrs)
        res.raise_for_status()
        r1 = res.json()
        tbl_hdrs = ['uid', 'name', 'wf_uid', 'st_time', 'end_time', 'nodestates', 'status', 'errmsg']
        if not output:
            print(f"Wf_tracker: {r1['uid']}")
            print(f"Name: {r1['name']}")
            print(f"Wf_uid: {r1['wf_uid']}")
            print(f"Overall Status: {r1['overall_status']}")
            print(f"Creation time: {datetime.fromtimestamp(int(r1['ctime'])) if r1['ctime'] else '-'}")
            print(f"Completion time: {datetime.fromtimestamp(int(r1['etime'])) if r1['etime'] else '-'}")
            if not element:
                for n in r1['nodestates']:
                    print("Wf_node: {}".format(n))
                    print("    State: {}".format(r1['nodestates'][n]))
                    print("    Status: {}".format(r1['status'][n]))
            print()
            print()


        options = ""
        if element:
            options = f"?element={element}"
        url = "{}/batch/bow/{}/wtasks{}".format(sc.engine(), wf_tracker, options)
        res = requests.get(url, verify=False, headers=hdrs)
        res.raise_for_status()
        r = res.json()
        if output == 'yaml':
            r.update(r1)
            print(yaml.dump(r, indent=4))
            return
        if output == 'json':
            r.update(r1)
            print(json.dumps(r, indent=4))
            return
        if verbose:
            tbl_hdrs = ['element_uid', 'topology', 'st_time', 'end_time', 'poolid', 'status', 'errmsg']
        else:
            tbl_hdrs = ['element_uid', 'topology | status | errmsg']
        if not element:
            data = []
            for item in r['items']:
                if item['context']:
                    elem = f"{item['element_uid']} \nctx: {item['context']}"
                else:
                    elem = item['element_uid']
                if verbose:
                    data.append([elem, item['info']['topology'], item['info']['st_time'], item['info']['end_time'], item['info']['poolid'], item['info']['status'], item['info']['errmsg']])
                else:
                    data.append([elem, pformat({x: f"{item['info']['topology'][x]}|{item['info']['status'][x]}|{item['info']['errmsg'][x]}" for x in item['info']['topology']}, indent=4)])
            print(tabulate(data, headers=tbl_hdrs))
        else:
            for item in r['items']:
                print("Element: {}".format(item['element_uid']))
                print("Context: {}".format(item['context'] if item['context'] else '-'))
                for nodeid, node in item['info'].items():
                    print("Wf_node: {}".format(nodeid))
                    print("    Topology: {}".format(node['topology']))
                    print("    Start Time: {}".format(datetime.fromtimestamp(int(node['st_time'])) if node['st_time'] else '-'))
                    print("    End Time: {}".format(datetime.fromtimestamp(int(node['end_time'])) if node['end_time'] else '-'))
                    print("    Poolid: {}".format(node['poolid']))
                    print("    Status: {}".format(node['status']))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get info on bow {}".format(wf_tracker))
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)


@batch.command()
@click.argument('wf_tracker', type=str)
def pause_bow(wf_tracker, **kwargs):
    '''List bows'''
    try:
        res = None
        hdrs = get_hdrs()
        url = "{}/batch/bow/{}/pause".format(sc.engine(), wf_tracker)
        res = requests.put(url, verify=False, headers=hdrs)
        res.raise_for_status()
        r = res.json()
        print(r['msg'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to pause bow {}".format(wf_tracker))
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)

@batch.command()
@click.argument('wf_tracker', type=str)
@click.option("-e", "--element", type=str)
@click.option("-a", "--action", type=click.Choice(['resume', 'ignore', 'restart', 'unpause']))
def resume_bow(wf_tracker, element, action, **kwargs):

    '''Resume bows'''
    try:
        res = None
        hdrs = get_hdrs()
        options = []
        if element:
            options.append(f"element={element}")
        if action:
            options.append(f"action={action.lower()}")
        options = '?' + '&'.join(options)
        url = "{}/batch/bow/{}/resume{}".format(sc.engine(), wf_tracker, options)
        res = requests.put(url, verify=False, headers=hdrs)
        res.raise_for_status()
        r = res.json()
        print(r['msg'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to resume bow {}".format(wf_tracker))
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)

@batch.command()
@click.option('--wftrackers', '-w', type=str, multiple=True, help="Wf trackers to archive")
@click.option("-t", "--time", type=str, help="Select BoWs completed before time supplied. Format: Ad:Bh:Cm:Ds. A is #days, B is #hours, C is #minutes, D is #seconds")
@click.option("-y", "--yes", is_flag=True, help="Confirm yes with prompt", default=False)
def archive_bow(wftrackers, time, yes, **kwargs):
    '''Archive old BoW information'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        if not time and not wftrackers:
            print("Need to pass time parameters or wftrackers")
            exit(1)
        if time:
            total = parse_time(time)
            if total < 60 * 60 * 24:
                print("WARNING: Trying to archive BoW less than 1 day old")
                if not yes:
                    val = input("Confirm [y/n] ? ")
                else:
                    val = 'y'
                if val.lower() not in ['y', 'yes']:
                    exit(0)
                data['force'] = True
            data['age'] = total
        data['wf_trackers'] = wftrackers
        r = requests.post(f"{sc.engine()}/batch/bow/archive", verify=False, json=data, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@batch.command(aliases=['run'])
@click.argument('jsonfile', type=str, required=False)
@click.option('--function', '-f', type=str, help="Function to run as part of batch operation")
@click.option('--fanout', '-s', type=int, help="Fan out value of batch operation.")
@click.option('--kind', '-e', '-k',
              type=click.Choice(['VM', 'SWITCH', 'BM', 'VRAN', 'ROBINCLUSTER', 'GC', 'NETWORK_FUNCTION'], case_sensitive=False),
              help="Valid element types ('VM', 'SWITCH', 'BM', 'VRAN', 'ROBINCLUSTER', 'GC') for this function")
@click.option("-l", "--labels", type=str, multiple=True, help="Add labels to help with grouping and filtering. Format: key1:val1,key2val2...")
@click.option('--batchid', '-b', type=str, help="Batch id for the batch.")
@click.option('-n', '--name', type=str, help="Name of the batch")
def execute(jsonfile, function, fanout, kind, labels, batchid, name, **kwargs):
    '''Execute a batch'''
    try:
        res = None
        hdrs = get_hdrs()
        payload = {}
        if jsonfile:
            payload = read_json_file(jsonfile)
        else:
            mandatory = [function, kind, labels, batchid, name]
            missing = ['function', 'kind', 'labels', 'batchid', 'name']
            missing_args = []
            for i, m in enumerate(mandatory):
                if not m:
                    missing_args.append(missing[i])
            if missing_args:
                raise Exception("The following arguments are missing: {}".format(", ".join(missing_args)))

        if batchid:
            payload['batch_id'] = batchid

        if name:
            payload['name'] = name

        if function:
            payload['function'] = function

        if fanout:
            payload['fanout'] = fanout

        if kind:
            payload['etype'] = kind

        if labels:
            payload['labels'] = parse_labels(labels, ret_dict=True)

        url = "{}/batch".format(sc.engine())
        res = requests.post(url, json=payload, verify=False, headers=hdrs)
        res.raise_for_status()
        r = res.json()
        batchid = r.get('batchid', r.get('batch_id'))
        if r.get('status') != TaskState.FAILED:
        # print(r.get('batchid', r.get('batch_id', "Batchid not found")))
            print("Successfully submitted batch {}".format(batchid))
        else:
            print("Failed to submit batch {}".format(batchid))
            print(r)
        # print(res.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add batch. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs, data=payload)

@batch.command()
@click.argument('batchid', type=str)
@click.argument('poolid', type=int)
def inventory(batchid, poolid, **kwargs):
    '''Get batch inventory'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/batch/{batchid}/{poolid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to fetch inventory. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@batch.command()
@click.argument('batchuid', type=str)
def delete(batchuid, **kwargs):
    '''Delete a batch'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/batch/{batchuid}", verify=False, headers=hdrs)
        r.raise_for_status()
        # print(json.dumps(r.json(), indent=4))
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete batch. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@batch.command()
@click.option("-t", "--time", type=str, help="Select batches completed before time supplied. Format: Ad:Bh:Cm:Ds. A is #days, B is #hours, C is #minutes, D is #seconds")
def purge(time, **kwargs):
    '''Delete old batch information'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        total = parse_time(time)
        if total < 60 * 60 * 24:
            print("WARNING: Trying to delete batches less than 1 day old")
            val = input("Confirm [y/n] ? ")
            if val.lower() not in ['y', 'yes']:
                exit(0)
            data['force'] = True
        data['age'] = total
        r = requests.delete(f"{sc.engine()}/batch/purge", verify=False, json=data, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@batch.command()
@click.option('--batchids', '-b', type=str, multiple=True, help="Batchids to archive")
@click.option("-t", "--time", type=str, help="Select batches completed before time supplied. Format: Ad:Bh:Cm:Ds. A is #days, B is #hours, C is #minutes, D is #seconds")
@click.option("-y", "--yes", is_flag=True, help="Confirm yes with prompt", default=False)
def archive(batchids, time, yes, **kwargs):
    '''Archive old batch information'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        if not time and not batchids:
            print("Need to pass time parameters or batchids")
            exit(1)
        if time:
            total = parse_time(time)
            if total < 60 * 60 * 24:
                print("WARNING: Trying to archive batches less than 1 day old")
                if not yes:
                    val = input("Confirm [y/n] ? ")
                else:
                    val = 'y'
                if val.lower() not in ['y', 'yes']:
                    exit(0)
                data['force'] = True
            data['age'] = total
        data['batchids'] = batchids
        r = requests.post(f"{sc.engine()}/batch/archive", verify=False, json=data, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@batch.command()
@click.argument('batchid', type=str)
@click.argument('poolid', type=int)
def downloadfn(batchid, poolid):
    '''Download function from a batch'''
    try:
        r = requests.get(f"{sc.engine()}/batch/{batchid}/{poolid}?artifacts=true",
                         allow_redirects=True, verify=False)
        r.raise_for_status()
        path = f'/tmp/rorc-fn-{batchid}-{poolid}'
        with open(path, "wb") as fh:
            fh.write(r.content)
        print(f"Dumped the function to '{path}'")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to download function. ")

@batch.command()
@click.argument('batchid', type=str)
@click.option('--workerid', '-w', type=str, help="Specify worker id to see worker logs")
@click.option('--element_uid', '-e', type=str, help="Specify element uid to see element logs")
@click.option('--stream', '-f', is_flag=True, help="Stream logs", default=False)
def logs(batchid, workerid, element_uid, stream):
    '''Stream batch logs inventory'''
    try:
        if not workerid and not element_uid:
            print("Please specify either workerid or element uid to see the logs")
            return
        if workerid:
            if stream:
                r = requests.get(f"{sc.logstore()}/stream/{batchid}/worker/worker{workerid}.log", stream=True, verify=False)
            else:
                r = requests.get(f"{sc.logstore()}/{batchid}/worker/worker{workerid}.log", verify=False)
        elif element_uid:
            # get batch info to get pool
            r = requests.get(f"{sc.engine()}/batch/{batchid}", verify=False, headers=get_hdrs())
            r.raise_for_status()
            result = r.json()

            # if batch has workflowid, display elementid
            if result['workflowid']:
                hdrs, batches = _get_workflow_nodes(result, display_wf_stages=False, add_elements=True)
                # get element info to take decision on batch elementids
                r = requests.get(f"{sc.engine()}/element/{element_uid}", verify=False, headers=get_hdrs())
                r.raise_for_status()
                element = r.json()
                if element['type'] == 'ROBINCLUSTER':
                    inner_elements = []
                    for k, v in element['config']['infra'].items():
                        inner_elements.append(v['elem_uid'])
                    for batch in batches:
                        batch[2] = [value for value in inner_elements if value in batch[2]]
                print(f"Please use below information to track logs for element: {element_uid}")
                print(tabulate(batches, hdrs))
                return

            for task in result['tasks']:
                if task['element_uid'] == element_uid:
                    break
            else:
                print(f"Element UID: {element_uid} is not part of the batch execution: {batchid}. Please use valid element uids from mdcap batch info <batchid>")
                return
            poolid=task['poolid']
            r = requests.get(f"{sc.logstore()}/stream/{batchid}/{poolid}", stream=False, verify=False)
            r.raise_for_status()
            log_files = r.text.split(',')
            # batch mode
            if f"pool{poolid}.log" in log_files:
                if stream:
                    r = requests.get(f"{sc.logstore()}/stream/{batchid}/{poolid}/pool{poolid}.log", stream=True, verify=False)
                else:
                    r = requests.get(f"{sc.logstore()}/{batchid}/{poolid}/pool{poolid}.log", verify=False)
            # unit mode
            else:
                if stream:
                    r = requests.get(f"{sc.logstore()}/stream/{batchid}/{poolid}/{element_uid}.log", stream=True, verify=False)
                else:
                    r = requests.get(f"{sc.logstore()}/{batchid}/{poolid}/{element_uid}.log", verify=False)
        r.raise_for_status()
        if stream:
            for line in r.iter_lines():
                # filter out keep-alive new lines
                if line:
                    decoded_line = line.decode('utf-8')
                    print(decoded_line)
        else:
            print(r.content.decode('utf-8'))
    except Exception as ex:
        handle_error(ex)

@batch.command()
@click.option("-t", "--type", type=click.Choice(["function", "workflow", "dockerimg", "element_tags", "envs", "envs_per_element", "others"]), default="function")
@click.option("-o", "--output", help="Save the template to a file")
def gentpl(type, output):
    '''Provides batch execution templates'''
    try:
        type = type.lower()
        if type == "function":
            data = {
                "name": "batch-1",
                "batch_id": "batch1",
                "function": "uuid",
                "elements": ["uuid1", "uuid2", "uuid3"],
                "etype": "VM",
                "fanout": 1
            }
        elif type == "workflow":
            data = {
                "name": "batch-1",
                "batch_id": "batch1",
                "workflowid": "uuid",
                "elements": ["uuid1", "uuid2", "uuid3"],
                "etype": "VM",
                "fanout": 1
            }
        elif type == "dockerimg":
            data = {
                "name": "batch-1",
                "batch_id": "batch1",
                "dockerimg": "foo/bar:1.2",
                "elements": ["uuid1", "uuid2", "uuid3"],
                "etype": "VM",
                "fanout": 1
            }
        elif type == "element_tags":
            data = {
                "name": "batch-1",
                "batch_id": "batch1",
                "function": "uuid",
                "labels": {"location": "nyc", "site": "east-2"},
                "etype": "VM",
                "fanout": 1
            }
        elif type == "envs":
            data = {
                "name": "batch-1",
                "batch_id": "batch1",
                "function": "uuid",
                "elements": ["uuid1", "uuid2", "uuid3"],
                "etype": "VM",
                "fanout": 1,
                "env": {
                    "key1": "value1",
                    "key2": "value2"
                }
            }
        elif type == "envs_per_element":
            data = {
                "name": "batch-1",
                "batch_id": "batch1",
                "function": "uuid",
                "elements": ["uuid1", "uuid2"],
                "etype": "VM",
                "fanout": 1,
                "env": {
                    "uuid1": {
                        "key1": "value1",
                        "key2": "value2"
                    },
                    "uuid2": {
                        "key1": "value1",
                        "key2": "value2"
                    }
                }
            }
        elif type == "others":
            data = {
                "name": "batch-1",
                "batch_id": "batch1",
                "function": "uuid",
                "mem_size": 104857600,
                "cpu": 1,
                "customid": "foobar",
                "elements": ["uuid1", "uuid2", "uuid3"],
                "etype": "VM",
                "fanout": 1,
                "prioritylane": "gold"
            }
        if output:
            with open(output, "w") as fh:
                fh.write(json.dumps(data, indent=4))
            print(f"Batch execution template of type '{type}' is saved to {output}")
        else:
            print(json.dumps(data, indent=4))
    except Exception as e:
        print("Error generating/saving batch execution template: {}".format(str(e)))

# @job.command()
# @click.argument('jobid', type=int)
# def logs(jobid):
#     '''Get the logs for the given job id'''
#     try:
#         hdrs = get_hdrs()
#         r = requests.get(f"{sc.engine()}/job/{jobid}?logs=true", allow_redirects=True, verify=False, headers=hdrs)
#         r.raise_for_status()
#         host = r.json().get('job_hosts', None)
#         child_jobs = r.json().get('child_jobs').strip('][').split(', ')
#         if not host:
#             raise Exception("Error: Could not identify host for jobid")
#         for job in child_jobs:
#             print("Fetching logs from {} for jobid {}".format(host,job))
#             username = os.environ.get('ROBIN_LOGS_HOST_USER', 'root')
#             password = os.environ.get('ROBIN_LOGS_HOST_PASSWORD', 'password')
#             command = ''.join(['sshpass -p ', password, ' scp -r -o StrictHostKeyChecking=no ', \
#                                 username, '@', host, ':/var/log/robin/server/', \
#                                 job, ' robin-job-logs-', job])
#             command2 = ''.join(['sshpass -p ', password, ' scp -r -o StrictHostKeyChecking=no ', \
#                                 username, '@', host, ':/var/log/robin/agent/', job])
#             os.system(command)
#             os.system(command2)
#     except Exception as ex:
#         handle_error(ex)

@cli.group(cls=ClickAliasedGroup)
def playground():
    """Playground Management"""
    pass

@playground.command(aliases=['register'])
@click.argument('name', type=str)
@click.option('--username', '-u', default='root', type=str, help="Username needed to login into your playground. Default is root.")
@click.option('--password', '-p', default='password', type=str, help="Password for your playground. Default is password.")
@click.option('--img', '-i', type=str, help="The docker image which the playground will base on. \
                                            If not specified robin default image will be used.")
@click.option('--imgtype', '-t', default='docker', type=str, help="Type of image provided. Default is docker.")
@click.option('--description', '-d', type=str, help="Type of image provided. Default is docker.")
@click.option("-l", "--labels", type=str, multiple=True, help="Add labels to help with grouping and filtering. Format: key1:val1,key2val2...")
def add(name, username, password, img, imgtype, description, labels):
    """Register a Playground"""
    try:
        hdrs = get_hdrs()
        data = {
            'name': name,
            'username': username,
            'password': password,
            'img': img,
            'imgtype': imgtype,
            'description': description,
            'labels': parse_labels(labels, ret_dict=True) if labels else {}
        }
        r = requests.post(f"{sc.engine()}/playground", json=data,
                         allow_redirects=True, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Failed to create playground {}. ".format(name))


@playground.command()
def list():
    """List all Playgrounds"""
    try:
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/playground",
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        results = r.json()
        if not results:
            print("No results found")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list playgrounds. ")


@playground.command()
@click.argument('name', type=str)
@click.argument('username', type=str)
@click.argument('password', type=str)
def login(name, username, password):
    """Login into Playground"""
    try:
        r = requests.get(f"{sc.engine()}/playground?name={name}&&username={username}&&password={password}",
                         allow_redirects=True, verify=False)
        r.raise_for_status()
    except Exception as ex:
        handle_error(ex, action_msg="Failed to log into playground {}. ".format(name))


@cli.group(cls=ClickAliasedGroup)
def user():
    """User Management"""
    pass

@user.command(aliases=['register'])
@click.argument('userid', type=str)
@click.option('-p', '--password', prompt=True, confirmation_prompt=True,
              hide_input=True, required=True)
@click.option('-c', '--clone', type=str,
        help="user uid to clone role and element accesscontrol details from")
@click.option('-f', '--firstname', type=str,
        help="first name")
@click.option('-l', '--lastname', type=str,
        help="last name")
@add_options(common_options)
def add(userid, password, clone, firstname, lastname, **kwargs):
    """Add a user"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'userid': userid,
            'password': password,
            'firstname': firstname,
            'lastname': lastname,
            'clone_uid': clone if clone else None
        }
        r = requests.post("{}/user".format(sc.engine()), json=data,
                          allow_redirects=True, headers=hdrs, verify=False)
        r.raise_for_status()
        print(f"Successfully added user {userid}")
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@user.command()
@click.argument('uid', type=str)
@click.option('-e', '--elems', multiple=True, type=str,
                help="Element UIDS")
@click.option("-l", "--labels", type=str, multiple=True, help="Filter by labels used to idenftify elements. Format: key1:val1,key2val2...")
@add_options(common_options)
def grantaccess(uid, elems, labels, **kwargs):
    """Grant access to an element(s) for a user"""
    try:
        r = None
        if not elems and not labels:
            raise Exception("Need to pass at least one of either: --elems or --labels")
        hdrs = get_hdrs()
        data = {
            'element_uids': elems if elems else [],
            'labels': parse_labels(labels, ret_dict=True) if labels else {},
            'opcode': 'grantaccess'
        }
        r = requests.put("{}/user/{}".format(sc.engine(), uid), json=data,
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        if elems:
            print("Successfully assigned elements {} to user {}".
                format(", ".join(elems), uid))
        if labels:
            print("Successfully assigned elements of label(s) {} to user {}".
                format(labels, uid))
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@user.command()
@click.argument('uid', type=str)
@click.option('-e', '--elems', multiple=True, type=str,
                help="Element UIDs")
@click.option("-l", "--labels", type=str, multiple=True, help="Filter by labels used to idenftify elements. Format: key1:val1,key2val2...")
@add_options(common_options)
def revokeaccess(uid, elems, labels, **kwargs):
    """Revoke access to an element(s) for a user"""
    try:
        r = None
        hdrs = get_hdrs()
        if not elems and not labels:
            raise Exception("Need to pass at least one of either: --elems or --labels")
        data = {
            'element_uids': elems if elems else [],
            'labels': parse_labels(labels, ret_dict=True) if labels else {},
            'opcode': 'revokeaccess'
        }
        r = requests.put("{}/user/{}".format(sc.engine(), uid), json=data,
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        if elems:
            print("Successfully revoked elements {} from user {}".
                format(", ".join(elems), uid))
        if labels:
            print("Successfully revoked elements of label(s) {} from user {}".
                format(labels, uid))
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@user.command()
@click.argument('uid', type=str)
@click.argument('role_uid', type=str)
@add_options(common_options)
def addrole(uid, role_uid, **kwargs):
    """Assign a role to a user"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'role_uid': role_uid,
            'opcode': 'setrole'
        }
        r = requests.put("{}/user/{}".format(sc.engine(), uid), json=data,
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        print(f"Successfully added role to user {uid}")
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@user.command()
@click.argument('uid', type=str)
@click.argument('role_uid', type=str)
@add_options(common_options)
def removerole(uid, role_uid, **kwargs):
    """Unassign a role from a user"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'role_uid': role_uid,
            'opcode': 'unsetrole'
        }
        r = requests.put("{}/user/{}".format(sc.engine(), uid), json=data,
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        print(f"Successfully revoked role for user {uid}")
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@user.command()
@click.argument('uid', type=str)
@click.option('-f', '--firstname', type=str)
@click.option('-l', '--lastname', type=str)
@click.option('-u', '--userid', type=str)
@add_options(common_options)
def update(uid, firstname, lastname, userid, **kwargs):
    """Update user information"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'opcode': 'userinfo',
            'firstname': firstname if firstname else "",
            'lastname': lastname if lastname else "",
            'userid': userid if userid else ""
        }
        r = requests.put("{}/user/{}".format(sc.engine(), uid), json=data,
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        print(f"Successfully updated information of user {uid}")
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@user.command()
@click.argument('uid', type=str)
@click.option('-p', '--password', prompt=True, confirmation_prompt=True,
              hide_input=True, required=True)
@add_options(common_options)
def passwd(uid, password, **kwargs):
    """Change user password"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'opcode': 'userinfo',
            'password': password if password else ""
        }
        r = requests.put("{}/user/{}".format(sc.engine(), uid), json=data,
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        print(f"Successfully updated password of user {uid}")
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@user.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a user"""
    try:
        r = None
        check_uid(uid)
        hdrs = get_hdrs()
        r = requests.delete("{}/user/{}".format(sc.engine(), uid),
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete user. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@user.command()
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(output, **kwargs):
    """List all users"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get("{}/user".format(sc.engine()),
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        tbl_hdrs = ['id', 'userid', 'firstname', 'lastname', 'role']
        print(tabulate(r.json(), headers=tbl_hdrs))

    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@user.command()
@click.argument('uid', type=str)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, **kwargs):
    """Get information about a particular user"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/user/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        resp = r.json()
        # fname = resp['fname']
        # lname = resp['lname']
        username = resp['username']
        # pprint(f"First Name: {fname}")
        # pprint(f"Last Name: {lname}")
        pprint(f"Username: {username}")
        print(tabulate(resp['roleinfo'], headers=['role id', 'rolename', 'privileges']))
        print(tabulate(resp['elementinfo'], headers=['element id', 'name', 'type']))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to find information about user with uid {}".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@cli.group(cls=ClickAliasedGroup)
def role():
    """Role Management"""
    pass

@role.command()
@click.argument('name', type=str)
@click.option('-f', '--functions', multiple=True)
@click.option('-w', '--workflows', multiple=True)
@click.option('-p', '--privileges', multiple=True)
@add_options(common_options)
def add(name, functions, workflows, privileges, **kwargs):
    """Add a role"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            "name": name,
            "fn_uids": functions,
            "wf_uids": workflows,
            "privileges": privileges
        }
        r = requests.post("{}/role?format=uidlist".format(sc.engine()), json=data,
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@role.command()
@click.argument('role_uid', type=str, required=True)
@click.argument('operation', type=click.Choice(['add', 'remove']), required=True)
@click.option('-f', '--functions', multiple=True)
@click.option('-w', '--workflows', multiple=True)
@click.option('-p', '--privileges', multiple=True)
@add_options(common_options)
def update(role_uid, operation, functions, workflows, privileges, **kwargs):
    """Update a role"""
    try:
        r = None
        hdrs = get_hdrs()
        if operation not in ['add', 'remove']:
            raise Exception("Operation must be either one of: 'add' or 'remove'")
        data = {
            "operation": operation,
            "fn_uids": functions,
            "wf_uids": workflows,
            "privileges": privileges
        }
        r = requests.put("{}/role/{}".format(sc.engine(), role_uid), json=data,
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@role.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a role"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete("{}/role/{}".format(sc.engine(), uid),
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        click.echo(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@role.command()
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(output, **kwargs):
    """List all roles"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get("{}/role".format(sc.engine()),
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        tbl_hdrs = ['uid', 'role', 'desc']
        print(tabulate(r.json(), headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@role.command()
@click.argument('uid')
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, **kwargs):
    """Get information about a particular role"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get("{}/role/{}".format(sc.engine(), uid),
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        pprint(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Failed to Find Information about role with uid {}".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@cli.group(cls=ClickAliasedGroup)
def privileges():
    """Privilege management"""
    pass

@privileges.command()
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(output, **kwargs):
    """List all privileges"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get("{}/priv".format(sc.engine()),
                         allow_redirects=True, verify=False, headers=hdrs)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        pprint(r.json())
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@cli.group(cls=ClickAliasedGroup)
def fsm():
    """FSM Management"""
    pass

@fsm.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, output, **kwargs):
    """List all FSMs"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        limit_url = parameter_string(limit, offset)
        r = requests.get("{}/fsm{}".format(sc.engine(), limit_url), verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            data = []
            headers = ["uid", "kind"]
            for item in results['items']:
                data.append([item['uid'], item['etype']])
            print(tabulate(data, headers))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list FSM. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@fsm.command()
@click.argument('uid', type=str)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, **kwargs):
    """Get information about a particular FSM"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/fsm/{uid}", headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        print(yaml.dump(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to fetch FSM info. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@fsm.command(aliases=['register'])
@click.option('--kind', '-k', required=True,
              type=click.Choice(['VM', 'NETWORK_SERVICE', 'NETWORK_FUNCTION', 'SWITCH', 'BM', 'VRAN', 'ROBINCLUSTER', 'GC'], case_sensitive=False),
              help="Valid element types ('VM', 'SWITCH', 'NETWORK_SERVICE', 'NETWORK_FUNCTION', 'BM', 'VRAN', 'ROBINCLUSTER', 'GC') for this function")
@click.argument('input', type=click.File('rb'))
@add_options(common_options)
def add(kind, input, **kwargs):
    """Add a FSM"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'etype': kind,
            'config': yaml.load(input, Loader=yaml.FullLoader)
        }
        r = requests.post(f"{sc.engine()}/fsm", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json())
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to add FSM definition for element type {kind}")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@fsm.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a FSM"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/fsm/{uid}", headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete FSM with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@cli.group(cls=ClickAliasedGroup)
def iam():
    """IAM Credentials Management"""
    pass

@iam.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option('-t', "--type", 'kind', type=str, help="Filter by type")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, output, kind, **kwargs):
    """List all IAM Credentials"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        q_args = [limit, offset]
        if kind:
            q_args.append(f"kind={kind}")
        limit_url = parameter_string(q_args)
        r = requests.get("{}/iam{}".format(sc.engine(), limit_url), verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            data = []
            headers = ["uid", "name", "type", "description", "elem_ref"]
            for item in results['items']:
                data.append([item['uid'], item['name'], item['type'], item['description'] if item['description'] else "-", item['elem_ref'] if item['elem_ref'] else "-"])
            print(tabulate(data, headers))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list IAM. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@iam.command()
@click.argument('uid', type=str)
@click.option('-c', "--credentials", is_flag=True, help="Show credentials in output")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, credentials, output, **kwargs):
    """Get information about a particular IAM credential"""
    try:
        r = None
        hdrs = get_hdrs()
        show_creds = ""
        if credentials:
            show_creds = "?show_creds=True"
        r = requests.get(f"{sc.engine()}/iam/{uid}{show_creds}", headers=hdrs, verify=False)
        r.raise_for_status()
        req_json = r.json()

        if output == 'yaml':
            if credentials:
                req_json['credentials']=json.loads(req_json['credentials'])
                # if req_json['config'].get('kube_config'):

                    # cred_yaml = yaml.dump(req_json['config']['kube_config'], default_flow_style=False)
            print(yaml.dump(req_json, indent=2, default_flow_style=False))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        result = r.json()
        if not result:
            print("IAM '{}' does not exist".format(uid))
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            print("Name:        {}".format(result['name']))
            print("UUID:        {}".format(result['uid']))
            print("Type:        {}".format(result['type']))
            print("Description: {}".format(result['description'] if result.get('description') else "-"))
            print("Element Reference: {}".format(result['elem_ref'] if result['elem_ref'] else "-"))
            print()
            if credentials:
                print("Credentials:")
                creds = json.loads(result['credentials'])['config']
                creds.pop("type", None)
                creds.pop("name", None)
                creds.pop("description", None)
                print(json.dumps(creds, indent=4))

    except Exception as ex:
        handle_error(ex, action_msg="Failed to fetch IAM info")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@iam.command(aliases=['register'])
@click.argument('name', type=str)
@click.argument('file', type=click.File('r'))
@click.option('--type', '-t', required=True,
              type=click.Choice(['aws', 'gcp', 'kube_config'], case_sensitive=False),
              help="Valid element types ('aws', 'gcp', 'kube-config') for this function")
@click.option('-d', '--description', help="Description of Iam.")
@click.option('-e', '--elem-ref', help="Element Reference of the IAM")
@add_options(common_options)
def add(name, file, type, description, elem_ref, **kwargs):
    """Add an IAM credential"""
    try:
        r = None
        hdrs = get_hdrs()
        # if 'type' not in data['config'].keys():
        if not type:
            # print("Must give type in json or as flag")
            raise Exception("Must give 'type' in json or as flag")
        # data['config']['type'] = type.upper()
        # if type:
        #     data['config']['type'] = type.upper()
        # elif 'type' in data['config'].keys():
            # data['config']['type'] = type.upper()
        if type.upper() not in ['AWS', 'GCP', 'KUBE_CONFIG']:
            # print("Type needs to be one of ('AWS', 'GCP', 'KUBE_CONFIG')")
            raise Exception("Type needs to be one of ('AWS', 'GCP', 'KUBE_CONFIG')")

        data = {}
        creds = {}
        data['config'] = {}
        if type.upper() == 'KUBE_CONFIG':
            try:
                try:
                    import ruamel.yaml
                    ryaml = ruamel.yaml.YAML(typ='safe')
                    kube_config_json = ryaml.load(file)
                except:
                    kube_config_json = yaml.safe_load(file)
            except Exception as err:
                raise Exception(f"Failed to parse kubeconfig yaml {err}")
            data['config']['kube_config'] = kube_config_json
            
        else:
            try:
                creds = json.loads(file.read())
            except Exception as err:
                raise Exception(f"Failed to parse the json file. {err}")
            data['config'] = creds

        data['config']['type'] = type.upper()
        data['name'] = name
        data['elem_ref'] = elem_ref if elem_ref else creds.get('elem_ref', None)
        
        data['description'] = description if description else ""
        
        r = requests.post(f"{sc.engine()}/iam", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to add iam '{name}'")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@iam.command()
@click.argument('uid', type=str)
@click.option('-o', '--output', help='Output file path')
@add_options(common_options)
def download(uid, output, **kwargs):
    """Download an IAM credential"""
    try:
        resp = None
        hdrs = get_hdrs()
        resp = requests.get(f"{sc.engine()}/iam/{uid}?show_creds=True", headers=hdrs, verify=False)
        resp.raise_for_status()
        r = resp.json()
        # print(r)
        
        file_base = f"iam_{r['name']}_{uid[:8]}"
        if r['type'].upper() == 'KUBE_CONFIG':
            kube_config = json.loads(r['credentials'])['config']['kube_config']
            if output:
                filename = output
            else:
                filename = f"/tmp/{file_base}.yaml"
            with open(filename, 'w') as outfile:
                try:
                    import ruamel.yaml
                    ruamel.yaml.dump(kube_config, outfile, default_flow_style=False, indent=2)
                except:
                    yaml.dump(kube_config, outfile, default_flow_style=False)
            print(f"Downloaded kubeconfig credentials to {filename}")
        else:
            creds = json.loads(r['credentials'])
            if output:
                filename = output
            else:
                filename = f"/tmp/{file_base}.json"
            with open(filename, 'w') as f:
                json.dump(creds, filename)
                print(f"Downloaded {r['type'].upper()} credentials to {filename}")

        # print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to download iam with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(resp, headers=hdrs)

# @iam.command()
# @click.argument('iam_uid', type=str, required=True)
# @click.argument('key', type=str, required=True, help="key to update ['elem_ref'|'description']")
# @add_options(common_options)
# def update(iam_uid, key, **kwargs):
#     """Update an IAM"""
#     try:
#         r = None
#         hdrs = get_hdrs()
#         if key not in {'elem_ref', 'description', 'credentials'}:
#             raise Exception("Key must be either one of: 'elem_ref' or 'description' or 'credentials")
        
#     except Exception as ex:
#         handle_error(ex)
#     finally:
#         if kwargs.get('urlinfo') and r:
#             compute_curl_command(r, headers=hdrs, data=data)

@iam.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete an IAM credential"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/iam/{uid}", headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete iam with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@cli.group(cls=ClickAliasedGroup)
def dashboard():
    """Dashboard Management"""
    pass

@dashboard.command()
@click.option('-l', '--location', help="Show stats of a particular location")
@click.option('-d', '--date', help="Show stats of a particular location")
@add_options(common_options)
def stats(location, date, **kwargs):
    """Retrieve dashboard statistics"""
    try:
        r = None
        hdrs = get_hdrs()
        q_params = []
        if location:
            q_params.append("location={}".format(location))
        if date:
            q_params.append("date={}".format(datetime.fromisoformat(date).isoformat()))

        limit_url = parameter_string(q_params)
        r = requests.get(f"{sc.engine()}/stats{limit_url}", headers=hdrs, verify=False)
        r.raise_for_status()
        pprint(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get dashboard stats")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@cli.group()
def element_schema():
    """Element Schema Management"""

@element_schema.command()
@click.argument("uid", type=str)
@click.option('-p', "--path", type=str, help="Print only a part of the schema given in path. Example: /robin_config/secondary_masters", default=None)
@click.option("--spec", is_flag=True, help="Print only the spec section of the schema", default=False)
@click.option('-s', '--script',  is_flag=True, help="Dump the script instead of schema")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, path, spec, script, output, **kwargs):
    """Get information on a particular Element Schema"""
    try:
        r = None
        url = "{}/elementschema/{}".format(sc.engine(), uid)
        hdrs = get_hdrs()
        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()
        schema = r.json()
        if schema:
            if not spec:
                print(f'UID: {uid}')
                print(f'Name: {schema["name"]}')
                print(f'Kind: {schema["kind"]}')
                print(f'ApiVersion: {schema["apiversion"]}')
            else:
                path = 'spec'
            if not script:
                print('Schema:')
                cfg = schema["config"]
                if path:
                    for p in path.split("/"):
                        if len(p) == 0:
                            continue
                        cfg=cfg['properties'][p]
                if output == 'yaml':
                    print(yaml.dump(cfg, indent=4))
                else:
                    print(json.dumps(cfg, indent=4))
            else:
                print('Script:')
                print(schema['script'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for Element Schema '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@element_schema.command()
@click.option('-k', '--kind',  help="List schemas of this kind")
@click.option('-v', '--apiversion',  help="List schemas of this apiVersion")
@add_options(common_options)
def list(kind, apiversion, **kwargs):
    """List all Element Schemas"""
    try:
        r = None
        filters = ['all=true']
        if kind or apiversion:
            filters = []
            if kind:
                filters.append("kind={}".format(kind))
            if apiversion:
                filters.append("apiversion={}".format(version))


        if filters:
            url = "{}/elementschema?{}".format(sc.engine(),"&".join(filters))
        else:
            url = "{}/elementschema".format(sc.engine())

        hdrs = get_hdrs()
        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()
        headers = ['UID', 'Name', 'Kind', 'Active', 'ApiVersion']
        data = []
        for schema in r.json():
            data.append([schema["uid"], schema["name"], get_alias_element_type(schema["kind"]), schema["active"], schema['apiversion']])
        print(tabulate(data, headers))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list Element Schemas. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@element_schema.command()
@click.argument("uid", type=str)
@click.option("--schema", is_flag=True, help="Edit the schema", default=None)
@click.option("--documentation", is_flag=True, help="Edit the documentation", default=None)
@click.option("--api-upgrade-script", is_flag=True, help="Edit the upgrade scripts", default=None)
@click.option("--enable", is_flag=True, help="Enable this schema", default=None)
@click.option("--disable", is_flag=True, help="Disable this schema", default=None)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, schema, documentation, api_upgrade_script, output, enable, disable, **kwargs):
    """Update an Element Schema"""
    try:
        r = None
        if enable and disable:
            print("Cannot enable and disable at the same time")
            return
        if sum(bool(x) for x in [schema, documentation, api_upgrade_script]) > 1:
            print("Select schema or documentation or api-upgrade-script to edit - cannot update two configurations at the same time")
            return
        data_input = {}
        if enable or disable:
            data_input['active'] = True if enable else False

        if schema:
            mod = open_in_editor(uid, otype="elementschema", param="config", edit_fmt=output)
            if not mod:
                return
            data_input['config'] = mod
        elif documentation:
            mod = open_in_editor(uid, otype="elementschema", param="management.help", edit_fmt=output)
            if not mod:
                return
            data_input['management']['help'] = mod
        elif api_upgrade_script:
            mod = open_in_editor(uid, otype="elementschema", param="management.upgrade.script.prevalidate", edit_fmt=output)
            if not mod:
                return
            data_input['management']['help'] = mod
        if not data_input:
            raise Exception("At least one of the following parameters need to be specified: --schema, --documentation, --enable, --disable --api-upgrade-script")

        hdrs = get_hdrs()
        r = requests.put("{}/elementschema/{}".format(sc.engine(), uid), data=json.dumps(data_input), verify=False, headers=hdrs)

        r.raise_for_status()
        print(json.dumps(r.json()))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to update Element Schema with UID '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data_input)

@element_schema.command()
@click.argument('kind', type=str)
@click.argument("config_file", type=str)
@add_options(common_options)
def generate(kind, config_file, **kwargs):
    """Generate an Element Schema from an element's config file."""
    try:
        r = None
        data_input = {'apiVersion': 'mdcap.robin.io/v1'}
        if config_file[-4:] == "yaml":
            data_input["spec"] = read_yaml_file(config_file)
        else:
            data_input["spec"] = read_json_file(config_file)
        data_input['kind'] = kind
        hdrs = get_hdrs()
        r = requests.put("{}/elementschema/".format(sc.engine()), data=json.dumps(data_input), verify=False, headers=hdrs)
        r.raise_for_status()

        schema_dump = r.json()
        print(json.dumps(schema_dump, indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate schema.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data_input)

@element_schema.command()
@click.argument('kind', type=str)
@click.option('-v', '--apiversion', type=str, help="API Version", default="mdcap.robin.io/v1")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option("--explain", is_flag=True, help="Display examples and other guide for this command")
@click.option('-f', "--file", type=str, help="Output to file")
@click.option("--all", is_flag=True, help="Include non-mandatory fields")
@add_options(common_options)
def generate_config(kind, apiversion, output, explain, file, all, **kwargs):
    """Generate element config template"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {'template': True}

        bm = generate_element_template(kind, apiversion, fmt=output, print_doc=explain, include_non_mandatory=all)
        if explain:
           return
        if output == 'yaml':
            if file:
                with open(file, "w") as fp:
                    yaml.dump(bm, fp, indent=4)
            else:
                print(yaml.dump(bm, indent=4))
        else:
            if file:
                with open(file, "w") as fp:
                    json.dump(bm, fp, indent=4)
            else:
                print(json.dumps(bm, indent=4))
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to dump element template for kind {kind}. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@element_schema.command()
@click.argument('name', type=str)
@click.argument('kind', type=str)
@click.argument('apiversion', type=str)
@click.argument('file', type=str)
@click.option('-d', "--documentation-file", type=str, help="User documentation with examples will help user during element registration. Ex: {'help': {'example': {<example-payload>}}}")
@click.option('-a', "--api-upgrade-script-file", type=str, help="Element config upgrade scripts between api versions")
@add_options(common_options)
def register(name, kind, apiversion, file, documentation_file, api_upgrade_script_file, **kwargs):
    """Register an Element Schema"""
    try:
        r = None
        schema = None
        doc = None
        upgrade_script = None
        try:
            schema = read_json_file(file)
            if documentation_file:
                doc = read_json_file(documentation_file)
            if api_upgrade_script_file:
                upgrade_script = read_json_file(api_upgrade_script_file)
        except Exception:
            schema = read_yaml_file(file)

        payload = {}
        payload['name'] = name
        payload['kind'] = kind
        payload['apiversion'] = apiversion
        payload['config'] = schema
        payload['management'] = { 'help': doc, 'upgrade': { 'script': { 'prevalidate': upgrade_script }}}

        hdrs = get_hdrs()
        url = "{}/elementschema".format(sc.engine())
        r = requests.post(url, data=json.dumps(payload), verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Failed to register Element Schema '{}'. ".format(name))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=payload)


@cli.group()
def subscriber():
    """Subscriber Management"""


@subscriber.command('add')
@click.argument('name', type=str)
@click.option('-d', '--description', type=str)
@add_options(common_options)
def subscriber_add(name, description, **kwargs):
    """Add a subscriber"""
    try:
        r = None
        payload = {'name': name, 'description': description}
        url = "{}/subscriber".format(sc.engine())
        hdrs = get_hdrs()
        r = requests.post(url, data=json.dumps(payload), verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add subscriber. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=payload)


@subscriber.command('update')
@click.argument('subscriber-id', type=int)
@click.option('-n', '--name', type=str)
@click.option('-d', '--description', type=str)
@add_options(common_options)
def subscriber_update(subscriber_id, name, description, **kwargs):
    """Update a subscriber"""
    try:
        r = None
        hdrs = get_hdrs()
        payload = {}
        if name:
            payload['name'] = name
        if description:
            payload['description'] = description
        if not payload:
            raise Exception("At least one parameter to be updated needs to be provided")

        url = "{}/subscriber/{}".format(sc.engine(), subscriber_id)
        r = requests.put(url, data=json.dumps(payload), verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to update subscriber. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=payload)


@subscriber.command('delete')
@click.argument('subscriber-id', type=int)
@add_options(common_options)
def subscriber_delete(subscriber_id, **kwargs):
    """Delete a subscriber"""
    try:
        r = None
        hdrs = get_hdrs()
        url = "{}/subscriber/{}".format(sc.engine(), subscriber_id)
        r = requests.delete(url, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete subscriber. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@subscriber.command('list')
@add_options(common_options)
def subscriber_list(**kwargs):
    """List all subscribers"""
    try:
        res = None
        hdrs = get_hdrs()
        url = "{}/subscriber".format(sc.engine())
        res = requests.get(url, verify=False, headers=hdrs)
        res.raise_for_status()
        results = res.json()
        if not results:
            print("No subscribers found")
        else:
            table = []
            tbl_hdrs = ['id', 'name', 'description']
            for item in results:
                table.append([item['id'], item['name'], item.get('description', '')])
            print(tabulate(table, headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get subscribers. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)


@cli.group()
def notification():
    """Subscriber Notification Management"""


@notification.group()
def kafka():
    """Kafka Notification Management"""


@kafka.command('add')
@click.argument('subscriber-id', type=int, required=True)
@click.option('-b', '--brokers', type=str, required=True,
              help="The host / IP address of Kafka Brokers. Should be in"
                   " <hostname>:<port> or <ipv4-addr>:<port> or"
                   " <[ipv6-addr]>:<port> (required for kafka type")
@click.option('-t', '--topic', type=str, required=True,
              help="The Kafka topic where the events/alerts will be sent")
@click.option('-p', '--partition', type=int, required=False,
              help="The kafka partition where the events/alerts will be sent")
@add_options(common_options)
# @click.option('--sasl-mechanism', type=click.Choice(['PLAIN']),
#              help="The kafka broker SASL mechanism. Valid types are['PLAIN']")
# @click.option('--username', type=str, help="The kafka broker username")
# @click.option('--password', type=str, help="The kafka broker password")
# @click.option('--enable-ssl', is_flag=True, default=False,
#              help="Enable SSL for communication with Kafka brokers")
def kafka_add(subscriber_id, brokers, topic, partition, **kwargs):
    """Add a Kafka Subscription"""
    try:
        res = None
        hdrs = get_hdrs()
        payload = {'brokers': brokers, 'topic': topic}
        if partition:
            payload['partition'] = partition

        url = "{}/subscriber/{}/notification/kafka".format(sc.engine(), subscriber_id)
        res = requests.post(url, data=json.dumps(payload), verify=False, headers=hdrs)
        res.raise_for_status()
        print(res.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add kafka notification. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs, data=payload)


@kafka.command('update')
@click.argument('subscriber-id', type=int, required=True)
@click.option('-b', '--brokers', type=str,
              help="The host / IP address of Kafka Brokers. Should be in"
                   " <hostname>:<port> or <ipv4-addr>:<port> or"
                   " <[ipv6-addr]>:<port> (required for kafka type")
@click.option('-t', '--topic', type=str,
              help="The Kafka topic where the events/alerts will be sent")
@click.option('-p', '--partition', type=int,
              help="The kafka partition where the events/alerts will be sent")
@add_options(common_options)
# @click.option('--sasl-mechanism', type=click.Choice(['PLAIN']),
#              help="The kafka broker SASL mechanism. Valid types are['PLAIN']")
# @click.option('--username', type=str, help="The kafka broker username")
# @click.option('--password', type=str, help="The kafka broker password")
# @click.option('--enable-ssl', is_flag=True, default=False,
#              help="Enable SSL for communication with Kafka brokers")
def kafka_update(subscriber_id, brokers, topic, partition, **kwargs):
    """Update a Kafka Subscription"""
    try:
        res = None
        hdrs = get_hdrs()
        payload = {}
        if brokers:
            payload['brokers'] = brokers
        if topic:
            payload['topic'] = topic
        if partition is not None:
            payload['partition'] = partition
        if not payload:
            raise Exception("At least one parameter to be updated needs to be provided")

        url = "{}/subscriber/{}/notification/kafka".format(sc.engine(), subscriber_id)
        res = requests.put(url, data=json.dumps(payload), verify=False, headers=hdrs)
        res.raise_for_status()
        print(res.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to update kafka notification. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs, data=payload)


@kafka.command('delete')
@click.argument('subscriber-id', type=int, required=True)
@add_options(common_options)
def kafka_delete(subscriber_id, **kwargs):
    """Delete a Kafka Subscription"""
    try:
        res = None
        hdrs = get_hdrs()
        url = "{}/subscriber/{}/notification/kafka".format(sc.engine(), subscriber_id)
        res = requests.delete(url, verify=False, headers=hdrs)
        res.raise_for_status()
        print(res.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete kafka notification. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)


@kafka.command('info')
@click.argument('subscriber-id', type=int, required=True)
@add_options(common_options)
def kafka_info(subscriber_id, **kwargs):
    """Get information about a particular Kafka Subscription"""
    try:
        res = None
        hdrs = get_hdrs()
        url = "{}/subscriber/{}/notification/kafka".format(sc.engine(), subscriber_id)
        res = requests.get(url, verify=False, headers=hdrs)
        res.raise_for_status()
        item = res.json()
        if not item:
            print("No kafka notification found")
        else:
            table = []
            tbl_hdrs = ['id', 'Brokers', 'Topic', 'Partition']
            table.append([item['id'], item['brokers'], item['topic'], item.get('partition', '')])
            print(tabulate(table, headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get kafka notification. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)

def print_help(cmd, parent=None):
    ctx = click.core.Context(cmd, info_name=cmd.name, parent=parent)
    print(cmd.get_help(ctx).replace("Usage: cli", "Usage: mdcap"))
    print()
    commands = getattr(cmd, 'commands', {})
    for sub in commands.values():
        print_help(sub, ctx)

@cli.command()
def gendoc():
    '''Generate CLI Documentation'''
    print_help(cli)


@cli.group(cls=ClickAliasedGroup, aliases=['cr'])
def customresource():
    """Custom Resource Management"""
    pass

@customresource.command()
@click.argument('kind')
@add_options(common_options)
def scaffolding(kind, **kwargs):
    ''' Generate scaffolding for new element kinds
    '''
    generate_new_elem(kind)

@customresource.command()
@click.argument('kind', type=str)
@click.argument('location', type=str)
@add_options(common_options)
def add(kind, location, **kwargs):
    '''Add Custom Resource'''
    try:
        res = None
        hdrs = get_hdrs()
        if not os.path.exists(location):
            raise Exception("No file found at specified location: {}".format(location))
        files = {}
        files['file'] = open(location, 'rb')
        res = requests.post(f"{sc.engine()}/element/customresource/{kind}", files=files, headers=hdrs, verify=False)
        res.raise_for_status()
        out = res.json()
        print(out['msg'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add new element kind")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)


@customresource.command()
@click.argument('kind', type=str)
@click.argument('location', type=str)
@add_options(common_options)
def update(kind, location, **kwargs):
    '''Update Custom Resource tar'''
    try:
        res = None
        hdrs = get_hdrs()
        if not os.path.exists(location):
            raise Exception("No tarfile found at specified location: {}".format(location))
        files = {}
        files['file'] = open(location, 'rb')
        res = requests.put(f"{sc.engine()}/element/customresource/{kind}", files=files, headers=hdrs, verify=False)
        res.raise_for_status()
        out = res.json()
        print(out['msg'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add new element kind")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)


@customresource.command(name="update-cli")
@click.argument('kind', type=str)
@click.argument('cli_path', type=str)
@add_options(common_options)
def updatecli(kind, cli_path, **kwargs):
    '''Fetch updated MDCAP CLI'''
    try:
        res = None
        hdrs = get_hdrs()
        if not os.path.exists(cli_path):
            raise Exception("No cli file found at specified location: {}".format(cli_path))
        files = {}
        files['file'] = open(cli_path, 'rb')
        r = requests.get(f"{sc.engine()}/element/kinds", verify=False, headers=hdrs)
        r.raise_for_status()
        crs = r.json()
        if kind.upper() not in crs:
            print(f"Kind: {kind} is invalid, please provide valid kind")
            return
        res = requests.get(f"{sc.engine()}/element/customresource/cli/{kind.lower()}", files=files, headers=hdrs, verify=False)
        res.raise_for_status()
        out = res.content
        new_version = "./mdcap-" + str(int(datetime.now().timestamp()))
        with open(new_version, 'wb') as f:
            f.write(out)
        md5, err, status = run_command(f"chmod +x {new_version}")
        if status:
            print(f"Failed to add execute permission to {new_version}")
            return
        print(f"Successfully added cli of {kind}. Please access updated cli with `{new_version} {kind.lower()} --help`")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to update cli")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)

@customresource.command()
@add_options(common_options)
def list(**kwargs):
    """Retrieve Custom Resources"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/element/kinds", verify=False, headers=hdrs)
        r.raise_for_status()
        if not r.json():
            print("No results found")
        else:
            res = [[get_alias_element_type(r)] for r in r.json()]
            tbl_hdrs = ['Supported Types']
            print("\n", tabulate(res, headers=tbl_hdrs), "\n")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get element types. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@cli.group(cls=ClickAliasedGroup, aliases=['lbl'])
def label():
    """Labels"""
    pass

@label.command()
@add_options(common_options)
@click.argument('key', type=str)
def values(key, **kwargs):
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/labels/key/{key}", verify=False, headers=hdrs)
        r.raise_for_status()
        if not r.json():
            print("No results found")
        else:
            tbl_hdrs = ['Possible Values']
            print("\n", tabulate(r.json(), headers=tbl_hdrs), "\n")
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to get label values for key: {key}")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@label.command()
@add_options(common_options)
def list(**kwargs):
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/labels/", verify=False, headers=hdrs)
        r.raise_for_status()
        if not r.json():
            print("No results found")
        else:
            tbl_hdrs = ['Labels']
            print("\n", tabulate(r.json(), headers=tbl_hdrs), "\n")
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to get labels")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@cli.group(cls=ClickAliasedGroup)
def license():
    """License Management"""
    pass

@license.command()
@click.option("--usage", is_flag=True, help="Cluster wide usage details")
@click.option("-o", "--output", type=click.Choice(['json']))
@add_options(common_options)
def info(usage, output, **kwargs):
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/license", verify=False, headers=hdrs)
        r.raise_for_status()
        if output == "json":
            print(json.dumps(r.json(), indent=4))
            return
        response = r.json()['license_info']
        lic = response['license']
        profile = response['profile']

        if not usage:
            print("\nMDCAP License Information:\n")
            print("ID ......................... {}".format(repr(lic['id']).strip("'")))
            print("Type ....................... {}".format(lic.get('type', "N/A")))
            print("Created on ................. {} UTC".format(lic.get('createtime', "N/A")))
            print("Version .................... {}".format(lic.get('version', 'N/A')))
            num_days_expire = lic['num_days_expire']
            num_days_lockdown = lic['num_days_lockdown']
            if response['status'] != LicenseState.NOT_ACTIVATED:
                if num_days_expire >= 0:
                    if num_days_expire >= 10 * 365:
                        print("Expires on ................. NEVER")
                    else:
                        print("Expires on ................. {} UTC ({} day(s) remaining)".format(lic['expireson'],
                                                                                             num_days_expire))
                else:
                    if num_days_lockdown >= 0:
                        print("Expired on ................. {} UTC ({} day(s) remaining for application lockdown. Please "
                              "contact Robin to update your license.".format(lic['expireson'], num_days_lockdown))
                    else:
                        print("Expired on ................. {} UTC (Application is locked. Please "
                              "contact Robin to update your license.".format(lic['expireson']))
            if response['status'] != "OK":
                print(click.style("Status ..................... {}"
                                  .format(response['status']), fg='white', bg='red'))
            else:
                print("Status ..................... {}".format(response['status']))

            if lic['type'].lower() not in ["evaluation"]:
                cluster = lic['perapp']
                print("\nApplication Limits: ")
                cprint("  Max allowed elements ........ ", profile['elements'], cluster['elements'])

                features = lic['features']
                print("\nFeatures: ")
                print("  Dynamic element creation ................... {}"
                      .format("Supported" if features.get("dynamic_element", False) else "Unsupported"))

        else:
            print("Application wide usage:")
            print("  Elements ........ ", profile['elements'])

    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to fetch license information. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@license.command()
@click.option("-o", "--output", type=click.Choice(['json']))
@add_options(common_options)
def id(output, **kwargs):
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/license?id=true", verify=False, headers=hdrs)
        r.raise_for_status()
        if output == "json":
            print(json.dumps(r.json(), indent=4))
            return
        status = r.headers.get('X-Robin-License-Status', '')
        license = repr(r.json()['license_id']).strip("'").replace(r"\r\n", "")
        #url = "https://get.robin.io/activate?clusterid={}".format(license)
        print("License Id: {}".format(license))
        # if status == LicenseState.NOT_ACTIVATED:
        #     print("Please visit the following link to activate your license: {}".format(url))
        if status == LicenseState.NOT_ACTIVATED:
            print("Please  contact your MDCAP account manager to activate your license.")
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to fetch license ID. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@license.command()
@click.argument('license_file')
@click.option("--desc", type=str, help="License description", default='')
@click.option("--force", is_flag=True, help="Ignore inferior license", default=False)
@add_options(common_options)
def apply(license_file, desc, force, **kwargs):
    try:
        r = None
        hdrs = get_hdrs()
        content = None
        if license_file:
            if os.path.isfile(license_file):
                with open(license_file, 'rb') as f:
                    content = f.read()
            else:
                content = license_file
            if content is None:
                print("Please provide valid license file")
                return

            data = {'license': content, 
                    'desc': desc,
                    'force': force}

            r = requests.put(f"{sc.engine()}/license", verify=False, headers=hdrs, data=json.dumps(data))
            r.raise_for_status()
            if force:
                print("License has been applied successfully ignoring inferior check")
            else:
                print("License has been applied successfully")
        else:
            print("Please provide license file to update")
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to apply license, details: ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@cli.group(cls=ClickAliasedGroup, aliases=['pt'])
def policy_template():
    """Policy Template Management"""
    pass

@policy_template.command("add")
@click.argument('name', type=str)
@click.option("-v", "--version", type=str, default='')
@click.option("-d", "--description", type=str, default='')
@click.option("-u", "--url", type=str, default='')
@add_options(common_options)
def add_policy_template(name, version, description, url, **kwargs):
    '''Register a new Policy Template'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            "name": name,
            "version": version,
            "description": description,
            "url": url,
        }
        r = requests.post(f"{sc.engine()}/{_URLPATH_POLICY_TEMPLATE}", \
            json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to register Policy Template. Error: {ex}")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@policy_template.command("list")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list_policy_template(output, **kwargs):
    '''List all Policy Templates'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/{_URLPATH_POLICY_TEMPLATE}", verify=False, headers=hdrs)
        r.raise_for_status()

        results = r.json()

        if output == 'yaml':
            print(yaml.dump(results, indent=4))
            return

        if output == 'json':
            print(json.dumps(results, indent=4))
            return

        if not results['items']:
            print("No Policy Templates found")
        else:
            table=[]
            tbl_hdrs = ['uid', 'name', 'version', 'description', 'url']
            for item in results["items"]:
                table.append([item['uid'], item['name'],
                                item['version'], item['description'],
                                item['url']])

            print(tabulate(table, headers=tbl_hdrs))

    except Exception as ex:
        handle_error(ex, action_msg="Failed to list Policy Templates. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@policy_template.command("info")
@click.argument('uid', type=str)
@click.option('-c', '--show-content', is_flag=True, \
    help="Include template file content.", default=False)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info_policy_template(uid, show_content, output, **kwargs):
    """Get information for a particular Policy Template"""

    try:
        r = None
        hdrs = get_hdrs()
        url = f"{sc.engine()}/{_URLPATH_POLICY_TEMPLATE}/{uid}"
        q = []
        if show_content:
            q.append(f"content={show_content}")

        if q:
            url += f"?{'&'.join(q)}"

        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to display information for Policy Template with uid {uid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@policy_template.command("update")
@click.argument("uid", type=str)
@click.option("-n", "--name", type=str)
@click.option("-v", "--version", type=str, default='')
@click.option("-d", "--description", type=str, default='')
@click.option("-u", "--url", type=str, default='')
@add_options(common_options)
def update_policy_template(uid, name, version, description, url, **kwargs):
    '''Update a Policy Template'''
    try:
        r = None
        hdrs = get_hdrs()
        data = {}

        if not name and name == "":
            raise Exception("Name cannot be empty.")

        if name:
            data["name"] = name
        if version or version == "":
            data["version"] = version
        if description or description == "":
            data['description'] = description
        if url or url == "":
            data["url"] = url

        r = requests.put(f"{sc.engine()}/{_URLPATH_POLICY_TEMPLATE}/{uid}",
                         json=data,
                         verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to update Policy Template with uid: {uid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@policy_template.command("delete")
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a Policy Template"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/{_URLPATH_POLICY_TEMPLATE}/{uid}", \
            verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to delete Policy Template with uid: {uid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@cli.group(cls=ClickAliasedGroup)
def policy():
    """Policy Management"""
    pass

@policy.command("add")
@click.argument('name', type=str)
@click.option("-v", "--apiversion", type=str, default='')
@click.option("-d", "--description", type=str, default='')
@click.option("-a", "--active", is_flag=True, type=bool, default=True)
@click.option("-s", "--selector", type=str, multiple=True)
@click.argument('config', type=str)
@add_options(common_options)
def add_policy(name, apiversion, description, active, selector, config, **kwargs):
    '''Register a new Policy'''
    try:
        r = None
        hdrs = get_hdrs()
        data = json.load(open(config)) if os.path.exists(config) else {}

        if name:
            data["name"] = name
        if apiversion:
            data["apiversion"] = apiversion
        if description:
            data["description"] = description
        if active:
            data["active"] = active
        if selector:
            data['selector'] = parse_labels(selector, ret_dict=True)

        r = requests.post(f"{sc.engine()}/{_URLPATH_POLICY}", \
            json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg="Failed to register Policy. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@policy.command("list")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list_policy(output, **kwargs):
    '''List all Policies'''
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/{_URLPATH_POLICY}", verify=False, headers=hdrs)
        r.raise_for_status()

        results = r.json()

        if output == 'yaml':
            print(yaml.dump(results, indent=4))
            return

        if output == 'json':
            print(json.dumps(results, indent=4))
            return

        if not results['items']:
            print("No Policies found")
        else:
            table=[]
            tbl_hdrs = ['uid', 'name', 'apiversion', 'description', 'active', 'selector', 'spec']
            for item in results["items"]:
                table.append([item['uid'], item['name'],
                                item['apiversion'], item['description'],
                                item['active'], item['selector'], item['spec']])

            print(tabulate(table, headers=tbl_hdrs))

    except Exception as ex:
        handle_error(ex, action_msg="Failed to list Policy Templates. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@policy.command("info")
@click.argument('uid', type=str)
@click.option('-c', '--show-content', is_flag=True, \
    help="Include constraint file content.", default=False)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info_policy(uid, show_content, output, **kwargs):
    """Get information for a particular Policy"""

    try:
        r = None
        hdrs = get_hdrs()
        url = f"{sc.engine()}/{_URLPATH_POLICY}/{uid}"
        q = []
        if show_content:
            q.append(f"content={show_content}")

        if q:
            url += f"?{'&'.join(q)}"

        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to display information for Policy with uid {uid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@policy.command("update")
@click.argument("uid", type=str)
@click.option("-n", "--name", type=str)
@click.option("-v", "--apiversion", type=str)
@click.option("-d", "--description", type=str)
@click.option("-a", "--active")
@click.option("-s", "--selector", type=str, multiple=True)
@click.argument('config', type=str)
@add_options(common_options)
def update_policy(uid, name, apiversion, description, active, selector, config, **kwargs):
    '''Update a Policy'''
    try:
        r = None
        hdrs = get_hdrs()
        data = json.load(open(config)) if os.path.exists(config) else {}

        if name:
            data["name"] = name

        if 'name' in data and data['name'] == "":
            raise Exception("Name cannot be empty.")

        if apiversion or apiversion == "":
            data["apiversion"] = apiversion
        if description or description == "":
            data['description'] = description
        if active or active == False:
            data["active"] = active
        if selector or selector == []:
            data['selector'] = parse_labels(selector, ret_dict=True)

        r = requests.put(f"{sc.engine()}/{_URLPATH_POLICY}/{uid}",
                         json=data,
                         verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])

    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to update Policy with uid: {uid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@policy.command("delete")
@click.argument('uid', type=str)
@add_options(common_options)
def delete_policy(uid, **kwargs):
    """Delete a Policy"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/{_URLPATH_POLICY}/{uid}", \
            verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to delete Policy with uid: {uid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@policy.command("apply")
@click.argument('uid', type=str)
@add_options(common_options)
def apply_policy(uid, **kwargs):
    """Apply a Policy"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'action': 'apply'
        }
        r = requests.post(f"{sc.engine()}/{_URLPATH_POLICY}/{uid}/action", \
            json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to apply Policy with uid: {uid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@policy.command("remove")
@click.argument('uid', type=str)
@add_options(common_options)
def remove_policy(uid, **kwargs):
    """Remove a Policy"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'action': 'delete'
        }
        r = requests.post(f"{sc.engine()}/{_URLPATH_POLICY}/{uid}/action", \
            json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to remove Policy with uid: {uid}.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@policy.command("violations")
@click.argument('uid', type=str)
@click.argument('element-uid', type=str)
@click.option('-t', '--template-uid', type=str, help="Policy Template UID to filter violations.")
@click.option('-r', '--refresh', is_flag=True, help="Refresh Policy Violations for passed element.")
@add_options(common_options)
def policy_violations(uid, element_uid, template_uid, refresh, **kwargs):
    """Get/Refresh Policy violations for a target element"""

    try:
        r = None
        hdrs = get_hdrs()
        url = f"{sc.engine()}/{_URLPATH_POLICY}/{uid}/violations"
        if refresh:
            data = {
                'action': 'refresh',
                'element_uid': element_uid,
            }
            r = requests.post(url, json=data, verify=False, headers=hdrs)

            r.raise_for_status()
            resp = r.json()

            print(f"Successfully submitted batch {resp['msg']}")

        else:
            q = [f"element_uid={element_uid}"]

            if template_uid:
                q.append(f"template_uid={template_uid}")

            url += f"?{'&'.join(q)}"

            r = requests.get(url, verify=False, headers=hdrs)

            r.raise_for_status()
            print(json.dumps(r.json(), indent=4))

    except Exception as ex:
        if refresh:
            handle_error(ex, action_msg=f"Failed to refresh violations for Policy with uid {uid}.")
        else:
            handle_error(ex, action_msg=f"Failed to get violations for Policy with uid {uid}.")

    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

from os import system
@cli.group(cls=ClickAliasedGroup, aliases=['bm'])
def baremetal():
    """BareMetal Management"""
    pass

def _validate_rendered_schema(schema, unresolved_items):
    for k, v in schema.items():
        if type(v) == jinja2schema.model.Dictionary or type(v) == dict:
            _validate_rendered_schema(v, unresolved_items)
        elif type(v) == jinja2schema.model.Scalar:
            unresolved_items.add(k)
        elif type(v) == jinja2schema.model.List:
            if type(v.item) == jinja2schema.model.Scalar:
                unresolved_items.add(k)

def _validate_ks_config(profile, additional_config, data):
    resp = requests.get(profile)
    if resp.status_code != 200:
        raise Exception("Failed to download kickstarter profile, status code: {}".format(resp.status_code))
    with tempfile.NamedTemporaryFile(delete=False) as f:
        ksfile = f.name
        f.write(resp.content)
    '''
    1. Get jinja macros from ks file
    2. Render with additional config and write to another file
    3. Make sure there are no jinja macros in rendered file
    '''
    templateLoader = FileSystemLoader(searchpath="/tmp")
    env = Environment(loader=templateLoader)
    filename = ksfile.split('/')[-1]
    #template = env.get_template(filename)
    template_source = env.loader.get_source(env, filename)[0]
    schema = jinja2schema.infer(template_source)

    # pop out auto-discovered items
    schema['config']['os'].pop('sriov_mac_list')

    config = read_json_file(additional_config)
    config.update(data)

    schema = dict(schema)
    schema.update(config)

    # if any of the values in schema_dict is scalar, throw Exception
    unresolved_items = set()
    _validate_rendered_schema(schema, unresolved_items)
    if unresolved_items:
        raise Exception("Please provide values for the following items: {}".format(unresolved_items))

    os.unlink(ksfile)


@baremetal.command(aliases=['register'])
@click.argument('name', type=str)
@click.option('-v', '--apiversion', help="API Version against to register", default="mdcap.robin.io/v1")
@click.option('-d', '--description', help="Description of BareMetal Server")
@click.option("-l", "--labels", type=str, multiple=True, help="Add labels to help with grouping and filtering. Format: key1:val1,key2val2...")
@click.option('-u', '--sshuser', help="SSH username")
@click.option('-p', '--sshpass', help="SSH password")
@click.option('-i', '--sshipaddr', help="SSH IP Address")
@click.option('-U', '--bmcuser', help="BMC username")
@click.option('-P', '--bmcpass', help="BMC password")
@click.option('-I', '--bmcipaddr', help="BMC IP Address")
# Optional parameters which further define bare metal server
@click.option('-a', '--artifactory', help="Artifactory uuid")
@click.option('-f', '--profile', help="Profile UUID")
@click.option('-c', '--values', help="Path to element configuration")
@add_options(common_options)
def add(name, apiversion, description, labels, sshuser, sshpass, sshipaddr, bmcuser, bmcpass, bmcipaddr, artifactory, profile, values, **kwargs):
    """Register a BareMetal element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'apiVersion': apiversion,
            'kind': 'BM',
            'metadata': {
                'name': name,
                'description': description if description else "",
                'labels': parse_labels(labels, ret_dict=True) if labels else {},
            },
            'spec': {
                'connectors': {}
            }
        }
        if values:
            data['spec'].update(read_json_file(values)['spec'])
        elif profile:
            r = requests.get(f"{sc.engine()}/bmprofile/{profile}", headers=hdrs, verify=False)
            r.raise_for_status()
            profile_r = r.json()
            data['spec'].update(profile_r['profile'])

        if sshuser and sshpass:
            data['spec']['connectors']['ssh'] = {
                'sshhost': sshipaddr,
                'username': sshuser,
                'password': sshpass,
            }
        if bmcuser and bmcpass:
            data['spec']['connectors']['bmc'] = {
                'bmchost': bmcipaddr,
                'username': bmcuser,
                'password': bmcpass,
            }
        if profile:
            data['spec']['profile_uuid'] = profile
        else:
            data['spec'].pop('profile_uuid', None)
        if artifactory:
            r = requests.get(f"{sc.engine()}/artifactory/{artifactory}", headers=hdrs, verify=False)
            if r.status_code != 200:
                raise Exception("Artifactory: {} doesn't exist".format(artifactory))
            if not data['spec'].get('config'):
                data['spec']['config'] = {}
            data['spec']['config']['artifactory'] = json.loads(r.json()['config'])
        r = requests.post(f"{sc.engine()}/bm", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@baremetal.command()
@click.argument('filelocation', type=str)
@click.option('-p', '--profile', help="Apply the profile UUID")
@click.option('-cd', '--column-delimiter', help="Columns delimiter in csv - default ','", default=",")
@click.option('-rd', '--row-delimiter', help="Rows delimiter in csv - default 'new-line'", default="\n")
@click.option('-d', "--dry-run", type=bool, help="Dry run and inspect the BM payload", hidden=True, default=False)
@click.option('-v', '--apiversion', help="API Version against to import", default="mdcap.robin.io/v1")
@add_options(common_set_options)
@add_options(common_options)
def import_csv(filelocation, profile, column_delimiter, row_delimiter, dry_run, apiversion, **kwargs):
    """Import BareMetal element from a CSV file in format [<name>, <sship>, <sshuser>, <sshpass>, <bmcip>, <bmcuser>, <bmcpass>]"""
    try:

        overrides = {}
        if kwargs.get('set'):
            overrides = create_dict_fromkeys(kwargs.get('set'), kwargs.get('setadd'))

        r = None
        hdrs = get_hdrs()

        prof_json = {}
        if profile:
            r = requests.get(f"{sc.engine()}/bmprofile/{profile}", headers=hdrs, verify=False)
            r.raise_for_status()
            data = r.json()
            prof_json = data['profile']
        records = read_csv_file(filelocation, columndelimiter=column_delimiter, rowdelimiter=row_delimiter)
        for record in records:
            data = {
                'apiVersion': apiversion,
                'kind': 'BM',
                'metadata': {
                    'name': record['name'],
                    'description': ""
                },
                'spec': {
                    'connectors': {}
                }
            }
            data['spec']['connectors']['ssh'] = {
                'sshhost': record['sship']
            }
            if 'sshuser' in record:
                data['spec']['connectors']['ssh']['username'] = record['sshuser']
            if 'sshpass' in record:
                data['spec']['connectors']['ssh']['password'] = record['sshpass']
            if 'bmcip' in record:
                data['spec']['connectors']['bmc'] = {
                    'bmchost': record['bmcip']
                }
                if 'bmcuser' in record:
                    data['spec']['connectors']['bmc']['username'] = record['bmcuser']
                if 'bmcpass' in record:
                    data['spec']['connectors']['bmc']['password'] = record['bmcpass']
            if profile:
                data['spec']['profile_uuid'] = profile
                merge_dict(data['spec'], prof_json)
            if overrides:
                merge_dict(data['spec'], overrides)
            record.pop('name', None)
            record.pop('sship', None)
            record.pop('sshuser', None)
            record.pop('sshpass', None)
            record.pop('bmcip', None)
            record.pop('bmcuser', None)
            record.pop('bmcpass', None)
            if record:
                merge_dict(data['spec'], record)

            if not dry_run:
                r = requests.post(f"{sc.engine()}/bm", json=data, headers=hdrs, verify=False)
                r.raise_for_status()
                print(r.json()['msg'])
            else:
                pprint(data)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@baremetal.command()
@click.argument('uid', type=str)
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-i', '--ignore-wf', is_flag=True, help="Don't trigger workflow for this config update", default=False)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, output, ignore_wf, **kwargs):
    """Update a BareMetal element"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = requests.put(f"{sc.engine()}/bm/{uid}?ignorewf={str(ignore_wf)}", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@baremetal.command()
@click.argument('uid', type=str)
@click.argument('profileuid', type=str)
@click.option('-e', "--edit", is_flag=True, help="Allow edit before submitting")
@click.option('--set', type=str, multiple=True, help="Override the default values of BM profile")
@click.option('--setadd', type=str, multiple=True, help="Set key value pair to append an array in the element configuration in values file. Example: --set-add os.dns=dns1 --set-add os.dns=dns2")
@click.option('-d', '--dry-run', is_flag=True, default=False, help="Show the required values from kickstarter file, don't add bare metal profile")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def applyprofile(uid, profileuid, edit, set, setadd, dry_run, output, **kwargs):
    """Apply a profile to a baremetal element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        if edit:
            r = requests.get(f"{sc.engine()}/bm/{uid}?applyprofile={profileuid}", verify=False, headers=hdrs)
            r.raise_for_status()
            config = r.json()
            if not output:
                output = "json"

            data = open_in_editor(None, content=json.dumps(config, indent=4), edit_fmt=output, accept_no_changes=True)
            if not data:
                return
            if dry_run:
                print("BM element config would like:")
                pprint(data)
                return
            r = requests.put(f"{sc.engine()}/bm/{uid}", json=data, verify=False, headers=hdrs)
        else:
            if set or setadd:
                r = requests.get(f"{sc.engine()}/bm/{uid}?applyprofile={profileuid}", verify=False, headers=hdrs)
                r.raise_for_status()
                data = r.json()
                result = create_dict_fromkeys(set, setadd)
                merge_dict(data, result, overwrite=True)
                if dry_run:
                    print("BM element config would like:")
                    pprint(data)
                    return
                r = requests.put(f"{sc.engine()}/bm/{uid}", json=data, verify=False, headers=hdrs)
            else:
                if dry_run:
                    r = requests.get(f"{sc.engine()}/bm/{uid}?applyprofile={profileuid}", verify=False, headers=hdrs)
                    r.raise_for_status()
                    data = r.json()
                    print("BM element config would like:")
                    pprint(data)
                    return
                r = requests.put(f"{sc.engine()}/bm/{uid}?applyprofile={profileuid}", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@baremetal.command()
@click.argument('uid', type=str)
@click.option('-e', "--edit", is_flag=True, help="Allow edit before submitting")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def removeprofile(uid, edit, output, **kwargs):
    """Remove the current profile from the baremetal element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        if edit:
            r = requests.get(f"{sc.engine()}/bm/{uid}?removeprofile=ifexists", verify=False, headers=hdrs)
            r.raise_for_status()
            config = r.json()
            if not output:
                output = "json"

            data = open_in_editor(None, content=json.dumps(config, indent=4), edit_fmt=output, accept_no_changes=True)
            if not data:
                return

            r = requests.put(f"{sc.engine()}/bm/{uid}", json=data, verify=False, headers=hdrs)
        else:
            r = requests.put(f"{sc.engine()}/bm/{uid}?removeprofile=ifexists", json=data, verify=False, headers=hdrs)
            r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@baremetal.command()
@click.option('-u', '--uid', type=str, help="UID of bare metal to be modified")
@click.option('-s', "--schema-uid", type=str, help="Validate the configuration using this schema uid")
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-v', '--apiversion', help="API Version against to validate", default="mdcap.robin.io/v1")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def validate(uid, schema_uid, config, apiversion, output, **kwargs):
    """Validates new or modified BareMetal element configuration"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = common_validate(uid, schema_uid, "bm", apiversion, data)
        r.raise_for_status()
        print(r.json())
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@baremetal.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a BareMetal element"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/bm/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@baremetal.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l", "--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all BareMetal elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/bm{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            print(tabulate(elem_format(results['items'], keys=['uid', 'name', 'flavor', 'version', 'description', 'liveness', 'readiness']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list BMs. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@baremetal.command()
@click.argument('uid', type=str)
@click.option('-e', "--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the Baremetal config")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option("-s", "--systemdetails", is_flag=True, help="Fetch hardware details from BIOS") 
@add_options(common_options)
def info(uid, output, evaluate, systemdetails, **kwargs):
    """Get information on a particular BareMetal element"""
    try:
        r = None
        hdrs = get_hdrs()
        sd_str= ""
        evaluate_str = "?evaluate=true" if evaluate else ""
        if systemdetails:
            sd_str = "?sd=true"
            if evaluate_str:
                sd_str = "&sd=true"
        r = requests.get(f"{sc.engine()}/bm/{uid}{evaluate_str}{sd_str}", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        result = r.json()
        if not result:
            print("BM '{}' does not exist".format(uid))
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            print("Name:        {}".format(result['metadata']['name']))
            print("UUID:        {}".format(result['metadata']['uid']))
            print("LABELS :       {}".format(result['metadata']['labels']))
            print("Description: {}".format(result['metadata']['description'] if result['metadata']['description'] else "-"))
            print()
            print("SSH Config:")
            print("    SSH Host:     {}".format(result['spec']['connectors']['ssh']['sshhost']))
            print("    SSH Username: {}".format(result['spec']['connectors']['ssh']['username']))
            if 'password' in result['spec']['connectors']['ssh']:
                print("    SSH Password: {}".format(result['spec']['connectors']['ssh']['password']))
            print()
            if result['spec']['connectors'].get('bmc'):
                print("BMC Config:")
                print("    BMC Host:     {}".format(result['spec']['connectors']['bmc']['bmchost']))
                print("    BMC Username: {}".format(result['spec']['connectors']['bmc']['username']))
                print("    BMC Password: {}".format(result['spec']['connectors']['bmc']['password']))
            if result['spec']:
                print()
                if 'os' in result['spec']:
                    print("Operating System:")
                    print_nested(result['spec']['os'], indent=0)
                if 'network' in result['spec']:
                    print("Network:")
                    print_nested(result['spec']['network'], indent=0)
                if 'storage' in result['spec']:
                    print("Storage:")
                    print_nested(result['spec']['storage'], indent=0)
                if 'artifactory' in result['spec']:
                    print("Artifactory:")
                    print_nested(result['spec']['artifactory'], indent=0)
                if 'config_url' in result['spec']:
                    print("Kickstart:")
                    print_nested(result['spec']['config_url'], indent=0)
                if 'profile_uuid' in result['spec']:
                    print("BM Profile:")
                    print_nested(result['spec']['profile_uuid'], indent=0)
                if 'metrics' in result['spec']:
                    print("Metrics:")
                    metrics_found = False
                    for metric in result['spec']['metrics']:
                        if metric.get('url'):
                            metrics_found = True
                            print("    URL: {}".format(metric['url']))
                            print("    Enabled: {}".format(metric.get('enable', False))) 
                    if not metrics_found:
                        print("No metrics URL(s) available at this moment.")
                if systemdetails:
                    print("ComputerSystem Details:")
                    for k, v in result['systemdetails'].items():
                        print("    {:<30} {}".format(k,v))

    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for BM '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@baremetal.command()
@click.argument('uids', type=str)
@click.argument('workflow', type=str)
@click.option('-o', "--output-file", help="Output file to dump generated workflow to")
@add_options(common_options)
def generate(uids, workflow, output_file, **kwargs):
    """Generate a config file for a dynamic workflow of a BareMetal Machine"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'uids': uids.split(","),
            'wf_name': workflow
        }
        r = requests.put(f"{sc.engine()}/bm", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        if output_file:
            with open(output_file, 'w') as outfile:
                json.dump(r.json(), outfile)
        else:
            print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate workflow {} for Baremetal Machine(s) {}. ".format(workflow, uids))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@baremetal.command()
@click.option('-v', "--apiversion", type=str, help="API Version", default="mdcap.robin.io/v1")
@click.option('-p', "--bmprofile", type=str, help="UUID of bmprofile")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option("--explain", is_flag=True, help="Display examples and other guide for this command")
@click.option('-f', "--file", type=str, help="Output to file")
@click.option("--all", is_flag=True, help="Include non-mandatory fields")
@add_options(common_options)
def generate_config(apiversion, bmprofile, output, explain, file, all, **kwargs):
    """Generate element config"""
    hdrs = get_hdrs()
    data = {'template': True}
    r = None
    try:
        if explain and (bmprofile or file):
            print("Explain cannot be combined with output or bmprofile")
            return
        bm = generate_element_template('bm', apiversion, fmt=output, print_doc=explain, include_non_mandatory=all)
        if explain:
           return
        if bmprofile:
            r = requests.get(f"{sc.engine()}/bmprofile/{bmprofile}", headers=hdrs, verify=False)
            r.raise_for_status()
            bmp = r.json()
            bm = merge_dict(bm, {'spec': bmp['profile']})
            bm['spec']['profile_uuid'] = bmprofile
        bm['kind'] = 'bm'
        if output == 'yaml':
            if file:
                with open(file, "w") as fp:
                    yaml.dump(bm, fp, indent=4)
            else:
                print(yaml.dump(bm, indent=4))
        else:
            if file:
                with open(file, "w") as fp:
                    json.dump(bm, fp, indent=4)
            else:
                print(json.dumps(bm, indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to dump element template for kind BM. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@baremetal.command()
@click.argument('uid', type=str)
@click.argument('newprofile_uid', type=str)
@add_options(common_options)
def validate_new_profile(uid, newprofile_uid, **kwargs):
    """Check if new profile can be applied on this baremetal that has a profile already"""
    try:
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/bm/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        result = r.json()
        if 'profile_uuid' not in result['spec']:
            print('No profile in this bare metal to validate the new profile')
            return
        r = requests.get(f"{sc.engine()}/bmprofile/{result['spec']['profile_uuid']}?conformancecheck={newprofile_uid}", headers=hdrs, verify=False)
        r.raise_for_status()
        payload = r.json()
        print(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Failed to validate the BMProfiles")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=payload)

# @baremetal.command()
# @click.argument('bm_uid', type=str)
# @add_options(common_options)
# def metrics(bm_uid, **kwargs):
#     """View metrics on BareMetal Kind"""
#     try:
#         r = None
#         hdrs = get_hdrs()
#         r = requests.get(f"{sc.engine()}/bm/{bm_uid}", verify=False, headers=hdrs)
#         r.raise_for_status()
#         conf = r.json()
#         metrics = conf.get('spec').get('metrics')
#         if not metrics:
#             print("No metrics config found")
#         else:
#             if not metrics.get('enable', False):
#                 print("Metrics not enabled")
#                 return
#             else:
#                 url = metrics.get('url', None)
#                 if not url:
#                     print("No endpoint for metrics found")
#                 else:
#                     result = requests.get(url + '/metrics', verify=False)
# 
#     except Exception as ex:
#         handle_error(ex)
#     finally:
#         if kwargs.get('urlinfo') and r:
#             compute_curl_command(r, headers=hdrs)

@cli.group(cls=ClickAliasedGroup)
def element():
    """Element Management"""
    pass

@element.command()
@click.argument('kind', type=str)
@click.option('-v', "--apiversion", type=str, help="API Version", default="mdcap.robin.io/v1")
@click.option("--explain", is_flag=True, help="Display examples and other guide for this command")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option('-f', "--file", type=str, help="Output to file")
@click.option("--all", is_flag=True, help="Include non-mandatory fields")
@add_options(common_options)
def generate_config(kind, apiversion, explain, output, file, all, **kwargs):
    """Generate element config"""
    hdrs = get_hdrs()
    data = {'template': True}
    r = None
    try:
        if explain and (all or file):
            print("Explain cannot be combined with all or file")
            return
        if not output:
            output = 'json'
        ele = generate_element_template(kind, apiversion, fmt=output, print_doc=explain, include_non_mandatory=all, filename=file)
        if explain:
           return
        if not file:
            if output == 'yaml':
                print(yaml.dump(ele, indent=4))
            else:
                print(json.dumps(ele, indent=4))
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to dump element template for kind {kind}. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@element.command(aliases=['register'])
@click.argument('values', type=click.File('r'))
@click.option('--set', type=str, multiple=True, help="Set key value pair to add or override the element configuration in values file. Example: --set os.root_password=robin321 --set network.bootinterface.ip=1.2.3.4")
@click.option('--setadd', type=str, multiple=True, help="Set key value pair to append an array in the element configuration in values file. Example: --set-add os.dns=dns1 --set-add os.dns=dns2")
@add_options(common_options)
def add(values, set, setadd, **kwargs):
    '''Register an Element'''
    try:
        r = None
        hdrs = get_hdrs()
        payload = {}
        payload = json.load(values)

        if set:
            result = create_dict_fromkeys(set, setadd)
            merge_dict(payload, result)

        if setadd:
            print("--setadd not supported right now")
            return

        res = requests.post("{}/element".format(sc.engine()), json=payload, verify=False, headers=hdrs)
        res.raise_for_status()
        print(res.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=payload)

@element.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-t","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-k', '--kind', type=str, help="Filter by kind")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, kind, match, output, **kwargs):
    """List all elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        if kind:
            query_params.append(f"kind={kind}")
        limit_url = parameter_string(query_params)

        r = requests.get("{}/element{}".format(sc.engine(), limit_url), verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
            return
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            for element in results['items']:
                element['kind'] = get_alias_element_type(element['kind'])
            print(tabulate(elem_format(results['items']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list elements. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@element.command()
@click.argument('uid', type=str)
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-n', '--new-api-version', help="Upgrade to new api version", default="mdcap.robin.io/v1")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, new_api_version, output, **kwargs):
    """Update an element"""
    try:
        r = None
        kind = 'element'
        hdrs = get_hdrs()
        data = {}
        filters = ""
        query_params = []
        if config:
            if new_api_version:
                print('Cannot set new api version and config at the same time')
                return
            data = read_json_file(config)
        elif new_api_version:
            query_params.append(f"target_api_version={new_api_version}")
            r = requests.get(f"{sc.engine()}/element/{uid}", verify=False, headers=hdrs)
            r.raise_for_status()
            kind = r.json()['kind'].lower()
            r = None
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return
        filters = parameter_string(query_params)
        r = requests.put(f"{sc.engine()}/{kind}/{uid}{filters}", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json['msg'])
    except Exception as ex:
        handle_error(ex, action_msg=f"Failed to update element with uid {uid}. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@element.command()
@click.argument('uid', type=str)
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the element config")
@click.option("--expand", is_flag=True, help="Expand the element spec to include sub-elements")
@click.option("--secrets", is_flag=True, help="Resolve for secrets if any")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, evaluate, expand, secrets, **kwargs):
    """Get information about a particular element"""
    try:
        r = None
        hdrs = get_hdrs()
        query_params = []
        if evaluate:
            query_params.append("evaluate=true")
        if secrets:
            query_params.append("secrets=true")
        if expand:
            query_params.append("expand=true")
        limit_url = parameter_string(query_params)
        r = requests.get(f"{sc.engine()}/element/{uid}{limit_url}", verify=False, headers=hdrs)
        r.raise_for_status()
        request_json = r.json()
        mask_sensitive_data(request_json)
        if output == 'yaml':
            print(yaml.dump(request_json, indent=4))
            return

        if output == 'json':
            print(json.dumps(request_json, indent=4))
            return
        print(json.dumps(request_json, indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information about element with uid {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@element.command()
@click.argument('uid', type=str)
@click.option('-c', "--cascade", is_flag=True, help="Delete underlying base elements alongside the Robin Cluster")
@add_options(common_options)
def delete(uid, cascade, **kwargs):
    """Delete an element"""
    try:
        r = None
        hdrs = get_hdrs()
        cascade_str = "?cascade=true" if cascade else ""
        r = requests.delete(f"{sc.engine()}/element/{uid}{cascade_str}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete element with uid {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@element.command()
@add_options(common_options)
def kinds(**kwargs):
    """Retrieve element kinds"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.get(f"{sc.engine()}/element/kinds", verify=False, headers=hdrs)
        r.raise_for_status()
        if not r.json():
            print("No results found")
        else:
            res = [[get_alias_element_type(r)] for r in r.json()]
            tbl_hdrs = ['Supported Types']
            print("\n", tabulate(res, headers=tbl_hdrs), "\n")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get element types. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@element.command(name="import")
@click.argument('location', type=str)
@add_options(common_options)
def import_elements(location, **kwargs):
    '''Import elements'''
    try:
        res = None
        hdrs = get_hdrs()
        if not os.path.exists(location):
            raise Exception("No file found at specified location: {}".format(location))
        files = {}
        files['upload_file'] = open(location, 'rb')
        res = requests.post(f"{sc.engine()}/element/import", files=files, headers=hdrs, verify=False)
        out = res.json()
        res.raise_for_status()
        print(out)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to import elements")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs)


@element.command()
@click.argument('uid')
@click.argument('state')
@click.option('--trigger', '-t', default="")
@add_options(common_options)
def setstate(uid, state, trigger, **kwargs):
    '''Set state of element'''
    try:
        res = None
        hdrs = get_hdrs()
        url = "{}/element/{}".format(sc.engine(), uid)
        data = {
            'opcode': 'setstate',
            'desired_state': state,
            'trigger': trigger
        }
        res = requests.put(url, json=data, verify=False, headers=hdrs)
        res.raise_for_status()
        out = res.json()
        pprint(out)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to set state. ")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs, data=data)

@element.command()
@add_options(common_options)
@click.argument('uids', nargs=-1)
@click.option('--kinds', '-k', is_flag=True, help="Return the kinds of the elements as well")
def translate_uids(uids, kinds, **kwargs):
    '''Transalte element uids to names'''
    try:
        res = None
        hdrs = get_hdrs()
        options = ""
        if kinds:
            options = "?kinds=True"
        url = "{}/element/names{}".format(sc.engine(), options)
        data = {
            'uids': uids,
        }
        res = requests.post(url, json=data, verify=False, headers=hdrs)
        res.raise_for_status()
        out = res.json()
        pprint(out)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to translate element uids to names")
    finally:
        if kwargs.get('urlinfo') and res:
            compute_curl_command(res, headers=hdrs, data=data)

from pprint import pprint
# from sanic.log import logger

#TODO: Validation and schema definition

@cli.group(cls=ClickAliasedGroup)
def k8s():
    """K8S Cluster Management"""
    pass

@k8s.command()
@click.argument('config', type=str)
@add_options(common_options)
def add(config, **kwargs):
    """Register a K8S element"""
    try:
        hdrs = get_hdrs()
        data = json.load(open(config)) if os.path.exists(config) else {}
        r = requests.post(f"{sc.engine()}/k8s", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@k8s.command()
@click.argument('uid', type=str)
@click.option('-c', "--cascade", is_flag=True, help="Delete underlying base elements alongside the K8S Cluster")
@add_options(common_options)
def delete(uid, cascade, **kwargs):
    """Delete a K8S element"""
    try:
        r = None
        hdrs = get_hdrs()
        cascade_str = "?cascade=true" if cascade else ""
        r = requests.delete(f"{sc.engine()}/k8s/{uid}{cascade_str}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@k8s.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all Kubernetes elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/k8s{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
            return
        else:
            print(tabulate(elem_format(results['items'], keys=['uid', 'name', 'flavor', 'version', 'description', 'liveness', 'readiness']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list k8s. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@k8s.command()
@click.argument('uid', type=str)
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the Kubernetes Element config")
@click.option("--expand", is_flag=True, help="Expand infra elements referenced from registry within the Kubernetes Element config")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, evaluate, expand, **kwargs):
    """Get information on a particular Kubernetes element"""
    try:
        r = None
        hdrs = get_hdrs()
        evaluate_str = "?evaluate=true" if evaluate else ""
        expand_str = "?expand=true" if expand else ""
        r = requests.get(f"{sc.engine()}/k8s/{uid}{evaluate_str}{expand_str}", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        result = r.json()
        if not result:
            print("k8s '{}' does not exist".format(uid))
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            print("Name: {}".format(result['metadata']['name']))
            print("UUID: {}".format(result['metadata']['uid']))
            print("Description: {}".format(result['metadata']['description'] if result['metadata']['description'] else "-"))
            print()
            print(f"INFRA:\n")
            pprint(result['spec']['infra'])


            result['spec'].pop('kube_config', '')
            result['spec'].pop('infra', '')
            if result['spec']:
                print()
                print("Additional Config:")
                print_nested(result['spec'], indent=0)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for k8s '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@k8s.command()
@click.argument('uid', type=str)
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-i', '--ignore-wf', is_flag=True, help="Don't trigger workflow for this config update", default=False)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, ignore_wf, output, **kwargs):
    """Update a Kubernetes element"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = requests.put(f"{sc.engine()}/k8s/{uid}?ignorewf={str(ignore_wf)}", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

# @k8s.command()
# @click.option('--uid', type=str, help="UID of Kubernetes to be modified")
# @click.option("--schema-uid", type=str, help="Validate the configuration using this schema uid")
# @click.option('--config', help="Path to file containing config details")
# @click.option('--apiversion', help="API Version against to validate", default="mdcap.robin.io/v1")
# @click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
# @add_options(common_options)
# def validate(uid, schema_uid, config, apiversion, output, **kwargs):
#     """Validates new or modified Kubernetes Element element configuration"""
#     try:
#         r = None
#         hdrs = get_hdrs()
#         if config:
#             data = read_json_file(config)
#         else:
#             data = open_in_editor(uid, edit_fmt=output)
#             if not data:
#                 return

#         r = common_validate(uid, schema_uid, "k8s", apiversion, data)
#         r.raise_for_status()
#         print(r.json())

#     except Exception as ex:
#         handle_error(ex)
#     finally:
#         if kwargs.get('urlinfo') and r:
#             compute_curl_command(r, headers=hdrs, data=data)

@k8s.command()
@click.argument('uids', type=str)
@click.argument('workflow', type=str)
@click.option('-o', "--output-file", help="Output file to dump generated workflow to")
@add_options(common_options)
def genwf(uids, workflow, output_file, **kwargs):
    """Generate a config file for a dynamic workflow of a K8S Element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'uids': uids.split(","),
            'wf_name': workflow
        }
        r = requests.put(f"{sc.engine()}/k8s", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        if output_file:
            with open(output_file, 'w') as outfile:
                json.dump(r.json(), outfile)
        else:
            print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate workflow {} for K8S Element(s) {}. ".format(workflow, uids))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)




@cli.group(cls=ClickAliasedGroup, aliases=['nf'])
def network_function():
    """Network Function Management"""
    pass


@network_function.command(aliases=['register'])
@click.argument('name', type=str)
@click.argument('config', type=str)
@click.option('-v', '--apiversion', help="API Version against to register", default="mdcap.robin.io/v1")
@click.option('-d', '--description', help="Description of Network Function.")
@click.option("-l", "--labels", type=str, multiple=True, help="Add labels to help with grouping and filtering. Format: key1:val1,key2val2...")
@add_options(common_options)
def add(name, config, apiversion, description, labels, **kwargs):
    """Register a Network Function"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {'metadata': {}, 'spec': {}, 'apiVersion': apiversion}
        data.update(read_json_file(config))

        data['metadata']['name'] = name
        data['metadata']['description'] = description if description else ""
        data['labels'] = labels if labels else {}
        r = requests.post(f"{sc.engine()}/network_function", headers=hdrs, json=data, verify=False)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@network_function.command()
@click.argument('uids', type=str)
@click.argument('workflow', type=str)
@click.option('-o', "--output-file", help="Output file to dump generated workflow to")
@add_options(common_options)
def genwf(uids, workflow, output_file, **kwargs):
    """Generate a config file for a dynamic workflow of a Network Function"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'uids': uids.split(","),
            'wf_name': workflow
        }
        r = requests.put(f"{sc.engine()}/network_function", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        if output_file:
            with open(output_file, 'w') as outfile:
                json.dump(r.json(), outfile)
        else:
            print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate workflow {} for Network Function(s) {}. ".format(workflow, uids))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@network_function.command()
@click.argument('uid', type=str)
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-i', '--ignore-wf', is_flag=True, help="Don't trigger workflow for this config update", default=False)
@add_options(common_options)
def update(uid, config, ignore_wf, **kwargs):
    """Update Network Function"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid)
            if not data:
                return

        r = requests.put(f"{sc.engine()}/network_function/{uid}?ignorewf={str(ignore_wf)}", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@network_function.command()
@click.option('-u', '--uid', type=str, help="UID of network function to be modified")
@click.option('-s', "--schema-uid", type=str, help="Validate the configuration using this schema uid")
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-v', '--apiversion', help="API Version against to validate", default="mdcap.robin.io/v1")
@add_options(common_options)
def validate(uid, schema_uid, config, apiversion, **kwargs):
    """Validates new or modified Network Function configuration"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid)
            if not data:
                return

        r = common_validate(uid, schema_uid, "network_function", apiversion, data)
        r.raise_for_status()
        print(r.json())

    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@network_function.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a Network Function"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/network_function/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete Network Function with UID {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@network_function.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all Network Function elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/network_function{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            # hdrs = ['uid', 'type', 'name', 'description']
            print(tabulate(elem_format(results['items'], keys=['uid', 'name', 'flavor', 'version', 'description', 'liveness', 'readiness']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list Network Functions. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@network_function.command()
@click.argument('uid', type=str)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the Network Function config")
@click.option("--appjson", is_flag=True, help="Display network function application json.")
@add_options(common_options)
def info(uid, output, appjson, evaluate, **kwargs):
    """Get information about a particular Network Function"""
    try:
        r = None
        hdrs = get_hdrs()
        if appjson:
            r = requests.get(f"{sc.engine()}/network_function/{uid}?details=true", verify=False, headers=hdrs)
        else:
            evaluate_str = "&evaluate=true" if evaluate else ""
            r = requests.get(f"{sc.engine()}/network_function/{uid}?expand=true{evaluate_str}", verify=False, headers=hdrs)
        r.raise_for_status()
        result = r.json()
        if not result:
            print("Network Function '{}' does not exist".format(uid))
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            if appjson:
                print(json.dumps(result, indent=4))
                return

            if output == 'yaml':
                print(yaml.dump(r.json(), indent=4))
                return

            if output == 'json':
                print(json.dumps(r.json(), indent=4))
                return

            print("Name:        {}".format(result['metadata']['name']))
            print("UUID:        {}".format(result['metadata']['uid']))
            print("Description: {}".format(result['metadata']['description'] if result.get('metadata', {}).get('description') else "-"))
            print("Class:       {}".format(result['spec']['class'] if result.get('spec', {}).get('class') else "-"))
            print()
            print("Cluster:")
            print("    Name:        {}".format(result['spec']['cluster']['metadata']['name']))
            print("    Description: {}".format(result['spec']['cluster']['metadata']['description'] if result['spec']['cluster']['metadata'].get('description') else "-"))
            print()
            print("Runtime Configuration:")
            print()
            print(yaml.dump(result['spec']['runtime_config']))
            print()
            print("Network Function Package:")
            print("    Name:    {}".format(result['spec'].get('nfp', {}).get('metadata', {}).get('name', "-")))
            print("    Vendor:  {}".format(result['spec'].get('nfp', {}).get('metadata', {}).get('vendor', "-")))
            print("    Version: {}".format(result['spec'].get('nfp', {}).get('metadata', {}).get('version', "-")))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for Network Function '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@cli.group(cls=ClickAliasedGroup, aliases=['ns'])
def network_service():
    """Network Service Management"""
    pass


@network_service.command(aliases=['register'])
@click.argument('name', type=str)
@click.argument('config', type=str)
@click.option('-d', '--description', help="Description of Network Service.")
@click.option("-t", "--labels", type=str, multiple=True, help="Add labels to help with grouping and filtering. Format: key1:val1,key2val2...")
@add_options(common_options)
def add(name, config, description, labels, **kwargs):
    """Register a Network Service"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {'metadata': {}, 'spec': {}}
        data.update(read_json_file(config))

        data['spec']['name'] = name
        data['spec']['description'] = description if description else ""
        data['spec']['labels'] = labels if labels else {}
        r = requests.post(f"{sc.engine()}/network_service", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@network_service.command()
@click.argument('uids', type=str)
@click.argument('workflow', type=str)
@click.option('-o', "--output-file", help="Output file to dump generated workflow to")
@add_options(common_options)
def genwf(uids, workflow, output_file, **kwargs):
    """Generate a config file for a dynamic workflow of a Network Service"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'uids': uids.split(","),
            'wf_name': workflow
        }
        r = requests.put(f"{sc.engine()}/network_service", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        if output_file:
            with open(output_file, 'w') as outfile:
                json.dump(r.json(), outfile)
        else:
            print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate workflow {} for Network Service(s) {}. ".format(workflow, uids))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@network_service.command()
@click.argument('uid', type=str)
@click.option('-c', "--cascade", is_flag=True, help="Delete underlying network functions alongside the Network Service")
@add_options(common_options)
def delete(uid, cascade, **kwargs):
    """Delete a Network Service"""
    try:
        r = None
        hdrs = get_hdrs()
        cascade_str = "?cascade=true" if cascade else ""
        r = requests.delete(f"{sc.engine()}/network_service/{uid}{cascade_str}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete Network Service {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@network_service.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all Network Service elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/network_service{}".format(sc.engine(), limit_url), verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            # hdrs = ['uid', 'type', 'name', 'description']
            print(tabulate(elem_format(results['items'], keys=['uid', 'name', 'flavor', 'version', 'description', 'liveness', 'readiness']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list Network Services. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@network_service.command()
@click.argument('uid', type=str)
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the Network Service config")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, evaluate, **kwargs):
    """Get information about a particular Network Service"""

    try:
        r = None
        hdrs = get_hdrs()
        evaluate_str = "&evaluate=true" if evaluate else ""
        r = requests.get("{}/network_service/{}?expand=true{}".format(sc.engine(), uid, evaluate_str), headers=hdrs, verify=False)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        pprint(r.json())
    except Exception as ex:
        handle_error(ex, action_msg="Failed to fetch Network service info. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)



@cli.group(cls=ClickAliasedGroup)
def nfp():
    """Network Function Package Management"""
    pass

@nfp.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all Network Function Packages"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/nfp{}".format(sc.engine(), limit_url), verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            headers = ["uid", "name", "version", "type"]
            data = ([item['metadata']['uid'], item['metadata']['name'], item['metadata']['version'], "Bundle" if item['spec'].get('bundle') else "Helm"] for item in results['items'])
            print(tabulate(data, headers))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list NFP. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@nfp.command()
@click.argument('uid', type=str)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the NFP config")
@add_options(common_options)
def info(uid, output, evaluate, **kwargs):
    """Get information about a particular Network Function Package"""
    try:
        r = None
        hdrs = get_hdrs()
        eval_string = ""
        if evaluate:
            eval_string = "&evaluate=true"
        r = requests.get(f"{sc.engine()}/nfp/{uid}?expand=true{eval_string}", headers=hdrs, verify=False)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return

        print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to fetch NFP info")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@nfp.command()
@click.argument('chart', type=str)
@click.argument('version', type=str)
@click.argument('repo_url', type=str)
@click.argument('repo_name', type=str)
@click.option("-u", "--repo_user", type=str)
@click.option("-p", "--repo_pass", hide_input=True)
@click.option("-d", "--dryrun", is_flag=True)
@add_options(common_options)
def add_helm(chart, version, repo_url, repo_name, repo_user, repo_pass, dryrun, **kwargs):
    """Create and register a Helm based Network Function Package"""
    try:
        r = None
        data = {
            "apiVersion": "mdcap.robin.io/v1",
            "kind": "NFP",
            "metadata": {
                "flavor": "default",
                "version": version,
                "description": chart,
                "name": chart.split('/')[-1],
                "labels": {}
            },
            "spec": {
                "helm": {
                    'repo_url': repo_url,
                    'repo_name': repo_name,
                    'repo_user': repo_user,
                    'repo_pass': repo_pass,
                    'chart': chart,
                }
            }
        }

        if dryrun:
            print(json.dumps(data, indent=4))
            return
        hdrs = get_hdrs()
        r = requests.post(f"{sc.engine()}/nfp", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@nfp.command(aliases=['register'])
@click.argument('file_path', type=str)
@add_options(common_options)
def add(file_path, **kwargs):
    """Add a Network Function Package"""
    try:
        r = None
        hdrs = get_hdrs()
        try:
            data = read_yaml_file(file_path)
        except:
            try:
                data = read_json_file(file_path)
            except:
                raise Exception("Please ensure file specified is a valid YAML or JSON and exists at specified path.")

        r = requests.post(f"{sc.engine()}/nfp", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@nfp.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a Network Function Package"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/nfp/{uid}", headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete NFP with uid: {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)



@cli.group(cls=ClickAliasedGroup)
def postgres():
    """POSTGRES Management"""
    pass

@postgres.command(aliases=['register'])
@click.argument('config', type=click.File('r'))
@add_options(common_options)
def add(config, **kwargs):
    """Register a POSTGRES element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = json.load(config)
        r = requests.post(f"{sc.engine()}/postgres", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@postgres.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a POSTGRES element"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/postgres/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@postgres.command()
@click.option("--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all POSTGRES elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/postgres{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
            return
        else:
            print(tabulate(elem_format(results['items']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            footer += "Displaying {}/{} elements from offset {}\n".format(results['count'], results['limit'], results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list postgress. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@postgres.command()
@click.argument('uid', type=str)
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the POSTGRES config")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, evaluate, **kwargs):
    """Get information on a particular POSTGRES element"""
    try:
        r = None
        hdrs = get_hdrs()
        evaluate_str = "?evaluate=true" if evaluate else ""
        r = requests.get(f"{sc.engine()}/postgres/{uid}{evaluate_str}", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        result = r.json()
        if not result:
            print("postgres '{}' does not exist".format(uid))
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            print("Name: {}".format(result['metadata']['name']))
            print("UUID: {}".format(result['metadata']['uid']))
            print("Description: {}".format(result['metadata']['description'] if result['metadata']['description'] else "-"))
            print()
            if result['spec']:
                print()
                print("Additional Config:")
                print_nested(result['spec'], indent=0)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for postgres '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@postgres.command()
@click.argument('uid', type=str)
@click.option('--config', help="Path to file containing config details")
@click.option('--ignore-wf', is_flag=True, help="Don't trigger workflow for this config update", default=False)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, output, ignore_wf, **kwargs):
    """Update a POSTGRES element"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = requests.put(f"{sc.engine()}/postgres/{uid}?ignorewf={str(ignore_wf)}", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@postgres.command()
@click.option('--uid', type=str, help="UID of POSTGRES to be modified")
@click.option("--schema-uid", type=str, help="Validate the configuration using this schema uid")
@click.option('--config', help="Path to file containing config details")
@click.option('--apiversion', help="API Version against to validate", default="mdcap.robin.io/v1")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def validate(uid, schema_uid, config, apiversion, output, **kwargs):
    """Validates new or modified POSTGRES element configuration"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = common_validate(uid, schema_uid, "postgres", apiversion, data)
        r.raise_for_status()
        print(r.json())

    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@postgres.command()
@click.argument('name', type=str)
@click.argument('workflow', type=str)
@click.option("--output-file", help="Output file to dump generated workflow to")
@add_options(common_options)
def generate(name, workflow, output_file, **kwargs):
    """Generate a config file for a dynamic workflow of a POSTGRES"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'name': name,
            'wf_name': workflow
        }
        r = requests.put(f"{sc.engine()}/postgres", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        if output_file:
            with open(output_file, 'w') as outfile:
                json.dump(r.json(), outfile)
        else:
            print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate workflow {} for POSTGRES {}. ".format(workflow, name))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@postgres.command(name="import")
@click.argument('filename', type=str)
@add_options(common_options)
def import_postgress(filename, **kwargs):
    """Import POSTGRESs from a file"""
    if not os.path.exists(filename):
        raise Exception("No file found at specified location: {}".format(filename))
    with open(filename, 'r') as fh:
        postgress = json.load(fh)
        print(f"Importing {len(postgress)} postgress...")
        for postgres in postgress:
            try:
                r, hdrs = None, get_hdrs()
                data = postgres
                r = requests.post(f"{sc.engine()}/postgres", json=data, verify=False, headers=hdrs)
                r.raise_for_status()
                print(r.json()['msg'])
            except Exception as ex:
                handle_error(ex)
            finally:
                if kwargs.get('urlinfo') and r:
                    compute_curl_command(r, headers=hdrs, data=data)


@cli.group(cls=ClickAliasedGroup, aliases=['rc'])
def robincluster():
    """Robin Cluster Management"""
    pass


@robincluster.command()
@click.argument('config', type=str)
@add_options(common_options)
def add(config, **kwargs):
    """Register a Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        data.update(read_json_file(config))
        r = requests.post(f"{sc.engine()}/robincluster", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@robincluster.command()
@click.argument('name', type=str)
@click.option('-h', '--ha',  is_flag=True, default=False, help="Is this a HA deployment")
@click.option('-v', '--vm', multiple=True, required=True, help="Virtual machine name")
@click.option('-u', '--sshuser', default="root", help="SSH username for all VMs")
@click.option('-p', '--sshpass', required=True, help="SSH password for all VMs")
@click.option('-U', '--robinuser', default="robin", help="SSH username for all VMs")
@click.option('-P', '--robinpass', required=True, help="SSH password for all VMs")
@click.option('--vrid', help="Is this a HA deployment")
@click.option('--vip',  help="Is this a HA deployment")
@click.option('-b', '--buildurl',  required=True, help="Artifactory URL for ROBIN binaries")
@click.option('-v', '--version',  required=True, help="Robin version (5.2.3-10612)")
@click.option('-d', '--dryrun',  is_flag=True, help="Just dump the config")
@add_options(common_options)
def register(name, ha, vm, sshuser, sshpass, robinuser, robinpass,
             vrid, vip, buildurl, version, dryrun, **kwargs):
    """Register a Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        if ha:
            if len(vm) < 3:
                raise Exception("Minimum server count is 3 for HA install")
            if not vrid or not vip:
                raise Exception("VRID and VIP are required for HA install")

        # Construct the infra
        infra = {}
        for v in vm:
            infra[v] = {
                "kind": "VM",
                "name": v,
                "description": "I am {}".format(v),
                "connectors": {
                    "ssh": {
                            "sshhost": v,
                            "username": sshuser,
                            "password": sshpass,
                    }
                }
            }

        conf = {
            'name': name,
            "robin_config": {
                    "name": name,
                    "robin_user": robinuser,
                    "robin_password": robinpass,
                    "install_type": "ha" if ha else "non-ha",
                    "build_url": buildurl,
                    "version": version,
                    "primary_master": vm[0],
                    "secondary_masters": vm[1:3] if ha else [],
                    "agents": vm[3:] if ha else vm[1:],
            },
            "infra": infra
        }

        if dryrun:
            print(json.dumps(conf, indent=4))
            return

        r = requests.post(f"{sc.engine()}/robincluster", json=conf, headers=hdrs,
                          verify=False)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=conf)


@robincluster.command()
@click.argument('uid', type=str)
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-aa', '--add-agents', help="Add one or more new agents to the robincluster. Example -aa <UID1>,<UID2>..")
@click.option('-ra', '--remove-agents', help="Remove one or more agents from the robincluster. Example -ra <UID1>,<UID2>..")
@click.option('-am', '--add-master', help="Add a new secondary master to the robincluster. Example -am <UID1>")
@click.option('-rm', '--remove-master', help="Remove a secondary master from the robincluster. Example -rm <UID1>")
@click.option('-i', '--ignore-wf', is_flag=True, help="Don't trigger workflow for this config update", default=False)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, add_agents, remove_agents, add_master, remove_master, output, ignore_wf, **kwargs):
    """Update a Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            if add_agents or remove_agents or add_master or remove_master:
                print("Cannot select config and other scaleout options together")
                return
            data = read_json_file(config)
            data = open_in_editor(uid, edit_fmt=output, merge_config=data)
            if not data:
                return
        else:
            count = 0
            for fl in [add_agents or remove_agents or add_master or remove_master]:
                count = count + 1
                if count > 1:
                    print("Cannot select multiple re-scale operations together")
                    return
            if add_agents or remove_agents or add_master or remove_master:
                if add_agents:
                    r = requests.put(f"{sc.engine()}/robincluster/{uid}?add-agents={add_agents}", headers=hdrs, verify=False)
                elif remove_agents:
                    r = requests.put(f"{sc.engine()}/robincluster/{uid}?remove-agents={remove_agents}", headers=hdrs, verify=False)
                elif add_master:
                    r = requests.put(f"{sc.engine()}/robincluster/{uid}?add-master={add_master}", headers=hdrs, verify=False)
                else:
                    r = requests.put(f"{sc.engine()}/robincluster/{uid}?remove-master={remove_master}", headers=hdrs, verify=False)
                r.raise_for_status()
                data = open_in_editor(None, content=json.dumps(r.json(), indent=4), edit_fmt=output)
            else:
                data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = requests.put(f"{sc.engine()}/robincluster/{uid}?ignorewf={str(ignore_wf)}", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@robincluster.command()
@click.option('-u', '--uid', type=str, help="UID of Robin Cluster to be modified")
@click.option('-s', "--schema-uid", type=str, help="Validate the configuration using this schema uid")
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-v', '--apiversion', help="API Version against to validate", default="mdcap.robin.io/v1")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def validate(uid, schema_uid, config, apiversion, output, **kwargs):
    """Validates new or modified Robin Cluster element configuration"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = common_validate(uid, schema_uid, "robincluster", apiversion, data)
        r.raise_for_status()
        print(r.json())

    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@robincluster.command()
@click.argument('uids', type=str)
@click.argument('workflow', type=str)
@click.option('-o', "--output-file", help="Output file to dump generated workflow to")
@add_options(common_options)
def genwf(uids, workflow, output_file, **kwargs):
    """Generate a config file for a dynamic workflow of a Robin Cluster"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'uids': uids.split(","),
            'wf_name': workflow
        }
        r = requests.put(f"{sc.engine()}/robincluster", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        if output_file:
            with open(output_file, 'w') as outfile:
                json.dump(r.json(), outfile)
        else:
            print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate workflow {} for Robin Cluster(s) {}. ".format(workflow, uids))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@robincluster.command()
@click.option('-v', "--apiversion", type=str, help="API Version", default="mdcap.robin.io/v1")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option('-c', "--cluster", help="Add secondary and agents to this cluster")
@click.option('-p', "--primary", help="Primary node for the robincluster")
@click.option('-s', "--secondaries", help="Secondary nodes to be added to the robincluster (csv format)")
@click.option('-a', "--agents", help="Agent nodes to be added to the robincluster (csv format)")
@click.option("--all", is_flag=True, help="Include non-mandatory fields")
@add_options(common_options)
def generate_config(apiversion, output, cluster, primary, secondaries, agents, all, **kwargs):
    """Generate robin cluster config"""
    hdrs = get_hdrs()
    r = None
    try:
        if cluster and primary:
            print("Primary cannot be set on existing cluster")
            return
        rc = {}
        if not cluster:
            rc = generate_element_template('robincluster', apiversion, fmt=output, include_non_mandatory=all)
        else:
            r = requests.get(f"{sc.engine()}/robincluster/{cluster}?expand=true", verify=False, headers=hdrs)
            r.raise_for_status()
            rc = r.json()
        def get_element(uid):
            r = requests.get(f"{sc.engine()}/element/{uid}", verify=False, headers=hdrs)
            r.raise_for_status()
            elem = r.json()
            return {elem['metadata']['name']: {'kind': r.json()['kind'], '_ref': uid}}

        if 'infra' not in rc['spec']:
            rc['spec']['infra'] = {}
        if 'robin_config' not in rc['spec']:
            rc['spec']['robin_config'] = {}
        if 'secondaries' not in rc['spec']:
            rc['spec']['robin_config']['secondary_masters'] = []
        if 'agents' not in rc['spec']:
            rc['spec']['robin_config']['agents'] = []
        if secondaries:
            for secondary in secondaries.split(","):
                if secondary in rc['spec']['robin_config']['secondary_masters'] or secondary in rc['spec']['robin_config']['agents']:
                    print(f"Secondary master {secondary} is already part of cluster")
                    return
                element = get_element(secondary)
                for key in element.keys():
                    rc['spec']['robin_config']['secondary_masters'].append(key)
                    rc['spec']['infra'][key] = element[key]
                    break
        if agents:
            for agent in agents.split(","):
                if agent in rc['spec']['robin_config']['agents'] or agent in rc['spec']['robin_config']['secondary_masters']:
                    print(f"Agent {agent} is already part of cluster")
                    return
                element = get_element(agent)
                for key in element.keys():
                    rc['spec']['robin_config']['agents'].append(key)
                    rc['spec']['infra'][key] = element[key]
                    break

        rc['kind'] = 'ROBINCLUSTER'
        pprint(rc)
    except Exception as ex:
        print(ex)
        handle_error(ex, action_msg="Failed to dump element template for kind ROBINCLUSTER. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data={})


@robincluster.command()
@click.argument('uid', type=str)
@click.option('-c', "--cascade", is_flag=True, help="Delete underlying base elements alongside the Robin Cluster")
@add_options(common_options)
def delete(uid, cascade, **kwargs):
    """Delete a Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        cascade_str = "?cascade=true" if cascade else ""
        r = requests.delete(f"{sc.engine()}/robincluster/{uid}{cascade_str}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@robincluster.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all Robin Cluster elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/robincluster{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            # hdrs = ['uid', 'type', 'name', 'description']
            print(tabulate(elem_format(results['items'], keys=['uid', 'name', 'flavor', 'version', 'description', 'liveness', 'readiness']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list Robin Clusters. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@robincluster.command()
@click.argument('uid', type=str)
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the Robin Cluster config")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@click.option("-c", "--clusternodes", is_flag=True, help="Robin cluster node details")
@add_options(common_options)
def info(uid, output, evaluate, clusternodes, **kwargs):
    """Get information about a particular Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        evaluate_str = "&evaluate=true" if evaluate else ""
        cn_str = "&cn=true" if clusternodes else ""
        r = requests.get(f"{sc.engine()}/robincluster/{uid}?expand=true{evaluate_str}{cn_str}", verify=False, headers=hdrs)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        result = r.json()
        if not result:
            print("ROBINCLUSTER '{}' does not exist".format(uid))
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            print("Name: {}".format(result['metadata']['name']))
            print("UUID: {}".format(result['metadata']['uid']))
            print("Description: {}".format(result['metadata']['description'] if result['metadata'].get('description') else "-"))
            print()
            print("Robin Config:")
            print("    Robin User: {}".format(result['spec']['robin_config']['robin_user']))
            print("    Robin Password: {}".format(result['spec']['robin_config']['robin_password']))
            print("    Installation Type: {}".format(result['spec']['robin_config']['install_type']))
            if result['spec']['robin_config']['install_type'].upper() == "HA":
                print("    Virtual IP Address: {}".format(result['spec']['robin_config']['vip']))
                print("    Virtual Router ID: {}".format(result['spec']['robin_config']['vrid']))
            print("    Version: {}".format(result['spec']['robin_config']['version'] if result['spec']['robin_config'].get('version') else "-" ))
            print("    Build URL: {}".format(result['spec']['robin_config']['build_url'] if result['spec']['robin_config'].get('build_url') else "-" ))
            print("    Primary Master: {}".format(result['spec']['robin_config']['primary_master']))
            if result['spec']['robin_config'].get('secondary_masters'):
                print("    Secondary Masters: {}".format(", ".join(result['spec']['robin_config']['secondary_masters'])))
            if result['spec']['robin_config'].get('agents'):
                print("    Agents: {}".format(", ".join(result['spec']['robin_config']['agents'])))
            clusternodes = result.get("clusternodes", None)
            if clusternodes:
                print ("\n    {:<60} {:<10} {:<10}".format("Hostname", "State", "Status"))
                for node in clusternodes['items']:
                    print (f"    {node['hostname']:<60} {node['state']:<10} {node['status']:<10}")


    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for Robin Cluster '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@robincluster.group("kafka-consumer")
def kafka_consumer():
    """Event and alert Kafka consumer Management"""


@kafka_consumer.command("register")
@click.argument('uid', type=str)
@click.option('-b', '--brokers', type=str, required=True,
              help="The host / IP address of Kafka Brokers. Should be in"
                   " <hostname>:<port> or <ipv4-addr>:<port> or"
                   " <[ipv6-addr]>:<port> (required for kafka type")
# @click.option('--sasl-mechanism', type=click.Choice(['PLAIN']),
#              help="The kafka broker SASL mechanism. Valid types are['PLAIN']")
# @click.option('--username', type=str, help="The kafka broker username")
# @click.option('--password', type=str, help="The kafka broker password")
# @click.option('--enable-ssl', is_flag=True, default=False,
#              help="Enable SSL for communication with Kafka brokers")
@add_options(common_options)
def kafka_consumer_register(uid, brokers, **kwargs):
    """Kafka Consumer for robin cluster events and alerts"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {"kind": "ROBINCLUSTER", 'notification_kafka_brokers': brokers}
        r = requests.put(f"{sc.engine()}/robincluster/{uid}?register-consumer=true", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        res = r.json()
        print(f"Submitted batch {res['id']} for kafka consumer registration")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to add consumer for robin cluster {} with brokers {}".format(uid, brokers))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@kafka_consumer.command("delete")
@click.argument('uid', type=str)
@add_options(common_options)
def kafka_consumer_delete(uid, **kwargs):
    """Delete Kafka Consumer robin cluster"""
    hdrs = get_hdrs()
    r = None
    try:
        hdrs = get_hdrs()
        data = {"kind": "ROBINCLUSTER"}
        r = requests.put(f"{sc.engine()}/robincluster/{uid}?deregister-consumer=true", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        res = r.json()
        print(f"Submitted batch {res['id']} for kafka consumer deregistration")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to remove consumer for robin cluster {}".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@kafka_consumer.command("list")
@add_options(common_options)
def kafka_consumer_list(**kwargs):
    hdrs = get_hdrs()
    r = None
    try:
        url = f"{sc.eventserver()}/event-server/api/v1/consumer/kafka?element-type=robincluster"
        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()
        res = r.json()
        consumers = res.get('items', [])
        if not consumers:
            print("No kafka consumers found")
            return
        tbl_hdrs = ['uid', 'brokers', 'message-type', 'topic', 'description']
        table = []
        for c in consumers:
            elem_uid = c['element-uid']
            brokers = c['brokers']
            desc = c.get('description', '')
            for t in c.get("topic-info", []):
                table.append([elem_uid, brokers, t['message-type'], t['topic'], desc])
                elem_uid = brokers = desc = ""

        print(tabulate(table, headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get kafka consumers")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@kafka_consumer.command("info")
@click.argument('uid', type=str)
@add_options(common_options)
def kafka_consumer_info(uid, **kwargs):
    """Get information a kafka consumer"""
    hdrs = get_hdrs()
    r = None
    try:
        url = f"{sc.eventserver()}/event-server/api/v1/consumer/kafka/{uid}"
        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()
        c = r.json()
        if not c:
            print("No kafka consumer found")
            return
        tbl_hdrs = ['uid', 'brokers', 'message-type', 'topic', 'description']
        table = []
        elem_uid = c['element-uid']
        brokers = c['brokers']
        desc = c.get('description', '')
        for t in c.get("topic-info", []):
            table.append([elem_uid, brokers, t['message-type'], t['topic'], desc])
            elem_uid = brokers = desc = ""
        print(tabulate(table, headers=tbl_hdrs))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get kafka consumer")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@robincluster.group()
def event():
    """Event Management"""


@event.command('list')
@click.option('-u', '--uid', type=str)
@click.option('-n', '--page-num', type=int, help="Page number, defaults to 1")
@click.option('-s', '--page-size', type=int, help="Page size, defaults to 1000")
@click.option('-t', '--create-time', type=str, help="Filter based on creation time of the event (RFC 3339 format)."
                                              " Supported operator 'eq:', 'ne:', 'gt:', 'lt:', 'ge:', 'le:'.")
@click.option('-l', '--severity-level', type=str, help="Severity level of the event (INFO, MINOR, MAJOR, ERROR, CRITICAL)"
                                                 ".Supported operator 'eq:', 'ne:', 'gt:', 'lt:', 'ge:', 'le:'."
                                                 " Defaults to 'ge:INFO'")
@click.option('--ascending', is_flag=True, help="Sort in ascending order of the event id."
                                                " Default sorting is descending")
@click.option('--total', is_flag=True, help="Returns the total events matching query")
@add_options(common_options)
def event_list(uid, page_num, page_size, create_time, severity_level,
               ascending, total, **kwargs):
    """Get the list of events"""
    hdrs = get_hdrs()
    r = None
    try:
        url = f"{sc.eventserver()}/event-server/api/v1/event/robincluster"
        if uid:
            url += f"/{uid}"
        page_size = 20 if not page_size else page_size
        q = f"page-size={page_size}"
        if page_num:
            q = f"&page-num={page_num}"
        if create_time:
            q += f"&create-time={create_time}"
        if severity_level:
            q += f"&severity-level={severity_level}"
        if ascending:
            q += f"&sort=id"
        if total:
            q += f"&total=true"

        url += f"?{q}"
        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()
        res = r.json()
        if res.get('items'):
            table = []
            tbl_hdrs = ['id', 'element-uid', 'severity-level', 'create-time', 'description']
            for evt in res['items']:
                table.append([evt['id'], evt['element-uid'], evt['severity-level'],
                              evt['create-time'], evt.get('description', '')])
            print(tabulate(table, headers=tbl_hdrs))
        print(f"\nTotal events: {res['total']}")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get events.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@robincluster.group()
def alert():
    """Robin cluster alerts information"""


@alert.command('list')
@click.option('-u', '--uid', type=str, help="Element UUID")
@click.option('-n', '--page-num', type=int, help="Page number, defaults to 1")
@click.option('-s', '--page-size', type=int, help="Page size, defaults to 1000")
@click.option('-t', '--create-time', type=str, help="Filter based on creation time of the event (RFC 3339 format)."
                                              " Supported operator 'eq:', 'ne:', 'gt:', 'lt:', 'ge:', 'le:'.")
@click.option('-l', '--severity-level', type=str, help="Severity level of the event (INFO, MINOR, MAJOR, ERROR, CRITICAL)"
                                                 ".Supported operator 'eq:', 'ne:', 'gt:', 'lt:', 'ge:', 'le:'."
                                                 " Defaults to 'ge:INFO'")
@click.option('-a', '--alert-state', type=str, help="Alert state. Valid values (ACTIVE, RESOLVED)")
@click.option('--ascending', is_flag=True,
              help="Sort in ascending order of the event id. Default sorting is descending")
@click.option('--total', is_flag=True, help="Returns the total events matching query")
@add_options(common_options)
def alert_list(uid, page_num, page_size, create_time, severity_level, alert_state,
               ascending, total, **kwargs):
    """Get the list of alerts"""
    hdrs = get_hdrs()
    r = None
    try:
        url = f"{sc.eventserver()}/event-server/api/v1/alert/robincluster"
        if uid:
            url += f"/{uid}"
        page_size = 20 if not page_size else page_size
        q = f"page-size={page_size}"
        if page_num:
            q = f"&page-num={page_num}"
        if create_time:
            q += f"&create-time={create_time}"
        if severity_level:
            q += f"&severity-level={severity_level}"
        if alert_state:
            q += f"&alert-state={alert_state}"
        if ascending:
            q += f"&sort=id"
        if total:
            q += f"&total=true"

        url += f"?{q}"
        r = requests.get(url, verify=False, headers=hdrs)
        r.raise_for_status()
        res = r.json()
        if res.get('items'):
            table = []
            tbl_hdrs = ['id', 'element-uid', 'severity-level', 'state', 'create-time',
                        'end-time', 'description']
            for a in res.get('items', []):
                table.append([a['id'], a['element-uid'], a['severity-level'],
                              a['state'], a['create-time'], a.get('end-time', ''),
                              a.get('description', '')])
            print(tabulate(table, headers=tbl_hdrs))
        print(f"\nTotal alerts: {res['total']}")
    except Exception as ex:
        handle_error(ex, action_msg="Failed to get alerts.")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)



@cli.group(cls=ClickAliasedGroup, aliases=['rc-aws'])
def robincluster_aws():
    """AWS Robin Cluster Management"""
    pass


@robincluster_aws.command()
@click.argument('config', type=str)
@add_options(common_options)
def add(config, **kwargs):
    """Register a Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        data.update(read_json_file(config))
        r = requests.post(f"{sc.engine()}/robinclusteraws", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@robincluster_aws.command()
@click.argument('uid', type=str)
@click.option('-c', '--config', help="Path to file containing config details")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, output, **kwargs):
    """Update a Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = requests.put(f"{sc.engine()}/robinclusteraws/{uid}", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@robincluster_aws.command()
@click.option('-u', '--uid', type=str, help="UID of AWS Robin Cluster to be modified")
@click.option('-s', "--schema-uid", type=str, help="Validate the configuration using this schema uid")
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-v', '--apiversion', help="API Version against to validate", default="mdcap.robin.io/v1")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def validate(uid, schema_uid, config, apiversion, output, **kwargs):
    """Validates new or modified Robin Cluster element configuration"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = common_validate(uid, schema_uid, "robinclusteraws", apiversion, data)
        r.raise_for_status()
        print(r.json())

    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@robincluster_aws.command()
@click.argument('uids', type=str)
@click.argument('workflow', type=str)
@click.option('-o', "--output-file", help="Output file to dump generated workflow to")
@add_options(common_options)
def genwf(uids, workflow, output_file, **kwargs):
    """Generate a config file for a dynamic workflow of AWS Robin Cluster"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'uids': uids.split(","),
            'wf_name': workflow
        }
        r = requests.put(f"{sc.engine()}/robinclusteraws", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        if output_file:
            with open(output_file, 'w') as outfile:
                json.dump(r.json(), outfile)
        else:
            print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate workflow {} for AWS Robin Cluster(s) {}. ".format(workflow, uids))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@robincluster_aws.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/robinclusteraws/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@robincluster_aws.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all Robin Cluster elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/robinclusteraws{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            # hdrs = ['uid', 'type', 'name', 'description']
            print(tabulate(elem_format(results['items'], keys=['uid', 'name', 'flavor', 'version', 'description', 'liveness', 'readiness']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list AWS Robin Clusters. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@robincluster_aws.command()
@click.argument('uid', type=str)
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the Robin Cluster config")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, evaluate, **kwargs):
    """Get information about a particular Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        evaluate_str = "&evaluate=true" if evaluate else ""
        r = requests.get(f"{sc.engine()}/robinclusteraws/{uid}?expand=true{evaluate_str}", verify=False, headers=hdrs)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        result = r.json()
        if not result:
            print("AWS Robin Cluster '{}' does not exist".format(uid))
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            print("Name:        {}".format(result['metadata']['name']))
            print("UUID:        {}".format(result['metadata']['uid']))
            print("Description: {}".format(result['metadata']['description'] if result['metadata'].get('description') else "-"))
            print()
            print("Robin Config:")
            print("    Robin User:        {}".format(result['spec']['robin_config']['robin_user']))
            print("    Robin Password:    {}".format(result['spec']['robin_config']['robin_password']))
            print("    Installation Type: {}".format(result['spec']['robin_config']['install_type']))
            print("    Region (Zone):     {} ({})".format(result['spec']['robin_config']['region'], result['spec']['robin_config']['zone']))
            print("    AMI:               {}".format(result['spec']['robin_config']['ami']))

            ## Add info about installed primary master if available

    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for Robin Cluster '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@cli.group(cls=ClickAliasedGroup, aliases=['rc-gcp'])
def robincluster_gcp():
    """GCP Robin Cluster Management"""
    pass


@robincluster_gcp.command()
@click.argument('config', type=str)
@add_options(common_options)
def add(config, **kwargs):
    """Register a Robin Cluster GCP element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {}
        data.update(read_json_file(config))
        r = requests.post(f"{sc.engine()}/robinclustergcp", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@robincluster_gcp.command()
@click.argument('uid', type=str)
@click.option('-c', '--config', help="Path to file containing config details")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, output, **kwargs):
    """Update a Robin Cluster GCP element"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = requests.put(f"{sc.engine()}/robinclustergcp/{uid}", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@robincluster_gcp.command()
@click.option('-u', '--uid', type=str, help="UID of GCP Robin Cluster to be modified")
@click.option('-s', "--schema-uid", type=str, help="Validate the configuration using this schema uid")
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-v', '--apiversion', help="API Version against to validate", default="mdcap.robin.io/v1")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def validate(uid, schema_uid, config, apiversion, output, **kwargs):
    """Validates new or modified Robin Cluster element configuration"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = common_validate(uid, schema_uid, "robinclustergcp", apiversion, data)
        r.raise_for_status()
        print(r.json())

    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@robincluster_gcp.command()
@click.argument('uids', type=str)
@click.argument('workflow', type=str)
@click.option('-o', "--output-file", help="Output file to dump generated workflow to")
@add_options(common_options)
def genwf(uids, workflow, output_file, **kwargs):
    """Generate a config file for a dynamic workflow of GCP Robin Cluster"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'uids': uids.split(","),
            'wf_name': workflow
        }
        r = requests.put(f"{sc.engine()}/robinclustergcp", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        if output_file:
            with open(output_file, 'w') as outfile:
                json.dump(r.json(), outfile)
        else:
            print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate workflow {} for GCP Robin Cluster(s) {}. ".format(workflow, uids))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@robincluster_gcp.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a GCP Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/robinclustergcp/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@robincluster_gcp.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all GCP Robin Cluster elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/robinclustergcp{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            # hdrs = ['uid', 'type', 'name', 'description']
            print(tabulate(elem_format(results['items'], keys=['uid', 'name', 'flavor', 'version', 'description', 'liveness', 'readiness']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list GCP Robin Clusters. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@robincluster_gcp.command()
@click.argument('uid', type=str)
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the Robin Cluster config")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, evaluate, **kwargs):
    """Get information about a particular GCP Robin Cluster element"""
    try:
        r = None
        hdrs = get_hdrs()
        evaluate_str = "&evaluate=true" if evaluate else ""
        r = requests.get(f"{sc.engine()}/robinclustergcp/{uid}?expand=true{evaluate_str}", verify=False, headers=hdrs)
        r.raise_for_status()
        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        result = r.json()
        if not result:
            print("GCP Robin Cluster '{}' does not exist".format(uid))
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            print("Name:        {}".format(result['metadata']['name']))
            print("UUID:        {}".format(result['metadata']['uid']))
            print("Description: {}".format(result['metadata']['description'] if result['metadata'].get('description') else "-"))
            print()
            print("Robin Config:")
            print("    Robin User:        {}".format(result['spec']['robin_config']['robin_user']))
            print("    Robin Password:    {}".format(result['spec']['robin_config']['robin_password']))
            print("    Installation Type: {}".format(result['spec']['robin_config']['install_type']))
            print("    Region (Zone):     {} ({})".format(result['spec']['robin_config']['region'], result['spec']['robin_config']['zone']))
            print("    Image Name:               {}".format(result['spec']['robin_config']['image-name']))

            ## Add info about installed primary master if available

    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for GCP Robin Cluster '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@cli.group(cls=ClickAliasedGroup)
def switch():
    """Switch Management"""
    pass


@switch.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a Switch"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/switch/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to delete Switch {}. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@switch.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all Switches"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/switch{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
        else:
            #hdrs = ['uid', 'type', 'name', 'description']
            print(tabulate(elem_format(results['items'], keys=['uid', 'name', 'flavor', 'version', 'description', 'liveness', 'readiness']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list Switches. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)


@switch.command(name="import")
@click.argument('filename', type=str)
@add_options(common_options)
def import_switches(filename, **kwargs):
    """Import Switches from a file"""
    if not os.path.exists(filename):
        raise Exception("No file found at specified location: {}".format(filename))
    with open(filename, 'r') as fh:
        switches = json.load(fh)
        print(f"Importing {len(switches)} switches...")
        for switch in switches:
            try:
                r, hdrs = None, get_hdrs()
                data = {
                    'apiVersion': switch['apiVersion'],
                    'kind': switch['kind'],
                    'metadata': {
                        'name': switch['metadata']['name'],
                        'description': switch['metadata'].get('description', ''),
                        'labels': parse_labels(switch['metadata']['labels'], ret_dict=True) if 'labels' in switch['metadata'] else {}
                    },
                    'spec': {
                        'connectors': {
                            'ssh': {
                                'sshhost': switch['spec']['connectors']['ssh'].get('sshhost', 'fillin'),
                                'username': switch['spec']['connectors']['ssh']['username'],
                                'password': switch['spec']['connectors']['ssh']['password']
                            }
                        }
                    }
                }
                r = requests.post(f"{sc.engine()}/switch", json=data, verify=False, headers=hdrs)
                r.raise_for_status()
                print(r.json()['msg'])
            except Exception as ex:
                handle_error(ex)
            finally:
                if kwargs.get('urlinfo') and r:
                    compute_curl_command(r, headers=hdrs, data=data)



@cli.group(cls=ClickAliasedGroup)
def unmanaged():
    """UNMANAGED Management"""
    pass

@unmanaged.command(aliases=['register'])
@click.argument('config', type=click.File('r'))
@add_options(common_options)
def add(config, **kwargs):
    """Register a UNMANAGED element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = json.load(config)
        r = requests.post(f"{sc.engine()}/unmanaged", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@unmanaged.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a UNMANAGED element"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/unmanaged/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@unmanaged.command()
@click.option("--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all UNMANAGED elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/unmanaged{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
            return
        else:
            print(tabulate(elem_format(results['items']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list unmanageds. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@unmanaged.command()
@click.argument('uid', type=str)
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the UNMANAGED config")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, evaluate, **kwargs):
    """Get information on a particular UNMANAGED element"""
    try:
        r = None
        hdrs = get_hdrs()
        evaluate_str = "?evaluate=true" if evaluate else ""
        r = requests.get(f"{sc.engine()}/unmanaged/{uid}{evaluate_str}", verify=False, headers=hdrs)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        result = r.json()
        if not result:
            print("unmanaged '{}' does not exist".format(uid))
        else:
            print_nested(result, indent=0)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for unmanaged '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@unmanaged.command()
@click.argument('uid', type=str)
@click.option('--config', help="Path to file containing config details")
@click.option('--ignore-wf', is_flag=True, help="Don't trigger workflow for this config update", default=False)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, output, ignore_wf, **kwargs):
    """Update a UNMANAGED element"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = requests.put(f"{sc.engine()}/unmanaged/{uid}?ignorewf={str(ignore_wf)}", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)


@cli.group(cls=ClickAliasedGroup)
def vm():
    """Virtual Machine Management"""
    pass

@vm.command(aliases=['register'])
@click.argument('name', type=str)
@click.option('-v', '--apiversion', help="API Version against to register", default="mdcap.robin.io/v1")
@click.option('-u', '--sshuser', '-u', help="SSH username", required=True)
@click.option('-p', '--sshpass', '-p', help="SSH password", required=True)
@click.option('-i', '--sshipaddr', '-i', help="SSH IP Address or Hostname")
@click.option('-c', '--additional-config', help="Path to file containing additional config details")
@click.option('-d', '--description', help="Description of Virtual Machine")
@click.option("-l", "--labels", type=str, multiple=True, help="Add labels to help with grouping and filtering. Format: key1:val1,key2val2...")
@add_options(common_options)
def add(name, apiversion, sshuser, sshpass, sshipaddr, description, labels, additional_config, **kwargs):
    """Register a Virtual Machine element"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
                    'apiVersion': apiversion,
                    'kind': 'VM',
                    'metadata': {
                        'name': name,
                        'description': description if description else "",
                        'labels': parse_labels(labels, ret_dict=True) if labels else {}
                    },
                    'spec': {
                        'connectors': {
                            'ssh': {
                                'sshhost': sshipaddr if sshipaddr else name,
                                'username': sshuser,
                                'password': sshpass}
                            }
                    }
                }

        data['config'] = {}

        if additional_config:
            data['spec'].update(read_json_file(additional_config))
        r = requests.post(f"{sc.engine()}/vm", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.json()['msg'])
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@vm.command()
@click.argument('uid', type=str)
@add_options(common_options)
def delete(uid, **kwargs):
    """Delete a Virtual Machine element"""
    try:
        r = None
        hdrs = get_hdrs()
        r = requests.delete(f"{sc.engine()}/vm/{uid}", verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@vm.command()
@click.option('-r', "--range", 'index', type=str, help="Option to display a range of entries. Can be specified as a range i.e. <start_idx>:<end_idx>.")
@click.option("-l","--labels", type=str, multiple=True, help="filter search based on key value pairs.")
@click.option('-m', '--match', type=str, help="Partial filter match")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def list(index, labels, match, output, **kwargs):
    """List all Virtual Machine elements"""
    try:
        r = None
        hdrs = get_hdrs()
        limit, offset = offset_limit_from_range(index)
        labellist = parse_labels(labels)
        query_params = [limit, offset, labellist]
        if match:
            query_params.append(f"match={match}")
        limit_url = parameter_string(query_params)
        r = requests.get("{}/vm{}".format(sc.engine(), limit_url), headers=hdrs, verify=False)
        r.raise_for_status()

        if output == 'yaml':
            print(yaml.dump(r.json(), indent=4))
            return

        if output == 'json':
            print(json.dumps(r.json(), indent=4))
            return
        results = r.json()
        if not results['items']:
            print("No results found")
            return
        else:
            print(tabulate(elem_format(results['items'], keys=['uid', 'name', 'flavor', 'version', 'description', 'liveness', 'readiness']), headers="keys"))
            footer = '\n--------------------------------------------\n'
            num, den = (results['count'], results['limit']) if results['count'] < results['limit'] else (results['limit'], results['count'])
            footer += "Displaying {}/{} elements from offset {}\n".format(num, den, results['offset'])
            footer += '--------------------------------------------\n'
            print(footer)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to list VMs. ")
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@vm.command()
@click.argument('uid', type=str)
@click.option("--evaluate", is_flag=True, help="Evaluate any properties referenced from registry within the Virtual Machine config")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']))
@add_options(common_options)
def info(uid, output, evaluate, **kwargs):
    """Get information on a particular Virtual Machine element"""
    try:
        r = None
        hdrs = get_hdrs()
        evaluate_str = "?evaluate=true" if evaluate else ""
        r = requests.get(f"{sc.engine()}/vm/{uid}{evaluate_str}", verify=False, headers=hdrs)
        r.raise_for_status()
        result = r.json()
        mask_sensitive_data(result)
        if output == 'yaml':
            print(yaml.dump(result, indent=4))
            return

        if output == 'json':
            print(json.dumps(result, indent=4))
            return

        if not result:
            print("VM '{}' does not exist".format(uid))
        else:
            #hdrs = ['uid', 'type', 'name', 'description']

            print("Name: {}".format(result['metadata']['name']))
            print("UUID: {}".format(result['metadata']['uid']))
            print("Description: {}".format(result['metadata']['description'] if result['metadata']['description'] else "-"))
            print()
            print("SSH Config:")
            print("    SSH Host: {}".format(result['spec']['connectors']['ssh']['sshhost']))
            print("    SSH Username: {}".format(result['spec']['connectors']['ssh']['username']))
            print("    SSH Password: {}".format(result['spec']['connectors']['ssh']['password']))
            result['spec'].pop('connectors')
            if result['spec']:
                print()
                print("Additional Config:")
                print_nested(result['spec'], indent=0)
    except Exception as ex:
        handle_error(ex, action_msg="Failed to display information for VM '{}'. ".format(uid))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs)

@vm.command()
@click.argument('uid', type=str)
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-i', '--ignore-wf', is_flag=True, help="Don't trigger workflow for this config update", default=False)
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def update(uid, config, output, ignore_wf, **kwargs):
    """Update a Virtual Machine element"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = requests.put(f"{sc.engine()}/vm/{uid}?ignorewf={str(ignore_wf)}", json=data, verify=False, headers=hdrs)
        r.raise_for_status()
        print(r.text)
    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@vm.command()
@click.option('-u', '--uid', type=str, help="UID of virtual machine to be modified")
@click.option('-s', "--schema-uid", type=str, help="Validate the configuration using this schema uid")
@click.option('-c', '--config', help="Path to file containing config details")
@click.option('-v', '--apiversion', help="API Version against to validate", default="mdcap.robin.io/v1")
@click.option("-o", "--output", type=click.Choice(['json', 'yaml']), default='json')
@add_options(common_options)
def validate(uid, schema_uid, config, apiversion, output, **kwargs):
    """Validates new or modified Virtual Machine element configuration"""
    try:
        r = None
        hdrs = get_hdrs()
        if config:
            data = read_json_file(config)
        else:
            data = open_in_editor(uid, edit_fmt=output)
            if not data:
                return

        r = common_validate(uid, schema_uid, "vm", apiversion, data)
        r.raise_for_status()
        print(r.json())

    except Exception as ex:
        handle_error(ex)
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@vm.command()
@click.argument('uids', type=str)
@click.argument('workflow', type=str)
@click.option('-o', "--output-file", help="Output file to dump generated workflow to")
@add_options(common_options)
def genwf(uids, workflow, output_file, **kwargs):
    """Generate a config file for a dynamic workflow of VM"""
    try:
        r = None
        hdrs = get_hdrs()
        data = {
            'uids': uids.split(","),
            'wf_name': workflow
        }
        r = requests.put(f"{sc.engine()}/vm", json=data, headers=hdrs, verify=False)
        r.raise_for_status()
        if output_file:
            with open(output_file, 'w') as outfile:
                json.dump(r.json(), outfile)
        else:
            print(json.dumps(r.json(), indent=4))
    except Exception as ex:
        handle_error(ex, action_msg="Failed to generate workflow {} for Virtual Machine(s) {}. ".format(workflow, uids))
    finally:
        if kwargs.get('urlinfo') and r:
            compute_curl_command(r, headers=hdrs, data=data)

@vm.command()
@click.argument('hostname', type=str)
@click.argument('username', type=str)
@click.argument('password', type=str)
@click.argument('type', type=click.Choice(['vcenter', 'hyperv']))
@add_options(common_options)
def discover(hostname, username, password, type, **kwargs):
    """Discover Virtual Machines from a specified hypervisor"""
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
    import wmi_client_wrapper as wmi
    def get_vcenter_vm_info(vm, result, depth=1):
        maxdepth = 10
        # if this is a group it will have children. if it does, recurse into them and then return
        if hasattr(vm, 'childEntity'):
            if depth > maxdepth:
                return
            vmList = vm.childEntity
            for c in vmList:
                get_vcenter_vm_info(c, result, depth + 1)
            return

        # if this is a vApp, it likely contains child VMs
        # (vApps can nest vApps, but it is hardly a common usecase, so ignore that)
        if isinstance(vm, vim.VirtualApp):
            vmList = vm.vm
            for c in vmList:
                get_vcenter_vm_info(c, result, depth + 1)
            return

        item = {
            "name": vm.summary.config.name,
            #"path": vm.summary.config.vmPathName,
            #"guest": vm.summary.config.guestFullName,
            #"annotation": vm.summary.config.annotation,
            #"state": vm.summary.runtime.powerState
            "connectors": {
                "ssh": {
                    "username": "root",
                    "password": "<FillIn>"
                }
            }
        }
        if vm.summary.guest != None and vm.summary.guest.ipAddress:
            item['connectors']['ssh']['sshhost'] = vm.summary.guest.ipAddress
        result.append(item)

    if type == 'vcenter':
        si = SmartConnect(host="cscale-82-200.robinsystems.com",
                          user="administrator@vsphere.local",
                          pwd="Robin123!",
                          sslContext=ssl._create_unverified_context())
        if not si:
            print("Could not connect to the specified host using specified username and password")
            return -1
        content = si.RetrieveContent()
        result = []
        for child in content.rootFolder.childEntity:
            if hasattr(child, 'vmFolder'):
                datacenter = child
                vmfolder = datacenter.vmFolder
                vmlist = vmfolder.childEntity
                for vm in vmlist:
                    get_vcenter_vm_info(vm, result)
        Disconnect(si)
    elif type == 'hyperv':
        result = []
        wmic = wmi.WmiClientWrapper(username=username, password=password, host=hostname, namespace='root\\virtualization\\v2')
        vms = wmic.query("SELECT * FROM Msvm_ComputerSystem")
        nwcfgs = wmic.query("SELECT * FROM Msvm_GuestNetworkAdapterConfiguration")
        for vm in vms:
            item = {}
            if 'virtual' in vm['Description'].lower():
                item['name'] = vm['ElementName']
                for nwcfg in nwcfgs:
                    if vm['Name'] in nwcfg['InstanceID']:
                        item['connectors']['ssh'] = {
                            'sshhost': nwcfg['IPAddresses'][0].split(',')[0],
                            'username': 'root',
                            'password': '<FillIn>'
                        }
                        break
                result.append(item)

    tfile = tempfile.NamedTemporaryFile(delete=False)
    with open(tfile.name, 'w') as fh:
        fh.write(json.dumps(result))
    print(f"VM(s) imported from {type} hypervisor {hostname} are dumped to {tfile.name}")

@vm.command(name="import")
@click.argument('filename', type=str)
@add_options(common_options)
def import_vms(filename, **kwargs):
    """Import Virtual Machines from a file"""
    if not os.path.exists(filename):
        raise Exception("No file found at specified location: {}".format(filename))
    with open(filename, 'r') as fh:
        vms = json.load(fh)
        print(f"Importing {len(vms)} vms...")
        for vm in vms:
            try:
                r, hdrs = None, get_hdrs()
                data = {
                    'apiVersion': vm['apiVersion'],
                    'kind': vm['kind'],
                    'metadata': {
                        'name': vm['metadata']['name'],
                        'description': vm['metadata'].get('description', ''),
                        'labels': parse_labels(vm['metadata']['labels'], ret_dict=True) if 'labels' in vm['metadata'] else {}
                    },
                    'spec': {
                        'connectors': {
                            'ssh': {
                                'sshhost': vm['spec']['connectors']['ssh'].get('sshhost', 'fillin'),
                                'username': vm['spec']['connectors']['ssh']['username'],
                                'password': vm['spec']['connectors']['ssh']['password']
                            }
                        }
                    }
                }
                r = requests.post(f"{sc.engine()}/vm", json=data, verify=False, headers=hdrs)
                r.raise_for_status()
                print(r.json()['msg'])
            except Exception as ex:
                handle_error(ex)
            finally:
                if kwargs.get('urlinfo') and r:
                    compute_curl_command(r, headers=hdrs, data=data)



if __name__ == '__main__':
    cli()
