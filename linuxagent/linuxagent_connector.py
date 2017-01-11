# --
# File: samplewhois_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from linuxagent_consts import *

import simplejson as json
import datetime

# my imports
import requests
import binascii


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


def unwrap(data):
        return json.loads(data)


def wrap(data):
        return json.dumps(data, ensure_ascii=True, indent=4, separators=(",", ": "))


# --- create the service request to be sent to the agent on the endpoint
def makeservice(service, config, param):
        userid = param["userid"] if "userid" in param else config["userid"]
        password = param["password"] if "password" in param else config["password"]
        server = param["server name"] if "server name" in param else config["server name"]
        port = param["server port"] if "server port" in param else config["server port"]
        directory = param["directory"] if "directory" in param else config["directory"]

        param["userid"] = userid
        param["password"] = password
        param["server name"] = server
        param["server port"] = port
        param["directory"] = directory

        url = "https://{0}:{1}/{2}/service".format(server, port, LINUXAGENT_API)
        data = {
                "Userid": userid,
                "Password": password,
                "Service": service
        }

        # --- add in optional parameters
        if "filename" in param:
                data["Path"] = param["filename"]
        if "sudo" in param and param["sudo"]:
                data["Sudo"] = "Yes"

        # --- apply the cert and key for the connector and the cert for the endpoint
        appdir = "{0}/{1}/".format(PHANTOM_APPSHOME, config["directory"])
        verify = appdir + "agent.crt"
        cert = (appdir + "app.crt", appdir + "app.key")

        return (url, wrap(data), verify, cert)


# Define the App Class
class LinuxAgentConnector(BaseConnector):

        ACTION_ID_TIME = "invoke_time_service"
        ACTION_ID_WHO = "invoke_who_service"
        ACTION_ID_CAT = "invoke_cat_service"

        def __init__(self):
                # Call the BaseConnectors init first
                super(LinuxAgentConnector, self).__init__()

        # --- bundle results here
        def makeresult(self, status, summary, data, param):
                action_result = ActionResult(dict(param))
                self.add_action_result(action_result)
                for e in data:
                        e["agent"] = "{0}:{1}".format(param["server name"], param["server port"])
                        e["server"] = param["server name"]
                        e["port"] = param["server port"]
                        e["user"] = param["userid"]
                        if "filename" in param:
                                e["filename"] = param["filename"]
                        if "sudo" in param and param["sudo"]:
                                e["sudo"] = True
                        action_result.add_data(e)
                action_result.update_summary(summary)
                action_result.set_status(status)

        # --- make a get time request
        # --- returns the number of seconds since the epoch from the endpoint's POV
        def __handle_time(self, param):
                config = self.get_config()
                url, service, vfile, cfile = makeservice("time", config, param)

                self.debug_print(url, service)
                try:
                        r = requests.post(url, service, verify=vfile, cert=cfile)
                        if r.status_code != requests.codes.ok:
                                r.raise_for_status()
                except Exception as e:
                        return self.set_status_save_progress(phantom.APP_ERROR, str(e))

                response = r.json()
                self.debug_print(url, wrap(response))
                self.makeresult(phantom.APP_SUCCESS, { "time": response["seconds_since_epoch"] }, [ { "time": response["seconds_since_epoch"] } ], param)
                return(phantom.APP_SUCCESS, url)

        # --- make a /bin/who request
        # --- returns a line for each user sessions as provided by the /bin/who command as well as the raw data
        def _handle_who(self, param):
                config = self.get_config()
                url, service, vfile, cfile = makeservice("who", config, param)

                self.debug_print(url, service)
                try:
                        r = requests.post(url, service, verify=vfile, cert=cfile)
                        if r.status_code != requests.codes.ok:
                                r.raise_for_status()
                except Exception as e:
                        return self.set_status_save_progress(phantom.APP_ERROR, str(e))

                response = r.json()
                self.debug_print(url, wrap(response))
                # --- return each session as separate piece of data
                list_of_sessions = response["parsed"]

                # --- return number of sessions per user as summary
                summary = {}
                for s in list_of_sessions:
                        key = s["NAME"]
                        summary[key] = summary[key] + 1 if key in summary else 1

                for s in summary:
                        summary[s] = "{0} {1}".format(summary[s], "sessions" if summary[s] > 1 else "session")

                self.makeresult(phantom.APP_SUCCESS, summary, list_of_sessions, param)
                return self.set_status_save_progress(phantom.APP_SUCCESS, "{0}: {1}".format(url, LINUXAGENT_SUCC_WHO_COMMAND))

        # --- make a /bin/cat filename request
        # --- this command may be run with sudo to provide root privileges. The userid on the endpoint must
        # --- be configured to run sudo with the ability to run /bin/cat
        # --- returns the content of the file
        def _handle_cat(self, param):
                config = self.get_config()
                url, service, vfile, cfile = makeservice("cat", config, param)

                self.debug_print(url, service)
                try:
                        r = requests.post(url, service, verify=vfile, cert=cfile)
                        if r.status_code != requests.codes.ok:
                                r.raise_for_status()
                except Exception as e:
                        return self.set_status_save_progress(phantom.APP_ERROR, str(e))

                response = r.json()
                self.debug_print(url, wrap(response))

                # --- decode content of file
                file = binascii.a2b_base64(response['file-content'])
                filesplit = file.split("\n")

                # --- summary is the size of the file + first line.
                summary = {}
                summary[param["filename"]] = "{0} bytes, first_line={1}".format(len(file), filesplit[0])
                self.makeresult(phantom.APP_SUCCESS, summary, [ { "content": file } ], param)
                return self.set_status_save_progress(phantom.APP_SUCCESS, "{0}: {1}".format(url, LINUXAGENT_SUCC_CAT_COMMAND))

        # --- the get time function is also used for network connectivity testing.
        # --- this is the wrapper the get time function
        def _handle_time(self, param):
                status, url = self.__handle_time(param)
                if status == phantom.APP_SUCCESS:
                        return self.set_status_save_progress(phantom.APP_SUCCESS, "{0}: {1}".format(url, LINUXAGENT_SUCC_TIME_COMMAND))
                else:
                        return self.set_status_save_progress(phantom.APP_ERROR, "{0}: {1}".format(url, LINUXAGENT_ERR_TIME_COMMAND))

        # --- the get time function is also used for network connectivity testing.
        # --- this is the wrapper the test connectivity function
        def _test_connectivity(self, param):
                status, url = self.__handle_time(param)
                if status == phantom.APP_SUCCESS:
                        return self.set_status_save_progress(phantom.APP_SUCCESS, "{0}: {1}".format(url, LINUXAGENT_SUCC_CONNECTIVITY_TEST))
                else:
                        return self.set_status_save_progress(phantom.APP_ERROR, "{0}: {1}".format(url, LINUXAGENT_ERR_CONNECTIVITY_FAILED))

        def handle_action(self, param):
                ret_val = phantom.APP_SUCCESS

                # Get the action that we are supposed to execute for this App Run
                action_id = self.get_action_identifier()

                self.save_progress("Handle_Action: " + action_id)

                try:
                        if (action_id == self.ACTION_ID_WHO):
                                ret_val = self._handle_who(param)
                        elif (action_id == self.ACTION_ID_TIME):
                                ret_val = self._handle_time(param)
                        elif (action_id == self.ACTION_ID_CAT):
                                ret_val = self._handle_cat(param)
                        elif (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
                                ret_val = self._test_connectivity(param)
                except:
                        # --- this shouldn't happen as all exceptions should be handled within the _handle_* methods
                        return phantom.APP_ERR

                return ret_val


if __name__ == "__main__":

    import sys
    # import pudb
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        # print(json.dumps(in_json, indent=4))
        connector = LinuxAgentConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print("-" * 70)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
