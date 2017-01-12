#! /usr/bin/env python2.7
# --- Serve agent data to phantom app via RESTful api
# --- Only use modules included from base python2.7 package as to be as portable as possible.
# ---
# --- Needs to run as root to authenticate incoming requests
# --- Use "kill" to stop server because a STOP service request will require a more 
# --- sophisticated http implementation (due forking/setuid to provided user credentials)
# ---
# --- This agent utilize mutually verified SSL certificates to ensure security. This requires;
# --- 1. a X.509 certificate/key generated for this https service to be provided to the agent program on the endpoint
# --- 2. The X.509 certificate (generated in step 1) identifying this service to be provided to the Phantom connector app on the Phantom appliance
# --- 3. a X.509 certificate generated for the https client to be provided to the Phantom connector app on the Phantom appliance
# --- 4. The X.509 certificate (generated in step 3) identifying the Phantom connector app to be provided to the agent progrom on the endpoint
# ---
# --- potential focus for future enhancements
# ---	whitelist for path access validation
# ---	whitelist for ip access validation
# ---	listing package revisions
# ---	hashing/checksuming files
# ---	listing/killing process, sessions
# ---	starting/stopping services
# ---	rewriting http service to gracefully handle remote agent shutdown and restarts, potentially via the service/systemctl mechanism

AGENT_CERTIFICATE = "agent.crt"
AGENT_PRIVATE_KEY = "agent.key"
APP_CERTIFICATE = "app.crt"

LISTEN_ADDR = ""
LISTEN_PORT = 4443

from SocketServer import ForkingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import ssl, subprocess, json, binascii
import time, datetime
import pwd, spwd, crypt
import os

def wrap(data):
	return json.dumps(data, ensure_ascii=True, indent=4, separators=(",", ": "))

def set_creds(pw):
	os.setgid(pw.pw_gid)
	os.setuid(pw.pw_uid)

def send_response(handler, service, data):
	handler.send_response(200, "SERVICE: {0}".format(service))
	handler.send_header("Content-type", "application/json")
	handler.end_headers()
	handler.wfile.write(data)

def dorun(cmd, handler):
	# --- add sudo command if we want to run as root
	if handler.sudo:
		cmd = [ "/usr/bin/sudo", "-kS" ] + cmd

	process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
	if handler.sudo:
		output = process.communicate("{0}\n".format(handler.password))
	else:
		output = process.communicate()

	# --- let calling function deal with exceptions
	return process.returncode, output, cmd


class Services:
	# --- return time from the point of view of the agent
	@staticmethod
	def time(handler):
		set_creds(handler.userpw)
		cmd = [ "internal_time" ]
		data = {}
		data["service"] = "time"
		data["command"] = " ".join(cmd)
		data["date"] = str(datetime.datetime.utcnow())
		data["seconds_since_epoch"] = time.time()
		send_response(handler, "time", wrap(data))

	# --- /bin/cat a file if user has permissions, permits sudo
	@staticmethod
	def cat(handler):
		if "Path" not in handler.content:
			return handler.send_error(400, "Service Request missing fields: 'Path'")

		set_creds(handler.userpw)
		cmd = [ "/bin/cat", handler.content["Path"] ]
		data = {}
		data["service"] = "cat"
		data["date"] = str(datetime.datetime.utcnow())

		if not os.path.isfile(handler.content["Path"]):
			return handler.send_error(400, "Path is not a file: {0}".format(handler.content["Path"]))

		# --- here is where we try and run /bin/cat
		try:
			returncode, output, cmd = dorun(cmd, handler)

		except Exception as e:
			return handler.send_error(400, "Execution error: {0}: {1}".format(handler.content["Path"], e))

		# --- check for errors from the execution of the command
		if returncode != 0:
			return handler.send_error(400, "Execution error: {0}".format(output[1]))
			
		data["command"] = " ".join(cmd)
		data["file-content"] = output[0]
		data["file-length"] = len(data["file-content"])

		# --- encode the file so not to lose anything in the json translations
		data["file-content"] = binascii.b2a_base64(data["file-content"])
		data["file-encoded-length"] = len(data["file-content"])
		send_response(handler, "cat", wrap(data))

	# --- /bin/who output, no sudo available, but we will set credentials to the provided user
	@staticmethod
	def who(handler):
		set_creds(handler.userpw)
		cmd = [ "/usr/bin/who" ]
		data = {}
		data["service"] = "who"
		data["command"] = " ".join(cmd)
		data["date"] = str(datetime.datetime.utcnow())
		try:
			returncode, output, cmd = dorun(cmd, handler)

		except Exception as e:
			return handler.send_error(400, "Execution error: {0}".format(e))

		# --- check for errors from the execution of the command
		if returncode != 0:
			return handler.send_error(400, "Execution error: {0}: out={1} err={2}".format(" ".join(cmd), output[0], output[1]))

		data["command"] = " ".join(cmd)
		data["output"] = output[0].split("\n")

		# --- parse output for easier digestion by client
		vdata = []
		for l in data["output"]:
			if l == "":
				continue
			elm = l.split(None, 5)
			while len(elm) < 5:
				elm.append("")
			vdata.append({ "NAME": elm[0], "LINE": elm[1], "TIME": "{0} {1}".format(elm[2], elm[3]), "COMMENT": elm[4].lstrip("(").rstrip(")") })
		data["parsed"] = vdata
		send_response(handler, "time", wrap(data))


class RequestHandler(BaseHTTPRequestHandler):
	# --- only support POST as user credentials are <POST>ed as part of the HTTP request

	# --- wrap the actual do_POST. There should not be any uncaught exceptions at this point but, just in case
	# ---
	def do_POST(self):
		try:
			self.really_do_POST()

		except Exception as e:
			self.send_error(500, "Unknown Server error: {0}".format(e))
			

	def really_do_POST(self):
		# --- load up the body from the POST as that is the real service request
		try:
			self.content_length = int(self.headers.getheader("Content-Length"))
			self.content = self.rfile.read(self.content_length)

		except KeyError as e:
			return self.send_error(400, "Service Request missing")

		except OSError as e:
			return self.send_error(400, "Service Request corrupted: {0}".format(e))

		# --- url/path must be "https://<server:port>/<api>/<command>"
		# --- <api> is mapped to a python class providing a set of services, currently only api "1" is supported
		# --- <command> is currently ignored and currently taken from the "Service" entry of the <POST>ed data packet
		try:
			(self.api, command) = self.path.lstrip("/").split("/")

		except ValueError as e:
			return self.send_error(400, "PATH error: {0}".format(self.path))

		# --- load the Service request
		self.request = self.unwrap_content()
		if not self.content:
			return self.send_error(400, "Service Request not JSON")
		try:
			self.command = self.request["Service"]
			self.userid = self.request["Userid"]
			self.password = self.request["Password"]

		except KeyError as e:
			return self.send_error(400, "Service Request missing fields: {0}".format(e))

		self.sudo = True if "Sudo" in self.request and self.request['Sudo'] == "Yes" else False
			
		# --- determine service requested
		try:
			global apis
			func = getattr(apis[self.api], self.command)

		except KeyError:
			return self.send_error(400, "API error: {0}".format(self.api))

		except AttributeError:
			return self.send_error(400, "Service doesn't exists: {0}/{1}".format(self.api, self.command))

		# --- try to authenticate the userid/password
		try:
			userspw = spwd.getspnam(self.userid)

		except KeyError as e:
			return self.send_error(400, "Bad Userid: {0}".format(self.userid))

		if userspw.sp_pwd == crypt.crypt(self.request["Password"], userspw.sp_pwd):
			# --- User is authenticated, save creds and run service
			self.userpw = pwd.getpwnam(self.userid)
			func(self)
		else:
			# --- Request has bad user credentials
			return self.send_error(400, "Bad Password for: {0}".format(self.userid))
			

	def unwrap_content(self):
		if self.content:
			self.content = json.loads(self.content)
			return self.content


# --- since we are changing our process user credentials, we should fork off into a child process first.
class ForkingHTTPServer(ForkingMixIn, HTTPServer):
	pass


def main():
	# --- only supporting api "1"
	global apis
	apis = { "1": Services }

	httpd = ForkingHTTPServer((LISTEN_ADDR, LISTEN_PORT), RequestHandler)
	#httpd = HTTPServer((LISTEN_ADDR, LISTEN_PORT), RequestHandler)
	
	# --- setup for mutual certificate authentication so both app/agent can trust each other
	context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
	context.options |= ssl.OP_NO_SSLv2
	context.options |= ssl.OP_NO_SSLv3
	context.verify_mode = ssl.CERT_REQUIRED
	context.check_hostname = False
	context.load_cert_chain(AGENT_CERTIFICATE, keyfile=AGENT_PRIVATE_KEY)
	context.load_verify_locations(cafile=APP_CERTIFICATE)
	httpd.socket = context.wrap_socket(httpd.socket)

	# --- serve forever
	httpd.serve_forever()

main()
