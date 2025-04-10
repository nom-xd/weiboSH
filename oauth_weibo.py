import hashlib
import json
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl 
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, quote_plus
import requests
from time import sleep
import platform

SCOPE = "all"

HOST = "127.0.0.1"
PORT = 8779

IS_LINUX = platform.platform()[:5].lower() == "linux"
prefix_home = "/home/nom-xd" if IS_LINUX else "C:/Users/nnoom/OneDrive"
prefix_font = "/media/nom-xd/windows" if IS_LINUX else "C:"
prefix_data = "/media/nom-xd/Data" if IS_LINUX else "D:"

#libretranslate --load-only en,zh --host 192.168.1.23 --port 8779
def get_ssl_context(certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    context.set_ciphers("@SECLEVEL=1:ALL")
    return context

class RequestHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        self.do_HEAD()
        self.server: "Nom__XD"
        print("HERE1")
        if "?" in self.path:
            self.server.query_params = dict(parse_qsl(self.path.split("?")[1]))
        self.wfile.write(b"<html><h1>We are in!</h1></html>")
        self.server.done = True

    def do_POST(self):
        content_length = int(self.headers["Content-length"])
        post_data = self.rfile.read(content_length)
        print(post_data.decode("utf-8"))
        print("HERE2")
        if "?" in self.path:
            self.server.query_params = dict(parse_qsl(self.path.split("?")[1]))
        self.wfile.write(b"<html><h1>We are in!</h1></html>")

class Server(HTTPServer):
    def __init__(self, host: str, port: int) -> None:
        super().__init__((host, port), RequestHandler)
        self.rhandle = RequestHandler
        self.query_params: dict[str,str] = {}
        self.done = False


def authorise(secrets: dict[str,str]) -> dict[str,str]:
    params = {
            "response_type": "code",
            "client_id": secrets['client_id'],
            "redirect_uri": secrets['redirect_uri'],
            "scope": SCOPE,
            "state": hashlib.sha256(os.urandom(1024)).hexdigest(),
            "language": "en"
            }

    url = f"{secrets['auth_uri']}?{urlencode(params)}"
    print("URL")
    print(url)

    if not webbrowser.open(url):
        raise RuntimeError("Failed to open default browser")
    print("SERVER") 
    server = Server(HOST, PORT)
    uri_path = prefix_data + "/eclipse/eclipse-workspace/Twitter_Profile_update/socials/security/certificates/"
    context = get_ssl_context(uri_path + "my_cert.cer", uri_path + "my_key.cer")
    server.socket = context.wrap_socket(server.socket, server_side=True)

    try:
        while not server.done: 
            server.handle_request() #serve_forever()
            sleep(2)
    finally:
        server.server_close()
    print(server.server_name)
    print(params["state"])
    print(server.query_params["state"])
    if params["state"] != server.query_params["state"]:
        raise RuntimeError("Invalid state! Someone is trying to forge responses")

    code = server.query_params["code"]
    print(code)
    params = {
            "grant_type": "authorization_code",
            "client_id": secrets['client_id'],
            "client_secret": secrets['client_secret'],
            "redirect_uri": secrets['redirect_uri'],
            "code": code,
            }
    with requests.post(
            secrets["token_uri"],
            data = params,
            headers = {"Content-type": "application/x-www-form-urlencoded"},) as response:
        print(response)
        if response.status_code != 200:
            raise RuntimeError("Failed to authorise")
        return response.json()
    return {}

def prepare_auth():
    data = json.loads(Path(prefix_data + "/eclipse/eclipse-workspace/Twitter_Profile_update/socials/Weibo/token.json").read_text())
    user_id = data['uid']
    access_token = data['access_token']
    return (user_id, access_token)

def check_access_token():
    _, access_token = prepare_auth()
    #shared_image = "https://drive.google.com/file/d/1sSdQ9pr0ixdiLlbMc9tGPw8BegfvfYlQ"
    #shared_image = "https://drive.google.com/uc?export=download&id=1sSdQ9pr0ixdiLlbMc9tGPw8BegfvfYlQ"
    params = {
            "access_token": access_token
            }
    with requests.post(
            "https://api.weibo.com/oauth2/get_token_info",
            data = params,
            headers = {"Content-type": "application/x-www-form-urlencoded"},) as response:
        print(response)
        if response.status_code != 200:
            raise RuntimeError("Failed to authorise")
        return response.json()

    
def post_weibo_inner(text, path_to_file):
    _, access_token = prepare_auth()
    my_ip = requests.get('https://api.ipify.org').content.decode('utf8')
    print(my_ip)
    params = {
            "status" : quote_plus(text) + " http://nomxd.great-site.net",                # open.weibo.com 140 chinese chars(280 bytes)
            "rip": quote_plus(my_ip),
            "access_token": quote_plus(access_token)
            }
    files  = {
            "pic":open(path_to_file,"rb") # image JPEG, GIF, PNG < 5M 
            }
    with requests.post(
            "https://api.weibo.com/2/statuses/share.json",
            data = params,
            files=files) as response:
        print(response)
        print(response.json())
        if response.status_code != 200:
            raise RuntimeError("Failed to authorise")
        return response.json()
  
if __name__ == "__main__": #157671303 157671281
    #secrets = json.loads(Path("secrets.json").read_text())["configuration"]
    #tokens = authorise(secrets)
    #print(f" Tokens: {tokens}")
    #with open('D:/eclipse/eclipse-workspace/Twitter_Profile_update/socials/Weibo/token.json', 'w', encoding='utf-8') as my_file:
    #    json.dump(tokens, my_file, ensure_ascii=False)
    #print(check_access_token())
    post_weibo_inner("测试", ("/media/nom-xd/windows/Users/nomxd" if IS_LINUX else "C:/Users/nomxd") + "/mama_noel.jpg")
