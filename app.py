from flask import Flask, Response, jsonify, render_template, request
import threading
import datetime
import socket
import json
import time
import logging
import traceback
import atexit
from urllib.parse import urlparse, parse_qs
import re
import queue

app = Flask(__name__)

host = '127.0.0.1'
port = 65432
delimiter = "__END_OF_RESPONSE__"
sse_queue = queue.Queue() # Create a new Queue to pass data to sse.

# Set up custom loggers
socket_logger = logging.getLogger('socket_client')
socket_logger.setLevel(logging.DEBUG)
socket_handler = logging.StreamHandler()
socket_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
socket_handler.setFormatter(socket_formatter)
socket_logger.addHandler(socket_handler)

app_logger = logging.getLogger('app')
app_logger.setLevel(logging.DEBUG)
app_handler = logging.StreamHandler()
app_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
app_handler.setFormatter(app_formatter)
app_logger.addHandler(app_handler)


class CustomFormatter(logging.Formatter):
    """A custom logging formatter that prepends the logger name."""
    ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def format(self, record):
      log_time = datetime.datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
      if(isinstance(record.msg,str)):
          cleaned_msg = CustomFormatter.ANSI_ESCAPE.sub('', record.msg)
          return f"{log_time} - {record.name}: {cleaned_msg}"
      else:
          return f"{log_time} - {record.name}: {record.msg}"

socket_handler.setFormatter(CustomFormatter())
app_handler.setFormatter(CustomFormatter())

class SocketClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.connect()
        self.keep_alive_interval = 300 # Send keep alive every 300 seconds / 5 minutes
        self.auto_refresh_interval = -1
        self.start_keep_alive_thread()
        self.start_auto_refresh_thread()

    def connect(self):
      try:
          socket_logger.info(f"Attempting to connect to SocTools at: {self.host}:{self.port}")
          self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          self.socket.connect((self.host, self.port))
          local_address = self.socket.getsockname()
          ip, port = local_address
          socket_logger.info(f"Connected Established!")
          socket_logger.info(f"app.py({ip}:{port}) <---> SocTools.ps1({self.host}:{self.port})")
      except Exception as e:
        socket_logger.error(f"Error connecting to socket: {e}\n {traceback.format_exc()}")
    def send_command(self, command):
        try:
          if(self.socket == None or self.socket.fileno() == -1):
             socket_logger.info("Reconnecting due to closed socket.")
             self.connect()
          self.socket.sendall((command + '\n').encode('utf-8'))
          data = b""
          while True:
              chunk = self.socket.recv(4096)
              if not chunk:
                break
              data += chunk
              if delimiter.encode('utf-8') in data:
                break
          data_str = data.decode('utf-8', 'ignore')
          data_str = data_str.split(delimiter)[0] # Remove the delimiter before parsing the json
          result = json.loads(data_str.strip())
          return result

        except Exception as e:
           socket_logger.error(f"Error sending command to powershell: {e}\n {traceback.format_exc()}")
           return None

    def close(self):
        if self.socket:
            socket_logger.info(f"Closing connection to {self.host}:{self.port}")
            self.socket.close()
        else:
            socket_logger.info("Socket already closed.")

    def set_refresh_interval(self, value):
        self.auto_refresh_interval = value
        log_write(f"Auto Refresh interval changed to : {self.auto_refresh_interval}")

    def start_auto_refresh_thread(self):
        auto_refresh_thread = threading.Thread(target=self._auto_refresh, daemon=True)
        auto_refresh_thread.start()

    def _auto_refresh(self):
        while True:
            if(int(self.auto_refresh_interval) != -1):
                time.sleep(int(self.auto_refresh_interval))
                try:
                    result = self.send_command(json.dumps({"action": "GetCurrentUserInfo"}))
                    log_write(f"Received from powershell before processing: {result}")# Added logging here.
                    sse_queue.put(result)
                except Exception as e:
                    socket_logger.error(f"Error sending keep alive: {e}\n {traceback.format_exc()}")

    def start_keep_alive_thread(self):
        keep_alive_thread = threading.Thread(target=self._send_keep_alive, daemon=True)
        keep_alive_thread.start()

    def _send_keep_alive(self):
       while True:
          time.sleep(self.keep_alive_interval)
          try:
              self.send_command(json.dumps({"action": "keepalive"}))
          except Exception as e:
              socket_logger.error(f"Error sending keep alive: {e}\n {traceback.format_exc()}")
# Instantiate the socket client at app startup
socket_client = SocketClient(host, port)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/harddelete')
def hard_delete():
    return render_template('exoutils/harddelete.html')


@app.route('/omeportal')
def ome_portal():
    return render_template('exoutils/omeportal.html')


@app.route('/revokemessage')
def revoke_message():
    return render_template('exoutils/revokemessage.html')

@app.route('/events', methods=['GET', 'POST'])
def events():
    if request.method == 'GET':
        def generate():
            yield f'data: {json.dumps({"message": "keepalive"})}\n\n'
            time.sleep(1)
            yield f'data: {json.dumps({"message": "keepalive2"})}\n\n'
            try:
                while True:
                    message = sse_queue.get()
                    yield f'data: {json.dumps(message)}\n\n'
            except GeneratorExit:
                log_write("Generator Exited")
                return


        return Response(generate(), mimetype='text/event-stream')
    elif request.method == 'POST':
        command = request.get_json()
        if command and command.get("action"):
            if(command.get("action") == "changeRefreshInterval"):
                result = socket_client.set_refresh_interval(json.dumps(command.get("input")))
            else:
                log_write(f"Sending Command: {command}")
                result = socket_client.send_command(json.dumps(command))
                log_write(f"Received from powershell before processing: {result}")# Added logging here.
                sse_queue.put(result) # add the result to the queue, so that the events are sent
            return jsonify(result)
        else:
            return { "error": "command not found"}


def log_write(log_message):
    logFile = "logs/SocTools.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"{timestamp} - app.py: {log_message}\n"
    try:
        with open(logFile, "a") as f:
            f.write(log_line)
    except Exception as e:
        print(f"Error writing to log file {logFile}: {e}")


def close_socket_connection():
    socket_client.close()

# close the socket when the app shuts down.
atexit.register(close_socket_connection)

if __name__ == '__main__':
    app.run(debug=True, threaded = True, use_reloader=False)