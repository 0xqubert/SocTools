#app.py
#Author: Scott Stage
#Created: 12/31/2024

from flask import Flask, Response, jsonify, make_response, render_template, request
                                   #https://flask.palletsprojects.com/en/stable/
import os                          #https://github.com/python/cpython/blob/3.13/Lib/os.py
import threading                   #https://github.com/python/cpython/blob/3.13/Lib/threading.py
import datetime                    #https://github.com/python/cpython/blob/3.13/Lib/datetime.py
import socket                      #https://github.com/python/cpython/blob/3.13/Lib/socket.py
import json                        #https://github.com/python/cpython/blob/3.13/Lib/json/__init__.py
import time                        #https://github.com/python/cpython/blob/main/Doc/library/time.rst
import traceback                   #https://github.com/python/cpython/blob/3.13/Lib/traceback.py
import atexit                      #https://github.com/python/cpython/blob/main/Doc/library/atexit.rst
import queue                       #https://github.com/python/cpython/blob/3.13/Lib/queue.py

app = Flask(__name__)

host = '127.0.0.1'
port = 65432
delimiter = "__END_OF_RESPONSE__"
sse_queue = queue.Queue() # Create a new Queue to pass data to sse.

def log_write(log_message):
    logFile = "logs/SocTools.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"{timestamp} -       app.py: {log_message}\n"
    try:
        with open(logFile, "a") as f:
            f.write(log_line)
    except Exception as e:
        print(f"Error writing to log file {logFile}: {e}")


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
          log_write(f"Attempting to connect to SocTools at: {self.host}:{self.port}")
          self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          self.socket.connect((self.host, self.port))
          local_address = self.socket.getsockname()
          ip, port = local_address
          log_write(f"Connected Established!")
          log_write(f"app.py({ip}:{port}) <---> SocTools.ps1({self.host}:{self.port})")
      except Exception as e:
        log_write(f"Error connecting to socket: {e}\n {traceback.format_exc()}")

    def send_command(self, command):
        try:
          if(self.socket == None or self.socket.fileno() == -1):
             log_write("Reconnecting due to closed socket.")
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
           log_write(f"Error sending command to powershell: {e}\n {traceback.format_exc()}")
           return None

    def close(self):
        if self.socket:
            log_write(f"Closing connection to {self.host}:{self.port}")
            self.socket.close()
        else:
            log_write("Socket already closed.")

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
                    log_write(f"Error sending keep alive: {e}\n {traceback.format_exc()}")

    def start_keep_alive_thread(self):
        keep_alive_thread = threading.Thread(target=self._send_keep_alive, daemon=True)
        keep_alive_thread.start()

    def _send_keep_alive(self):
       while True:
          time.sleep(self.keep_alive_interval)
          try:
              self.send_command(json.dumps({"action": "keepalive"}))
          except Exception as e:
              log_write(f"Error sending keep alive: {e}\n {traceback.format_exc()}")
# Instantiate the socket client at app startup
socket_client = SocketClient(host, port)

@app.route('/')
def index():
    # Get the current time
    current_timestamp = time.time()
    # Prepare the response and cache control headers
    response = make_response(render_template("index.html", current_time=current_timestamp))
    # Set cache control headers to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/logs')
def get_text_content():
    return render_template("logs.html")

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
                log_write(f"Response received: {result}")# Added logging here.
                sse_queue.put(result) # add the result to the queue, so that the events are sent
            return jsonify(result)
        else:
            return { "error": "command not found"}



        

def generate_log_events():
    logFile = "logs/SocTools.log"
    last_modified_time = os.path.getmtime(logFile)
    try:
        with open(logFile, 'r') as f:
            text_content = f.read()
            yield f"data: {json.dumps({'content': text_content})}\n\n"
    except FileNotFoundError:
        yield f"data: {json.dumps({'content': 'File Not Found'})}\n\n"

    while True:
        time.sleep(1)  # Check every second
        current_modified_time = os.path.getmtime(logFile)
        if current_modified_time != last_modified_time:
            last_modified_time = current_modified_time
            try:
                with open(logFile, 'r') as f:
                    text_content = f.read()
                    yield f"data: {json.dumps({'content': text_content})}\n\n"
            except FileNotFoundError:
                    yield f"data: {json.dumps({'content': 'File Not Found'})}\n\n"

@app.route('/log-stream')
def log_stream():
    return Response(generate_log_events(), mimetype='text/event-stream')

def close_socket_connection():
    socket_client.close()

# close the socket when the app shuts down.
atexit.register(close_socket_connection)

if __name__ == '__main__':
    app.run(debug=True, threaded = True, use_reloader=False)