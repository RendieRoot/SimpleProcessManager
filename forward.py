import os
import sys
import time
import psutil
import socket
import hashlib
import requests
import threading
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler, HTTPServer

allprocess = {}
virustotal_result = {}

def log(action):
    if action == 'info':
        with open('active_process.log', 'w') as active_process:
            for item in allprocess:
                oclock = time.strftime("%H:%M:%S %d.%m.%Y", time.localtime(allprocess[item]['createtime']))
                hostip = socket.gethostbyname(allprocess[item]['hostname'])
                log_line = 'createtime="{0}", hostname="{1}", user="{2}", processname="{3}", pid="{4}", path="{5}", parent="{6}", hash="{7}", hostip="{8}"\n'.format(oclock, allprocess[item]['hostname'],
                allprocess[item]['user'], item, allprocess[item]['pid'], allprocess[item]['path'], allprocess[item]['parent'], allprocess[item]['hash'], hostip)
                active_process.write(log_line)
    elif action == 'virustotal':
        with open('virustotal.log', 'w') as virustotal:
            for item in virustotal_result:
                log_line = 'hash="{0}", result="{1}"'.format(item, virustotal_result[item])
                virustotal.write(log_line)

class ProcessInfo:
    def Hash(self, filePath):
        filePath = filePath.replace('\\', '/')
        try:
            with open(filePath, 'rb') as f:
                m = hashlib.sha256()
                while True:
                    data = f.read(8192)
                    if not data:
                        break
                    m.update(data)
                return m.hexdigest()
        except Exception as error:
            print(error)

    def GetInfoThread(self, proc):
        process = {}
        try:
            if 'C:\\Windows\\System32' not in proc.exe():
                processName = proc.name()
                process['hostname'] = socket.gethostname()
                process['createtime'] = proc.create_time()
                process['pid'] = proc.pid
                process['user'] = proc.username()
                process['path'] = proc.exe()
                parent = str(proc.parent())
                process['parent'] = parent.replace('psutil.Process(', '').replace('\'', '').replace(')', '').replace('pid', 'ppid').replace('name', 'pprocessname').replace('started', 'pcreatetime')
                process['hash'] = self.Hash(proc.exe())
                allprocess[processName] = process
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    def GetInfo(self):
        for proc in psutil.process_iter():
            threading.Thread(target=self.GetInfoThread, args=(proc,)).start()
        log('info')
    
    def VirusTotal(self, hash):
        try:
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': 'api', 'resource': hash}
            response = requests.get(url, params=params).json()
            virustotal_result[hash] = '{0}/{1}'.format(response['positives'], response['total'])
            log('virustotal')
        except Exception as error:
            print(error)

class Server(ThreadingMixIn, HTTPServer):
    pass

class ProcessControl:
    def StopProcess(self, pid):
        try:
            if psutil.pid_exists(int(pid)):
                os.system('taskkill /T /F -pid {0}'.format(pid))
                if psutil.pid_exists(int(pid)):
                    print('Process not closed.')
                else:
                    print('Process closed.')
            else:
                print('Process not found.')
        except Exception as error:
            print(error)

    def UploadFile(self, path):
        try:
            if os.path.isdir('get') == False:
                os.mkdir('get')
            
            if os.path.exists(path):
                from shutil import copyfile

                copyfile(path, 'get\\{0}'.format(os.path.basename(path)))
                os.chdir('get')
                server = Server(('0.0.0.0', 8899), SimpleHTTPRequestHandler)
                try:
                    while True:
                        sys.stdout.flush()
                        server.handle_request()
                except KeyboardInterrupt:
                    pass
        except Exception as error:
            print(error)

if __name__ == '__main__':
    try:
        args = sys.argv[1:]
        if args:
            for arg in args:
                if arg == '--help':
                    print('If the arguments are empty, processes are scanned.\n--scan [hash] - Scan hash on VirusTotal.'+
                        '\n--stop [pid] - Stop process.')
                    break
                if arg == '--scan':
                    if len(sys.argv[2]) > 1:
                        process = ProcessInfo()
                        process.VirusTotal(sys.argv[2])
                        break
                    else:
                        print('Example: --scan [hash]')
                        break
                if arg == '--stop':
                    if len(sys.argv[2]) > 1:
                        process = ProcessControl()
                        process.StopProcess(sys.argv[2])
                        break
                    else:
                        print('Example: --stop [pid]')
                        break
                if arg == '--upload':
                    if len(sys.argv[2]) > 1:
                        process = ProcessControl()
                        process.UploadFile(sys.argv[2])
                        break
                    else:
                        print('Example: --upload [path]')
                        break
                else:
                    print('Argument not found. Use [--help]')
                    break
        else:
            process = ProcessInfo()
            process.GetInfo()
    except:
        pass