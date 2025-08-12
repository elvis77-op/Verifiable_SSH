import logging
import os
import glob
logger = logging.getLogger(__name__)

class bash_command():
    def __init__(self, port, private_key, known_host, host_name):
        self.port = port
        self.private_key = private_key
        self.known_host = known_host
        self.host_name = host_name
        self.destination = "root@"+self.host_name
        logging.basicConfig(level=logging.INFO)

    def ssh_key_scan(self):
        logger.info("list-arg: "+self.port+" / "+self.host_name+" / "+self.known_host)

        os.execlp('ssh-keyscan', 'ssh-keyscan', '-p', self.port, self.host_name)
        
        print("SSH key successfully added to known_hosts.")

    def secure_copy(self, local_path, remote_path):
        logger.info("list-arg-scp: "+self.port+" / "+self.host_name+" / "+self.known_host+" / "+local_path+" / "+self.destination+" / "+remote_path)

        files_to_transfer = glob.glob(local_path)

        command = ['scp', '-v', '-P', '10086', '-i', '/root/keys/private_ssh_key.pem',
                '-o', 'UserKnownHostsFile=/root/keys/known_hosts',
                '-o', 'StrictHostKeyChecking=no'] + files_to_transfer + [self.destination+":"+remote_path]
        
        os.execlp(command)
                    

    def secure_shell(self, command):
        
        command = ["ssh", "-p", self.port, "-i", self.private_key, "-o", f"UserKnownHostsFile={self.known_host}", self.destination, command],
        os.execlp(command)

    def VSSH_main(self):
        scripts = "/root/scripts/*.sh"
        self.ssh_key_scan()
        script_files = glob.glob(scripts)
        self.secure_copy(scripts, scripts.split("*")[0])
        self.secure_shell("chmod +x " + scripts)
    
    
        for idx, script in enumerate(script_files):
            print(f"{idx}: {script}")
    
        while True:
            user_input = input("input index to execute corresponding program in TDVM \nor enter q to quit: ").strip()
            
            if user_input.lower() == 'q':
                logger.info("stopping VSSH client")
                break
                
            if re.match(r'^\d+$', user_input) and int(user_input) < len(scripts):
                self.secure_shell(script_files[int(user_input)])
            else:
                logger.info("invalid index")
                
            