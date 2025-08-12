from config import *
import glob
import base64
import os
import re
import grpc
import logging
logger = logging.getLogger(__name__)

import AS_pb2
import AS_pb2_grpc

import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

import subprocess
def generate_quote(nonce, public_key):
    public_key_pem = load_public_key(public_key)
    public_key_bytes = base64.b64decode(public_key_pem.encode('utf-8'))
    fd = os.open("/dev/attestation/user_report_data", os.O_RDWR)
    report_data = generate_report_data(public_key_bytes, nonce)
    os.write(fd, report_data)
    os.close(fd)

    with open('/dev/attestation/quote', 'rb') as fd:
        quote = fd.read()
    quote_base64 = base64.b64encode(quote)
    quote = quote_base64.decode('utf-8')
    return quote
    
def load_public_key(public_key):
    with open(public_key, 'r') as f:
        public_key_pem = f.read().strip().split()[1]
        

    return public_key_pem

def generate_report_data( public_ssh_key, nonce):

    hashed_key = hashlib.sha384(public_ssh_key).digest() 

    nonce = base64.b64decode(nonce)

    report_data = bytes(hashed_key) + bytes(nonce)
    return report_data

def native_ssh_key_gen(private_ssh_key):
    command = ['ssh-keygen', '-f', private_ssh_key, '-t', 'rsa']

    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        stdout, stderr = process.communicate(input='\n', timeout=10)

        if process.returncode == 0:
            logger.info("keys generated successfully.")
            logger.debug(f"keygen stdout: {stdout}")
            logger.debug(f"keygen stderr: {stderr}")
        else:
            logger.error(f"Error generating keys: {process.returncode}")
            logger.error(f"keygen stdout: {stdout}")
            logger.error(f"keygen stderr: {stderr}")

    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")

def print_keys(public_ssh_key, private_ssh_key):
    with open(public_ssh_key, 'rb') as f:
        public_key_pem = serialization.load_pem_public_key(
            f.read(),
            backend=None
        )
    public_key_pem = public_key_pem.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_key_pem = base64.b64encode(public_key_pem).decode('utf-8')
    
    logger.info("public_key: "+public_key_pem)

    with open(private_ssh_key, "rb") as key_file:
        private_key_pem = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=None)
    private_key_pem = private_key_pem.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_pem = base64.b64encode(private_key_pem).decode('utf-8')
    logger.info("private_key: "+private_key_pem)

def generate_ssh_keys(private_ssh_key):
    command = ['ssh-keygen', '-f', private_ssh_key, '-t', 'rsa']

    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        stdout, stderr = process.communicate(input='\n', timeout=10)

        if process.returncode == 0:
            logger.info("keys generated successfully.")
            logger.debug(f"keygen stdout: {stdout}")
        else:
            logger.error(f"Error generating keys: {process.returncode}")
            logger.error(f"keygen stderr: {stderr}")

    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")


def verify_signature(public_key, signature, data):
    signature_data = base64.b64decode(signature.encode('utf-8'))
    with open(public_key, 'rb') as f:
        public_key_pem = serialization.load_pem_public_key(
            f.read(),
            backend=None
        )
    try:
        public_key_pem.verify(
            signature_data,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    except Exception as e:
        logger.error("signature verification failed")
        raise

class bash_command():
    def __init__(self, port, private_key, known_host, host_name):
        self.port = port
        self.private_key = private_key
        self.known_host = known_host
        self.host_name = host_name
        self.destination = "root@"+self.host_name

    def ssh_key_scan(self):
        # try:
        #     result = subprocess.run(["whoami"], capture_output=True, text=True, check=True)
        #     logger.info(result.stdout)
        # except subprocess.CalledProcessError as e:
        #     logger.error(f"Command failed with error: {e}")
        #     logger.error(f"Stderr: {e.stderr}")

        command = ['ssh-keyscan', '-p', self.port, self.host_name]
        
        with open(self.known_host, 'a') as f:
            result = subprocess.run(command, stdout=f) 

        logger.info("known_hosts has been updated")

        # try:
        #     result = subprocess.run(["ls", "-la", "/root/keys/"], capture_output=True, text=True, check=True)
        #     print("after keyscan output:")
        #     print(result.stdout)
        # except subprocess.CalledProcessError as e:
        #     print(f"Command failed with error: {e}")
        #     print(f"Stderr: {e.stderr}")

    def secure_copy(self, local_path, remote_path):
        try:
            files_to_transfer = glob.glob(local_path)
            logger.debug(f"Files with index: {files_to_transfer}")

            if not files_to_transfer:
                logger.warning("No .sh files found in %s", local_path)
            else:
                command = ['scp', '-P', self.port, '-i', self.private_key,
                        '-o', f'UserKnownHostsFile={self.known_host}',
                        '-o', 'StrictHostKeyChecking=no'] + files_to_transfer + [self.destination+":"+remote_path]

                try:
                    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    stdout, stderr = process.communicate(input='yes\n', timeout=10)

                    if process.returncode == 0:
                        logger.info("Files transferred successfully.")
                        logger.debug(stdout)
                    else:
                        logger.error(f"Error transferring files: {process.returncode}")
                        logger.error(stderr)

                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    logger.error("SCP command timed out.")
                    logger.error(f"SCP stdout: {stdout}")
                    logger.error(f"SCP stderr: {stderr}")
                except Exception as e:
                    logger.exception(f"An unexpected error occurred: {e}")
        except Exception as e:
            logger.exception(f"An unexpected error occurred: {e}")
        
    def secure_shell(self, command):
        # result = subprocess.run(
        #     ["ssh", "-p", self.port, "-i", self.private_key, "-o", f"UserKnownHostsFile={self.known_host}", self.destination, command],
        #     stdout=subprocess.PIPE,
        #     stderr=subprocess.PIPE,
        #     text=True
        # )
        # if result.returncode == 0:
        #     logger.info("Files transferred successfully.")
        #     logger.debug(result.stdout)
        # else:
        #     logger.error(f"Error transferring files: {result.returncode}")
        #     logger.error(result.stderr)
        cmd = ['ssh', '-p', self.port, '-i', self.private_key,
                        '-o', f'UserKnownHostsFile={self.known_host}',
                        '-o', 'StrictHostKeyChecking=no', self.destination, command]

        try:
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                logger.info("script execute successfully.")
                logger.info(stdout)
            else:
                logger.error(f"Error executing with return code: {process.returncode}")
                logger.error(stderr)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            logger.error("ssh command timed out.")
            logger.error(f"ssh stdout: {stdout}")
            logger.error(f"ssh stderr: {stderr}")
        except Exception as e:
            logger.exception(f"An unexpected error occurred: {e}")


    def VSSH_main(self):
        scripts = "/root/scripts/*.sh"
        
        if not os.path.isfile(self.known_host):
            logger.info("create a dummy known_hosts ")
            with open(self.known_host, 'w') as f:
                pass
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
                
            if re.match(r'^\d+$', user_input) and int(user_input) < len(script_files):
                self.secure_shell(script_files[int(user_input)])
            else:
                logger.info("invalid index")
                

    

    

def AS_RUN(public_ssh_key, private_ssh_key, known_hosts):
    if not os.path.isfile(private_ssh_key):    
        logger.info("New System. Generating New Keys for ssh access")
        generate_ssh_keys(private_ssh_key)

    with grpc.insecure_channel(attestation_server_address) as channel:
        stub = AS_pb2_grpc.AttestationServiceStub(channel)
        response = stub.Handshake(
            AS_pb2.AttestationRequest(greeting = "Request to verify VSSH client")
        )

    verify_signature(server_public_key, response.signature, base64.b64decode(response.nonce.encode('utf-8')))

    quote = generate_quote(response.nonce, public_ssh_key)
    
    public_key_pem = load_public_key(public_ssh_key)

    with grpc.insecure_channel(attestation_server_address) as channel:
        stub = AS_pb2_grpc.AttestationServiceStub(channel)
        response = stub.Quoteverification(
            AS_pb2.SendQuote(
                quote = quote,
                publicsshkey = public_key_pem
            )
        )

    

    verify_signature(server_public_key, response.signature, response.result.encode("utf-8"))

    logger.info("quote verification result: " + response.result)

    if response.result == "error":
        logger.error("quote verification failed")
    elif response.result == "success":
        input("please check whether the public key shown in VSSH server is added in VM's authorized keys")
        vssh_main = bash_command(
            port = VSSH_server_port,
            private_key = private_ssh_key,
            known_host = known_hosts,
            host_name = VSSH_server_address
        )
        vssh_main.VSSH_main()


def data_wrangling(text):
    pattern = r"mr_signer:\s*([0-9a-f]+).*?mr_enclave:\s*([0-9a-f]+)"
    compressed_text = ' '.join(text.split())
    match = re.search(pattern, compressed_text)

    mrsigner = match.group(1)
    mrenclave = match.group(2)

    mrsigner_reverse = ""
    for i in range((len(mrsigner)+1)//2):  
        mrsigner_reverse += mrsigner[-2*(i+1):-2*i or None].upper() 

    mrenclave_reverse = ""
    for i in range((len(mrenclave)+1)//2): 
        mrenclave_reverse += mrenclave[-2*(i+1):-2*i or None].upper() 

    logger.info("assert mrenclave and mrsigner as reference in ./Quote/Appraisal")
    logger.info("mrenclave: " + mrenclave_reverse)
    logger.info("mrsigner: " + mrsigner_reverse)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    public_ssh_key = "/root/keys/private_ssh_key.pub"
    private_ssh_key = "/root/keys/private_ssh_key"
    known_hosts = "/root/keys/known_hosts"

    with open('signature_view.txt', 'r') as fd:
        sigstruct = fd.read()
    data_wrangling(sigstruct)

    AS_RUN(public_ssh_key, private_ssh_key, known_hosts)
