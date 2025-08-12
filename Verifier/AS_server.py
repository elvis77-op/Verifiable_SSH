import AS_pb2
import AS_pb2_grpc
from config import *
import os
import base64
import logging
logger = logging.getLogger(__name__)
import asyncio
import signal
import secrets
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import grpc
from concurrent import futures 
import binascii
import subprocess

class AttestationService(AS_pb2_grpc.AttestationServiceServicer):
    def __init__(self):
        self._private_key = grpc_server_private_key
        self.nonces = {}
        self.public_ssh_keys = {}

    def generate_nonce(self):
        nonce_bytes = secrets.token_bytes(16)
        return base64.b64encode(nonce_bytes).decode('utf-8')

    def generate_signature(self, private_key_path, data):
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=None)
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def get_report_data(self, quote):
        pos = 0x170
        count = 0x40
        report_data = quote[pos : pos + count]
        return report_data

    def get_nonce(self, report_data):
        stt = 48
        end = 64
        nonce = report_data[stt : end]
        return nonce

    def get_public_key_hash(self, report_data):
        stt = 0
        end = 48
        public_key_hash = report_data[stt : end]
        return public_key_hash

    def verify_quote(self, quote):

        pid = os.getpid()
        quote_id = f"quote_{pid}.dat"
        try:
            with open(quote_id, "wb") as fobj:
                fobj.write(quote)
        except IOError as e:
            logger.error("Failed to write quote file: %s", str(e))
            raise
        result = subprocess.run(
            ["./QuoteAppraisal/QVLAppraisal/app", "-quote", quote_id],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.error(result.stderr)
            raise
        
        
        # finally:
        #     if os.path.exists(quote_id):
        #         os.remove(quote_id)


    def Handshake(self, request, context):
        peer = context.peer().split(':')[1]
        self.nonces[peer] = self.generate_nonce()
        logger.info(peer)
        signature = self.generate_signature(
            private_key_path = self._private_key, 
            data = base64.b64decode(self.nonces.get(peer, "").encode('utf-8'))
        )

        return AS_pb2.AttestationResponse(
            status = 1,
            signature = signature,
            nonce = self.nonces.get(peer, "")
        )

    def Quoteverification(self, request, context):
        peer = context.peer().split(':')[1]
        logger.info(peer)
        public_ssh_key_path = f"public_ssh_key_{peer}.pub"
        public_ssh_key_pkcs1_path = f"public_ssh_key_pkcs1_{peer}.pub"

        self.public_ssh_keys[peer] = request.publicsshkey
        quote_data = base64.b64decode(request.quote.encode('utf-8'))

        report_data = self.get_report_data(quote_data)

        nonce = base64.b64encode(self.get_nonce(report_data)).decode('utf-8')

        public_key_hash = self.get_public_key_hash(report_data)

        hash_reference = hashlib.sha384(base64.b64decode(request.publicsshkey.encode('utf-8'))).digest()

        result = "success"

        logger.info(f"quote from {peer} recieved: \n"+ request.quote)

        try:
            self.verify_quote(quote_data)
        except Exception as e:
            logger.error(f"Quote verification failed: {str(e)}")
            result = "error"
        
        logger.info("nonce_reference: "+ self.nonces.get(peer,""))
        logger.info("nonce_received: "+ nonce)

        if nonce != self.nonces.get(peer,""):

            result = "error"

        if public_key_hash != hash_reference:
            
            result = "error"
        
        if result == "success":
            logger.info("Paste the public key printed below to /root/.ssh/authorized_keys:\n"+ "ssh-rsa "+request.publicsshkey)

        signature = self.generate_signature(
            private_key_path = self._private_key,
            data = result.encode('utf-8')
        )

        return AS_pb2.VerificationResponse(
            status = 0,
            signature = signature,
            result = result
        )


def run_server():
    server = grpc.server(futures.ThreadPoolExecutor())
    AS = AttestationService()
    AS_pb2_grpc.add_AttestationServiceServicer_to_server(AS, server)
    server.add_insecure_port('[::]:' + listening_port)
    logger.info("gRPC server is listening at " + listening_port)
    server.start()

    def shutdown(signum, frame):
        server.stop(2)

    signal.signal(signal.SIGINT, shutdown)

    server.wait_for_termination()




if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_server()
