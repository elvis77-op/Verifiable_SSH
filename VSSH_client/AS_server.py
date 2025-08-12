import AS_pb2
import AS_pb2_grpc
from verifier_config import *
import os
import base64
import logging
logger = logging.getLogger(__name__)
import asyncio
import secrets
from Cryptodome.Hash import SHA384
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import grpc
from concurrent import futures 

class AttestationService(AS_pb2_grpc.AttestationServiceServicer):
    def __init__(self):
        self._private_key = grpc_server_private_key
        self.nonces = {}

    def generate_nonce(self):
        nonce_bytes = secrets.token_bytes(16)
        return base64.b64encode(nonce_bytes).decode('utf-8')

    def generate_signature(self, private_key, data):
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature


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
        try:
            result = subprocess.run(
                ["./QuoteAppraisal/QVLAppraisal/app", "-quote", quote_id],
                capture_output=True,
                text=True,
                check=True 
            )
            logger.debug(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error("%s failed, returncode: %d", e.cmd[0], e.returncode)
            logger.error(e.stderr)
            raise
        except Exception as e:
            logger.error("Unexpected error: %s", str(e))
            raise
        finally:
            if os.path.exists(quote_id):
                os.remove(quote_id)


    def Handshake(self, request, context):
        peer = context.peer()
        self.nonces.get(peer, "") = self.generate_nonce()
        signature = self.generate_signature(
            private_key = self._private_key, 
            data = base64.b64decode(self.nonces.get(peer, "").encode('utf-8'))
        )

        return AS_pb2.AttestationResponse(
            signature = signature,
            nonce = self.nonces.get(peer, "")
        )

    def Quoteverification(self, request, context):
        peer = context.peer()
        quote_data = base64.b64decode(request.quote.encode('utf-8'))
        report_data = self.get_report_data(quote_data)

        nonce = base64.b64encode(self.get_nonce(report_data)).decode('utf-8')

        public_key_hash = self.get_public_key_hash(report_data)
        hashed = SHA384.new()
        hashed.update(request.publicsshkey.encode('utf-8'))
        hash_reference = hashed.digest()

        status = True
        signature = self.generate_signature(
            private_key = self._private_key,
            data = bytes([int(True)])
        )

        try:
            self.verify_quote(quote_data)
        except Exception as e:
            logger.error(f"Quote verification failed: {str(e)}")
            status = False
            signature = self.generate_signature(
                private_key = self._private_key,
                data = bytes([int(False)])
            )
        
        if nonce != self.nonces.get(peer,""):

            status = False
            signature = self.generate_signature(
                private_key = self._private_key,
                data = bytes([int(False)])
            )

        if public_key_hash != hash_reference:
            
            status = False
            signature = self.generate_signature(
                private_key = self._private_key,
                data = bytes([int(False)])
            )
        
        if status == True:
            logger.info("Paste the public key printed below to /root/.ssh/authorized_keys: \n" + request.publicsshkey)

        

        return AS_pb2.AttestationResponse(
            signature = signature,
            status = status
        )


def run_server():
    server = grpc.server(futures.ThreadPoolExecutor())
    AS = AttestationService()
    AS_pb2_grpc.add_AttestationServiceServicer_to_server(AS, server)
    server.add_insecure_port('[::]:' + listening_port)
    logger.info("gRPC server is listening at " + listening_port)
    server.start()

    signal.signal(signal.SIGINT, shutdown)

    def shutdown(signum, frame):
        server.stop()

    server.wait_for_termination()




if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_server()