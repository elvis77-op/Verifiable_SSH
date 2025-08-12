FROM gramineproject/gramine:latest

# edit your proxy settings
# ENV http_proxy=
# ENV https_proxy=
# edit here if you have local IP addresses that do not need proxy
# ENV no_proxy=

RUN apt-get clean && apt-get update \
 && apt-get install -y build-essential curl cmake gcc wget git ssh pkg-config libcurl4-openssl-dev libssl-dev libprotobuf-c-dev protobuf-c-compiler \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN apt update -y && apt upgrade -y && apt install -y --no-install-recommends build-essential libsgx-dcap-ql-dev libsgx-dcap-default-qpl-dev libssl-dev libsgx-dcap-quote-verify-dev
RUN apt-get update && apt-get install -y python3-pip python3-click python3-jinja2 python3-pyelftools python3-pytest python3-pip python3-protobuf python3-venv --no-install-recommends
RUN python3 -m pip install --break-system-packages 'meson>=0.56' 'toml>=0.10' 'tomli>=1.1.0' 'tomli-w>=0.4.0' colorlog ecdsa grpcio grpcio-tools cryptography pycryptodomex toml protobuf 

USER root
WORKDIR /root/

RUN git clone --depth 1  https://github.com/gramineproject/gramine.git
RUN gramine-sgx-gen-private-key

COPY ./ .
COPY scripts/* /root/scripts/

RUN python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. AS.proto

RUN mkdir -m 700 /root/enc_keys/
RUN chmod +x *.py
RUN chmod +x *.sh

RUN make SGX=1
RUN gramine-sgx-sigstruct-view python.sig > signature_view.txt

ENTRYPOINT ["gramine-sgx", "python", "AS_client.py"]
