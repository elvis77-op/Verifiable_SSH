FROM ubuntu:24.04

# edit your proxy settings
# ENV http_proxy=
# ENV https_proxy=
# edit here if you have local IP addresses that do not need proxy
# ENV no_proxy=

RUN apt update && apt install -y wget curl ssh libssl-dev python3 python3-pip && python3 -m pip install grpcio grpcio-tools cryptography --break-system-packages
RUN echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && cat intel-sgx-deb.key | tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
RUN apt update && apt install -y libtdx-attest-dev libsgx-dcap-quote-verify-dev libsgx-dcap-default-qpl-dev tee-appraisal-tool

WORKDIR /root/
COPY . ./
RUN python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. AS.proto
RUN make

CMD ["python3", "AS_server.py"]