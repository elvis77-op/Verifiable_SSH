FROM ubuntu:24.04

ENV http_proxy=http://child-prc.intel.com:913
ENV https_proxy=http://child-prc.intel.com:913
ENV no_proxy=10.0.2.15,127.0.0.1,localhost,10.244.0.0/16,10.0.2.2,10.239.45.1,10.239.82.94

RUN apt update && apt install -y wget curl ssh libssl-dev python3 python3-pip && python3 -m pip install grpcio grpcio-tools cryptography --break-system-packages
RUN echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && cat intel-sgx-deb.key | tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
RUN apt update && apt install -y libtdx-attest-dev libsgx-dcap-quote-verify-dev libsgx-dcap-default-qpl-dev tee-appraisal-tool

WORKDIR /root/
COPY . ./
RUN python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. AS.proto
RUN make

CMD ["python3", "AS_server.py"]