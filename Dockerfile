FROM gramineproject/gramine:latest

# edit your proxy settings
# ENV http_proxy=
# ENV https_proxy=

# edit here if you have local IP addresses that do not need proxy
# ENV no_proxy=

USER root
RUN apt update -y && apt upgrade -y && apt install -y --no-install-recommends build-essential git ssh
WORKDIR /root/

RUN git clone --depth 1  https://github.com/gramineproject/gramine.git
RUN gramine-sgx-gen-private-key
WORKDIR /root/gramine/CI-Examples/bash/

COPY manifest.template .
COPY main.sh .
COPY scripts/* /root/scripts/
RUN mkdir -m 700 /root/enc_keys/
RUN make SGX=1

ENTRYPOINT ["gramine-sgx", "./bash"]
