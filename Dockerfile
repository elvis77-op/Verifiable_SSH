FROM gramineproject/gramine:latest

#edit your proxy settings
ENV http_proxy=http://child-prc.intel.com:913
ENV https_proxy=http://child-prc.intel.com:913
#edit here if you have local IP addresses that do not need proxy
ENV no_proxy=localhost,172.18.0.1,10.239.82.88,10.239.53.33,127.0.0.1,10.239.45.1,.example.com
USER root
RUN apt update -y && apt upgrade -y && apt install -y --no-install-recommends build-essential git ssh
RUN apt install openssh-client
WORKDIR /root/

RUN git clone --depth 1  https://github.com/gramineproject/gramine.git
RUN gramine-sgx-gen-private-key
WORKDIR /root/gramine/CI-Examples/bash/


COPY manifest.template .
COPY script.sh .
COPY scripts/* /root/scripts/
#RUN mkdir /root/.ssh/
#RUN chmod 700 /root/.ssh
RUN mkdir -m 700 /root/enc_keys/
#RUN mkdir -m 700 /root/known_hosts/

# run directly
# RUN make clean; make
# run with sgx
RUN make SGX=1
# run directly
# ENTRYPOINT ["gramine-direct", "./bash"]
# run with sgx
ENTRYPOINT ["gramine-sgx", "./bash"]

CMD ["-c", "bash script.sh"]
