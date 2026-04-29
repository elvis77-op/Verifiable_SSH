/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <grpcpp/grpcpp.h>

#include <iostream>
#include <memory>
#include <string>

#include "attestation_service.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using attestation::v1::AttestationService;
using attestation::v1::ChallengeReply;
using attestation::v1::ChallengeRequest;
using attestation::v1::QuoteVerificationReply;
using attestation::v1::QuoteVerificationRequest;

// ===== Client =====
class AttestationClient {
 public:
  explicit AttestationClient(std::shared_ptr<Channel> channel)
      : stub_(AttestationService::NewStub(channel)) {}

  std::string RequestChallenge(const std::string& user) {
    ChallengeRequest request;
    request.set_name(user);

    ChallengeReply reply;
    ClientContext context;

    Status status = stub_->Challenge(&context, request, &reply);

    if (status.ok()) {
      return reply.nonce();
    } else {
      std::cout << status.error_code() << ": "
                << status.error_message() << std::endl;
      return "RPC failed";
    }
  }

  std::string SendQuote(const std::string& quote) {
    QuoteVerificationRequest request;
    request.set_quote(quote);

    QuoteVerificationReply reply;
    ClientContext context;

    Status status =
        stub_->QuoteVerification(&context, request, &reply);

    if (status.ok()) {
      return reply.result();
    } else {
      return "Quote verification failed";
    }
  }

 private:
  std::unique_ptr<AttestationService::Stub> stub_;
};

// ===== main =====
int main(int argc, char** argv) {
  std::string target_str = "127.0.0.1:50051";

  AttestationClient client(
      grpc::CreateChannel(target_str,
                          grpc::InsecureChannelCredentials()));

  std::string user = "initrd_01";

  std::string nonce = client.RequestChallenge(user);
  std::cout << "Received nonce: " << nonce << std::endl;

  std::string quote = "fake_quote_with_nonce_" + nonce;

  std::string result = client.SendQuote(quote);
  std::cout << "Verification result: " << result << std::endl;

  return 0;
}
