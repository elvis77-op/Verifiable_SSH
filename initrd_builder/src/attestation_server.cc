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
#include <grpcpp/health_check_service_interface.h>

#include <iostream>
#include <memory>
#include <string>

#include "attestation_service.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using attestation::v1::AttestationService;
using attestation::v1::ChallengeReply;
using attestation::v1::ChallengeRequest;
using attestation::v1::QuoteVerificationReply;
using attestation::v1::QuoteVerificationRequest;

// ===== Service Implementation =====
class AttestationServiceImpl final : public AttestationService::Service {
 public:
  Status Challenge(ServerContext* context,
                   const ChallengeRequest* request,
                   ChallengeReply* reply) override {
    reply->set_nonce("hi " + request->name());
    return Status::OK;
  }

  Status QuoteVerification(ServerContext* context,
                           const QuoteVerificationRequest* request,
                           QuoteVerificationReply* reply) override {
    reply->set_result("verified");
    return Status::OK;
  }
};

// ===== Run Server =====
void RunServer(uint16_t port) {
  std::string server_address = "0.0.0.0:" + std::to_string(port);

  AttestationServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);

  ServerBuilder builder;
  builder.AddListeningPort(server_address,
                           grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::unique_ptr<Server> server(builder.BuildAndStart());

  std::cout << "Server listening on " << server_address << std::endl;

  server->Wait();
}

int main(int argc, char** argv) {
  uint16_t port = 50052;

  std::string server_address = "0.0.0.0:" + std::to_string(port);

  AttestationServiceImpl service;

  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address,
                           grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

  std::cout << "Server listening on " << server_address << std::endl;

  server->Wait();
}