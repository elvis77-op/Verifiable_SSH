SESSION_KEY = session_key.pem

.PHONY: all proto generation appraisal
all: $(SESSION_KEY) proto generation appraisal

$(SESSION_KEY):
	openssl genrsa -out $(SESSION_KEY) 3072

proto: AS.proto
	python3 -m grpc_tools.protoc -I. --python_out=. --pyi_out=. --grpc_python_out=. AS.proto

# generation:
# 	$(MAKE) -C QuoteGeneration

appraisal:
	$(MAKE) -C QuoteAppraisal/QVLAppraisal


.PHONY: clean
clean:
	$(MAKE) -C QuoteGeneration clean
	$(MAKE) -C QuoteAppraisal/QVLAppraisal clean
	$(RM) *.dat $(SESSION_KEY)
