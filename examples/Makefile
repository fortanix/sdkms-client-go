
EXAMPLES = approval_request \
	   encrypt_decrypt \
	   invoke_plugin \
	   plugin_approval_request \
	   session \
	   sign_verify

BINS = $(patsubst %,bin/%,$(EXAMPLES))

all: bin $(BINS)

bin:
	mkdir -p bin

bin/%: %/main.go
	cd $* && go build && mv $* ../bin/$*

clean:
	rm -rf bin
