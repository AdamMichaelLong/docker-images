include ../Makefile.conf

VERSION=7.0.12-0

all: build tag

build: clean
	$(DOCKER) build \
	--build-arg VCS_REF=`git rev-parse --short HEAD` \
	--build-arg VCS_URL=`git config --get remote.origin.url` \
	--build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` \
	--build-arg VERSION=$(VERSION) \
		. | tee buildlog.txt

tag:
	$(eval IMAGE_HASH=$(shell tail -n 1 buildlog.txt | $(AWK) '{print $$NF}'))
	$(DOCKER) tag $(IMAGE_HASH) $(ORGANISATION)/$(IMAGE):$(VERSION)

push:
	$(DOCKER) push $(ORGANISATION)/$(IMAGE):$(VERSION)

clean:
	$(RM) -f buildlog.txt

clean_images:
	@echo Clean up intemediate images.
	for i in `$(GREP) '^ ---> ([a-z0-9]){12}$$' buildlog.txt | $(AWK) '{print $$2}'`; do \
		$(DOCKER) rmi -f $$i; \
	done

mrproper: clean_images clean
