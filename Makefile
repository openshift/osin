GO_BUILD_PACKAGES := .

include $(addprefix ./vendor/github.com/openshift/build-machinery-go/make/, \
    golang.mk \
    targets/openshift/deps.mk \
)

build-examples: 
	@ for d in `find ./example -maxdepth 1 -mindepth 1 -type d`; do \
		echo "building $$d" ; \
		go build -race "$$d" ; \
	done

clean:
	@ for d in `find ./example -maxdepth 1 -mindepth 1 -type d -exec basename {} \; `; do \
		echo "removing $$d" ; \
		rm -f "$$d" ; \
	done
