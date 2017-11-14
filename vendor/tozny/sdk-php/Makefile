
VERSION_MAJOR := 1
VERSION_MINOR := 4

ifdef BUILD_NUMBER
VERSION := $(VERSION_MAJOR).$(VERSION_MINOR).$(BUILD_NUMBER)
else
VERSION := $(VERSION_MAJOR).$(VERSION_MINOR)-SNAPSHOT
endif

$(info VERSION = $(VERSION))

package: docker_build 
	docker run --rm -v $(PWD):/tozny-sdk-php/target tozny/sdk-php "$(VERSION)"

docker_build: 
	docker build -t tozny/sdk-php .

clean:
	rm -f *.deb

