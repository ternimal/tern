VERSION ?= dev
# -buildid= keeps the build ID independent of where the toolchain (and, for
# android/amd64, the NDK) is installed, so a rebuild elsewhere has the same bytes.
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)
GOFLAGS := -trimpath
CMDS    := tern ternd ternr rtern

# Every file in a release zip is dated at this time, in seconds since 1970: the
# commit time of HEAD, or SOURCE_DATE_EPOCH when set (1980-01-01 outside a git
# checkout), so a rebuild of the same commit packs the same bytes.
ifeq ($(origin SOURCE_DATE_EPOCH),undefined)
SOURCE_DATE_EPOCH := $(shell git log -1 --format=%ct 2>/dev/null)
endif

# OS/ARCH targets. All build as pure Go (CGO_ENABLED=0) EXCEPT android/amd64:
# Go links android binaries internally only on arm64, so android/amd64 must be
# linked externally, which needs cgo + the Android NDK clang.
PLATFORMS := \
	linux/amd64 linux/arm64 \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/arm64 \
	android/arm64 android/amd64

# C compiler for the one cgo target, android/amd64 (x86_64 emulators / Android-x86).
# The release workflow points this at the NDK's clang; override locally with the full path to
# .../toolchains/llvm/prebuilt/<host>/bin/x86_64-linux-android<API>-clang
NDK_CC_AMD64 ?= x86_64-linux-android21-clang

.PHONY: all build test vet lint tidy clean release $(PLATFORMS)

# Pinned (bump together with go-version in .github/workflows: an old pin fails to compile on a newer Go).
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2

all: build

# gofmt check + go vet + staticcheck (the project's code-standard gate)
lint:
	@unformatted="$$(gofmt -l ./cmd ./internal ./test)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed on:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	go run $(STATICCHECK) ./...

tidy:
	go mod tidy

vet:
	go vet ./...

test:
	go test -count=1 ./...

# native pure-Go (CGO_ENABLED=0) build of all four binaries into bin/
build:
	@mkdir -p bin
	@for c in $(CMDS); do \
		CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o bin/$$c ./cmd/$$c || exit 1; \
		echo "built bin/$$c"; \
	done

# cross-build every binary for every platform and pack dist/ternimal-<os>-<arch>.zip:
# the four binaries, LICENSE, NOTICE and THIRD_PARTY_NOTICES.txt, which
# internal/release writes from the binaries' build information with the license
# files of the Go standard library and of every module linked in, read from
# GOROOT and the module cache (offline). The android/amd64 notices also carry the
# NDK sysroot's NOTICE, for the C start files its linker adds. With a VERSION
# other than dev, each zip is also copied to dist/ternimal-<VERSION>-<os>-<arch>.zip:
# the same bytes under a name that says the version, while the name without it
# keeps the releases/latest/download links stable.
# (any failed build or zip fails the target, so a release never ships a partial set)
release: $(PLATFORMS)

$(PLATFORMS):
	@os=$(word 1,$(subst /, ,$@)); arch=$(word 2,$(subst /, ,$@)); \
	mkdir -p dist; \
	staging=$$(mktemp -d); \
	cgo=0; cc=; \
	if [ "$$os/$$arch" = android/amd64 ]; then cgo=1; cc="$(NDK_CC_AMD64)"; fi; \
	bins=; \
	for c in $(CMDS); do \
		out=$$staging/$$c; [ "$$os" = windows ] && out=$$out.exe; \
		env CGO_ENABLED=$$cgo $${cc:+CC=$$cc} GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $$out ./cmd/$$c \
			|| { rm -rf $$staging; exit 1; }; \
		echo "built $$c ($$os/$$arch)"; \
		bins="$$bins $$out"; \
	done; \
	zipname=dist/ternimal-$$os-$$arch.zip; \
	set -- -o $$zipname -mtime "$(or $(SOURCE_DATE_EPOCH),0)" -text LICENSE,NOTICE \
		-goroot "$$(go env GOROOT)" -modcache "$$(go env GOMODCACHE)"; \
	if [ "$$cgo" = 1 ]; then \
		crt=$$($$cc -print-file-name=crtbegin_dynamic.o) || { rm -rf $$staging; exit 1; }; \
		set -- "$$@" -notice "Android NDK C start files (crtbegin_dynamic.o, crtend_android.o)=$${crt%/usr/lib/*}/NOTICE"; \
	fi; \
	GOPROXY=off go run ./internal/release "$$@" $$bins || { rm -rf $$staging; exit 1; }; \
	echo "packed $$zipname"; \
	if [ "$(VERSION)" != dev ]; then \
		cp "$$zipname" "dist/ternimal-$(VERSION)-$$os-$$arch.zip" || { rm -rf $$staging; exit 1; }; \
		echo "copied it to dist/ternimal-$(VERSION)-$$os-$$arch.zip"; \
	fi; \
	rm -rf $$staging

clean:
	rm -rf bin dist

# --- notes ---
# android/arm64: pure Go, no cgo, no NDK (real devices are arm64); runs under
#   Termux or `adb shell`. android/amd64 (emulators / Android-x86): Go forces
#   external linking on every android arch except arm64, so it needs cgo + the
#   NDK clang (NDK_CC_AMD64).
# ios: no runnable CLI exists on iOS (the sandbox forbids fork/exec, which the
#   agent needs). internal/tern compiles for GOOS=ios, but embedding it in an
#   app would need a public wrapper package (gomobile cannot bind an internal
#   package); none ships. The same applies to an Android app library.
