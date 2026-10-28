# Copr SCM method "make srpm".
# make -f <repo>/.copr/Makefile srpm outdir="<outdir>" spec="<spec>"
#
# make_srpm has no chroot package list, so this target installs cargo,
# rust, rpm-build, tar, xz, and gzip with dnf. Override DNF (e.g.
# DNF=true) when the host already has those tools, such as GitHub
# Actions.
#
# Network is allowed in this step only. It vendors Cargo.lock and packs
# that tree as Source1. The RPM build does not fetch crates. vendor/ is
# not committed. The tree root is this Makefile's parent; git is not
# required.

DNF ?= dnf

root := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
outdir ?= $(root)

ifeq ($(strip $(spec)),)
spec_path := $(root)/packaging/dillo.spec
else ifneq ($(filter /%,$(spec)),)
spec_path := $(spec)
else
spec_path := $(root)/$(spec)
endif

# RPM package name. Matches Name: in the spec. Not the cargo crate
# (that stays dillo) and not the installed binary (/usr/bin/dillo).
name := dillo-vm
version := $(shell awk '/^Version:/{print $$2; exit}' $(spec_path))
tarball := $(outdir)/$(name)-$(version).tar.gz
vendor_tarball := $(outdir)/$(name)-$(version)-vendor.tar.xz

.PHONY: srpm
srpm:
	$(DNF) -y install cargo rust rpm-build tar xz gzip
	mkdir -p "$(outdir)"
	cd "$(root)" && RUSTC_BOOTSTRAP=1 cargo -Z bindeps vendor --locked --versioned-dirs vendor > "$(outdir)/cargo-vendor-config.toml"
	grep -E '^\[source\."git\+' "$(outdir)/cargo-vendor-config.toml" > "$(outdir)/git-sources.txt"
	grep -F -f "$(outdir)/git-sources.txt" "$(root)/packaging/cargo-vendor-git.toml" >/dev/null
	test "$$(grep -c . '$(outdir)/git-sources.txt')" -eq "$$(grep -c '^\[source\."git+' '$(root)/packaging/cargo-vendor-git.toml')"
	tar -C "$(root)" -cJf "$(vendor_tarball)" vendor
	rm -rf "$(root)/vendor" "$(outdir)/cargo-vendor-config.toml" "$(outdir)/git-sources.txt"
	tar -C "$(root)" -czf "$(tarball)" \
		--exclude-vcs \
		--exclude=target \
		--exclude=vendor \
		--exclude=$(name)-$(version).tar.gz \
		--exclude=$(name)-$(version)-vendor.tar.xz \
		--warning=no-file-changed \
		--transform 's,^\./,$(name)-$(version)/,' \
		.
	rpmbuild -bs "$(spec_path)" \
		--define "_sourcedir $(outdir)" \
		--define "_srcrpmdir $(outdir)" \
		--define "_disable_source_fetch 1"
