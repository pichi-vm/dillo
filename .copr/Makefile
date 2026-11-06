# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

.ONESHELL:
.SHELLFLAGS := -eu -c

.PHONY: srpm
srpm:
	dnf -y install rpm-build tar gzip
	name=$$(rpmspec -q --srpm --qf '%{name}-%{version}' "$(spec)")
	mkdir -p "$(outdir)"
	tar --exclude-vcs --exclude=target --exclude=vendor \
		--transform "s,^\./,$$name/," -czf "$(outdir)/$$name.tar.gz" .
	rpmbuild -bs "$(spec)" --define "_sourcedir $(outdir)" \
		--define "_srcrpmdir $(outdir)"
