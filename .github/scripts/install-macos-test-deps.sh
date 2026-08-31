#!/usr/bin/env bash
# Copyright (C) all contributors <meta@public-inbox.org>
# License: AGPL-3.0+ <https://www.gnu.org/licenses/agpl-3.0.txt>

set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP must be set by GitHub Actions}"
: "${GITHUB_ENV:?GITHUB_ENV must be set by GitHub Actions}"
: "${GITHUB_PATH:?GITHUB_PATH must be set by GitHub Actions}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE must be set by GitHub Actions}"
: "${XAPIAN_BINDINGS_VERSION:?XAPIAN_BINDINGS_VERSION must be set}"
: "${XAPIAN_BINDINGS_SHA256:?XAPIAN_BINDINGS_SHA256 must be set}"

brew update
brew install cpanminus perl sqlite xapian

perl_prefix="$(brew --prefix perl)"
xapian_prefix="$(brew --prefix xapian)"
perl_root="$RUNNER_TEMP/perl5"
xapian_root="$RUNNER_TEMP/xapian-perl"

export PATH="$perl_prefix/bin:$PATH"
export PERL5LIB="$perl_root/lib/perl5"

mkdir -p "$perl_root" "$xapian_root"
cpanm --notest --local-lib-contained "$perl_root" \
	DBI \
	DBD::SQLite \
	File::FcntlLock \
	IO::Compress \
	Inline::C \
	Mail::IMAPClient \
	Parse::RecDescent \
	URI

xapian_version="$($xapian_prefix/bin/xapian-config --version)"
xapian_version="${xapian_version##* }"
if [[ "$xapian_version" != "$XAPIAN_BINDINGS_VERSION" ]]; then
	printf 'xapian core is %s; update the pinned %s bindings resource\n' \
		"$xapian_version" "$XAPIAN_BINDINGS_VERSION" >&2
	exit 1
fi

archive="$RUNNER_TEMP/xapian-bindings-$XAPIAN_BINDINGS_VERSION.tar.xz"
source_dir="$RUNNER_TEMP/xapian-bindings-$XAPIAN_BINDINGS_VERSION"
curl --fail --location --retry 3 --output "$archive" \
	"https://oligarchy.co.uk/xapian/$XAPIAN_BINDINGS_VERSION/xapian-bindings-$XAPIAN_BINDINGS_VERSION.tar.xz"
printf '%s  %s\n' "$XAPIAN_BINDINGS_SHA256" "$archive" | shasum -a 256 --check
tar -C "$RUNNER_TEMP" -xf "$archive"

export PERL="$perl_prefix/bin/perl"
export PERL_ARCH="$perl_root/lib/perl5"
export PERL_LIB="$perl_root/lib/perl5"
export XAPIAN_CONFIG="$xapian_prefix/bin/xapian-config"

cd "$source_dir"
./configure \
	--prefix="$xapian_root" \
	--disable-dependency-tracking \
	--disable-silent-rules \
	--with-perl
make -j2
make install

xapian_pm="$(find "$perl_root" "$xapian_root" -type f -name Xapian.pm -print -quit)"
if [[ -z "$xapian_pm" ]]; then
	echo 'Xapian.pm was not installed by xapian-bindings' >&2
	exit 1
fi
xapian_perl_dir="$(dirname "$xapian_pm")"

{
	printf '%s\n' "$perl_prefix/bin"
	printf '%s\n' "$perl_root/bin"
} >>"$GITHUB_PATH"

printf 'PERL5LIB=%s:%s:%s/lib\n' \
	"$perl_root/lib/perl5" "$xapian_perl_dir" "$GITHUB_WORKSPACE" >>"$GITHUB_ENV"
