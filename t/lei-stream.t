#!perl -w
# Copyright (C) all contributors <meta@public-inbox.org>
# License: AGPL-3.0+ <https://www.gnu.org/licenses/agpl-3.0.txt>
use v5.12;
use PublicInbox::TestCommon;

local $ENV{PI_TEST_LEI_STREAM} = 1;
test_lei(sub {
	lei_ok(qw(import -F eml t/data/0001.patch),
		\'import succeeds with descriptor-backed stream IPC');
	lei_ok(qw(q -f mboxrd s:boolean),
		\'query succeeds with descriptor-backed stream IPC');
	like($lei_out, qr/^Subject: .*boolean/im,
		'imported message is readable through stream-backed query');
	ok(-S "$ENV{XDG_RUNTIME_DIR}/lei/5.stream.sock",
		'lei daemon uses transport-specific stream socket');
});

done_testing;
