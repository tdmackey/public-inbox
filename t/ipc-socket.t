#!perl -w
# Copyright (C) all contributors <meta@public-inbox.org>
# License: AGPL-3.0+ <https://www.gnu.org/licenses/agpl-3.0.txt>
use v5.12;
use PublicInbox::TestCommon;
use Socket qw(SOL_SOCKET SO_TYPE SOCK_STREAM);
use PublicInbox::IPCSocket qw(lei_client_socket lei_sock_path lei_sock_type);

is(lei_sock_path('/run/user/1/lei', 5, 'seq'),
	'/run/user/1/lei/5.seq.sock', 'legacy seqpacket pathname unchanged');
is(lei_sock_path('/run/user/1/lei', 5, 'stream'),
	'/run/user/1/lei/5.stream.sock', 'stream pathname is transport-specific');

{
	local $ENV{PI_TEST_LEI_STREAM} = 1;
	my ($sock, $type) = lei_client_socket();
	is($type, 'stream', 'test knob forces stream transport');
	my $so_type = getsockopt($sock, SOL_SOCKET, SO_TYPE);
	is(unpack('i', $so_type), SOCK_STREAM, 'forced socket is SOCK_STREAM');
}

my ($sock, $type) = lei_client_socket();
ok($type eq 'seq' || $type eq 'stream', 'native transport selected');
is(lei_sock_type($type), unpack('i', getsockopt($sock, SOL_SOCKET, SO_TYPE)),
	'native type agrees with socket SO_TYPE');

done_testing;
