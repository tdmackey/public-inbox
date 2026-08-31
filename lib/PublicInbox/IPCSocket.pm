# Copyright (C) all contributors <meta@public-inbox.org>
# License: AGPL-3.0+ <https://www.gnu.org/licenses/agpl-3.0.txt>

# Socket type and pathname selection for lei client/daemon IPC.
package PublicInbox::IPCSocket;
use v5.12;
use parent qw(Exporter);
use Carp qw(croak);
use Socket qw(AF_UNIX SOCK_SEQPACKET SOCK_STREAM);

our @EXPORT_OK = qw(ipc_pair lei_client_socket lei_sock_path lei_sock_type);

sub _seqpacket_unsupported () {
	$!{EPROTONOSUPPORT} || $!{ESOCKTNOSUPPORT} || $!{EPROTOTYPE} ||
		$!{EOPNOTSUPP} || $!{EAFNOSUPPORT} || $!{EINVAL};
}

sub ipc_pair () {
	my ($s1, $s2);
	unless ($ENV{PI_TEST_LEI_STREAM}) {
		return ($s1, $s2, 'seq') if
			socketpair($s1, $s2, AF_UNIX, SOCK_SEQPACKET, 0);
		my $e = $! + 0;
		unless (_seqpacket_unsupported()) {
			$! = $e;
			croak "socketpair(AF_UNIX, SOCK_SEQPACKET): $!";
		}
	}
	socketpair($s1, $s2, AF_UNIX, SOCK_STREAM, 0) or
		croak "socketpair(AF_UNIX, SOCK_STREAM): $!";
	${*$s1}{pi_ipc_stream} = ${*$s2}{pi_ipc_stream} = 1;
	($s1, $s2, 'stream');
}

sub lei_sock_type ($) {
	$_[0] eq 'seq' ? SOCK_SEQPACKET :
		$_[0] eq 'stream' ? SOCK_STREAM : croak "unknown IPC type: $_[0]";
}

sub lei_sock_path ($$$) {
	my ($runtime_dir, $narg, $type) = @_;
	lei_sock_type($type); # validate before using it in a pathname
	"$runtime_dir/$narg.$type.sock";
}

sub lei_client_socket () {
	my $sock;
	unless ($ENV{PI_TEST_LEI_STREAM}) {
		return ($sock, 'seq') if socket($sock, AF_UNIX, SOCK_SEQPACKET, 0);
		my $e = $! + 0;
		unless (_seqpacket_unsupported()) {
			$! = $e;
			croak "socket(AF_UNIX, SOCK_SEQPACKET): $!";
		}
	}
	socket($sock, AF_UNIX, SOCK_STREAM, 0) or
		croak "socket(AF_UNIX, SOCK_STREAM): $!";
	($sock, 'stream');
}

1;
