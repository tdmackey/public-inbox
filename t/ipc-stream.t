#!perl -w
# Copyright (C) all contributors <meta@public-inbox.org>
# License: AGPL-3.0+ <https://www.gnu.org/licenses/agpl-3.0.txt>
use v5.12;
use PublicInbox::TestCommon;
use autodie qw(close fork open pipe seek sysread syswrite);
use Fcntl qw(F_GETFL);
use Socket qw(AF_UNIX SOCK_SEQPACKET SOCK_STREAM SOL_SOCKET SO_SNDBUF);
use POSIX qw(_exit);
use Errno qw(EAGAIN ETOOMANYREFS);
require_mods '+SCM_RIGHTS';
require PublicInbox::IPC;
use PublicInbox::Syscall qw(MY_SEQPACKET_MAX);
no warnings 'once';

sub stream_pair { socketpair($_[0], $_[1], AF_UNIX, SOCK_STREAM, 0) or
	BAIL_OUT "socketpair(SOCK_STREAM): $!" }

my ($s1, $s2);
stream_pair($s1, $s2);
pipe(my $r, my $w);
my $src = 'stream payload' x 100;
is(PublicInbox::IPC::sendcmd($s1, [ $r, $w ], $src), length($src),
	'descriptor-backed stream record sent');
my @io = PublicInbox::IPC::recvcmd($s2, my $buf);
is($buf, $src, 'descriptor-backed stream record received');
is(scalar(@io), 2, 'declared number of FDs received');
ok(fcntl($_, F_GETFL, 0), 'received FD is open') for @io;
my @exp = stat($r);
my @cur = stat($io[0]);
is("$exp[0]\0$exp[1]", "$cur[0]\0$cur[1]", 'first FD matches');
@exp = stat($w);
@cur = stat($io[1]);
is("$exp[0]\0$exp[1]", "$cur[0]\0$cur[1]", 'second FD matches');

PublicInbox::IPC::send_pkt($s1, 'one');
PublicInbox::IPC::send_pkt($s1, 'two');
@io = PublicInbox::IPC::recvcmd($s2, $buf);
is_deeply([ $buf, scalar(@io) ], [ 'one', 0 ], 'first frame isolated');
@io = PublicInbox::IPC::recvcmd($s2, $buf);
is_deeply([ $buf, scalar(@io) ], [ 'two', 0 ], 'second frame isolated');

my $large = 'x' x (MY_SEQPACKET_MAX + 1);
is(PublicInbox::IPC::sendcmd($s1, [], $large), length($large),
	'record larger than the seqpacket limit sent');
@io = PublicInbox::IPC::recvcmd($s2, $buf);
is($buf, $large, 'large stream record restored from its record FD');
is(scalar(@io), 0, 'record FD hidden from command receiver');

stream_pair($s1, $s2);
$s2->blocking(0);
@io = PublicInbox::IPC::recvcmd($s2, $buf);
is_deeply(\@io, [ undef ], 'empty nonblocking stream returns EAGAIN');
is($buf, '', 'buffer cleared on EAGAIN');

sub raw_record {
	my ($s, $record, @io) = @_;
	open my $fh, '+>', undef;
	print $fh $record or BAIL_OUT "write raw record: $!";
	$fh->flush or BAIL_OUT "flush raw record: $!";
	seek($fh, 0, 0);
	my $n = $PublicInbox::IPC::send_cmd->($s, [ $fh, @io ], "\0", 0);
	defined($n) && $n == 1 or BAIL_OUT "send raw record: $!";
}

stream_pair($s1, $s2);
syswrite($s1, "\0");
eval { PublicInbox::IPC::recvcmd($s2, $buf) };
like($@, qr/record FD missing/, 'notification without a record FD rejected');

stream_pair($s1, $s2);
raw_record($s1, pack('a4N', 'BAD!', 0).'bad');
eval { PublicInbox::IPC::recvcmd($s2, $buf) };
like($@, qr/record magic mismatch/, 'bad record magic rejected');

stream_pair($s1, $s2);
raw_record($s1, pack('a4N', PublicInbox::IPC::STREAM_MAGIC(), 1).
	'bad');
eval { PublicInbox::IPC::recvcmd($s2, $buf) };
like($@, qr/FD count mismatch/, 'missing application FD rejected');

stream_pair($s1, $s2);
raw_record($s1, pack('a4N', PublicInbox::IPC::STREAM_MAGIC(), 0).
	('x' x 4097));
eval { PublicInbox::IPC::recvcmd($s2, $buf, 4096) };
like($@, qr/record too large/, 'oversize record rejected before reading');

stream_pair($s1, $s2);
my (@ten_r, @ten_w);
for (1..PublicInbox::IPC::STREAM_MAX_FDS()) {
	pipe(my $fr, my $fw);
	push @ten_r, $fr;
	push @ten_w, $fw;
}
is(PublicInbox::IPC::sendcmd($s1, \@ten_r, 'ten descriptors'), 15,
	'maximum application FD count sent with record FD');
@io = PublicInbox::IPC::recvcmd($s2, $buf);
is(scalar(@io), 10, 'all ten application FDs received');
for my $i (0..$#io) {
	my @want = stat($ten_r[$i]);
	my @have = stat($io[$i]);
	is("$have[0]\0$have[1]", "$want[0]\0$want[1]",
		"application FD $i retained its identity");
}
eval {
	PublicInbox::IPC::sendcmd($s1, [ @ten_r, $ten_w[0] ], 'too many')
};
like($@, qr/too many FDs/, 'eleven application FDs rejected');
$s2->blocking(0);
@io = PublicInbox::IPC::recvcmd($s2, $buf);
is_deeply(\@io, [ undef ], 'rejected FD set emitted no notification');

stream_pair($s1, $s2);
setsockopt($s1, SOL_SOCKET, SO_SNDBUF, pack('i', 1024)) or
	BAIL_OUT "setsockopt(SO_SNDBUF): $!";
$s1->blocking(0);
my $queued = 0;
while ($queued < 10000) {
	defined(PublicInbox::IPC::sendcmd($s1, [], "queued $queued", 0)) or
		last;
	++$queued;
}
my $fill_errno = 0 + $!;
ok($queued > 0 && $queued < 10000, 'nonblocking notification queue filled');
is($fill_errno, EAGAIN, 'queue saturation reports EAGAIN');
my ($default_ret, $default_err, $default_errno);
{
	local $SIG{ALRM} = sub { die "default send blocked on EAGAIN\n" };
	alarm 3;
	eval { $default_ret = PublicInbox::IPC::sendcmd($s1, [], 'default') };
	$default_err = $@;
	$default_errno = 0 + $!;
	alarm 0;
}
is($default_err, '', 'default send returns promptly on EAGAIN');
ok(!defined($default_ret) && $default_errno == EAGAIN,
	'default send preserves undef/EAGAIN');
$s2->blocking(1);
for my $i (0..$queued - 1) {
	PublicInbox::IPC::recvcmd($s2, $buf);
	is($buf, "queued $i", "queued record $i retained");
}
$s2->blocking(0);
@io = PublicInbox::IPC::recvcmd($s2, $buf);
is_deeply(\@io, [ undef ], 'failed sends left no receive-side record');

stream_pair($s1, $s2);
{
	local $PublicInbox::IPC::send_cmd = sub {
		$! = ETOOMANYREFS;
		undef;
	};
	my $ret = PublicInbox::IPC::sendcmd_nonblock($s1, [], 'fd pressure');
	ok(!defined($ret) && $! == ETOOMANYREFS,
		'nonblocking FD pressure is returned for timer retry');
}
$s2->blocking(0);
@io = PublicInbox::IPC::recvcmd($s2, $buf);
is_deeply(\@io, [ undef ], 'FD-pressure failure emitted no notification');

# Pass one stream socket to concurrent producers.  Each one-byte notification
# and SCM_RIGHTS record must remain associated under backpressure.
stream_pair($s1, $s2);
setsockopt($s1, SOL_SOCKET, SO_SNDBUF, pack('i', 1024)) or
	BAIL_OUT "setsockopt(SO_SNDBUF): $!";
$s1->blocking(0);
pipe(my $start_r, my $start_w);
my (@ctl, @pid, @payload);
for my $mark ('A', 'B') {
	stream_pair(my $parent, my $child);
	my @child_payload = map { "$mark:$_:".($mark x 10000) } 1..32;
	push @payload, @child_payload;
	my $pid = fork;
	if ($pid == 0) {
		close $parent;
		close $start_w;
		close $s1;
		close $s2;
		my @passed = eval {
			PublicInbox::IPC::recvcmd($child, my $tag)
		};
		_exit(2) if $@ || @passed != 1;
		sysread($start_r, my $go, 1) == 1 or _exit(3);
		$passed[0]->blocking(1);
		eval {
			PublicInbox::IPC::sendcmd($passed[0], [], $_)
				for @child_payload;
		};
		_exit($@ ? 4 : 0);
	}
	close $child;
	push @ctl, $parent;
	push @pid, $pid;
}
PublicInbox::IPC::sendcmd($ctl[$_], [ $s1 ], "writer $_") for 0..$#ctl;
close $s1;
close $start_r;
syswrite($start_w, 'go') == 2 or BAIL_OUT "start writers: $!";
close $start_w;
select(undef, undef, undef, 0.05); # let both writers hit backpressure
my (@got, $recv_err);
{
	local $SIG{ALRM} = sub { die "timed out receiving writer frames\n" };
	alarm 10;
	eval {
		for (1..scalar(@payload)) {
			PublicInbox::IPC::recvcmd($s2, my $msg);
			push @got, $msg;
		}
	};
	$recv_err = $@;
	alarm 0;
}
kill 'TERM', @pid if $recv_err;
is($recv_err, '', 'concurrent passed-FD writers keep valid records');
is_deeply([ sort @got ], [ sort @payload ],
	'concurrent passed-FD writer payloads stay intact');
for my $pid (@pid) {
	is(waitpid($pid, 0), $pid, 'passed-FD writer reaped');
	is($?, 0, 'passed-FD writer exited successfully');
}

# Multiple workers may block in recvmsg(1) on the same stream.  Verify each
# notification and its descriptor-backed record is delivered exactly once.
stream_pair(my $producer, my $consumer);
pipe(my $result_r, my $result_w);
my @reader_pid;
for (1..2) {
	my $pid = fork;
	if ($pid == 0) {
		close $producer;
		close $result_r;
		for (1..32) {
			my (@fd, $msg);
			@fd = eval { PublicInbox::IPC::recvcmd($consumer, $msg) };
			_exit(5) if $@;
			_exit(6) if @fd != 1;
			sysread($fd[0], my $fd_data, 64) or _exit(7);
			my $line = "$msg=$fd_data\n";
			syswrite($result_w, $line) == length($line) or _exit(8);
		}
		close $result_w;
		_exit(0);
	}
	push @reader_pid, $pid;
}
close $consumer;
close $result_w;
my @expected;
for my $i (1..64) {
	open my $data, '+>', undef;
	print $data "fd-$i" or BAIL_OUT "write reader FD: $!";
	$data->flush or BAIL_OUT "flush reader FD: $!";
	seek($data, 0, 0);
	PublicInbox::IPC::sendcmd($producer, [ $data ], "msg-$i");
	push @expected, "msg-$i=fd-$i";
}
close $producer;
my (@result, $reader_err);
{
	local $SIG{ALRM} = sub { die "timed out receiving reader results\n" };
	alarm 10;
	eval { @result = <$result_r> };
	$reader_err = $@;
	alarm 0;
}
kill 'TERM', @reader_pid if $reader_err;
chomp @result;
is($reader_err, '', 'shared-stream readers finish before timeout');
is_deeply([ sort @result ], [ sort @expected ],
	'multiple readers receive every record and associated FD exactly once');
for my $pid (@reader_pid) {
	is(waitpid($pid, 0), $pid, 'shared-stream reader reaped');
	is($?, 0, 'shared-stream reader exited successfully');
}

SKIP: {
	my ($q1, $q2);
	socketpair($q1, $q2, AF_UNIX, SOCK_SEQPACKET, 0) or
		skip "SOCK_SEQPACKET unsupported: $!", 2;
	PublicInbox::IPC::sendcmd($q1, [], 'raw seqpacket');
	@io = PublicInbox::IPC::recvcmd_eor($q2, $buf);
	is($buf, 'raw seqpacket', 'seqpacket wire format remains unframed');
	is(scalar(@io), 0, 'seqpacket frame has no unexpected FDs');
}

done_testing;
