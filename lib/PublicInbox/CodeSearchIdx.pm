# Copyright (C) all contributors <meta@public-inbox.org>
# License: AGPL-3.0+ <https://www.gnu.org/licenses/agpl-3.0.txt>
#
# indexer for git coderepos, just commits and repo paths for now
# this stores normalized absolute paths of indexed GIT_DIR inside
# the DB itself and is designed to handle forks by designating roots
# At minimum, it needs to have the pathnames of all git repos in
# memory at runtime.  --join also requires all inbox pathnames to
# be in memory (as it happens when loaded from ~/.public-inbox/config).
#
# Unlike mail search, docid isn't tied to NNTP artnum or IMAP UID,
# there's no serial number dependency at all.  The first 32-bits of
# the commit SHA-(1|256) is used to select a shard.
#
# We shard repos using the first 32-bits of sha256($ABS_GIT_DIR)
#
# --join associates root commits of coderepos to inboxes based on prefixes.
#
# Internally, each inbox is assigned a non-negative integer index ($IBX_OFF),
# and each root commit object ID (SHA-1/SHA-256 hex) is also assigned
# a non-negative integer index ($ROOT_COMMIT_OID_ID).
#
# join dumps to 2 intermediate files in $TMPDIR:
#
# * to_root_off - each line is of the format:
#
#	$PFX @ROOT_COMMIT_OID_OFFS
#
# * to_ibx_off - each line is of the format:
#
#	$PFX @IBX_OFFS
#
# $IBX_OFFS is a comma-delimited list of integers ($IBX_ID)
# The $IBX_OFF here is ephemeral (per-join_data) and NOT related to
# the `ibx_off' column of `over.sqlite3' for extindex.
# @ROOT_COMMIT_OID_OFFS is space-delimited
# In both cases, $PFX is typically the value of the 7-(hex)char dfpost
# XDFPOST but it can be configured to use any combination of patchid,
# dfpre, dfpost or dfblob.
#
# WARNING: this is vulnerable to arbitrary memory usage attacks if we
# attempt to index or join against malicious coderepos with
# thousands/millions of root commits.  Most coderepos have only one
# root commit, some have several: git.git currently has 7,
# torvalds/linux.git has 4.
# --max-size= is required to keep memory usage reasonable for gigantic
# commits.
#
# See PublicInbox::CodeSearch (read-only API) for more
package PublicInbox::CodeSearchIdx;
use v5.12;
# parent order matters, we want ->DESTROY from IPC, not SearchIdx
use parent qw(PublicInbox::CodeSearch PublicInbox::IPC PublicInbox::SearchIdx);
use PublicInbox::Admin;
use PublicInbox::DS qw(awaitpid);
use PublicInbox::PktOp;
use PublicInbox::IPC qw(nproc_shards send_pkt);
use POSIX qw(WNOHANG SEEK_SET strftime);
use File::Path ();
use File::Spec::Functions qw(canonpath);
use List::Util qw(max);
use PublicInbox::SHA qw(sha256_hex sha_all);
use PublicInbox::Search qw(xap_terms);
use PublicInbox::SearchIdx qw(add_val add_bool_term);
use PublicInbox::Config qw(glob2re rel2abs_collapsed);
use PublicInbox::Spawn qw(which spawn popen_rd);
use PublicInbox::OnDestroy;
use PublicInbox::CidxLogP;
use PublicInbox::CidxComm;
use PublicInbox::Git qw(%OFMT2HEXLEN);
use PublicInbox::Compat qw(uniqstr);
use PublicInbox::Aspawn qw(run_await);
use Compress::Zlib qw(compress);
use Carp qw(croak);
use Time::Local qw(timegm);
use Errno qw(EINTR);
use autodie qw(close pipe open seek sysseek);
our $DO_QUIT = 15; # signal number
our (
	$LIVE_JOBS, # integer
	$GITS_NR, # number of coderepos
	$MY_SIG, # like %SIG
	$SIGSET,
	$TXN_BYTES, # number of bytes in current shard transaction
	$BATCH_BYTES,
	@RDONLY_XDB, # Xapian::Database
	@IDX_SHARDS, # clones of self
	$MAX_SIZE,
	$REINDEX, # PublicInbox::SharedKV
	@GIT_DIR_GONE, # [ git_dir1, git_dir2 ]
	$PRUNE_DONE, # marks off prune completions
	$NCHANGE, # current number of changes
	$NPROC,
	$XHC, # XapClient
	$REPO_CTX, # current repo being indexed in shards
	$IDXQ, # PublicInbox::Git object arrayref
	$SCANQ, # PublicInbox::Git object arrayref
	%ALT_FH, # hexlen => tmp IO for TMPDIR git alternates
	$TMPDIR, # File::Temp->newdir object for prune
	@PRUNEQ, # GIT_DIRs to prepare for pruning
	%TODO, @IBXQ, @IBX,
	@JOIN, # join(1) command for --join
	$CMD_ENV, # env for awk(1), comm(1), sort(1) commands during prune
	@AWK, @COMM, @SORT, # awk(1), comm(1), sort(1) commands
	%JOIN, # CLI --join= suboptions
	@JOIN_PFX, # any combination of XDFID, XDFPRE, XDFPOST
	@JOIN_DT, # YYYYmmddHHMMSS for dt:
	$QRY_STR, # common query string for both code and inbox associations
	$DUMP_IBX_WPIPE, # goes to sort(1)
	$ANY_SHARD, # shard round-robin for scan fingerprinting
	@OFF2ROOT,
	$GIT_VER,
	@NO_ABBREV,
);

# stop walking history if we see >$SEEN_MAX existing commits, this assumes
# branches don't diverge by more than this number of commits...
# git walks commits quickly if it doesn't have to read trees
our $SEEN_MAX = 100000;

# window for commits/emails to determine a inbox <-> coderepo association
my $JOIN_WINDOW = 50000;

our @PRUNE_BATCH = qw(cat-file --batch-all-objects --batch-check);

# TODO: do we care about committer name + email? or tree OID?
my @FMT = qw(H P ct an ae at s b); # (b)ody must be last

# git log --stdin buffers all commits before emitting, thus --reverse
# doesn't incur extra overhead.  We use --reverse to keep Xapian docids
# increasing so we may be able to avoid sorting results in some cases
my @LOG_STDIN = (qw(log --no-decorate --no-color --no-notes -p --stat -M
	--reverse --stdin --no-walk=unsorted), '--pretty=format:%n%x00'.
	join('%n', map { "%$_" } @FMT));

sub new {
	my (undef, $dir, $opt) = @_;
	my $l = $opt->{indexlevel} // 'full';
	$l !~ $PublicInbox::SearchIdx::INDEXLEVELS and
		die "invalid indexlevel=$l\n";
	$l eq 'basic' and die "E: indexlevel=basic not supported\n";
	my $self = bless {
		xpfx => "$dir/cidx".  PublicInbox::CodeSearch::CIDX_SCHEMA_VER,
		topdir => $dir,
		creat => 1, # TODO: get rid of this, should be implicit
		transact_bytes => 0, # for checkpoint
		total_bytes => 0, # for lock_release
		current_info => '',
		parallel => 1,
		-opt => $opt,
		lock_path => "$dir/cidx.lock",
	}, __PACKAGE__;
	$self->{nshard} = count_shards($self) ||
		nproc_shards({nproc => $opt->{jobs}});
	$self;
}

# This is similar to uniq(1) on the first column, but combines the
# contents of subsequent columns using $OFS.
our @UNIQ_FOLD = ($^X, $^W ? ('-w') : (), qw(-MList::Util=uniq -ane), <<'EOM');
BEGIN { $ofs = $ENV{OFS} // ','; $apfx = '' }
if ($F[0] eq $apfx) {
	shift @F;
	push @ids, @F;
} else {
	print $apfx.' '.join($ofs, uniq(@ids))."\n" if @ids;
	($apfx, @ids) = @F;
}
END { print $apfx.' '.join($ofs, uniq(@ids))."\n" if @ids }
EOM

# TODO: may be used for reshard/compact
sub count_shards { scalar($_[0]->xdb_shards_flat) }

sub update_commit ($$$) {
	my ($self, $cmt, $roots) = @_; # fields from @FMT
	my $x = 'Q'.$cmt->{H};
	my ($docid, @extra) = sort { $a <=> $b } $self->docids_by_postlist($x);
	@extra and warn "W: $cmt->{H} indexed multiple times, pruning ",
			join(', ', map { "#$_" } @extra), "\n";
	$self->{xdb}->delete_document($_) for @extra;
	my $doc = $PublicInbox::Search::X{Document}->new;
	$doc->add_boolean_term($x); # "Q$COMMIT_OIDHEX"
	$doc->add_boolean_term('G'.$_) for @$roots;
	$doc->add_boolean_term('XP'.$_) for split(/ /, $cmt->{P});
	$doc->add_boolean_term('T'.'c');

	# Author-Time is compatible with dt: for mail search schema_version=15
	add_val($doc, PublicInbox::CodeSearch::AT,
		POSIX::strftime('%Y%m%d%H%M%S', gmtime($cmt->{at})));

	# Commit-Time is the fallback used by rt: (TS) for mail search:
	add_val($doc, PublicInbox::CodeSearch::CT, $cmt->{ct});

	$self->term_generator->set_document($doc);

	# email address is always indexed with positional data for usability
	$self->index_phrase("$cmt->{an} <$cmt->{ae}>", 1, 'A');

	$x = $cmt->{'s'};
	$self->index_text($x, 1, 'S') if $x =~ /\S/s;
	$doc->set_data($x); # subject is the first (and currently only) line

	$x = delete $cmt->{b};
	$self->index_body_text($doc, \$x) if $x =~ /\S/s;
	defined($docid) ? $self->{xdb}->replace_document($docid, $doc) :
			$self->{xdb}->add_document($doc);
}

sub progress {
	my ($self, @msg) = @_;
	my $pr = $self->{-opt}->{-progress} or return;
	$pr->($self->{git} ? ("$self->{git}->{git_dir}: ") : (), @msg, "\n");
}

sub check_objfmt_status ($$$) {
	my ($git, $chld_err, $fmt) = @_;
	my ($status, $sig) = ($chld_err >> 8, $chld_err & 127);
	if (!$sig && $status == 1) { # unset, default is '' (SHA-1)
		$fmt = 'sha1';
	} elsif (!$sig && $status == 0) {
		chomp($fmt ||= 'sha1');
	}
	$fmt // warn("git --git-dir=$git->{git_dir} config \$?=$chld_err");
	$fmt;
}

sub store_repo { # wq_io_do, sends docid back
	my ($self, $repo) = @_;
	my $op_p = delete($self->{0}) // die 'BUG: no {0} op_p';
	my $git = bless $repo, 'PublicInbox::Git';
	my $rd = $git->popen(qw(config extensions.objectFormat));
	$self->begin_txn_lazy;
	$self->{xdb}->delete_document($_) for @{$repo->{to_delete}};
	my $doc = $PublicInbox::Search::X{Document}->new;
	add_val($doc, PublicInbox::CodeSearch::CT, $repo->{ct});
	add_bool_term($doc, "P$repo->{git_dir}");
	$doc->add_boolean_term('T'.'r');
	$doc->add_boolean_term('G'.$_) for @{$repo->{roots}};
	$doc->set_data($repo->{fp}); # \n delimited
	my $fmt = readline($rd);
	$rd->close;
	$fmt = check_objfmt_status $git, $?, $fmt;
	$OFMT2HEXLEN{$fmt} // warn <<EOM; # store unknown formats anyways
E: unknown extensions.objectFormat=$fmt in $repo->{git_dir}
EOM
	add_bool_term($doc, 'H'.$fmt);
	my $did = $repo->{docid};
	$did ? $self->{xdb}->replace_document($did, $doc)
		: ($did = $self->{xdb}->add_document($doc));
	send_pkt $op_p, "repo_stored $did";
}

sub cidx_ckpoint ($;$) {
	my ($self, $msg) = @_;
	progress($self, $msg) if defined($msg);
	$TXN_BYTES = $BATCH_BYTES; # reset
	return if $PublicInbox::Search::X{CLOEXEC_UNSET};
	$self->commit_txn_lazy;
	$self->begin_txn_lazy;
}

sub truncate_cmt ($$) {
	my ($cmt) = @_; # _[1] is $buf (giant)
	my ($orig_len, $len);
	$len = $orig_len = length($_[1]);
	@$cmt{@FMT} = split(/\n/, $_[1], scalar(@FMT));
	undef $_[1];
	$len -= length($cmt->{b});

	# try to keep the commit message body.
	# n.b. this diffstat split may be unreliable but it's not worth
	# perfection for giant commits:
	my ($bdy) = split(/^---\n/sm, delete($cmt->{b}), 2);
	if (($len + length($bdy)) <= $MAX_SIZE) {
		$len += length($bdy);
		$cmt->{b} = $bdy;
		warn <<EOM;
W: $cmt->{H}: truncated body ($orig_len => $len bytes)
W: to be under --max-size=$MAX_SIZE
EOM
	} else {
		$cmt->{b} = '';
		warn <<EOM;
W: $cmt->{H}: deleted body ($orig_len => $len bytes)
W: to be under --max-size=$MAX_SIZE
EOM
	}
	$len;
}

sub cidx_reap_log { # awaitpid cb
	my ($pid, $cmd, $self, $op_p) = @_;
	if (!$? || ($DO_QUIT && (($? & 127) == $DO_QUIT ||
				($? & 127) == POSIX::SIGPIPE))) {
		send_pkt $op_p, "shard_done $self->{shard}";
	} else {
		warn "W: @$cmd (\$?=$?)\n";
		$self->{xdb}->cancel_transaction;
	}
}

sub shard_index { # via wq_io_do in IDX_SHARDS
	my ($self, $git, $roots) = @_;

	my $in = delete($self->{0}) // die 'BUG: no {0} input';
	my $op_p = delete($self->{1}) // die 'BUG: no {1} op_p';
	sysseek($in, 0, SEEK_SET);
	my $cmd = $git->cmd(@NO_ABBREV, @LOG_STDIN);
	my $rd = popen_rd($cmd, undef, { 0 => $in },
				\&cidx_reap_log, $cmd, $self, $op_p);
	PublicInbox::CidxLogP->new($rd, $self, $git, $roots);
	# CidxLogP->event_step will call cidx_read_log_p once there's input
}

# sharded reader for `git log --pretty=format: --stdin'
sub cidx_read_log_p {
	my ($self, $log_p, $rd) = @_;
	my $git = delete $log_p->{git} // die 'BUG: no {git}';
	local $self->{current_info} = "$git->{git_dir} [$self->{shard}]";
	my $roots = delete $log_p->{roots} // die 'BUG: no {roots}';
	# local-ized in parent before fork
	$TXN_BYTES = $BATCH_BYTES;
	local $self->{git} = $git; # for patchid
	return if $DO_QUIT;
	my $nr = 0;

	# a patch may have \0, see c4201214cbf10636e2c1ab9131573f735b42c8d4
	# in linux.git, so we use $/ = "\n\0" to check end-of-patch
	my $FS = "\n\0";
	my $len;
	my $cmt = {};
	local $/ = $FS;
	my $buf = <$rd> // return; # leading $FS
	$buf eq $FS or die "BUG: not LF-NUL: $buf\n";
	$self->begin_txn_lazy;
	while (!$DO_QUIT && defined($buf = <$rd>)) {
		chomp($buf);
		$/ = "\n";
		$len = length($buf);
		if (defined($MAX_SIZE) && $len > $MAX_SIZE) {
			$len = truncate_cmt($cmt, $buf);
		} else {
			@$cmt{@FMT} = split(/\n/, $buf, scalar(@FMT));
		}
		if (($TXN_BYTES -= $len) <= 0) {
			cidx_ckpoint($self, "[$self->{shard}] $nr");
			$TXN_BYTES -= $len; # len may be huge, >TXN_BYTES;
		}
		update_commit($self, $cmt, $roots);
		++$nr;
		cidx_ckpoint($self, "[$self->{shard}] $nr") if $TXN_BYTES <= 0;
		$/ = $FS;
	}
	# return and wait for cidx_reap_log
}

sub shard_done { # called via PktOp on shard_index completion
	my ($self, $repo_ctx, $on_destroy, $n) = @_;
	$repo_ctx->{shard_ok}->{$n} = 1;
}

sub repo_stored {
	my ($self, $repo_ctx, $drs, $did) = @_;
	# check @IDX_SHARDS instead of DO_QUIT to avoid wasting prior work
	# because shard_commit is fast
	return unless @IDX_SHARDS;
	$did > 0 or die "BUG: $repo_ctx->{repo}->{git_dir}: docid=$did";
	my ($c, $p) = PublicInbox::PktOp->pair;
	$c->{ops}->{shard_done} = [ $self, $repo_ctx,
				on_destroy(\&next_repos, $repo_ctx, $drs)];
	# shard_done fires when all shards are committed
	my @active = keys %{$repo_ctx->{active}};
	$IDX_SHARDS[$_]->wq_io_do('shard_commit', [ $p->{op_p} ]) for @active;
}

sub prune_done { # called via prune_do completion
	my ($self, $drs, $n) = @_;
	return if $DO_QUIT || !$PRUNE_DONE;
	die "BUG: \$PRUNE_DONE->[$n] already defined" if $PRUNE_DONE->[$n];
	$PRUNE_DONE->[$n] = 1;
	if (grep(defined, @$PRUNE_DONE) == @IDX_SHARDS) {
		progress($self, 'prune done');
		index_next($self); # may kick dump_roots_start
	}
}

sub seen ($$) {
	my ($xdb, $q) = @_; # $q = "Q$COMMIT_HASH"
	for (1..100) {
		my $ret = eval {
			$xdb->postlist_begin($q) != $xdb->postlist_end($q);
		};
		return $ret unless $@;
		if (ref($@) =~ /\bDatabaseModifiedError\b/) {
			$xdb->reopen;
		} else {
			Carp::croak($@);
		}
	}
	Carp::croak('too many Xapian DB modifications in progress');
}

# used to select the shard for a GIT_DIR
sub git_dir_hash ($) { hex(substr(sha256_hex($_[0]), 0, 8)) }

sub _cb { # run_await cb
	my ($pid, $cmd, undef, $opt, $cb, $self, $git, @arg) = @_;
	return if $DO_QUIT;
	return $cb->($opt, $self, $git, @arg) if $opt->{quiet};
	$? ? ($git->{-cidx_err} = warn("W: @$cmd (\$?=$?)\n")) :
			$cb->($opt, $self, $git, @arg);
}

sub run_git {
	my ($cmd, $opt, $cb, $self, $git, @arg) = @_;
	run_await($git->cmd(@$cmd), undef, $opt, \&_cb, $cb, $self, $git, @arg)
}

# this is different from the grokmirror-compatible fingerprint since we
# only care about --heads (branches) and --tags, and not even their names
sub fp_start ($$) {
	my ($self, $git) = @_;
	return if $DO_QUIT;
	open my $refs, '+>', undef;
	$git->{-repo}->{refs} = $refs;
	my ($c, $p) = PublicInbox::PktOp->pair;
	my $next_on_err = on_destroy \&index_next, $self;
	$c->{ops}->{fp_done} = [ $self, $git, $next_on_err ];
	$IDX_SHARDS[++$ANY_SHARD % scalar(@IDX_SHARDS)]->wq_io_do('fp_async',
					[ $p->{op_p}, $refs ], $git->{git_dir})
}

sub fp_async { # via wq_io_do in worker
	my ($self, $git_dir) = @_;
	my $op_p = delete $self->{0} // die 'BUG: no {0} op_p';
	my $refs = delete $self->{1} // die 'BUG: no {1} refs';
	my $git = PublicInbox::Git->new($git_dir);
	run_git([qw(show-ref --heads --tags --hash)], { 1 => $refs },
		\&fp_async_done, $self, $git, $op_p);
}

sub fp_async_done { # run_git cb from worker
	my ($opt, $self, $git, $op_p) = @_;
	my $refs = delete $opt->{1} // 'BUG: no {-repo}->{refs}';
	sysseek($refs, 0, SEEK_SET);
	send_pkt $op_p, 'fp_done '.sha_all(256, $refs)->hexdigest;
}

sub fp_done { # called parent via PktOp by fp_async_done
	my ($self, $git, $next_on_err, $hex) = @_;
	$next_on_err->cancel;
	return if $DO_QUIT;
	$git->{-repo}->{fp} = $hex;
	my $n = git_dir_hash($git->{git_dir}) % scalar(@RDONLY_XDB);
	my $shard = bless { %$self, shard => $n }, ref($self);
	$git->{-repo}->{shard_n} = $n;
	delete @$shard{qw(lockfh lock_path)};
	local $shard->{xdb} = $RDONLY_XDB[$n] // die "BUG: shard[$n] undef";
	$shard->retry_reopen(\&check_existing, $self, $git);
}

sub check_existing { # retry_reopen callback
	my ($shard, $self, $git) = @_;
	my @docids = $shard->docids_of_git_dir($git->{git_dir});
	my $docid = shift(@docids) // return prep_repo($self, $git); # new repo
	my $doc = $shard->get_doc($docid) //
			die "BUG: no #$docid ($git->{git_dir})";
	my $old_fp = $REINDEX ? "\0invalid" : $doc->get_data;
	if ($old_fp eq $git->{-repo}->{fp}) { # no change
		delete $git->{-repo};
		return index_next($self);
	}
	$git->{-repo}->{docid} = $docid;
	if (@docids) {
		warn "BUG: $git->{git_dir} indexed multiple times, culling\n";
		$git->{-repo}->{to_delete} = \@docids; # XXX needed?
	}
	prep_repo($self, $git);
}

sub partition_refs ($$$) {
	my ($self, $git, $refs) = @_; # show-ref --heads --tags --hash output
	sysseek($refs, 0, SEEK_SET);
	my $rfh = $git->popen(qw(rev-list --stdin), undef, { 0 => $refs });
	my $seen = 0;
	my @shard_in = map {
		$_->reopen;
		open my $fh, '+>', undef;
		$fh;
	} @RDONLY_XDB;

	my $n0 = $NCHANGE;
	while (defined(my $cmt = <$rfh>)) {
		chomp $cmt;
		my $n = hex(substr($cmt, 0, 8)) % scalar(@RDONLY_XDB);
		if ($REINDEX && $REINDEX->set_maybe(pack('H*', $cmt), '')) {
			say { $shard_in[$n] } $cmt;
			++$NCHANGE;
		} elsif (seen($RDONLY_XDB[$n], 'Q'.$cmt)) {
			last if ++$seen > $SEEN_MAX;
		} else {
			say { $shard_in[$n] } $cmt;
			++$NCHANGE;
			$seen = 0;
		}
		if ($DO_QUIT) {
			$rfh->close;
			return ();
		}
	}
	$rfh->close;
	return () if $DO_QUIT;
	if (!$? || (($? & 127) == POSIX::SIGPIPE && $seen > $SEEN_MAX)) {
		my $n = $NCHANGE - $n0;
		progress($self, "$git->{git_dir}: $n commits") if $n;
		return @shard_in;
	}
	die "git --git-dir=$git->{git_dir} rev-list: \$?=$?\n";
}

sub shard_commit { # via wq_io_do
	my ($self) = @_;
	my $op_p = delete($self->{0}) // die 'BUG: no {0} op_p';
	$self->commit_txn_lazy;
	send_pkt $op_p, "shard_done $self->{shard}";
}

sub dump_roots_start {
	my ($self, $do_join) = @_;
	return if $DO_QUIT;
	$XHC //= PublicInbox::XapClient::start_helper("-j$NPROC");
	$do_join // die 'BUG: no $do_join';
	progress($self, 'dumping IDs from coderepos');
	local $self->{xdb};
	@OFF2ROOT = $self->all_terms('G');
	my $root2id = "$TMPDIR/root2id";
	open my $fh, '>', $root2id;
	my $nr = -1;
	for (@OFF2ROOT) { print $fh $_, "\0", ++$nr, "\0" } # mmap-friendly
	close $fh;
	# dump_roots | sort -k1,1 | OFS=' ' uniq_fold >to_root_off
	my ($sort_opt, $fold_opt);
	pipe(local $sort_opt->{0}, my $sort_w);
	pipe(local $fold_opt->{0}, local $sort_opt->{1});
	my @sort = (@SORT, '-k1,1');
	my $dst = "$TMPDIR/to_root_off";
	open $fold_opt->{1}, '>', $dst;
	my $fold_env = { %$CMD_ENV, OFS => ' ' };
	run_await(\@sort, $CMD_ENV, $sort_opt, \&cmd_done, $do_join);
	run_await(\@UNIQ_FOLD, $fold_env, $fold_opt, \&cmd_done, $do_join);
	my $window = $JOIN{window} // $JOIN_WINDOW;
	my @m = $window <= 0 ? () : ('-m', $window);
	my @arg = ((map { ('-A', $_) } @JOIN_PFX), '-c',
		@m, $root2id, $QRY_STR);
	for my $d ($self->shard_dirs) {
		pipe(my $err_r, my $err_w);
		$XHC->mkreq([$sort_w, $err_w], qw(dump_roots -d), $d, @arg);
		my $desc = "dump_roots $d";
		$self->{PENDING}->{$desc} = $do_join;
		PublicInbox::CidxXapHelperAux->new($err_r, $self, $desc);
	}
	progress($self, 'waiting on dump_roots sort');
}

sub dump_ibx { # sends to xap_helper.h
	my ($self, $ibx_off) = @_;
	my $ibx = $IBX[$ibx_off] // die "BUG: no IBX[$ibx_off]";
	my $ekey = $ibx->eidx_key;
	my $srch = $ibx->isrch or return warn <<EOM;
W: $ekey not indexed for search
EOM
	# note: we don't send `-m MAX' to dump_ibx since we have to
	# post-filter non-patch messages for now...
	my @cmd = ('dump_ibx', $srch->xh_args,
			(map { ('-A', $_) } @JOIN_PFX), $ibx_off, $QRY_STR);
	pipe(my $r, my $w);
	$XHC->mkreq([$DUMP_IBX_WPIPE, $w], @cmd);
	$self->{PENDING}->{$ekey} = $TODO{do_join};
	PublicInbox::CidxXapHelperAux->new($r, $self, $ekey);
}

sub dump_ibx_start {
	my ($self, $do_join) = @_;
	return if $DO_QUIT;
	$XHC //= PublicInbox::XapClient::start_helper("-j$NPROC");
	my ($sort_opt, $fold_opt);
	pipe(local $sort_opt->{0}, $DUMP_IBX_WPIPE);
	pipe(local $fold_opt->{0}, local $sort_opt->{1});
	my @sort = (@SORT, '-k1,1'); # sort only on JOIN_PFX
	# pipeline: dump_ibx | sort -k1,1 | uniq_fold >to_ibx_off
	open $fold_opt->{1}, '>', "$TMPDIR/to_ibx_off";
	run_await(\@sort, $CMD_ENV, $sort_opt, \&cmd_done, $do_join);
	run_await(\@UNIQ_FOLD, $CMD_ENV, $fold_opt, \&cmd_done, $do_join);
}

sub index_next ($) {
	my ($self) = @_;
	return if $DO_QUIT;
	if ($IDXQ && @$IDXQ) {
		index_repo($self, shift @$IDXQ);
	} elsif ($SCANQ && @$SCANQ) {
		fp_start $self, shift @$SCANQ;
	} elsif ($TMPDIR) {
		delete $TODO{dump_roots_start};
		delete $TODO{dump_ibx_start}; # runs OnDestroy once
		return dump_ibx($self, shift @IBXQ) if @IBXQ;
		undef $DUMP_IBX_WPIPE; # done dumping inboxes
		delete $TODO{do_join};
	}
	# else: wait for shards_active (post_loop_do) callback
}

sub next_repos { # OnDestroy cb
	my ($repo_ctx, $drs) = @_;
	my ($self, $repo, $active) = @$repo_ctx{qw(self repo active)};
	progress($self, "$repo->{git_dir}: done");
	return if $DO_QUIT || !$REPO_CTX;
	my $n = grep { ! $repo_ctx->{shard_ok}->{$_} } keys %$active;
	die "E: $repo->{git_dir} $n shards failed" if $n;
	$REPO_CTX == $repo_ctx or die "BUG: $REPO_CTX != $repo_ctx";
	$REPO_CTX = undef;
	index_next($self);
}

sub index_done { # OnDestroy cb called when done indexing each code repo
	my ($repo_ctx, $drs) = @_;
	return if $DO_QUIT;
	my ($self, $repo, $active) = @$repo_ctx{qw(self repo active)};
	# $active may be undef here, but it's fine to vivify
	my $n = grep { ! $repo_ctx->{shard_ok}->{$_} } keys %$active;
	die "E: $repo->{git_dir} $n shards failed" if $n;
	$repo_ctx->{shard_ok} = {}; # reset for future shard_done
	$n = $repo->{shard_n};
	$repo_ctx->{active}->{$n} = undef; # may vivify $repo_ctx->{active}
	my ($c, $p) = PublicInbox::PktOp->pair;
	$c->{ops}->{repo_stored} = [ $self, $repo_ctx, $drs ];
	$IDX_SHARDS[$n]->wq_io_do('store_repo', [ $p->{op_p} ], $repo);
	# repo_stored will fire once store_repo is done
}

sub index_repo {
	my ($self, $git) = @_;
	return if $DO_QUIT;
	my $repo = $git->{-repo} // die 'BUG: no {-repo}';
	return index_next($self) if $git->{-cidx_err};
	if (!defined($repo->{ct})) {
		warn "W: $git->{git_dir} has no commits, skipping\n";
		return index_next($self);
	}
	return push(@$IDXQ, $git) if $REPO_CTX; # busy
	delete $git->{-repo};
	my $roots_fh = delete $repo->{roots_fh} // die 'BUG: no {roots_fh}';
	seek($roots_fh, 0, SEEK_SET);
	chomp(my @roots = PublicInbox::IO::read_all $roots_fh);
	if (!@roots) {
		warn("E: $git->{git_dir} has no root commits\n");
		return index_next($self);
	}
	$repo->{roots} = \@roots;
	local $self->{current_info} = $git->{git_dir};
	my @shard_in = partition_refs($self, $git, delete($repo->{refs}));
	$repo->{git_dir} = $git->{git_dir};
	my $repo_ctx = $REPO_CTX = { self => $self, repo => $repo };
	delete $git->{-cidx_gits_fini}; # may fire gits_fini
	my $drs = delete $git->{-cidx_dump_roots_start};
	my $index_done = on_destroy \&index_done, $repo_ctx, $drs;
	my ($c, $p) = PublicInbox::PktOp->pair;
	$c->{ops}->{shard_done} = [ $self, $repo_ctx, $index_done ];
	for my $n (0..$#shard_in) {
		$shard_in[$n]->flush or die "flush shard[$n]: $!";
		-s $shard_in[$n] or next;
		last if $DO_QUIT;
		$IDX_SHARDS[$n]->wq_io_do('shard_index',
					[ $shard_in[$n], $p->{op_p} ],
					$git, \@roots);
		$repo_ctx->{active}->{$n} = undef;
	}
	# shard_done fires when shard_index is done
}

sub ct_fini { # run_git cb
	my ($opt, $self, $git, $index_repo) = @_;
	my ($ct) = split(/\s+/, ${$opt->{1}}); # drop TZ + LF
	$git->{-repo}->{ct} = $ct + 0;
}

# TODO: also index gitweb.owner and the full fingerprint for grokmirror?
sub prep_repo ($$) {
	my ($self, $git) = @_;
	return if $DO_QUIT;
	my $index_repo = on_destroy \&index_repo, $self, $git;
	my $refs = $git->{-repo}->{refs} // die 'BUG: no {-repo}->{refs}';
	sysseek($refs, 0, SEEK_SET);
	open my $roots_fh, '+>', undef;
	$git->{-repo}->{roots_fh} = $roots_fh;
	run_git([ qw(rev-list --stdin --max-parents=0) ],
		{ 0 => $refs, 1 => $roots_fh }, \&PublicInbox::Config::noop,
		$self, $git, $index_repo);
	run_git([ qw[for-each-ref --sort=-committerdate
		--format=%(committerdate:raw) --count=1
		refs/heads/ refs/tags/] ], undef, # capture like qx
		\&ct_fini, $self, $git, $index_repo);
}

# for PublicInbox::SearchIdx `git patch-id' call and with_umask
sub git { $_[0]->{git} }

sub load_existing ($) { # for -u/--update
	my ($self) = @_;
	my $dirs = $self->{git_dirs} //= [];
	if ($self->{-opt}->{update} || $self->{-opt}->{prune}) {
		local $self->{xdb};
		$self->xdb or
			die "E: $self->{topdir} non-existent for --update\n";
		my @cur = grep {
			if (-e $_) {
				1;
			} else {
				push @GIT_DIR_GONE, $_;
				undef;
			}
		} $self->all_terms('P');
		if (@GIT_DIR_GONE && !$self->{-opt}->{prune}) {
			warn "W: the following repos no longer exist:\n",
				(map { "W:\t$_\n" } @GIT_DIR_GONE),
				"W: use --prune to remove them from ",
				$self->{topdir}, "\n";
		}
		push @$dirs, @cur;
	}
	@$dirs = uniqstr @$dirs;
}

# SIG handlers:
sub shard_quit { $DO_QUIT = POSIX->can("SIG$_[0]")->() }
sub shard_usr1 { $TXN_BYTES = -1 }

sub cidx_init ($) {
	my ($self) = @_;
	my $dir = $self->{topdir};
	unless (-d $dir) {
		warn "# creating $dir\n" if !$self->{-opt}->{quiet};
		File::Path::mkpath($dir);
	}
	$self->lock_acquire;
	my @shards;
	my $l = $self->{indexlevel} //= $self->{-opt}->{indexlevel};

	for my $n (0..($self->{nshard} - 1)) {
		my $shard = bless { %$self, shard => $n }, ref($self);
		delete @$shard{qw(lockfh lock_path)};
		my $xdb = $shard->idx_acquire;
		if (!$n) {
			if (($l // '') eq 'medium') {
				$xdb->set_metadata('indexlevel', $l);
			} elsif (($l // '') eq 'full') {
				$xdb->set_metadata('indexlevel', ''); # unset
			}
			$l ||= $xdb->get_metadata('indexlevel') || 'full';
		}
		$shard->{indexlevel} = $l;
		$shard->idx_release;
		$shard->wq_workers_start("cidx shard[$n]", 1, $SIGSET, {
			siblings => \@shards, # for ipc_atfork_child
		}, \&shard_done_wait, $self);
		push @shards, $shard;
	}
	$self->{indexlevel} //= $l;
	# this warning needs to happen after idx_acquire
	state $once;
	warn <<EOM if $PublicInbox::Search::X{CLOEXEC_UNSET} && !$once++;
W: Xapian v1.2.21..v1.2.24 were missing close-on-exec on OFD locks,
W: memory usage may be high for large indexing runs
EOM
	@shards;
}

# called when all git coderepos are done
sub gits_fini {
	undef $GITS_NR;
	PublicInbox::DS::enqueue_reap(); # kick @post_loop_do
}

sub scan_git_dirs ($) {
	my ($self) = @_;
	@$SCANQ = () unless $self->{-opt}->{scan};
	$GITS_NR = @$SCANQ or return;
	my $gits_fini = on_destroy \&gits_fini;
	$_->{-cidx_gits_fini} = $gits_fini for @$SCANQ;
	if (my $drs = $TODO{dump_roots_start}) {
		$_->{-cidx_dump_roots_start} = $drs for @$SCANQ;
	}
	progress($self, "scanning $GITS_NR code repositories...");
}

sub prune_init { # via wq_io_do in IDX_SHARDS
	my ($self) = @_;
	$self->{nr_prune} = 0;
	$TXN_BYTES = $BATCH_BYTES;
	$self->begin_txn_lazy;
}

# <20230504084559.M203335@dcvr> thread on xapian-discuss@lists.xapian.org
# discusses getting an estimate term length to multiply the get_doclength()
# result to estimate memory use of uncommitted deletes.  We need to estimate
# length here since the data may no longer be available at all if we get to
# prune_one().
our $EST_LEN = 6;

sub prune_one { # via wq_io_do in IDX_SHARDS
	my ($self, $term) = @_;
	my @docids = $self->docids_by_postlist($term);
	for (@docids) {
		$TXN_BYTES -= $self->{xdb}->get_doclength($_) * $EST_LEN;
		$self->{xdb}->delete_document($_);
	}
	++$self->{nr_prune};
	$TXN_BYTES < 0 and
		cidx_ckpoint($self, "prune [$self->{shard}] $self->{nr_prune}");
}

sub prune_commit { # via wq_io_do in IDX_SHARDS
	my ($self) = @_;
	my $prune_op_p = delete $self->{0} // die 'BUG: no {0} op_p';
	my $nr = delete $self->{nr_prune} // die 'BUG: nr_prune undef';
	cidx_ckpoint($self, "prune [$self->{shard}] $nr done") if $nr;
	send_pkt $prune_op_p, "prune_done $self->{shard}";
}

sub shards_active { # post_loop_do
	return if $DO_QUIT;
	return if grep(defined, $PRUNE_DONE, $SCANQ, $IDXQ) != 3;
	return 1 if grep(defined, @$PRUNE_DONE) != @IDX_SHARDS;
	return 1 if $GITS_NR || scalar(@$IDXQ) || $REPO_CTX;
	return 1 if @IBXQ || keys(%TODO);
	for my $s (grep { $_->{-wq_s1} } @IDX_SHARDS) {
		$s->{-cidx_quit} = 1 if defined($s->{-wq_s1});
		$s->wq_close; # may recurse via awaitpid outside of event_loop
	}
	scalar(grep { $_->{-cidx_quit} } @IDX_SHARDS);
}

# signal handlers
sub kill_shards { $_->wq_kill(@_) for (@IDX_SHARDS) }

sub parent_quit {
	$DO_QUIT = POSIX->can("SIG$_[0]")->();
	$XHC = 0; # stops the process
	kill_shards(@_);
	warn "# SIG$_[0] received, quitting...\n";
}

sub prep_umask ($) {
	my ($self) = @_;
	if ($self->{-cidx_internal}) { # respect core.sharedRepository
		@{$self->{git_dirs}} == 1 or die 'BUG: only for GIT_DIR';
		local $self->{git} =
			PublicInbox::Git->new($self->{git_dirs}->[0]);
		$self->with_umask;
	} elsif (-d $self->{topdir}) { # respect existing perms
		my @st = stat(_);
		my $um = (~$st[2] & 0777);
		$self->{umask} = $um; # for SearchIdx->with_umask
		umask == $um or progress($self, 'using umask from ',
						$self->{topdir}, ': ',
						sprintf('0%03o', $um));
		on_destroy \&CORE::umask, umask($um);
	} else {
		$self->{umask} = umask; # for SearchIdx->with_umask
		undef;
	}
}

sub prep_alternate_end ($$) {
	my ($objdir, $fmt) = @_;
	my $hexlen = $OFMT2HEXLEN{$fmt} // return warn <<EOM;
E: ignoring objdir=$objdir, unknown extensions.objectFormat=$fmt
EOM
	unless ($ALT_FH{$hexlen}) {
		require PublicInbox::Import;
		my $git_dir = "$TMPDIR/hexlen$hexlen.git";
		PublicInbox::Import::init_bare($git_dir, 'cidx-all', $fmt);
		open $ALT_FH{$hexlen}, '>', "$git_dir/objects/info/alternates";
	}
	say { $ALT_FH{$hexlen} } $objdir;
}

sub store_objfmt { # via wq_do - make early cidx users happy
	my ($self, $docid, $git_dir, $fmt) = @_;
	$self->begin_txn_lazy;
	my $doc = $self->get_doc($docid) // return
		warn "BUG? #$docid for $git_dir missing";
	my @p = xap_terms('P', $doc) or return
		warn "BUG? #$docid for $git_dir has no P(ath)";
	@p == 1 or return warn "BUG? #$docid $git_dir multi: @p";
	$p[0] eq $git_dir or return warn "BUG? #$docid $git_dir != @p";
	add_bool_term($doc, 'H'.$fmt);
	$self->{xdb}->replace_document($docid, $doc);
	# wait for prune_commit to commit...
}

# TODO: remove prep_alternate_read and store_objfmt 1-2 years after 2.0 is out
# they are for compatibility with pre-release indices
sub prep_alternate_read { # run_git cb for config extensions.objectFormat
	my ($opt, $self, $git, $objdir, $docid, $shard_n, $run_prune) = @_;
	return if $DO_QUIT;
	my $chld_err = $?;
	prep_alternate_start($self, shift(@PRUNEQ), $run_prune) if @PRUNEQ;
	my $fmt = check_objfmt_status $git, $chld_err, ${$opt->{1}};
	$IDX_SHARDS[$shard_n]->wq_do('store_objfmt', # async
					$docid, $git->{git_dir}, $fmt);
	prep_alternate_end $objdir, $fmt;
}

sub prep_alternate_start {
	my ($self, $git, $run_prune) = @_;
	local $self->{xdb};
	my ($o, $n, @ids, @fmt);
start:
	$o = $git->git_path('objects');
	while (!-d $o) {
		$git = shift(@PRUNEQ) // return;
		$o = $git->git_path('objects');
	}
	$n = git_dir_hash($git->{git_dir}) % scalar(@RDONLY_XDB);
	$self->{xdb} = $RDONLY_XDB[$n] // croak("BUG: no shard[$n]");
	@ids = $self->docids_by_postlist('P'.$git->{git_dir});
	@fmt = @ids ? xap_terms('H', $self->{xdb}, $ids[0]) : ();
	@fmt > 1 and warn "BUG? multi `H' for shard[$n] #$ids[0]: @fmt";

	if (@fmt) { # cache hit
		prep_alternate_end $o, $fmt[0];
		$git = shift(@PRUNEQ) and goto start;
	} else { # compatibility w/ early cidx format
		run_git([qw(config extensions.objectFormat)], { quiet => 1 },
			\&prep_alternate_read, $self, $git, $o, $ids[0], $n,
			$run_prune);
	}
}

sub cmd_done { # run_await cb for sort, xapian-delve, sed failures
	my ($pid, $cmd, undef, undef, $run_on_destroy) = @_;
	$? and die "fatal: @$cmd (\$?=$?)\n";
	# $run_on_destroy calls do_join() or run_prune()
}

sub current_join_data ($) {
	my ($self) = @_;
	local $self->{xdb} = $RDONLY_XDB[0] // die 'BUG: shard[0] undef';
	# we support multiple PI_CONFIG files for a cindex:
	$self->join_data;
}

# combined previously stored stats with new
sub score_old_join_data ($$$) {
	my ($self, $score, $ekeys_new) = @_;
	my $old = ($JOIN{reset} ? undef : current_join_data($self)) or return;
	progress($self, 'merging old join data...');
	my ($ekeys_old, $roots_old, $ibx2root_old) =
					@$old{qw(ekeys roots ibx2root)};
	# score: "ibx_off root_off" => nr
	my $i = -1;
	my %root2id_new = map { $_ => ++$i } @OFF2ROOT;
	$i = -1;
	my %ekey2id_new = map { $_ => ++$i } @$ekeys_new;
	for my $ibx_off_old (0..$#$ibx2root_old) {
		my $root_offs_old = $ibx2root_old->[$ibx_off_old];
		my $ekey = $ekeys_old->[$ibx_off_old] // do {
			warn "W: no ibx #$ibx_off_old in old join data\n";
			next;
		};
		my $ibx_off_new = $ekey2id_new{$ekey} // do {
			warn "W: `$ekey' no longer exists\n";
			next;
		};
		for (@$root_offs_old) {
			my ($nr, $rid_old) = @$_;
			my $root_old = $roots_old->[$rid_old] // do {
				warn "W: no root #$rid_old in old data\n";
				next;
			};
			my $rid_new = $root2id_new{$root_old} // do {
				warn "W: root `$root_old' no longer exists\n";
				next;
			};
			$score->{"$ibx_off_new $rid_new"} += $nr;
		}
	}
}

sub metadata_set { # via wq_do
	my ($self, $key, $val, $commit) = @_;
	$self->begin_txn_lazy;
	$self->{xdb}->set_metadata($key, $val);
	$self->commit_txn_lazy if $commit || defined(wantarray);
}

# runs once all inboxes and shards are dumped via OnDestroy
sub do_join {
	my ($self) = @_;
	return if $DO_QUIT;
	$XHC = 0; # should not be recreated again
	@IDX_SHARDS or return warn("# aborting on no shards\n");
	unlink("$TMPDIR/root2id");
	my @pending = keys %{$self->{PENDING}};
	die "BUG: pending=@pending jobs not done\n" if @pending;
	progress($self, 'joining...');
	my @join = (@JOIN, 'to_ibx_off', 'to_root_off');
	if (my $time = which('time')) { unshift @join, $time };
	my $rd = popen_rd(\@join, $CMD_ENV, { -C => "$TMPDIR" });
	my %score;
	while (<$rd>) { # PFX ibx_offs root_off
		chop eq "\n" or die "no newline from @join: <$_>";
		my (undef, $ibx_offs, @root_offs) = split / /, $_;
		for my $ibx_off (split(/,/, $ibx_offs)) {
			++$score{"$ibx_off $_"} for @root_offs;
		}
	}
	$rd->close or die "fatal: @join failed: \$?=$?";
	my $nr = scalar(keys %score) or do {
		delete $TODO{joining};
		return progress($self, 'no potential new pairings');
	};
	progress($self, "$nr potential new pairings...");
	my @ekeys = map { $_->eidx_key } @IBX;
	score_old_join_data($self, \%score, \@ekeys);
	my $new;
	while (my ($k, $nr) = each %score) {
		my ($ibx_off, $root_off) = split(/ /, $k);
		my ($ekey, $root) = ($ekeys[$ibx_off], $OFF2ROOT[$root_off]);
		progress($self, "$ekey => $root has $nr matches");
		push @{$new->{ibx2root}->[$ibx_off]}, [ $nr, $root_off ];
	}
	for my $ary (values %$new) { # sort by nr (largest first)
		for (@$ary) { @$_ = sort { $b->[0] <=> $a->[0] } @$_ }
	}
	$new->{ekeys} = \@ekeys;
	$new->{roots} = \@OFF2ROOT;
	$new->{dt} = \@JOIN_DT;
	$new = compress(PublicInbox::Config::json()->encode($new));
	my $key = $self->join_data_key;
	my $wait = $IDX_SHARDS[0]->wq_do('metadata_set', $key, $new);
	delete $TODO{joining};
}

sub require_progs {
	my $op = shift;
	while (my ($x, $argv) = splice(@_, 0, 2)) {
		my $e = $x;
		$e =~ tr/a-z-/A-Z_/;
		my $c = $ENV{$e} // $x;
		$argv->[0] //= which($c) // die "E: `$x' required for --$op\n";
	}
}

sub init_join_postfork ($) {
	my ($self) = @_;
	return unless $self->{-opt}->{join};
	require_progs('join', join => \@JOIN);
	my $d2 = '([0-9]{2})';
	my $dt_re = qr!([0-9]{4})$d2$d2$d2$d2$d2!;
	if (my $cur = $JOIN{reset} ? undef : current_join_data($self)) {
		if (($cur->{dt}->[1] // '') =~ m!\A$dt_re\z!o) {
			my ($Y, $m, $d, $H, $M, $S) = ($1, $2, $3, $4, $5, $6);
			my $t = timegm($S, $M, $H, $d, $m - 1, $Y);
			$t = strftime('%Y%m%d%H%M%S', gmtime($t + 1));
			$JOIN{dt} //= "$t..";
		} else {
			warn <<EOM;
BUG?: previous --join invocation did not store usable `dt' key
EOM
		}
	}
	if ($JOIN{aggressive}) {
		$JOIN{window} //= -1;
		$JOIN{dt} //= '..1.month.ago';
	}
	$QRY_STR = $JOIN{dt} // '1.year.ago..';
	index($QRY_STR, '..') >= 0 or die "E: dt:$QRY_STR is not a range\n";
	# Account for send->apply delay (torvalds/linux.git mean is ~20 days
	# from Author to CommitDate in cases where CommitDate > AuthorDate
	$QRY_STR .= '1.month.ago' if $QRY_STR =~ /\.\.\z/;
	@{$self->{git_dirs} // []} or die "E: no coderepos to join\n";
	@IBX or die "E: no inboxes to join\n";
	my $approx_git = PublicInbox::Git->new($self->{git_dirs}->[0]); # ugh
	substr($QRY_STR, 0, 0) = 'dt:';
	$self->query_approxidate($approx_git, $QRY_STR); # in-place
	($JOIN_DT[1]) = ($QRY_STR =~ /\.\.([0-9]{14})\z/); # YYYYmmddHHMMSS
	($JOIN_DT[0]) = ($QRY_STR =~ /\Adt:([0-9]{14})/); # YYYYmmddHHMMSS
	$JOIN_DT[0] //= '19700101'.'000000'; # git uses unsigned times
	$TODO{do_join} = on_destroy \&do_join, $self;
	$TODO{joining} = 1; # keep shards_active() happy
	$TODO{dump_ibx_start} = on_destroy \&dump_ibx_start,
					$self, $TODO{do_join};
	$TODO{dump_roots_start} = on_destroy \&dump_roots_start,
					$self, $TODO{do_join};
	progress($self, "will join in $QRY_STR date range...");
	my $id = -1;
	@IBXQ = map { ++$id } @IBX;
}

sub init_prune ($) {
	my ($self) = @_;
	return (@$PRUNE_DONE = map { 1 } @IDX_SHARDS) if !$self->{-opt}->{prune};

	# Dealing with millions of commits here at once, so use faster tools.
	# xapian-delve is nearly an order-of-magnitude faster than Xapian Perl
	# bindings.  sed/awk are faster than Perl for simple stream ops, and
	# sort+comm are more memory-efficient with gigantic lists.
	# pipeline: delve | sed | sort >indexed_commits
	my @delve = (undef, qw(-A Q -1));
	my @sed = (undef, '-ne', 's/^Q//p');
	@COMM = (undef, qw(-2 -3 indexed_commits -));
	@AWK = (undef, '$2 == "commit" { print $1 }'); # --batch-check output
	require_progs('prune', 'xapian-delve' => \@delve, sed => \@sed,
			comm => \@COMM, awk => \@AWK);
	for (0..$#IDX_SHARDS) { push @delve, "$self->{xpfx}/$_" }
	my $run_prune = on_destroy \&run_prune, $self, $TODO{dump_roots_start};
	my ($sort_opt, $sed_opt, $delve_opt);
	pipe(local $sed_opt->{0}, local $delve_opt->{1});
	pipe(local $sort_opt->{0}, local $sed_opt->{1});
	open($sort_opt->{1}, '+>', "$TMPDIR/indexed_commits");
	run_await([@SORT, '-u'], $CMD_ENV, $sort_opt, \&cmd_done, $run_prune);
	run_await(\@sed, $CMD_ENV, $sed_opt, \&cmd_done, $run_prune);
	run_await(\@delve, undef, $delve_opt, \&cmd_done, $run_prune);
	@PRUNEQ = @$SCANQ;
	for (1..$LIVE_JOBS) {
		prep_alternate_start($self, shift(@PRUNEQ) // last, $run_prune);
	}
}

sub dump_git_commits { # run_await cb
	my ($pid, $cmd, undef, $batch_opt, $self) = @_;
	(defined($pid) && $?) and die "E: @$cmd \$?=$?";
	return if $DO_QUIT;
	my ($hexlen) = keys(%ALT_FH) or return; # done, DESTROY batch_opt->{1}
	close(delete $ALT_FH{$hexlen}); # flushes `say' buffer
	progress($self, "preparing $hexlen-byte hex OID commits for prune...");
	my $g = PublicInbox::Git->new("$TMPDIR/hexlen$hexlen.git");
	run_await($g->cmd(@PRUNE_BATCH), undef, $batch_opt,
			\&dump_git_commits, $self);
}

sub run_prune { # OnDestroy when `git config extensions.objectFormat' are done
	my ($self, $drs) = @_;
	return if $DO_QUIT;
	# setup the following pipeline: (
	#	git --git-dir=hexlen40.git cat-file \
	#		--batch-all-objects --batch-check &&
	#	git --git-dir=hexlen64.git cat-file \
	#		--batch-all-objects --batch-check
	# ) | awk | sort | comm | cidx_read_comm()
	my ($awk_opt, $sort_opt, $batch_opt);
	my $comm_opt = { -C => "$TMPDIR" };
	pipe(local $awk_opt->{0}, $batch_opt->{1});
	pipe(local $sort_opt->{0}, local $awk_opt->{1});
	pipe(local $comm_opt->{0}, local $sort_opt->{1});
	run_await(\@AWK, $CMD_ENV, $awk_opt, \&cmd_done);
	run_await([@SORT, '-u'], $CMD_ENV, $sort_opt, \&cmd_done);
	my $comm_rd = popen_rd(\@COMM, $CMD_ENV, $comm_opt, \&cmd_done, \@COMM);
	PublicInbox::CidxComm->new($comm_rd, $self, $drs); # ->cidx_read_comm
	push @PRUNE_BATCH, '--buffer' if $GIT_VER ge v2.6;

	# Yes, we pipe --unordered git output to sort(1) because sorting
	# inside git leads to orders-of-magnitude slowdowns on rotational
	# storage.  GNU sort(1) also works well on larger-than-memory
	# datasets, and it's not worth eliding sort(1) for old git.
	push @PRUNE_BATCH, '--unordered' if $GIT_VER ge v2.19;
	warn(sprintf(<<EOM, $GIT_VER)) if $GIT_VER lt v2.19;
W: git v2.19+ recommended for high-latency storage (have git v%vd)
EOM
	dump_git_commits(undef, undef, undef, $batch_opt, $self);
}

sub cidx_read_comm { # via PublicInbox::CidxComm::event_step
	my ($self, $comm_rd, $drs) = @_;
	return if $DO_QUIT;
	progress($self, 'starting prune...');
	$_->wq_do('prune_init') for @IDX_SHARDS;
	while (defined(my $cmt = <$comm_rd>)) {
		chop($cmt) eq "\n" or die "BUG: no LF in comm output ($cmt)";
		my $n = hex(substr($cmt, 0, 8)) % scalar(@IDX_SHARDS);
		$IDX_SHARDS[$n]->wq_do('prune_one', 'Q'.$cmt);
		last if $DO_QUIT;
	}
	for my $git_dir (@GIT_DIR_GONE) {
		my $n = git_dir_hash($git_dir) % scalar(@IDX_SHARDS);
		$IDX_SHARDS[$n]->wq_do('prune_one', 'P'.$git_dir);
		last if $DO_QUIT;
	}
	my ($c, $p) = PublicInbox::PktOp->pair;
	$c->{ops}->{prune_done} = [ $self, $drs ];
	$_->wq_io_do('prune_commit', [ $p->{op_p} ]) for @IDX_SHARDS;
}

sub init_join_prefork ($) {
	my ($self) = @_;
	my $subopt = $self->{-opt}->{join} // return;
	%JOIN = map {
		my ($k, $v) = split /:/, $_, 2;
		$k => $v // 1;
	} split(/,/, join(',', @$subopt));
	require PublicInbox::CidxXapHelperAux;
	require PublicInbox::XapClient;
	my @unknown;
	my $pfx = $JOIN{prefixes} // 'dfpost7';
	for my $p (split /\+/, $pfx) {
		my $n = '';
		$p =~ s/([0-9]+)\z// and $n = $1;
		my $v = $PublicInbox::Search::PATCH_BOOL_COMMON{$p} //
			push(@unknown, $p);
		push(@JOIN_PFX, map { $_.$n } split(/ /, $v));
	}
	@unknown and die <<EOM;
E: --join=prefixes= contains unsupported prefixes: @unknown
EOM
	@JOIN_PFX = uniqstr @JOIN_PFX;
	my %incl = map {
		if (-f "$_/inbox.lock" || -d "$_/public-inbox") {
			rel2abs_collapsed($_) => undef;
		} else {
			warn "W: `$_' is not a public inbox, skipping\n";
			();
		}
	} (@{$self->{-opt}->{'include-inbox'} // []});
	my $all = $self->{-opt}->{'all-inboxes'};
	if (my $only = $self->{-opt}->{'only-inbox'}) {
		die <<'' if $all;
E: --all-inboxes is incompatible with --only-inbox

		$incl{rel2abs_collapsed($_)} = undef for @$only;
	}
	unless (keys(%incl)) {
		$all = 1;
		warn <<EOM unless $self->{opt}->{quiet};
# --all-inboxes implied since no inboxes were specified with
# --only-inbox= or --include-inbox=
EOM
	}
	$self->{-opt}->{-pi_cfg}->each_inbox(\&_prep_ibx, $self, \%incl, $all);
	my $nr = scalar(@IBX) or die "E: no inboxes to join with\n";
	progress($self, "will join with $nr inboxes in ",
			$self->{-opt}->{-pi_cfg}->{-f}, " using: $pfx");
}

sub _prep_ibx { # each_inbox callback
	my ($ibx, $self, $incl, $all) = @_;
	($all || exists($incl->{$ibx->{inboxdir}})) and push @IBX, $ibx;
}

sub show_json { # for diagnostics (unstable output)
	my ($self) = @_;
	my $s = $self->{-opt}->{show} or return; # for diagnostics
	local $self->{xdb};
	my %ret;
	my @todo = @$s;
	while (defined(my $f = shift @todo)) {
		if ($f =~ /\A(?:roots2paths|paths2roots|join_data)\z/) {
			$ret{$f} = $self->$f;
		} elsif ($f eq '') { # default --show (no args)
			push @todo, qw(roots2paths join_data);
		} else {
			warn "E: cannot show `$f'\n";
		}
	}
	my $json = ref(PublicInbox::Config::json())->new;
	$json->utf8->canonical->pretty; # n.b. FS pathnames may not be UTF-8...
	say $json->encode(\%ret);
}

sub do_inits { # called via PublicInbox::DS::add_timer
	my ($self) = @_;
	grep !!$_, @{$self->{-opt}}{qw(scan prune)} and
		@$SCANQ = map PublicInbox::Git->new($_), @{$self->{git_dirs}};
	init_join_postfork $self;
	init_prune $self;
	scan_git_dirs $self;
	my $max = $TODO{do_join} ? max($LIVE_JOBS, $NPROC) : $LIVE_JOBS;
	index_next($self) for (1..$max);
}

sub cidx_run { # main entry point
	my ($self) = @_;
	my $restore_umask = prep_umask($self);
	local $SIGSET = PublicInbox::DS::block_signals(
					POSIX::SIGTSTP, POSIX::SIGCONT);
	my $restore = on_destroy \&PublicInbox::DS::sig_setmask, $SIGSET;
	local $PRUNE_DONE = [];
	local $IDXQ = [];
	local $SCANQ = [];
	local ($DO_QUIT, $REINDEX, $TXN_BYTES, @GIT_DIR_GONE, @PRUNEQ,
		$REPO_CTX, %ALT_FH, $TMPDIR, @AWK, @COMM, $CMD_ENV,
		%TODO, @IBXQ, @IBX, @JOIN, %JOIN, @JOIN_PFX, @NO_ABBREV,
		@JOIN_DT, $DUMP_IBX_WPIPE, @OFF2ROOT, $XHC, @SORT, $GITS_NR);
	local $BATCH_BYTES = $self->{-opt}->{batch_size} //
				$PublicInbox::SearchIdx::BATCH_BYTES;
	local $MAX_SIZE = $self->{-opt}->{max_size};
	local $self->{PENDING} = {}; # used by PublicInbox::CidxXapHelperAux
	my $cfg = $self->{-opt}->{-pi_cfg} // die 'BUG: -pi_cfg unset';
	$self->{-cfg_f} = $cfg->{-f} = rel2abs_collapsed($cfg->{-f});
	local $GIT_VER = PublicInbox::Git::git_version();
	@NO_ABBREV = ('-c', 'core.abbrev='.($GIT_VER lt v2.31.0 ? 40 : 'no'));
	if (grep { $_ } @{$self->{-opt}}{qw(prune join)}) {
		require File::Temp;
		$TMPDIR = File::Temp->newdir('cidx-all-git-XXXX', TMPDIR => 1);
		$CMD_ENV = { TMPDIR => "$TMPDIR", LC_ALL => 'C', LANG => 'C' };
		require_progs('(prune|join)', sort => \@SORT);
		for (qw(parallel compress-program buffer-size)) { # GNU sort
			my $v = $self->{-opt}->{"sort-$_"};
			push @SORT, "--$_=$v" if defined $v;
		}
		($self->{-opt}->{prune} && $GIT_VER le v2.6) and
			die "W: --prune requires git v2.6+\n";
		init_join_prefork($self)
	}
	local @IDX_SHARDS = cidx_init($self); # forks workers
	local $ANY_SHARD = -1;
	local $self->{current_info} = '';
	local $MY_SIG = {
		CHLD => \&PublicInbox::DS::enqueue_reap,
		USR1 => \&kill_shards,
	};
	local @PRUNE_BATCH = @PRUNE_BATCH;
	$MY_SIG->{$_} = \&parent_quit for qw(TERM QUIT INT);
	local $SIG{__WARN__} = PublicInbox::Admin::warn_cb $self;
	load_existing($self) unless $self->{-cidx_internal};
	if ($self->{-opt}->{reindex}) {
		require PublicInbox::SharedKV;
		$REINDEX = PublicInbox::SharedKV->new;
		delete $REINDEX->{lock_path};
		$REINDEX->dbh;
	}
	my $cwarn;
	for my $d (@{$self->{git_dirs}}) {
		my $c = canonpath $d;
		next if $c eq $d;
		$cwarn = warn <<EOM if !$cwarn;
E: BUG? paths in $self->{topdir} not canonicalized:
EOM
		warn "E: $d => $c\n";
		$d = $c;
	}
	if (defined(my $excl = $self->{-opt}->{exclude})) {
		my $re = '(?:'.join('\\z|', map {
				glob2re($_) // qr/\A\Q$_\E/
			} @$excl).'\\z)';
		my @excl;
		@{$self->{git_dirs}} = grep {
			$_ =~ /$re/ ? (push(@excl, $_), 0) : 1;
		} @{$self->{git_dirs}};
		warn("# excluding $_\n") for @excl;
		@GIT_DIR_GONE = uniqstr @GIT_DIR_GONE, @excl;
	}
	local $NCHANGE = 0;
	local $NPROC = PublicInbox::IPC::detect_nproc();
	local $LIVE_JOBS = $self->{-opt}->{jobs} || $NPROC || 2;
	local @RDONLY_XDB = $self->xdb_shards_flat;
	PublicInbox::DS::add_timer(0, \&do_inits, $self);

	# FreeBSD ignores/discards SIGCHLD while signals are blocked and
	# EVFILT_SIGNAL is inactive, so we pretend we have a SIGCHLD pending
	PublicInbox::DS::enqueue_reap();

	local @PublicInbox::DS::post_loop_do = (\&shards_active);
	PublicInbox::DS::event_loop($MY_SIG, $SIGSET);
	$self->lock_release(!!$NCHANGE);
	show_json($self);
}

sub ipc_atfork_child { # @IDX_SHARDS
	my ($self) = @_;
	$self->SUPER::ipc_atfork_child;
	$SIG{USR1} = \&shard_usr1;
	$SIG{$_} = \&shard_quit for qw(INT TERM QUIT);
	my $x = delete $self->{siblings} // die 'BUG: no {siblings}';
	$_->wq_close for @$x;
	undef;
}

sub shard_done_wait { # awaitpid cb via ipc_worker_reap
	my ($pid, $shard, $self) = @_;
	my $quit_req = delete($shard->{-cidx_quit});
	return if $DO_QUIT;
	if ($? == 0) { # success
		$quit_req // warn 'BUG: {-cidx_quit} unset';
	} else {
		warn "PID:$pid $shard->{shard} exited with \$?=$?\n";
		++$self->{shard_err} if defined($self->{shard_err});
	}
}

1;
