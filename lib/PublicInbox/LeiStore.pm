# Copyright (C) all contributors <meta@public-inbox.org>
# License: AGPL-3.0+ <https://www.gnu.org/licenses/agpl-3.0.txt>
#
# Local storage (cache/memo) for lei(1), suitable for personal/private
# mail iff on encrypted device/FS.  Based on v2, but only deduplicates
# git storage based on git OID (index deduplication is done in ContentHash)
#
# for xref3, the following are constant: $eidx_key = '.', $xnum = -1
#
# We rely on the synchronous IPC API for this in lei-daemon and
# multiple lei clients to write to it at once.  This allows the
# lei/store IPC process to be decoupled from network latency in
# lei WQ workers.
package PublicInbox::LeiStore;
use strict;
use v5.10.1;
use parent qw(PublicInbox::Lock PublicInbox::IPC);
use autodie qw(open pipe);
use PublicInbox::IPC qw(send_pkt);
use PublicInbox::ExtSearchIdx;
use PublicInbox::SearchIdx;
use PublicInbox::Eml;
use PublicInbox::Import;
use PublicInbox::InboxWritable qw(eml_from_path);
use PublicInbox::V2Writable;
use PublicInbox::ContentHash qw(content_hash);
use PublicInbox::MID qw(mids);
use PublicInbox::LeiSearch;
use PublicInbox::MDA;
use PublicInbox::Spawn qw(spawn);
use PublicInbox::MdirReader;
use PublicInbox::LeiToMail;
use PublicInbox::Compat qw(uniqstr);
use PublicInbox::OnDestroy;
use File::Temp qw(tmpnam);
use POSIX ();
use IO::Handle (); # ->autoflush
use Sys::Syslog qw(syslog openlog);
use Errno qw(EEXIST ENOENT);
use PublicInbox::Syscall qw(rename_noreplace);
use PublicInbox::LeiStoreErr;
use PublicInbox::DS qw(add_uniq_timer);

sub new {
	my (undef, $dir, $opt) = @_;
	$opt->{wal} = 1;
	my $eidx = PublicInbox::ExtSearchIdx->new($dir, $opt);
	my $self = bless { priv_eidx => $eidx }, __PACKAGE__;
	eidx_init($self)->done if $opt->{creat};
	$self;
}

sub git { $_[0]->{priv_eidx}->git } # read-only

sub packing_factor { $PublicInbox::V2Writable::PACKING_FACTOR }

sub rotate_bytes {
	$_[0]->{rotate_bytes} // ((1024 * 1024 * 1024) / $_[0]->packing_factor)
}

sub git_ident ($) {
	my ($git) = @_;
	my $rdr = {};
	open $rdr->{2}, '>', '/dev/null';
	chomp(my $i = $git->qx([qw(var GIT_COMMITTER_IDENT)], undef, $rdr));
	$i =~ /\A(.+) <([^>]+)> [0-9]+ [-\+]?[0-9]+$/ and return ($1, $2);
	my ($user, undef, undef, undef, undef, undef, $gecos) = getpwuid($<);
	($user) = (($user // $ENV{USER} // '') =~ /([\w\-\.\+]+)/);
	$user //= 'lei-user';
	($gecos) = (($gecos // '') =~ /([\w\-\.\+ \t]+)/);
	$gecos //= 'lei user';
	require Sys::Hostname;
	my ($host) = (Sys::Hostname::hostname() =~ /([\w\-\.]+)/);
	$host //= 'localhost';
	($gecos, "$user\@$host")
}

sub importer {
	my ($self) = @_;
	my $max;
	my $im = $self->{im};
	if ($im) {
		return $im if $im->{bytes_added} < $self->rotate_bytes;

		delete $self->{im};
		$im->done;
		undef $im;
		$self->barrier;
		$max = $self->{priv_eidx}->{mg}->git_epochs + 1;
	}
	my (undef, $tl) = eidx_init($self); # acquire lock
	$max //= $self->{priv_eidx}->{mg}->git_epochs;
	while (1) {
		my $latest = $self->{priv_eidx}->{mg}->add_epoch($max);
		my $git = PublicInbox::Git->new($latest);
		$self->done; # unlock
		# re-acquire lock, update alternates for new epoch
		(undef, $tl) = eidx_init($self);
		my $unpacked_bytes = int($git->packed_bytes / $self->packing_factor);
		if ($unpacked_bytes >= $self->rotate_bytes) {
			$max++;
			next;
		}
		my ($n, $e) = git_ident($git);
		$self->{im} = $im = PublicInbox::Import->new($git, $n, $e);
		$im->{bytes_added} = $unpacked_bytes;
		$im->{lock_path} = undef;
		$im->{path_type} = 'v2';
		return $im;
	}
}

sub search {
	PublicInbox::LeiSearch->new($_[0]->{priv_eidx}->{topdir});
}

sub cat_blob {
	my ($self, $oid) = @_;
	$self->{im} ? $self->{im}->cat_blob($oid) : undef;
}

sub schedule_commit {
	my ($self, $sec) = @_;
	add_uniq_timer($self->{priv_eidx}->{topdir}, $sec, \&barrier, $self);
}

# follows the stderr file
sub _tail_err {
	my ($self) = @_;
	my $err = $self->{-tmp_err} // return;
	$err->clearerr; # clear EOF marker
	my @msg = readline($err);
	PublicInbox::LeiStoreErr::emit($self->{-err_wr}, @msg) and return;
	# syslog is the last resort if lei-daemon broke
	syslog('warning', '%s', $_) for @msg;
}

sub eidx_init {
	my ($self) = @_;
	my $eidx = $self->{priv_eidx};
	my $tl = wantarray && $self->{-err_wr} ?
			on_destroy(\&_tail_err, $self) :
			undef;
	$eidx->idx_init({wal => 1, -private => 1}); # acquires lock
	wantarray ? ($eidx, $tl) : $eidx;
}

sub _docids_for ($$) {
	my ($self, $eml) = @_;
	my %docids;
	my $eidx = $self->{priv_eidx};
	my ($chash, $mids) = PublicInbox::LeiSearch::content_key($eml);
	my $oidx = $eidx->{oidx};
	my $im = $self->{im};
	for my $mid (@$mids) {
		my ($id, $prev);
		while (my $cur = $oidx->next_by_mid($mid, \$id, \$prev)) {
			next if $cur->{bytes} == 0; # external-only message
			my $oid = $cur->{blob};
			my $docid = $cur->{num};
			my $bref = $im ? $im->cat_blob($oid) : undef;
			$bref //= $eidx->git->cat_file($oid) //
				_lms_rw($self)->local_blob($oid, 1) // do {
				warn "W: $oid (#$docid) <$mid> not found\n";
				next;
			};
			local $self->{current_info} = $oid;
			my $x = PublicInbox::Eml->new($bref);
			$docids{$docid} = $docid if content_hash($x) eq $chash;
		}
	}
	sort { $a <=> $b } values %docids;
}

# n.b. similar to LeiExportKw->export_kw_md, but this is for a single eml
sub export1_kw_md ($$$$$) {
	my ($self, $mdir, $bn, $oidbin, $vmdish) = @_; # vmd/vmd_mod
	my $orig = $bn;
	my (@try, $unkn, $kw);
	if ($bn =~ s/:2,([a-zA-Z]*)\z//) {
		($kw, $unkn) = PublicInbox::MdirReader::flags2kw($1);
		if (my $set = $vmdish->{kw}) {
			$kw = $set;
		} elsif (my $add = $vmdish->{'+kw'}) {
			@$kw{@$add} = ();
		} elsif (my $del = $vmdish->{-kw}) {
			delete @$kw{@$del};
		} # else no changes...
		@try = qw(cur new);
	} else { # no keywords, yet, could be in new/
		@try = qw(new cur);
		$unkn = [];
		if (my $set = $vmdish->{kw}) {
			$kw = $set;
		} elsif (my $add = $vmdish->{'+kw'}) {
			@$kw{@$add} = (); # auto-vivify
		} else { # ignore $vmdish->{-kw}
			$kw = [];
		}
	}
	$kw = [ keys %$kw ] if ref($kw) eq 'HASH';
	$bn .= ':2,'. PublicInbox::LeiToMail::kw2suffix($kw, @$unkn);
	return if $orig eq $bn; # no change

	# we use link(2) + unlink(2) since rename(2) may
	# inadvertently clobber if the "uniquefilename" part wasn't
	# actually unique.
	my $dst = "$mdir/cur/$bn";
	for my $d (@try) {
		my $src = "$mdir/$d/$orig";
		if (rename_noreplace($src, $dst)) {
			# TODO: verify oidbin?
			$self->{lms}->mv_src("maildir:$mdir",
					$oidbin, \$orig, $bn);
			return;
		} elsif ($! == EEXIST) { # lost race with "lei export-kw"?
			return;
		} elsif ($! != ENOENT) {
			syslog('warning', "rename_noreplace($src -> $dst): $!");
		}
	}
	for (@try) { return if -e "$mdir/$_/$orig" };
	$self->{lms}->clear_src("maildir:$mdir", \$orig);
}

sub sto_export_kw ($$$) {
	my ($self, $docid, $vmdish) = @_; # vmdish (vmd or vmd_mod)
	my ($eidx, $tl) = eidx_init($self);
	my $lms = _lms_rw($self) // return;
	my $xr3 = $eidx->{oidx}->get_xref3($docid, 1);
	for my $row (@$xr3) {
		my (undef, undef, $oidbin) = @$row;
		my $locs = $lms->locations_for($oidbin) // next;
		while (my ($loc, $ids) = each %$locs) {
			if ($loc =~ s!\Amaildir:!!i) {
				for my $id (@$ids) {
					export1_kw_md($self, $loc, $id,
							$oidbin, $vmdish);
				}
			}
			# TODO: IMAP
		}
	}
}

# commit every 5s to get under the default DBD::SQLite timeout of 30s
sub _schedule_checkpoint ($) {
	my ($self) = @_;
	add_uniq_timer("$self-ckpt", $PublicInbox::SearchIdx::CHECKPOINT_INTVL,
			\&_commit, $self, 'barrier');
}

# vmd = { kw => [ qw(seen ...) ], L => [ qw(inbox ...) ] }
sub set_eml_vmd {
	my ($self, $eml, $vmd, $docids) = @_;
	my ($eidx, $tl) = eidx_init($self);
	$docids //= [ _docids_for($self, $eml) ];
	for my $docid (@$docids) {
		$eidx->idx_shard($docid)->ipc_do('set_vmd', $docid, $vmd);
		sto_export_kw($self, $docid, $vmd);
	}
	_schedule_checkpoint $self;
	$docids;
}

sub add_eml_vmd {
	my ($self, $eml, $vmd) = @_;
	my ($eidx, $tl) = eidx_init($self);
	my @docids = _docids_for($self, $eml);
	for my $docid (@docids) {
		$eidx->idx_shard($docid)->ipc_do('add_vmd', $docid, $vmd);
	}
	_schedule_checkpoint $self;
	\@docids;
}

sub remove_eml_vmd { # remove just the VMD
	my ($self, $eml, $vmd) = @_;
	my ($eidx, $tl) = eidx_init($self);
	my @docids = _docids_for($self, $eml);
	for my $docid (@docids) {
		$eidx->idx_shard($docid)->ipc_do('remove_vmd', $docid, $vmd);
	}
	_schedule_checkpoint $self;
	\@docids;
}

sub _lms_rw ($) { # it is important to have eidx processes open before lms
	my ($self) = @_;
	$self->{lms} // do {
		require PublicInbox::LeiMailSync;
		my ($eidx, $tl) = eidx_init($self);
		my $f = "$self->{priv_eidx}->{topdir}/mail_sync.sqlite3";
		my $lms = PublicInbox::LeiMailSync->new($f);
		$lms->lms_write_prepare;
		$self->{lms} = $lms;
	};
}

sub _remove_if_local { # git->cat_async arg
	my ($bref, $oidhex, $type, $size, $self) = @_;
	$self->{im}->remove($bref) if $bref;
}

sub remove_docids ($;@) {
	my ($self, @docids) = @_;
	my $eidx = eidx_init($self);
	for my $docid (@docids) {
		$eidx->remove_doc($docid);
		$eidx->{oidx}->{dbh}->do(<<EOF, undef, $docid);
DELETE FROM xref3 WHERE docid = ?
EOF
	}
}

# remove the entire message from the index, does not touch mail_sync.sqlite3
sub remove_eml {
	my ($self, $eml) = @_;
	my $im = $self->importer; # may create new epoch
	my ($eidx, $tl) = eidx_init($self);
	my $oidx = $eidx->{oidx};
	my @docids = _docids_for($self, $eml);
	my $git = $eidx->git;
	for my $docid (@docids) {
		my $xr3 = $oidx->get_xref3($docid, 1);
		for my $row (@$xr3) {
			my (undef, undef, $oidbin) = @$row;
			my $oidhex = unpack('H*', $oidbin);
			$git->cat_async($oidhex, \&_remove_if_local, $self);
		}
	}
	$git->async_wait_all;
	remove_docids($self, @docids);
	_schedule_checkpoint $self;
	\@docids;
}

sub oid2docid ($$) {
	my ($self, $oid) = @_;
	my $eidx = eidx_init($self);
	my ($docid, @cull) = $eidx->{oidx}->blob_exists($oid);
	if (@cull) { # fixup old bugs...
		warn <<EOF;
W: $oid indexed as multiple docids: $docid @cull, culling to fixup old bugs
EOF
		remove_docids($self, @cull);
	}
	$docid;
}

sub _add_vmd ($$$$) {
	my ($self, $idx, $docid, $vmd) = @_;
	$idx->ipc_do('add_vmd', $docid, $vmd);
	sto_export_kw($self, $docid, $vmd);
}

sub _docids_and_maybe_kw ($$) {
	my ($self, $docids) = @_;
	_schedule_checkpoint $self;
	return $docids unless wantarray;
	my (@kw, $idx, @tmp);
	for my $num (@$docids) { # likely only 1, unless ContentHash changes
		# can't use ->search->msg_keywords on uncommitted docs
		$idx = $self->{priv_eidx}->idx_shard($num);
		@tmp = eval { $idx->ipc_do('get_terms', 'K', $num) };
		$@ ? warn("#$num get_terms: $@") : push(@kw, @tmp);
	}
	@kw = sort(uniqstr(@kw)) if @$docids > 1;
	($docids, \@kw);
}

sub _reindex_1 { # git->cat_async callback
	my ($bref, $hex, $type, $size, $smsg) = @_;
	my $self = delete $smsg->{-sto};
	my ($eidx, $tl) = eidx_init($self);
	$bref //= _lms_rw($self)->local_blob($hex, 1);
	if ($bref) {
		my $eml = PublicInbox::Eml->new($bref);
		$smsg->{-merge_vmd} = 1; # preserve existing keywords
		$eidx->idx_shard($smsg->{num})->index_eml($eml, $smsg);
	} elsif ($type eq 'missing') {
		# pre-release/buggy lei may've indexed external-only msgs,
		# try to correct that, here
		warn("E: missing $hex, culling (ancient lei artifact?)\n");
		$smsg->{to} = $smsg->{cc} = $smsg->{from} = '';
		$smsg->{bytes} = 0;
		$eidx->{oidx}->update_blob($smsg, '');
		my $eml = PublicInbox::Eml->new("\r\n\r\n");
		$eidx->idx_shard($smsg->{num})->index_eml($eml, $smsg);
	} else {
		warn("E: $type $hex\n");
	}
	_schedule_checkpoint $self;
}

sub reindex_art {
	my ($self, $art) = @_;
	my ($eidx, $tl) = eidx_init($self);
	my $smsg = $eidx->{oidx}->get_art($art) // return;
	return if $smsg->{bytes} == 0; # external-only message
	$smsg->{-sto} = $self;
	$eidx->git->cat_async($smsg->{blob} // die("no blob (#$art)"),
				\&_reindex_1, $smsg);
}

sub _ridx_done { # OnDestroy cb
	my ($self, $rireq) = @_;
	local @$self{0, 1} = @$rireq{qw(errfh lei_sock)};
	barrier($self);
	# $rireq->{eof_wr} goes out-of-scope to trigger lei->dclose
}

sub reindex_done ($$) {
	my ($self, $rireq) = @_;
	my ($eidx, $tl) = eidx_init($self);
	$eidx->git->watch_async;
	$eidx->git->async_barrier(on_destroy(\&_ridx_done, $self, $rireq));
	# ->done to be called via sto_barrier_request
}

sub event_step {
	my ($self) = @_;
	for my $reqid (keys %{$self->{ridx}}) {
		my $rireq = $self->{ridx}->{$reqid};
		if ($rireq->{cur} < $rireq->{max}) {
			reindex_art($self, $rireq->{cur}++);
		} else {
			delete $self->{ridx}->{$reqid};
			reindex_done($self, $rireq);
		}
	}
	# run ->event_step again if more to do
	keys(%{$self->{ridx}}) ? PublicInbox::DS::requeue($self)
				: delete($self->{ridx});
}

sub reindex_range {
	my ($self, $min, $max, $reqid) = @_;
	$self->{ridx}->{$reqid} = {
		errfh => $self->{0},
		lei_sock => $self->{1},
		eof_wr => $self->{2}, # calls lei->dclose via EOFpipe
		cur => $min, max => $max,
	};
	PublicInbox::DS::requeue($self); # runs ->event_step
}

sub abort_long_req {
	my ($self, $reqid) = @_;
	my $reqs = $self->{ridx} // return;
	my $rireq = $reqs->{$reqid} // return;
	$rireq->{cur} = $rireq->{max}; # ->event_step finishes up
}

sub add_eml {
	my ($self, $eml, $vmd, $xoids) = @_;
	my $im = $self->{-fake_im} // $self->importer; # may create new epoch
	my ($eidx, $tl) = eidx_init($self);
	my $oidx = $eidx->{oidx}; # PublicInbox::Import::add checks this
	my $smsg = bless { -oidx => $oidx }, 'PublicInbox::Smsg';
	$smsg->{-eidx_git} = $eidx->git if !$self->{-fake_im};
	my $im_mark = $im->add($eml, undef, $smsg);
	if ($vmd && $vmd->{sync_info}) {
		_lms_rw($self)->set_src($smsg->oidbin, @{$vmd->{sync_info}});
	}
	unless ($im_mark) { # duplicate blob returns undef
		return unless wantarray || $vmd;
		my @docids = $oidx->blob_exists($smsg->{blob});
		if ($vmd) {
			for my $docid (@docids) {
				my $idx = $eidx->idx_shard($docid);
				_add_vmd($self, $idx, $docid, $vmd);
			}
		}
		return _docids_and_maybe_kw $self, \@docids;
	}

	local $self->{current_info} = $smsg->{blob};
	my $vivify_xvmd = delete($smsg->{-vivify_xvmd}) // []; # exact matches
	if ($xoids) { # fuzzy matches from externals in ale->xoids_for
		delete $xoids->{$smsg->{blob}}; # added later
		if (scalar keys %$xoids) {
			my %docids = map { $_ => 1 } @$vivify_xvmd;
			for my $oid (keys %$xoids) {
				my $docid = oid2docid($self, $oid);
				$docids{$docid} = $docid if defined($docid);
			}
			@$vivify_xvmd = sort { $a <=> $b } keys(%docids);
		}
	}
	if (@$vivify_xvmd) { # docids list
		$xoids //= {};
		$xoids->{$smsg->{blob}} = 1;
		for my $docid (@$vivify_xvmd) {
			my $cur = $oidx->get_art($docid);
			my $idx = $eidx->idx_shard($docid);
			if (!$cur || $cur->{bytes} == 0) { # really vivifying
				$smsg->{num} = $docid;
				$oidx->add_overview($eml, $smsg);
				$smsg->{-merge_vmd} = 1;
				$idx->index_eml($eml, $smsg);
			} else { # lse fuzzy hit off ale
				$idx->add_eidx_info($docid, '.', $eml);
			}
			for my $oid (keys %$xoids) {
				$oidx->add_xref3($docid, -1, $oid, '.');
			}
			_add_vmd($self, $idx, $docid, $vmd) if $vmd;
		}
		_docids_and_maybe_kw $self, $vivify_xvmd;
	} elsif (my @docids = _docids_for($self, $eml)) {
		# fuzzy match from within lei/store
		for my $docid (@docids) {
			my $idx = $eidx->idx_shard($docid);
			$oidx->add_xref3($docid, -1, $smsg->{blob}, '.');
			# add_eidx_info for List-Id
			$idx->add_eidx_info($docid, '.', $eml);
			_add_vmd($self, $idx, $docid, $vmd) if $vmd;
		}
		_docids_and_maybe_kw $self, \@docids;
	} else { # totally new message, no keywords
		delete $smsg->{-oidx}; # for IPC-friendliness
		$smsg->{num} = $oidx->adj_counter('eidx_docid', '+');
		$oidx->add_overview($eml, $smsg);
		$oidx->add_xref3($smsg->{num}, -1, $smsg->{blob}, '.');
		my $idx = $eidx->idx_shard($smsg->{num});
		$idx->index_eml($eml, $smsg);
		_add_vmd($self, $idx, $smsg->{num}, $vmd) if $vmd;
		_schedule_checkpoint $self;
		wantarray ? ($smsg, []) : $smsg;
	}
}

sub set_eml {
	my ($self, $eml, $vmd, $xoids) = @_;
	add_eml($self, $eml, $vmd, $xoids) //
		set_eml_vmd($self, $eml, $vmd);
}

sub index_eml_only {
	my ($self, $eml, $vmd, $xoids) = @_;
	require PublicInbox::FakeImport;
	local $self->{-fake_im} = PublicInbox::FakeImport->new;
	set_eml($self, $eml, $vmd, $xoids);
}

# store {kw} / {L} info for a message which is only in an external
sub _external_only ($$$) {
	my ($self, $xoids, $eml) = @_;
	my $eidx = $self->{priv_eidx};
	my $oidx = $eidx->{oidx} // die 'BUG: {oidx} missing';
	my $smsg = bless { blob => '' }, 'PublicInbox::Smsg';
	$smsg->{num} = $oidx->adj_counter('eidx_docid', '+');
	# save space for an externals-only message
	my $hdr = $eml->header_obj;
	$smsg->populate($hdr); # sets lines == 0
	$smsg->{bytes} = 0;
	delete @$smsg{qw(From Subject)};
	$smsg->{to} = $smsg->{cc} = $smsg->{from} = '';
	$oidx->add_overview($hdr, $smsg); # subject+references for threading
	$smsg->{subject} = '';
	for my $oid (keys %$xoids) {
		$oidx->add_xref3($smsg->{num}, -1, $oid, '.');
	}
	my $idx = $eidx->idx_shard($smsg->{num});
	$idx->index_eml(PublicInbox::Eml->new("\n\n"), $smsg);
	($smsg, $idx);
}

sub update_xvmd {
	my ($self, $xoids, $eml, $vmd_mod) = @_;
	my ($eidx, $tl) = eidx_init($self);
	my $oidx = $eidx->{oidx};
	my %seen;
	_schedule_checkpoint $self;
	for my $oid (keys %$xoids) {
		my $docid = oid2docid($self, $oid) // next;
		delete $xoids->{$oid};
		next if $seen{$docid}++;
		my $idx = $eidx->idx_shard($docid);
		$idx->ipc_do('update_vmd', $docid, $vmd_mod);
		sto_export_kw($self, $docid, $vmd_mod);
	}
	return unless scalar(keys(%$xoids));

	# see if it was indexed, but with different OID(s)
	if (my @docids = _docids_for($self, $eml)) {
		for my $docid (@docids) {
			next if $seen{$docid};
			for my $oid (keys %$xoids) {
				$oidx->add_xref3($docid, -1, $oid, '.');
			}
			my $idx = $eidx->idx_shard($docid);
			$idx->ipc_do('update_vmd', $docid, $vmd_mod);
			sto_export_kw($self, $docid, $vmd_mod);
		}
		return;
	}
	# totally unseen
	my ($smsg, $idx) = _external_only($self, $xoids, $eml);
	$idx->ipc_do('update_vmd', $smsg->{num}, $vmd_mod);
	sto_export_kw($self, $smsg->{num}, $vmd_mod);
}

# set or update keywords for external message, called via ipc_do
sub set_xvmd {
	my ($self, $xoids, $eml, $vmd) = @_;

	my ($eidx, $tl) = eidx_init($self);
	my $oidx = $eidx->{oidx};
	my %seen;

	_schedule_checkpoint $self;

	# see if we can just update existing docs
	for my $oid (keys %$xoids) {
		my $docid = oid2docid($self, $oid) // next;
		delete $xoids->{$oid}; # all done with this oid
		next if $seen{$docid}++;
		my $idx = $eidx->idx_shard($docid);
		$idx->ipc_do('set_vmd', $docid, $vmd);
		sto_export_kw($self, $docid, $vmd);
	}
	return unless scalar(keys(%$xoids));

	# n.b. we don't do _docids_for here, we expect the caller
	# already checked $lse->kw_changed before calling this sub

	return unless (@{$vmd->{kw} // []}) || (@{$vmd->{L} // []});
	# totally unseen:
	my ($smsg, $idx) = _external_only($self, $xoids, $eml);
	$idx->ipc_do('add_vmd', $smsg->{num}, $vmd);
	sto_export_kw($self, $smsg->{num}, $vmd);
}

sub check_done {
	my ($self) = @_;
	$self->git->cat_active ?
		add_uniq_timer("$self-check_done", 5, \&check_done, $self) :
		done($self);
}

sub xchg_stderr {
	my ($self) = @_;
	_tail_err($self) if $self->{-err_wr};
	my $dir = $self->{priv_eidx}->{topdir};
	return unless -e $dir;
	delete $self->{-tmp_err};
	my ($err, $name) = tmpnam();
	open STDERR, '>>', $name;
	unlink $name; # ignore errors
	STDERR->autoflush(1); # shared with shard subprocesses
	$self->{-tmp_err} = $err; # separate file description for RO access
	undef;
}

sub _commit ($$) {
	my ($self, $cmd) = @_; # cmd is 'done' or 'barrier'
	my ($errfh, $lei_sock) = @$self{0, 1}; # via sto_barrier_request
	my @err;
	if ($self->{im}) {
		eval { $self->{im}->$cmd };
		push(@err, "E: import $cmd: $@\n") if $@;
	}
	delete $self->{lms};
	eval { $self->{priv_eidx}->$cmd };
	push(@err, "E: priv_eidx $cmd: $@\n") if $@;
	print { $errfh // \*STDERR } @err;
	eval { send_pkt $lei_sock, 'child_error 256' } if @err && $lei_sock;
	xchg_stderr($self);
	die @err if @err;
	# $lei_sock goes out-of-scope and script/lei can terminate
}

sub barrier {
	my ($self) = @_;
	_commit $self, 'barrier';
	add_uniq_timer("$self-check_done", 5, \&check_done, $self);
	undef;
}

sub done { _commit $_[0], 'done' }

sub ipc_atfork_child {
	my ($self) = @_;
	my $lei = $self->{lei};
	$lei->_lei_atfork_child(1) if $lei;
	xchg_stderr($self);
	if (my $to_close = delete($self->{to_close})) {
		close($_) for @$to_close;
	}
	openlog('lei/store', 'pid,nowait,nofatal,ndelay', 'user');
	$self->SUPER::ipc_atfork_child;
}

sub recv_and_run {
	my ($self, @args) = @_;
	local $PublicInbox::DS::in_loop = 0; # waitpid synchronously
	$self->SUPER::recv_and_run(@args);
}

sub _sto_atexit { # awaitpid cb
	my ($pid) = @_;
	warn "lei/store PID:$pid died \$?=$?\n" if $?;
}

sub write_prepare {
	my ($self, $lei) = @_;
	$lei // die 'BUG: $lei not passed';
	unless ($self->{-wq_s1}) {
		my $dir = $lei->store_path;
		substr($dir, -length('/lei/store'), 10, '');
		pipe(my $r, my $w);
		$w->autoflush(1);
		# Mail we import into lei are private, so headers filtered out
		# by -mda for public mail are not appropriate
		local @PublicInbox::MDA::BAD_HEADERS = ();
		local $SIG{ALRM} = 'IGNORE';
		$self->wq_workers_start("lei/store $dir", 1, $lei->oldset, {
					lei => $lei,
					-err_wr => $w,
					to_close => [ $r ],
				}, \&_sto_atexit);
		PublicInbox::LeiStoreErr->new($r, $lei);
	}
	$lei->{sto} = $self;
}

1;
