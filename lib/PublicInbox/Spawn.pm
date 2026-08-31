# Copyright (C) all contributors <meta@public-inbox.org>
# License: AGPL-3.0+ <https://www.gnu.org/licenses/agpl-3.0.txt>
#
# This allows vfork to be used for spawning subprocesses if
# ~/.cache/public-inbox/inline-c is writable or if PERL_INLINE_DIRECTORY
# is explicitly defined in the environment (and writable).
# Under Linux, vfork can make a big difference in spawning performance
# as process size increases (fork still needs to mark pages for CoW use).
# None of this is intended to be thread-safe since Perl5 maintainers
# officially discourage the use of threads.
#
# n.b. consider dropping Inline::C for SCM_RIGHTS in favor of `syscall'
# and use pack templates (with help from devel/sysdefs-list).
#
# We only need (Inline::C || XS) to support vfork(2) since Perl can't
# guarantee a child won't modify global state.  `syscall' and pack/unpack
# ought to handle everything else.
#
# We don't want too many DSOs: https://udrepper.livejournal.com/8790.html
# and can rely on devel/sysdefs-list to write (or even generate) `pack'
# perlop templates.

package PublicInbox::Spawn;
use v5.12;
use parent qw(Exporter);
use PublicInbox::Lock;
use Fcntl qw(SEEK_SET);
use IO::Handle ();
use Carp qw(croak);
use PublicInbox::IO;
our @EXPORT_OK = qw(which spawn popen_rd popen_wr run_die run_wait run_qx);
our (@RLIMITS, %RLIMITS);
use autodie qw(close open pipe seek sysseek truncate);

BEGIN {
	@RLIMITS = qw(RLIMIT_CPU RLIMIT_CORE RLIMIT_DATA);
	my $all_libc = qq[#line ${\__LINE__} "${\__FILE__}"\n]. <<'ALL_LIBC';
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>

/*
 * From the av_len apidoc:
 *   Note that, unlike what the name implies, it returns
 *   the highest index in the array, so to get the size of
 *   the array you need to use "av_len(av) + 1".
 *   This is unlike "sv_len", which returns what you would expect.
 */
#define AV2C_COPY(dst, src) do { \
	static size_t dst##__capa; \
	I32 i; \
	I32 top_index = av_len(src); \
	I32 real_len = top_index + 1; \
	I32 capa = real_len + 1; \
	if (capa > dst##__capa) { \
		dst##__capa = 0; /* in case Newx croaks */ \
		Safefree(dst); \
		Newx(dst, capa, char *); \
		dst##__capa = capa; \
	} \
	for (i = 0; i < real_len; i++) { \
		SV **sv = av_fetch(src, i, 0); \
		dst[i] = SvPV_nolen(*sv); \
	} \
	dst[real_len] = 0; \
} while (0)

/* needs to be safe inside a vfork'ed process */
static void exit_err(const char *fn, volatile int *cerrnum)
{
	*cerrnum = errno;
	write(2, fn, strlen(fn));
	_exit(1);
}

/*
 * unstable internal API.  It'll be updated depending on
 * whatever we'll need in the future.
 * Be sure to update PublicInbox::SpawnPP if this changes
 */
int pi_fork_exec(SV *redirref, SV *file, SV *cmdref, SV *envref, SV *rlimref,
		 const char *cd, int pgid)
{
	AV *redir = (AV *)SvRV(redirref);
	AV *cmd = (AV *)SvRV(cmdref);
	AV *env = (AV *)SvRV(envref);
	AV *rlim = (AV *)SvRV(rlimref);
	const char *filename = SvPV_nolen(file);
	pid_t pid = -1;
	static char **argv, **envp;
	sigset_t set, old;
	int ret, perrnum;
	volatile int cerrnum = 0; /* shared due to vfork */
	int chld_is_member; /* needed due to shared memory w/ vfork */
	I32 max_fd = av_len(redir);

	AV2C_COPY(argv, cmd);
	AV2C_COPY(envp, env);

	if (sigfillset(&set)) goto out;
	if (sigdelset(&set, SIGABRT)) goto out;
	if (sigdelset(&set, SIGBUS)) goto out;
	if (sigdelset(&set, SIGFPE)) goto out;
	if (sigdelset(&set, SIGILL)) goto out;
	if (sigdelset(&set, SIGSEGV)) goto out;
	/* no XCPU/XFSZ here */
	if (sigprocmask(SIG_SETMASK, &set, &old)) goto out;
	chld_is_member = sigismember(&old, SIGCHLD);
	if (chld_is_member < 0) goto out;
	if (chld_is_member > 0 && sigdelset(&old, SIGCHLD)) goto out;

	pid = vfork();
	if (pid == 0) {
		int sig;
		I32 i, child_fd, max_rlim;

		for (child_fd = 0; child_fd <= max_fd; child_fd++) {
			SV **parent = av_fetch(redir, child_fd, 0);
			int parent_fd = SvIV(*parent);
			if (parent_fd == child_fd)
				continue;
			if (dup2(parent_fd, child_fd) < 0)
				exit_err("dup2", &cerrnum);
		}
		if (pgid >= 0 && setpgid(0, pgid) < 0)
			exit_err("setpgid", &cerrnum);
		for (sig = 1; sig < NSIG; sig++)
			signal(sig, SIG_DFL); /* ignore errors on signals */
		if (*cd && chdir(cd) < 0) {
			write(2, "cd ", 3);
			exit_err(cd, &cerrnum);
		}

		max_rlim = av_len(rlim);
		for (i = 0; i < max_rlim; i += 3) {
			struct rlimit rl;
			SV **res = av_fetch(rlim, i, 0);
			SV **soft = av_fetch(rlim, i + 1, 0);
			SV **hard = av_fetch(rlim, i + 2, 0);

			rl.rlim_cur = SvIV(*soft);
			rl.rlim_max = SvIV(*hard);
			if (setrlimit(SvIV(*res), &rl) < 0)
				exit_err("setrlimit", &cerrnum);
		}

		(void)sigprocmask(SIG_SETMASK, &old, NULL);
		execve(filename, argv, envp);
		exit_err("execve", &cerrnum);
	}
	perrnum = errno;
	if (chld_is_member > 0)
		sigaddset(&old, SIGCHLD);
	ret = sigprocmask(SIG_SETMASK, &old, NULL);
	assert(ret == 0 && "BUG calling sigprocmask to restore");
	if (cerrnum) {
		int err_fd = STDERR_FILENO;
		if (err_fd <= max_fd) {
			SV **parent = av_fetch(redir, err_fd, 0);
			err_fd = SvIV(*parent);
		}
		if (pid > 0)
			waitpid(pid, NULL, 0);
		pid = -1;
		/* continue message started by exit_err in child */
		dprintf(err_fd, ": %s\n", strerror(cerrnum));
		errno = cerrnum;
	} else if (perrnum) {
		errno = perrnum;
	}
out:
	if (pid < 0)
		croak("E: fork_exec %s: %s\n", filename, strerror(errno));
	return (int)pid;
}

static int sendmsg_retry(long *tries)
{
	const struct timespec req = { 0, 100000000 }; /* 100ms */
	int err = errno;
	switch (err) {
	case EINTR: PERL_ASYNC_CHECK(); return 1;
	case ENOBUFS: case ENOMEM: case ETOOMANYREFS:
		if (*tries-- == 0) return 0;
		if (!(*tries & 15))
			fprintf(stderr,
				"# sleeping on sendmsg: %s (%ld tries left)\n",
				strerror(err), *tries);
		nanosleep(&req, NULL);
		PERL_ASYNC_CHECK();
		return 1;
	default: return 0;
	}
}

#if defined(CMSG_SPACE) && defined(CMSG_LEN)
#define SEND_FD_CAPA 11
#define SEND_FD_SPACE (SEND_FD_CAPA * sizeof(int))
union my_cmsg {
	struct cmsghdr hdr;
	char pad[sizeof(struct cmsghdr) + 16 + SEND_FD_SPACE];
};

SV *send_cmd4_(PerlIO *s, SV *sio, SV *data, int flags, long tries)
{
	struct msghdr msg = { 0 };
	union my_cmsg cmsg = { 0 };
	STRLEN dlen = 0;
	struct iovec iov;
	ssize_t sent;
	I32 i;
	int *fdp;
	AV *io = SvROK(sio) ? (AV *)SvRV(sio) : NULL;
	I32 nfds = io ? (I32)(av_len(io) + 1) : 0;

	if (SvOK(data)) {
		iov.iov_base = SvPV(data, dlen);
		iov.iov_len = dlen;
	}
	if (!dlen) { /* must be non-zero */
		iov.iov_base = &msg.msg_namelen; /* whatever */
		iov.iov_len = 1;
	}
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (nfds) {
		if (nfds > SEND_FD_CAPA) {
			fprintf(stderr, "FIXME: bump SEND_FD_CAPA=%d\n", nfds);
			nfds = SEND_FD_CAPA;
		}
		msg.msg_control = &cmsg.hdr;
		msg.msg_controllen = CMSG_SPACE(nfds * sizeof(int));
		cmsg.hdr.cmsg_level = SOL_SOCKET;
		cmsg.hdr.cmsg_type = SCM_RIGHTS;
		cmsg.hdr.cmsg_len = CMSG_LEN(nfds * sizeof(int));
		fdp = (int *)CMSG_DATA(&cmsg.hdr);
		for (i = 0; i < nfds; i++) {
			SV **svio = av_fetch(io, i, 0);
			*fdp++ = PerlIO_fileno(IoIFP(sv_2io(*svio)));
		}
	}
	do {
		sent = sendmsg(PerlIO_fileno(s), &msg, flags);
	} while (sent < 0 && sendmsg_retry(&tries));
	return sent >= 0 ? newSViv(sent) : &PL_sv_undef;
}

static SV *my_fdopen(int fd)
{
	GV *gv = newGVgen("PublicInbox::Spawn");
	SV *ret = newRV_noinc((SV*)gv);
	IO *io = GvIOn(gv);
	IoTYPE(io) = '+';
	IoIFP(io) = PerlIO_fdopen(fd, "r");
	IoOFP(io) = PerlIO_fdopen(fd, "w");
	sv_bless(ret, gv_stashpv("IO::File", TRUE));

	return ret;
}

void recv_cmd4(PerlIO *s, SV *buf, STRLEN n)
{
	union my_cmsg cmsg = { 0 };
	struct msghdr msg = { 0 };
	struct iovec iov;
	ssize_t i;
	Inline_Stack_Vars;
	Inline_Stack_Reset;

	if (!SvOK(buf))
		sv_setpvn(buf, "", 0);
	iov.iov_base = SvGROW(buf, n + 1);
	iov.iov_len = n;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsg.hdr;
	msg.msg_controllen = CMSG_SPACE(SEND_FD_SPACE);

	for (;;) {
		i = recvmsg(PerlIO_fileno(s), &msg, 0);
		if (i >= 0 || errno != EINTR) break;
		PERL_ASYNC_CHECK();
	}
	if (i >= 0) {
		SvCUR_set(buf, i);
		if (cmsg.hdr.cmsg_level == SOL_SOCKET &&
				cmsg.hdr.cmsg_type == SCM_RIGHTS) {
			size_t len = cmsg.hdr.cmsg_len;
			int *fd = (int *)CMSG_DATA(&cmsg.hdr);
			for (i = 0; CMSG_LEN((i + 1) * sizeof(int)) <= len; i++)
				Inline_Stack_Push(sv_2mortal(my_fdopen(*fd++)));
		}
		Inline_Stack_Done;
		if (msg.msg_flags & (MSG_CTRUNC|MSG_TRUNC))
			croak("recvmsg %zu => %zd trunc %d\n",
				(size_t)n, i, msg.msg_flags);
	} else {
		Inline_Stack_Push(&PL_sv_undef);
		SvCUR_set(buf, 0);
		Inline_Stack_Done;
	}
}
#endif /* defined(CMSG_SPACE) && defined(CMSG_LEN) */

void rlimit_map()
{
	Inline_Stack_Vars;
	Inline_Stack_Reset;
ALL_LIBC
	my $inline_dir = $ENV{PERL_INLINE_DIRECTORY} // (
			$ENV{XDG_CACHE_HOME} //
			( ($ENV{HOME} // '/nonexistent').'/.cache' )
		).'/public-inbox/inline-c';
	undef $all_libc unless -d $inline_dir;
	if (defined $all_libc) {
		$all_libc .= qq[#line ${\__LINE__} "${\__FILE__}"\n];
		for (@RLIMITS, 'RLIM_INFINITY') {
			$all_libc .= <<EOM;
	Inline_Stack_Push(sv_2mortal(newSVpvs("$_")));
	Inline_Stack_Push(sv_2mortal(newSViv($_)));
EOM
		}
		$all_libc .= <<EOM;
	Inline_Stack_Done;
} // rlimit_map
EOM
		local $ENV{PERL_INLINE_DIRECTORY} = $inline_dir;
		# CentOS 7.x ships Inline 0.53, 0.64+ has built-in locking
		my $lk = PublicInbox::Lock->new($inline_dir.
						'/.public-inbox.lock');
		my $fh = $lk->lock_acquire;
		open my $oldout, '>&', \*STDOUT;
		open my $olderr, '>&', \*STDERR;
		open STDOUT, '>&', $fh;
		open STDERR, '>&', $fh;
		STDERR->autoflush(1);
		STDOUT->autoflush(1);
		my $have_inline;
		eval {
			require Inline;
			$have_inline = 1;
			Inline->import(C => $all_libc, BUILD_NOISY => 1);
		};
		my $err = $have_inline ? $@ : ($all_libc = undef);
		open(STDERR, '>&', $olderr);
		open(STDOUT, '>&', $oldout);
		if ($err) {
			seek($fh, 0, SEEK_SET);
			my @msg = <$fh>;
			truncate($fh, 0);
			warn "Inline::C build failed:\n", $err, "\n", @msg;
			$all_libc = undef;
		}
	}
	if (defined $all_libc) { # set for Lg2
		$ENV{PERL_INLINE_DIRECTORY} = $inline_dir;
		%RLIMITS = rlimit_map();
		*send_cmd4 = sub ($$$$;$) {
			send_cmd4_($_[0], $_[1], $_[2], $_[3], $_[4] // 50);
		};
	} else {
		require PublicInbox::SpawnPP;
		*pi_fork_exec = \&PublicInbox::SpawnPP::pi_fork_exec
	}
} # /BEGIN

sub which ($) {
	my ($file) = @_;
	return $file if index($file, '/') >= 0;
	for my $p (split(/:/, $ENV{PATH})) {
		$p .= "/$file";
		return $p if (-x $p && ! -d _);
	}
	undef;
}

sub spawn ($;$$) {
	my ($cmd, $env, $opt) = @_;
	my $f = which($cmd->[0]) // die "$cmd->[0]: command not found\n";
	my (@env, @rdr);
	my %env = (%ENV, $env ? %$env : ());
	while (my ($k, $v) = each %env) {
		push @env, "$k=$v" if defined($v);
	}
	for my $child_fd (0..2) {
		my $pfd = $opt->{$child_fd};
		if ('SCALAR' eq ref($pfd)) {
			open my $fh, '+>', undef;
			$opt->{"fh.$child_fd"} = $fh; # for read_out_err
			if ($child_fd == 0) {
				print $fh $$pfd;
				$fh->flush or die "$fh->flush: $!";
				sysseek($fh, 0, SEEK_SET);
			}
			$pfd = fileno($fh);
		} elsif (defined($pfd) && $pfd !~ /\A[0-9]+\z/) {
			my $fd = fileno($pfd) //
					croak "BUG: $pfd not an IO GLOB? $!";
			$pfd = $fd;
		}
		$rdr[$child_fd] = $pfd // $child_fd;
	}
	my $rlim = [];
	foreach my $l (@RLIMITS) {
		my $v = $opt->{$l} // next;
		my $r = $RLIMITS{$l} // eval {
				require BSD::Resource;
				my $rl = BSD::Resource::get_rlimits();
				@RLIMITS{@RLIMITS} = @$rl{@RLIMITS};
				$RLIMITS{$l};
			} // do {
				warn "$l undefined by BSD::Resource: $@\n";
				next;
			};
		push @$rlim, $r, @$v;
	}
	my $cd = $opt->{'-C'} // ''; # undef => NULL mapping doesn't work?
	my $pgid = $opt->{pgid} // -1;
	pi_fork_exec(\@rdr, $f, $cmd, \@env, $rlim, $cd, $pgid);
}

sub popen_rd {
	my ($cmd, $env, $opt, @cb_arg) = @_;
	pipe(my $r, local $opt->{1});
	PublicInbox::IO::attach_pid($r, spawn($cmd, $env, $opt), @cb_arg);
}

sub popen_wr {
	my ($cmd, $env, $opt, @cb_arg) = @_;
	pipe(local $opt->{0}, my $w);
	$w->autoflush(1);
	PublicInbox::IO::attach_pid($w, spawn($cmd, $env, $opt), @cb_arg);
}

sub read_out_err ($) {
	my ($opt) = @_;
	for my $fd (1, 2) { # read stdout/stderr
		my $fh = delete($opt->{"fh.$fd"}) // next;
		seek($fh, 0, SEEK_SET);
		PublicInbox::IO::read_all $fh, undef, $opt->{$fd};
	}
}

sub run_wait ($;$$) {
	my ($cmd, $env, $opt) = @_;
	waitpid(spawn($cmd, $env, $opt), 0);
	read_out_err($opt);
	$?
}

sub run_die ($;$$) {
	my ($cmd, $env, $rdr) = @_;
	run_wait($cmd, $env, $rdr) and croak "E: @$cmd failed: \$?=$?";
}

sub run_qx {
	my ($cmd, $env, $opt) = @_;
	my $fh = popen_rd($cmd, $env, $opt);
	my @ret;
	if (wantarray) {
		@ret = <$fh>;
	} else {
		local $/;
		$ret[0] = <$fh>;
	}
	$fh->close; # caller should check $?
	read_out_err($opt);
	wantarray ? @ret : $ret[0];
}

1;
