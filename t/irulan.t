#!perl
#
# test the irulan(1) command line interface

use strict;
use warnings;
use feature qw(state);
use File::Spec::Functions qw(catfile);
use File::Temp qw(tempdir);
use Mojo::SQLite;
use Test::Cmd;
use Test::More;
use Test::UnixExit;
use Web::Irulan::Model::Hostkeys;

# init an empty database, somewhere (to debug, set CLEANUP => 0 and then
# inspect the resulting irulan.db in the temporary directory)
BEGIN {
    my $dir = tempdir("irulan.XXXXXXXXXX", CLEANUP => 1, TMPDIR => 1);
    $ENV{IRULAN_DB_PATH} = catfile($dir, 'irulan.db');
    #diag "IRULAN_DB_PATH=$ENV{IRULAN_DB_PATH}";
}
my $msl = Mojo::SQLite->new->from_filename($ENV{IRULAN_DB_PATH});
my $wmh = Web::Irulan::Model::Hostkeys->new(sqlite => $msl);
$wmh->sqlite->auto_migrate(1)->migrations->name('irulan')
  ->from_file('schema/irulan.sql');

my $db = $wmh->sqlite->db;

# did the schema load? (and are there no systems already?)
is $db->query(q{SELECT COUNT(*) FROM systems})->array->[0], 0;

sub irulan {
    my %t = @_;
    state $cmd = Test::Cmd->new(prog => './script/irulan', workdir => '',);
    $t{status} //= 0;
    $t{stdout} //= qr/^$/;
    $t{stderr} //= qr/^$/;

    $cmd->run(exists $t{args} ? (args => $t{args}) : ());
    $t{args} //= '';

    exit_is($?, $t{status}, "STATUS irulan $t{args}");
    ok($cmd->stdout =~ m/$t{stdout}/, "STDOUT irulan $t{args}")
      or diag 'STDOUT: ' . ($cmd->stdout // '');
    ok($cmd->stderr =~ m/$t{stderr}/, "STDERR irulan $t{args}")
      or diag 'STDERR: ' . ($cmd->stderr // '');
}

irulan status => 64, stderr => qr/^Usage: /;
irulan status => 64, stderr => qr/^Usage: /, args => '-h';

my $uuid_re =
  qr{[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}};

# same as x.pub
my $edkey =
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRKsmsvI5XgFhpxI97PB5KvEKlxwM1jCbojuhZDX/Ds';

# insert key as new system
irulan args => 'cat t/x.pub';

is $db->query(q{SELECT COUNT(*) FROM systems})->array->[0], 1;

my ($sysid, $info) = @{ $db->query(q{SELECT sysid,info FROM systems})->array };
is $info, 'stdin';
is $db->query(q{SELECT COUNT(*) FROM sshkeys})->array->[0], 1;

my ($refid, $pubkey) =
  @{ $db->query(q{SELECT sysid,pubkey FROM sshkeys})->array };
is $sysid,  $refid;
is $pubkey, $edkey;

# list is for systems with associated host records, so nothing there yet
irulan args => 'list';

# new key should be unhosted, lacking a host record
irulan args => 'unhosted', stdout => qr/^$sysid $uuid_re stdin$/;

# in theory there should be a "localhost" entry that points to 127.0.0.1
# in practice folks break DNS or /etc/hosts in strange ways
diag 'NOTE tests may fail if getaddrinfo/localhost is broken';

irulan args => "addhost $sysid localhost";

# sysid now associated with hostname
irulan args => 'list', stdout => qr/^$sysid localhost$/;

# ssh_known_hosts (w/ w/o epoch) (w/ w/o -n)
# NOTE DNS or /etc/hosts results may not be portable hence the loose match
irulan args => 'ssh_known_hosts', stdout => qr/^\S*localhost\S+ $edkey/;

irulan args => '-n ssh_known_hosts', stdout => qr/^localhost $edkey/;

# nothing more recent than now (unless the system clock meanwhile has
# gone backwards to before when the above records where added)
my $now = time();
irulan args => "ssh_known_hosts -n $now", status => 2;
# and hopefully we're past the zero epoch and that 2038 related problems
# have all been dealt with
irulan args => '-n ssh_known_hosts 0', stdout => qr/^localhost $edkey/;

my $randport = 1024 + int rand 100;
irulan args => "-n addhost $sysid 127.0.0.1 $randport";
irulan
  args   => 'list',
  stdout => qr/^$sysid 127.0.0.1 $randport\n$sysid localhost$/;
irulan
  args   => '-n ssh_known_hosts',
  stdout => qr/^\[127.0.0.1\]:$randport $edkey\nlocalhost $edkey/;

irulan args => "rmhost 127.0.0.1 $randport";

irulan args => 'list', stdout => qr/^$sysid localhost$/;

# NOTE $^X may not be portable, see perldoc -v '$^X'
irulan args => qq(-P "$^X -e 'exit 42'" rmsystem $sysid), status => 42;

irulan args => 'list';

if ($ENV{IRULAN_KEYSCAN}) {
    my ($host, $port) = split ' ', $ENV{IRULAN_KEYSCAN}, 2;
    $port = (defined $port and $port != 22) ? " $port" : '';
    # ssh-keyscan may produce noise on stderr
    irulan args => "keyscan -n $host$port", stderr => qr/^/;
    irulan args => 'unhosted', stdout => qr/^\d+ $uuid_re $host$port$/a;
} else {
    diag 'set IRULAN_KEYSCAN to test keyscan support';
}

done_testing();
