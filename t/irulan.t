#!perl
#
# test the irulan(1) command line interface

use strict;
use warnings;
use feature qw(state);
use File::Spec::Functions qw(catfile);
use File::Temp qw(tempdir);
use Mojo::SQLite;
use Test::More;
use Test::UnixCmdWrap;
use Web::Irulan::Model::Hostkeys;

# init an empty database, somewhere
BEGIN {
    my $clean = $ENV{IRULAN_KEEPDB} ? 0 : 1;
    my $dir   = tempdir("irulan.XXXXXXXXXX", CLEANUP => $clean, TMPDIR => 1);
    $ENV{IRULAN_DB_PATH} = catfile($dir, 'irulan.db');
    diag "IRULAN_DB_PATH=$ENV{IRULAN_DB_PATH}" unless $clean;
}
my $msl = Mojo::SQLite->new->from_filename($ENV{IRULAN_DB_PATH});
my $wmh = Web::Irulan::Model::Hostkeys->new(sqlite => $msl);
$wmh->sqlite->auto_migrate(1)->migrations->name('irulan')
  ->from_file('schema/irulan.sql');

my $db = $wmh->sqlite->db;

# did the schema load? (and are there no systems already?)
is $db->query(q{SELECT COUNT(*) FROM systems})->array->[0], 0;

my $irulan = Test::UnixCmdWrap->new(cmd => './script/irulan');

$irulan->run(status => 64, stderr => qr/^Usage: /);
$irulan->run(status => 64, stderr => qr/^Usage: /, args => '-h');

my $uuid_re =
  qr{[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}};

# same as x.pub
my $edkey =
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRKsmsvI5XgFhpxI97PB5KvEKlxwM1jCbojuhZDX/Ds';

# insert key as new system
$irulan->run(args => 'cat t/x.pub');

is $db->query(q{SELECT COUNT(*) FROM systems})->array->[0], 1;

my ($sysid, $info) = @{ $db->query(q{SELECT sysid,info FROM systems})->array };
like $info, qr/^cat \d+/;
is $db->query(q{SELECT COUNT(*) FROM sshkeys})->array->[0], 1;

my ($refid, $pubkey) =
  @{ $db->query(q{SELECT sysid,pubkey FROM sshkeys})->array };
is $sysid,  $refid;
is $pubkey, $edkey;

# list is for systems with associated host records, so nothing there yet
$irulan->run(args => 'list');

# new key should be unhosted, lacking a host record
$irulan->run(args => 'unhosted', stdout => qr/^$sysid $uuid_re cat \d+$/);

# in theory there should be a "localhost" entry that points to 127.0.0.1
# in practice folks break DNS or /etc/hosts in strange ways
diag 'NOTE tests may fail if getaddrinfo/localhost is broken';

$irulan->run(args => "addhost $sysid localhost");

# sysid now associated with hostname
$irulan->run(args => 'list', stdout => qr/^$sysid localhost$/);

# NOTE DNS or /etc/hosts results may not be portable hence the loose match
$irulan->run(args => 'ssh_known_hosts', stdout => qr/^\S*localhost\S+ $edkey/);

$irulan->run(args => '-n ssh_known_hosts', stdout => qr/^localhost $edkey/);

# nothing more recent than now (unless the system clock meanwhile has
# gone backwards to before when the above records where added)
my $now = time();
$irulan->run(args => "ssh_known_hosts -n $now", status => 2);
# and hopefully we're past the zero epoch and that 2038 related problems
# have all been dealt with
$irulan->run(args => '-n ssh_known_hosts 0', stdout => qr/^localhost $edkey/);

# IP addresses should in theory be canonified by inet_* calls
my $randport = 1024 + int rand 100;
$irulan->run(
    args => "-n addhost $sysid 0000:0000:0000:0000:0000:0000:0000:0001 $randport");
$irulan->run(
    args   => 'list',
    stdout => qr/^$sysid ::1 $randport\n$sysid localhost$/
);
$irulan->run(
    args   => '-n ssh_known_hosts',
    stdout => qr/^\[::1\]:$randport $edkey\nlocalhost $edkey/
);

$irulan->run(args => "rmhost ::1 $randport");

$irulan->run(args => 'list', stdout => qr/^$sysid localhost$/);

# NOTE $^X may not be portable, see perldoc -v '$^X'
$irulan->run(
    args   => qq(-P "$^X -E 'say shift; exit 42'" rmsystem $sysid),
    status => 42,
    stdout => qr/^rmsystem$/
);

$irulan->run(args => 'list');

if ($ENV{IRULAN_KEYSCAN}) {
    my ($host, $port) = split ' ', $ENV{IRULAN_KEYSCAN}, 2;
    $port = (defined $port and $port != 22) ? " $port" : '';
    # ssh-keyscan may produce noise on stderr
    $irulan->run(args => "keyscan -n $host$port", stderr => qr/^/);
    $irulan->run(args => 'unhosted', stdout => qr/^\d+ $uuid_re $host$port$/a);

    my ($sysid, $info) = @{ $db->query(q{SELECT sysid,info FROM systems})->array };
    $irulan->run(args => "addhost $sysid $host $port");
    $ENV{IRULAN_AUDIT_CMD} = './ssh-hkaudit' unless exists $ENV{IRULAN_AUDIT_CMD};
    $irulan->run(args => "audit $host $port", stdout => qr/^$host.*ok$/);
} else {
    diag 'set IRULAN_KEYSCAN to test keyscan and audit support';
}

done_testing();
