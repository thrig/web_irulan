#!perl
#
# test the /ssh/hostkeys interface that is used for client ssh
# hostkey uploads

use Mojo::Base -strict;

use Data::UUID;
use File::Spec::Functions qw(catfile);
use File::Temp qw(tempdir);
use Test::Mojo;
use Test::More;

BEGIN {
    my $dir = tempdir("irulan.XXXXXXXXXX", CLEANUP => 1, TMPDIR => 1);
    $ENV{IRULAN_DB_PATH} = catfile($dir, 'irulan.db');
}
my $t = Test::Mojo->new('Web::Irulan');

my $authkey = $t->app->plugin('Config')->{authkey};
my $uuid    = Data::UUID->new->create_str;
my $edkey =
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRKsmsvI5XgFhpxI97PB5KvEKlxwM1jCbojuhZDX/Ds';

$t->get_ok('/')->status_is(200)->content_like(qr/Irulan/);

sub post_ssh_hostkeys {
    my (%param) = @_;
    $param{headers} //= {};
    $param{form}    //= {};
    my $req = $t->ua->build_tx(
        POST => '/ssh/hostkeys' => $param{headers} => form => $param{form});
    $t->request_ok($req)->status_is($param{status})
      ->json_like(%{ $param{content} });
}

# various invalid conditions
post_ssh_hostkeys(status => 401, content => { '/error' => qr/unauthorized/ });
post_ssh_hostkeys(
    headers => { 'X-Irulan-Auth' => $authkey },
    status  => 401,
    content => { '/error' => qr/unidentified/ }
);
post_ssh_hostkeys(
    headers => { 'X-Irulan-Auth' => $authkey, 'X-Irulan-ID' => "bad" },
    status  => 401,
    content => { '/error' => qr/unidentified/ }
);
post_ssh_hostkeys(
    headers => { 'X-Irulan-Auth' => $authkey, 'X-Irulan-ID' => $uuid },
    status  => 406,
    content => { '/error' => qr/invalid request/ }
);
post_ssh_hostkeys(
    headers => { 'X-Irulan-Auth' => $authkey, 'X-Irulan-ID' => $uuid },
    form    => { in              => '' },
    status  => 406,
    content => { '/error' => qr/invalid request/ }
);
post_ssh_hostkeys(
    headers => { 'X-Irulan-Auth' => $authkey, 'X-Irulan-ID' => $uuid },
    form    => { in              => "bad" },
    status  => 406,
    content => { '/error' => qr/no keys found/ }
);
# and finally a valid key upload?
post_ssh_hostkeys(
    headers => { 'X-Irulan-Auth' => $authkey, 'X-Irulan-ID' => $uuid },
    form    => { in              => $edkey },
    status  => 200,
    content => { '/id' => qr/^\d+$/a }
);
# ... that should fail should the UUID be reused
post_ssh_hostkeys(
    headers => { 'X-Irulan-Auth' => $authkey, 'X-Irulan-ID' => $uuid },
    form    => { in              => $edkey },
    status  => 500,
    content => { '/error' => qr/internal error/ }
);

done_testing();
