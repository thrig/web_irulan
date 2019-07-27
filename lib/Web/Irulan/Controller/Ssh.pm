# -*- Perl -*-
#
# handles client SSH host key uploads

package Web::Irulan::Controller::Ssh;
use Mojo::Base 'Mojolicious::Controller';

use Data::SSHPubkey;

my $uuid_re =
  qr{[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}};

sub upload {
    my ($self) = @_;
    my $remote = $self->tx->remote_address;
    my $logger = $self->app->log;
    my $resp   = { error => undef };
    my $status = 200;

    my $uuid = $self->req->headers->header('X-Irulan-ID');

    if (!defined $uuid or $uuid !~ m/$uuid_re/) {
        $logger->warn('no or invalid UUID from ' . $remote);
        $resp->{error} = 'unidentified';
        $status = 401;
        goto RESPONSE;
    }

    my $input = $self->param('in');

    if (!defined $input or !length $input) {
        $logger->warn('invalid request from ' . $remote);
        $resp->{error} = 'invalid request';
        $status = 406;
        goto RESPONSE;
    }

    my $pubkeys = Data::SSHPubkey::pubkeys(\$input);
    # NOTE this strips out the PEM PKCS8 RFC4716 types (which are
    # unlikely to be uploaded by an OpenSSH client)
    @$pubkeys =
      map { $_->[0] =~ m/^(ecdsa|ed25519|rsa)$/ ? $_->[1] : () } @$pubkeys;
    if (!@$pubkeys) {
        $logger->warn("failed to parse keys from remote=$remote uuid=$uuid");
        $resp->{error} = 'no keys found';
        $status = 406;
        goto RESPONSE;
    }

    # IP address of client given as info to help relate random UUID to a
    # host (which NAT or SLAAC can confound)
    my $sysid;
    eval { $sysid = $self->hostkeys->add_system($uuid, $remote, $pubkeys) };
    if ($@) {
        # mostly likely cause would be a client reusing a previous UUID
        # for new keys; clients must instead use a new UUID. or it could
        # be some other database error...
        $logger->warn("failed to save keys from remote=$remote uuid=$uuid msg=$@");
        $resp->{error} = 'internal error';
        $status = 500;
        goto RESPONSE;
    }

    $logger->warn("new hostkeys remote=$remote sysid=$sysid uuid=$uuid count="
          . scalar @$pubkeys);
    $resp->{id} = $sysid;

  RESPONSE:
    $self->render(json => $resp, status => $status);
}

1;
