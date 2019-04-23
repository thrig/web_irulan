# -*- Perl -*-
#
# handles client SSH host key uploads

package Web::Irulan::Controller::Ssh;
use Mojo::Base 'Mojolicious::Controller';

use Data::SSHPubkey;
use Irulan::DB;
use Sys::Syslog qw(openlog syslog);

openlog( 'irulan', 'ndelay,pid', 'LOG_USER' );

my $uuid_re =
  qr{[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}};

sub response {
    my $self   = shift;
    my %params = @_;
    syslog( 'warning', $params{syslog} ) if exists $params{syslog};
    $params{status} = 200 unless exists $params{status};
    return $self->render(
        format => 'txt',
        text   => $params{text} . "\n",
        status => $params{status},
    );
}

sub hostkeys {
    my $self   = shift;
    my $remote = $self->tx->remote_address;
    # since anyone with access to the server can upload, at least
    # prevent invalid UUID from getting into the database
    my $uuid = $self->req->headers->header('X-Irulan-ID');
    if ( !defined $uuid or $uuid !~ m/$uuid_re/ ) {
        return response(
            $self,
            syslog => 'no or invalid UUID from ' . $remote,
            text   => 'not ok - unauthenticated',
            status => 401
        );
    }
    my $input = $self->param('in');
    if ( !defined $input ) {
        return response(
            $self,
            syslog => 'invalid request from ' . $remote,
            text   => 'not ok - invalid request',
            status => 406
        );
    }
    # TODO need to strip out PEM PKCS8 RFC4716 types, or use ssh-keygen
    # to instead convert them
    my $pubkeys = Data::SSHPubkey::pubkeys( \$input );
    if (@$pubkeys) {
        # IP address of client given as info to help relate random UUID
        # to an IP address (which SLAAC or NAT can confound)
        my ( $sysid, $msg ) =
          Irulan::DB::new_system( $uuid, $remote, map { $_->[1] } @$pubkeys );
        if ( defined $sysid ) {
            return response(
                $self,
                syslog => "new hostkeys remote=$remote sysid=$sysid uuid=$uuid keys="
                  . scalar @$pubkeys,
                text => $sysid
            );
        } else {
            # mostly likely cause would be a client reusing a previous
            # UUID while uploading new keys -- probably want that to be
            # a manual intervention to reset the client UUID or to clear
            # database entries for host first
            # (my systems get blown away on reinstall so reuse is not
            # much of a problem)
            return response(
                $self,
                syslog => "failed to save keys from remote=$remote uuid=$uuid msg=$msg",
                text   => 'not ok - internal error',
                status => 500
            );
        }
    } else {
        return response(
            $self,
            syslog => "failed to parse keys from remote=$remote uuid=$uuid",
            text   => 'not ok - no keys found',
            status => 406
        );
    }
}

1;
