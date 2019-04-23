# -*- Perl -*-

package Web::Irulan;
use Mojo::Base 'Mojolicious';

sub startup {
    my $self   = shift;
    my $config = $self->plugin('Config');
    $self->secrets( $config->{secrets} );

    my $r = $self->routes;

    $r->post('/ssh/hostkeys')->to('ssh#hostkeys');

    $r->get( '/' => sub { $_[0]->render( format => 'txt', text => 'Irulan' ) } );
}

1;
