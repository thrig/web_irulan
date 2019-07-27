# -*- Perl -*-

package Web::Irulan;
use Mojo::Base 'Mojolicious';

use Web::Irulan::Model::Hostkeys;
use Mojo::SQLite;

sub startup {
    my ($self) = @_;

    my $config = $self->plugin('Config');
    $self->secrets($config->{secrets});

    $self->helper(
        sqlite => sub {
            state $sql =
              Mojo::SQLite->new->from_filename($ENV{IRULAN_DB_PATH} // 'irulan.db');
        }
    );
    $self->helper(
        hostkeys => sub {
            state $hkeys = Web::Irulan::Model::Hostkeys->new(sqlite => $_[0]->sqlite);
        }
    );

    my $path = $self->home->child(qw(schema irulan.sql));
    $self->sqlite->auto_migrate(1)->migrations->name('irulan')->from_file($path);

    # app may be running under some not-/ path that it will need to
    # know about
    if (my $path = $ENV{MOJO_REVERSE_PROXY}) {
        my @path_parts = grep /\S/, split m{/}, $path;
        $self->hook(
            before_dispatch => sub {
                my ($c)  = @_;
                my $url  = $c->req->url;
                my $base = $url->base;
                push @{ $base->path }, @path_parts;
                $base->path->trailing_slash(1);
                $url->path->leading_slash(0);
            }
        );
    }

    my $r = $self->routes;
    $r->get('/')->to(
        cb => sub {
            my ($c) = @_;
            $c->render(text => 'Irulan');
        }
    );

    my $ssh = $r->under(
        '/ssh' => sub {
            my ($c) = @_;
            my $token = $c->req->headers->header('X-Irulan-Auth') // '';
            return 1 if $token eq $config->{authkey};
            $c->render(json => { error => 'unauthorized' }, status => 401);
            return undef;
        }
    );
    $ssh->post('/hostkeys')->to('ssh#upload');
}

1;
