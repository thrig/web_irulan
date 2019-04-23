# -*- Perl -*-
#
# some wrapper functions for the Irulan database

package Web::Irulan::DB;

use strict;
use warnings;
use Carp qw(croak);
use DBI;
use SQL::Abstract;

my $sql = SQL::Abstract->new;

# $dbh does not linger due to locking problems TODO improve that or
# instead upgrade to Mojo::Pg or something
sub db_connect {
    # TODO this needs to come from the Mojo config (or have something
    # like Ansible fill it in as necessary)
    my $dbh = DBI->connect( 'dbi:SQLite:dbname=/TODOFIXME/irulan.db',
        '', '', { AutoCommit => 0, RaiseError => 1 } );

    # NOTE be sure to also set this if fooling around via the sqlite3
    # command line interface. also this requires sqlite >= 3.6.19
    #
    # however this led to
    #   DBD::SQLite::db prepare failed: foreign key mismatch - "sshkeys" referencing "systems"
    # errors so while a nice idea too annoying in practice; let
    # application level logic deal with the relations as need be
    #$dbh->do("PRAGMA foreign_keys = ON");

    # KLUGE avoid the immediate failure if the database is locked;
    # DBD::SQLite (since 1.38_01) uses "BEGIN IMMEDIATE" to avoid
    # deferred locking problems
    $dbh->sqlite_busy_timeout(2000);

    return $dbh;
}

sub add_record {
    my $dbh    = shift;
    my $table  = shift;
    my %record = ( @_, mtime => scalar time() );
    my ( $statement, @bind ) = $sql->insert( $table, \%record );
    my $sth = $dbh->prepare($statement);
    $sth->execute(@bind);
    return $dbh->sqlite_last_insert_rowid();
}
sub add_system { add_record $_[0], 'systems', uuid => $_[1], info => $_[2] }
sub add_host { add_record $_[0], 'hosts', sysid => $_[1], hostname => $_[2] }
sub add_sshkey { add_record $_[0], 'sshkeys', sysid => $_[1], pubkey => $_[2] }

sub get_sysid {
    my ( $dbh, $sysid ) = @_;
    my $ret = $dbh->selectall_hashref( q{SELECT * FROM systems WHERE sysid = ?},
        'sysid', {}, $sysid );
    return $ret->{$sysid} // {};
}

# hostname and public keys associated with that hostname by the linking
# sysid; "new_host" links a sysid to a hostname while "new_system" is
# how the pubkeys for an (as yet unhosted) host get uploaded
sub host_pubkeys {
    my $dbh = db_connect;
    # this is complicated because there can be multiple host (CNAME,
    # multihomed firewalls, etc) entries for a given system so we here
    # first collect the hostnames associated with each system, then find
    # the pubkeys associated with each system (doing this in a single
    # SQL query is a bit beyond me)
    my $hosts;
    my $ret = $dbh->selectall_arrayref(q{SELECT sysid,hostname FROM hosts});
    for my $row (@$ret) {
        push @{ $hosts->{ $row->[0] }->{hosts} }, $row->[1];
    }
    my $sth = $dbh->prepare(q{SELECT pubkey FROM sshkeys WHERE sysid = ?});
    for my $sysid ( keys %$hosts ) {
        $hosts->{$sysid}->{id} = $sysid;
        $sth->execute($sysid);
        while ( my $row = $sth->fetchrow_arrayref ) {
            push @{ $hosts->{$sysid}->{pubkey} }, $row->[0];
        }
    }
    $dbh->disconnect;
    return $hosts;
}

sub list_hosts {
    my $dbh = db_connect;
    my $ret =
      $dbh->selectall_arrayref(q{SELECT sysid,hostname,port FROM hosts ORDER BY sysid});
    $dbh->disconnect;
    return $ret;
}

# this is how a system (by sysid) gets linked to a hostname (presumably
# manually by a sysadmin having reviewed what just got uploaded)
sub new_host {
    my ( $sysid, $hostname, $port ) = @_;
    $port //= 22;
    my $hostid;
    my $msg;
    my $dbh;
    eval {
        $dbh = db_connect;
        my $sys = get_sysid $dbh, $sysid;
        croak "no data for sysid $sysid" unless keys %$sys;
        $hostid = add_host $dbh, $sysid, $hostname;
        $msg    = "link $hostname:$port to $sysid " . $sys->{uuid} . ' ' . $sys->{info};
    };
    if ($@) {
        $dbh->rollback;
        $msg = $@;
    } else {
        $dbh->commit;
    }
    $dbh->disconnect;
    return $hostid, $msg;
}

# this is how new systems get their public keys added to the database
sub new_system {
    my $uuid = shift;
    my $info = shift;
    my $sysid;
    my $msg = 'ok';
    my $dbh;
    eval {
        $dbh   = db_connect;
        $sysid = add_system $dbh, $uuid, $info;
        for my $pubkey (@_) {
            add_sshkey $dbh, $sysid, $pubkey;
        }
    };
    if ($@) {
        $dbh->rollback;
        $msg = $@;
    } else {
        $dbh->commit;
    }
    $dbh->disconnect;
    return $sysid, $msg;
}

sub rm_host {
    my ( $host, $port ) = @_;
    $port //= 22;
    my $dbh;
    my $msg = 'ok';
    my $status;
    eval {
        $dbh = db_connect;
        $dbh->do( q{DELETE FROM hosts WHERE hostname = ? AND port = ?},
            {}, $host, $port );
    };
    if ($@) {
        $dbh->rollback;
        $msg = $@;
    } else {
        $dbh->commit;
        $status = 1;
    }
    $dbh->disconnect;
    return $status, $msg;
}

sub rm_system {
    my ($sysid) = @_;
    my $dbh;
    my $msg = 'ok';
    my $status;
    eval {
        $dbh = db_connect;
        $dbh->do( q{DELETE FROM hosts WHERE sysid = ?},   {}, $sysid );
        $dbh->do( q{DELETE FROM sshkeys WHERE sysid = ?}, {}, $sysid );
        $dbh->do( q{DELETE FROM systems WHERE sysid = ?}, {}, $sysid );
    };
    if ($@) {
        $dbh->rollback;
        $msg = $@;
    } else {
        $dbh->commit;
        $status = 1;
    }
    $dbh->disconnect;
    return $status, $msg;
}

sub unhosted {
    my $dbh = db_connect;
    my $ret = $dbh->selectall_hashref(
        q{SELECT s.sysid,s.uuid,s.info FROM systems s WHERE s.sysid NOT IN (SELECT hosts.sysid FROM hosts ORDER BY sysid)},
        'sysid'
    );
    $dbh->disconnect;
    return $ret;
}

1;
