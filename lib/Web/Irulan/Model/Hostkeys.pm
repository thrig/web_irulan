# -*- Perl -*-

package Web::Irulan::Model::Hostkeys;
use Mojo::Base -base;

has 'sqlite';

sub add_host {
    my ($self, $sysid, $host, $port) = @_;
    my $now = time();
    $self->sqlite->db->insert('hosts',
        { hostname => $host, port => $port, mtime => $now, sysid => $sysid })
      ->last_insert_id;
}

sub add_system {
    my ($self, $uuid, $info, @pubkeys) = @_;
    my $db  = $self->sqlite->db;
    my $now = time();
    my $id =
      $db->insert('systems', { uuid => $uuid, info => $info, mtime => $now })
      ->last_insert_id;
    for my $key (@pubkeys) {
        $db->insert('sshkeys', { sysid => $id, pubkey => $key, mtime => $now });
    }
    return $id;
}

sub hosts {
    $_[0]->sqlite->db->query(
        q{SELECT sysid,hostname,port FROM hosts ORDER BY sysid,hostname,port});
}

# the ORDER BY is to keep the listing in the generated file stable so
# diff(1) is easier to read when something changes (also less work for
# rsync-based file distribution or backup systems)
# hmm, want all records but abort if none are more recent than ... maybe
# want some other query to see if there's a mtime and then call this
sub known_hosts {
    $_[0]->sqlite->db->query(
        q{SELECT h.hostname,h.port,s.pubkey,h.mtime AS mtime1,s.mtime AS mtime2 FROM hosts h INNER JOIN sshkeys s USING (sysid) ORDER BY h.hostname,h.port,s.pubkey}
    );
}

sub most_recent {
    $_[0]->sqlite->db->query(
        q{SELECT max(mtime) FROM (SELECT mtime FROM systems UNION SELECT mtime FROM hosts UNION SELECT mtime FROM sshkeys)}
    )->array->[0];
}

sub pubkeys {
    my ($self, $host, $port) = @_;
    $_[0]->sqlite->db->query(
        q{SELECT pubkey FROM sshkeys WHERE sysid = (SELECT sysid FROM hosts WHERE hostname=? AND port=?)},
        $host, $port
    )->arrays->each;
}

sub remove_host {
    my ($self, $host, $port) = @_;
    $self->sqlite->db->delete('hosts', { hostname => $host, port => $port });
}

sub remove_system {
    my ($self, $sysid) = @_;
    my $db = $self->sqlite->db;
    for my $table (qw{sshkeys hosts systems}) {
        $db->delete($table, { sysid => $sysid });
    }
}

sub unhosted {
    $_[0]->sqlite->db->query(
        q{SELECT s.sysid,s.uuid,s.info FROM systems s WHERE s.sysid NOT IN (SELECT hosts.sysid FROM hosts) ORDER BY s.sysid}
    );
}

1;
