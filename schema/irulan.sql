-- 1 up
CREATE TABLE IF NOT EXISTS systems (
  sysid INTEGER PRIMARY KEY NOT NULL,
  uuid TEXT UNIQUE,
  mtime INTEGER,
  info TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
  hostid INTEGER PRIMARY KEY,
  hostname TEXT,
  port INTEGER,
  mtime INTEGER,
  sysid INTEGER NOT NULL,
  FOREIGN KEY(sysid) REFERENCES systems(systemid)
    ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sshkeys (
  sshkeyid INTEGER PRIMARY KEY,
  pubkey TEXT,
  mtime INTEGER,
  sysid INTEGER NOT NULL,
  FOREIGN KEY(sysid) REFERENCES systems(systemid)
    ON UPDATE CASCADE ON DELETE CASCADE
);

-- 1 down
DROP TABLE IF EXISTS hosts;
DROP TABLE IF EXISTS sshkeys;
DROP TABLE IF EXISTS systems;
