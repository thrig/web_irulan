# v5.16.0 is for getaddrinfo and the NIx_* constants based on what old
# perl versions contain; I have only tested with perl 5.28 on OpenBSD
# 6.5. Mojo::SQLite might be tricky to install on older systems (e.g.
# Centos7) due to the sqlite version they ship with
#
# this otherwise assumes App::cpanminus is installed (and possibly
# local::lib too). production systems may not need all the test modules
depend:
	perl -e 'use 5.16.0'
	cpanm --installdeps .

test:
	@prove --lib --nocolor

clean:
	@-rm irulan.db

# may be necessary if you've set CLEANUP => 0 to leave test temp
# database around for debugging (but these may be in a shared tmp
# directory so whacking them with rm -rf could be very, very bad)
realclean: clean
	@-ls -ld `perl -MFile::Spec::Functions=tmpdir -E 'say tmpdir'`/irulan.??????????

.PHONY: clean depend realclean test
