use strict;
use Test::More;
use Data::Dumper;

use_ok("AuthoritySEED");

my $auth = new_ok("AuthoritySEED", ["WebAppBackend", "bio-admin-3.mcs.anl.gov", "rast"]);

ok(!$auth->authenticate("foo", "bar"));
ok($auth->authenticate("olson", "glassHeads"));
my $prof = $auth->user_profile("olson");
ok($prof);
is_deeply($prof, { email => 'olson@mcs.anl.gov', fullname => "Robert Olson" });
done_testing;