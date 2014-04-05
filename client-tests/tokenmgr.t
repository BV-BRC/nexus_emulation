use Test::More;
use strict;
#use Test::TempDir;
use File::Temp 'tempdir';

BEGIN { use_ok('TokenManager') };

my $dir = File::Temp->newdir();

my $mgr = new_ok(TokenManager => [$dir, "bogus-url"]);

my $priv_key = <<END;
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDZsp1T/DXWIEvcMYVkmkeaMYIuKf26vBjlYqVG2rHAPR2tnbaX
Sf6sSSxfs14G6tsQWHEfeF545nFmsC5CxsmG0yQj3f594hVa5ICq0m6DhQclE2VK
XbJI2YufMa1hD3KEDcU2ailRfpG/XGeWNqj9t5JRMxtzWhwpIYh8hotelwIDAQAB
AoGAQUhL37ShXF4BAb4j92BAmp/AHyHegdIIUTl8wLuyVCi/rqG98K5y3a1vzh8W
0lI5cTRkcACDrBPG6/lnVgUQx30EKnZDN7aU7YGXiDvVINAi0lr/Ozr+tlVV4gld
ptv0HyOK7x14TF8wAJW3NS7ax2KiWSPxZe8ShJFtHuf1ZOECQQDygCe4xYs22SM2
gCSUXWSZ9tStJe4q909sZK6VPJoYh8qWkW53v+fqg/JCwQU8gfSpsLBi8ARxukd4
M2PP1ZORAkEA5dD/H24YJbXaaCFM0a+S2/VUr/Q5JGpg0Cjw6E7axOkK/JnAxwD1
f0/H5LqMrYILf2thjhuYYFvk6y7SYqLrpwJAOAVrJ8BbHNykyd5olO3OY9Ml5qow
jzR64KuRuWA6qRgVsRr/ziJDTWYV/V3h+8x53Qm4deLE5BEImbglgsnwQQJAcV7a
nFypWOEPL1NOHBrq7ctmza5DCi3YOJgZz+AmmAEGxHns2b8lXHq096b3gximJ2OH
qpz+XHq4wTRF4RbR/QJAR42HesI0FW/wHKq9Ge1AaacNkO4CAOcVtx45h3T4PBPn
iWXOfQGiAlht5O7+jdKaK5/FQRxwLM1lIPR2p7hBtQ==
-----END RSA PRIVATE KEY-----
END

my $pub_key = <<END;
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANmynVP8NdYgS9wxhWSaR5oxgi4p/bq8GOVipUbascA9Ha2dtpdJ/qxJ
LF+zXgbq2xBYcR94XnjmcWawLkLGyYbTJCPd/n3iFVrkgKrSboOFByUTZUpdskjZ
i58xrWEPcoQNxTZqKVF+kb9cZ5Y2qP23klEzG3NaHCkhiHyGi16XAgMBAAE=
-----END RSA PUBLIC KEY-----
END

#
# First do some tests with known keys.
#

ok($mgr->tied);
ok($mgr->db_hash);
my $keyid = "deadbeef";
$mgr->db_hash->{default_key} = $keyid;
$mgr->db_hash->{"pub.$keyid"} = $pub_key;
$mgr->db_hash->{"priv.$keyid"} = $priv_key;

diag("Test with known key");

is($pub_key, $mgr->public_key($keyid));
is($keyid, $mgr->default_key);

my $test_data = "Test Data";
my $test_sig = "732d54d2c9e515a2356711d8dc17de84d2c2abcef7445f3c5b180f1fa80fe346d8d2998baea714330fbf1da9c00b067ac5afb3d23af03b0069615eb1608f4d23851c1f36959f2952ead57efb71223a672be705ee86d41de642ab29dda77bcf904c5f7779d3a2c6ea2bca8f2b99c40a7a1704aa7ad6953eef4f858cf36e5fe112";

is($mgr->sign($keyid, $test_data), $test_sig);

undef $dir;
undef $mgr;

my $dir = File::Temp->newdir();

my $url = "http://bogus-url";
my $mgr = new_ok(TokenManager => [$dir, $url]);

my $key = $mgr->default_key();
ok($key);
diag("create new key $key");

isnt($mgr->sign($key, $test_data), $test_sig);

my $token = $mgr->create_signed_token("user");
diag("token=$token");
ok($token);
like($token, qr/un=user\|/);
like($token, qr!\|SigningSubject=$url/goauth/keys/$key\|!);;
like($token, qr/\|sig=[0-9a-f]+$/);

ok($mgr->validate($token, 'user'));

done_testing();
