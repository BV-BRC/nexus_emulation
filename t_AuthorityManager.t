use Test::More;
use strict;
use Data::Dumper;

use_ok('Bio::KBase::NexusEmulation::AuthorityManager');
use_ok('Bio::KBase::DeploymentConfig');

$ENV{KB_SERVICE_NAME} = 'NexusEmulation';
$ENV{KB_DEPLOYMENT_CONFIG} = 'test_deploy.cfg';

my $config = new_ok('Bio::KBase::DeploymentConfig');

my $mgr = new_ok('Bio::KBase::NexusEmulation::AuthorityManager', [ $config ]);

diag Dumper($mgr);

my $seed_token = 'un=olson|tokenid=5335990A-A719-11E4-B14C-E9AB42A49C03|expiry=1454004793|client_id=olson|token_type=Bearer|SigningSubject=http://rast.nmpdr.org/goauth/keys/E087E220-F8B1-11E3-9175-BD9D42A49C03|sig=deadbeef';

my $globus_token = 'un=olson|tokenid=7b35976a-ab16-11e4-a38c-123139141556|expiry=1454443377|client_id=olson|token_type=Bearer|SigningSubject=https://nexus.api.globusonline.org/goauth/keys/45fbfa46-a8a8-11e4-a6e7-22000ab68755|sig=ece4cfa';

my $patric_token = 'un=bob|tokenid=9e3476fd-a975-42ff-8e9c-86375d3e5e5d|expiry=1421435443|client_id=bob|token_type=Bearer|SigningSubject=http://user.alpha.patricbrc.org/public_key|sig=ee0b';

my $auth = $mgr->find_matching_authority_by_token($seed_token);
ok($auth->realm eq 'SEED');

my $auth = $mgr->find_matching_authority_by_token($globus_token);
ok(!defined($auth));

my $auth = $mgr->find_matching_authority_by_token($patric_token);
ok($auth->realm eq 'PATRIC');

my $auth = $mgr->find_matching_authority_by_realm('SEED');
ok($auth && $auth->realm eq 'SEED');

my $auth = $mgr->find_matching_authority_by_realm('FOO');
ok(!defined($auth));

my $auth = $mgr->find_matching_authority_by_realm('PATRIC');
ok($auth && $auth->realm eq 'PATRIC');

done_testing();