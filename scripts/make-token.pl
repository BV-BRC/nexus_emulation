use strict;
use TokenManager;

use Bio::KBase::DeploymentConfig;

our $config = Bio::KBase::DeploymentConfig->new("TokenServer");

our $url_base = $config->setting("url-base");
our $storage = $config->setting("storage");

our $mgr = TokenManager->new($storage, $url_base);

@ARGV == 1 or die "Usage: make-token username\n";

my $user = shift;

my $token = $mgr->create_signed_token($user);
print "$token\n";
