package Bio::KBase::NexusEmulation::token_server;

use Data::Dumper;
use Dancer;
use JSON::XS;
use Bio::KBase::NexusEmulation::TokenManager;

use Bio::KBase::DeploymentConfig;

our $config = Bio::KBase::DeploymentConfig->new();
print Dumper($config);

our $url_base = $config->setting("url-base");
our $storage = $config->setting("storage");

our $mgr = Bio::KBase::NexusEmulation::TokenManager->new($storage, $url_base);

my $auth_name = $config->setting("authority");

eval "require $auth_name;";

my $auth_params = $config->setting("authority-params");
my $authority = $auth_name->new(@$auth_params);

set serializer => 'JSON';

get '/goauth/token' => sub {
    my $grant_type = param('grant_type');
    my $client_id = param('client_id');
    my $auth = request->headers->authorization_basic;

    if (!$auth || $grant_type ne 'client_credentials')
    {
	return send_error("Invalid request");
    }

    my($user, $pass) = split(/:/, $auth, 2);

    $client_id ||= $user;

    if ($authority->authenticate($user, $pass))
    {
	my $val = $mgr->create_signed_token($user, $client_id);
	if ($val)
	{
	    status 201;
	    return $val;
	}
	else
	{
	    return send_error("error creating token");
	}
    }
    else
    {
	return send_error("permission denied", 503);
    }
					  

};

get '/users/:user' => sub {
    my $user = param('user');
    my $auth = request->headers->authorization;

    my($auth_type, $token) = split(/\s+/, $auth, 2);
    unless (lc($auth_type) eq 'oauth' || lc($auth_type) eq 'globus-goauthtoken')
    {
	return send_error("permission denied", 503);
    }
    unless ($mgr->validate($token, $user))
    {
	return send_error("permission denied", 503);
    }

    my $res = $authority->user_profile($user);

    unless (ref($res))
    {
	return send_error("permission denied", 503);
    }

    return $res;
};

get '/goauth/keys/:key' => sub {
    my $key = param('key');

    my $str;
    eval {
	$str = $mgr->public_key($key);
    };
    if ($@)
    {
	print STDERR "no key: $@\n";
	#return Dancer::ER
	return send_error("Key $key not found", 500, "Key $key not found");
    }
    my $data = { valid => 1,
		 pubkey => $str,
		 };
    return $data;

};

1;

	
