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


#
# returns an AuthUser
# #
post '/Sessions/Login' => sub {

#	String dataStr = "user_id=" + URLEncoder.encode(userName, "UTF-8") +
#					 "&password=" + URLEncoder.encode(password, "UTF-8") +
#					 "&cookie=1&fields=user_id,name,email,groups,kbase_sessionid,token,verified,opt_in,system_admin";

    my $user_id = param('user_id');
    my $password = param('password');
    my $token_in = param('token');

my $params= params;
#print STDERR Dumper($params);

    if ($token_in)
    {
	$user_id = $mgr->validate_and_get_user($token_in);
	if (!$user_id)
	{
print STDERR "did not validate token $token_in\n";
	    return send_error("invalid token", 503);
	}
    }
    else
    {
	if (!$authority->authenticate($user_id, $password))
	{
	    return send_error("permission denied", 503);
	}
	# not used for now
	#$token = $mgr->create_signed_token($user_id, $user_id);
    }

    my $profile = $authority->user_profile($user_id);
    if ($profile)
    {
	status 200;
#	my $tok = $val->{access_token};
#	my @parts = split(/\|/, $tok);
#	my %parts = map { my($a, $b) = split(/=/, $_); ($a => $b) } @parts;
#	my $sig = $parts{sig};
#	my $subj = $parts{SigningSubject};
#	my $dat = $tok;
#	$dat =~ s/\|sig=.*$//;
#	    my $token_obj = {
#			tokenStr => $val->{access_token},
#			userName => $user_id,
#			tokenId => $val->{token_id},
#			clientId => $user_id,
#			issued => $val->{issued_on},
#			tokenType => $val->{token_type},
#			signingSubject => $subj,
#			signature => $sig,
#			tokenData => $dat,
#			};
#		    

	my $ret = { verified => JSON::XS::true,
		    user_id => $user_id,
		    email  => ($profile->{email} ? $profile->{email} : "user\@example.com"),
		    groups => [],
		    name => $profile->{fullname},
		    kbase_sessionid => '',
		    error_msg => '',
		    opt_in => JSON::XS::true,
		    system_admin => JSON::XS::false,
		};

#print STDERR "Returning: " . Dumper($ret);
	return $ret;
    }
    else
    {
	return send_error("error creating token");
    }
};

1;

	
