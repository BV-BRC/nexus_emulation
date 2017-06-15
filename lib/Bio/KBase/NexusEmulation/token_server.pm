package Bio::KBase::NexusEmulation::token_server;

use Data::Dumper;
use Dancer;
use JSON::XS;
use MIME::Base64;
use Bio::KBase::NexusEmulation::TokenManager;
use Bio::KBase::NexusEmulation::AuthorityManager;
use Digest::SHA 'sha256_hex';
use Crypt::OpenSSL::Random;
use Apache::Htpasswd;
use LWP::UserAgent;

use Bio::KBase::DeploymentConfig;

our $config = Bio::KBase::DeploymentConfig->new();
# print Dumper($config);

our $url_base = $config->setting("url-base");
our $storage = $config->setting("storage");

our $patric_auth_url = $config->setting("patric-auth-url");

our $override_password_file = $config->setting("override-password-file");

our $mgr = Bio::KBase::NexusEmulation::TokenManager->new($storage, $url_base);

our $authority_manager = Bio::KBase::NexusEmulation::AuthorityManager->new($config);

my $salt = $config->setting("salt") || "(African || European)?";

set serializer => 'JSON';
set show_errors => 1;
set plack_middlewares => [
    [ 'CrossOrigin' => (origins => "*", headers => "*")],
];

hook 'before' => sub {
    if (request->path_info =~ m,^//(.*),)
    {
        request->path_info("/$1");
    }
};

get '/goauth/token' => sub {
    my $grant_type = param('grant_type');
    my $client_id = param('client_id');
    my $user_for_override = param('user_for_override');
    my $auth = request->headers->authorization_basic;

    if (!$auth)
    {
	my $auth_str = param('auth');
	if ($auth_str)
	{
	    $auth = decode_base64($auth_str);
	}
    }

    if ($user_for_override && !$override_password_file)
    {
	return send_error("Unauthorized", 401);
    }

    if ($grant_type ne 'client_credentials')
    {
	return send_error("Invalid request");
    }

    my($ok, $user);

    if ($auth)
    {
	my $pass;
	($user, $pass) = split(/:/, $auth, 2);

	#
	# Special case code for PATRIC. Return a PATRIC token from its auth server
	# upon request for a user@patricbrc.org token.
	#
	
	if ($patric_auth_url && $user =~ /^([^\@]+)\@patricbrc\.org$/)
	{
	    my $puser = $1;
	    my $req = {
		username => $puser,
		password => $pass,
	    };
	    my $ua = LWP::UserAgent->new;
	    my $res = $ua->post($patric_auth_url, $req);
	    if ($res->is_success)
	    {
		my $token = $res->content;
		if ($token =~ /un=([^|]+)/)
		{
		    my @parts = split(/\|/, $token);
		    my %fields;
		    for my $p (@parts)
		    {
			my($a,$b) = split(/=/, $p, 2);
			$fields{$a} = $b;
		    }
		    
		    my $now = time;
		    my $expires_in = $fields{expiry} - $now;
		    return {
			access_token => $token,
			client_id => $fields{client_id},
			user_name => $fields{un},
			expires_in => $expires_in,
			expiry => $fields{expiry},
			issued_on => $now,
			lifetime => $expires_in,
			scopes => [],
			token_id => $fields{tokenid},
			token_type => $fields{token_type},
		    };
		}
		else
		{
		    warn "Invalid token return '$token' from $patric_auth_url for $puser\n";
		    return send_error("Unauthorized", 401);
		}
	    }
	    else
	    {
		return send_error("Unauthorized", 401);
	    }
	} # end PATRIC spcial case

	$client_id ||= ($user_for_override ? $user_for_override : $user);

	my $authority = $authority_manager->default_authority();

	#
	# If we're passed an override user, check the local password to authenticate
	# $user/$pass. If that works create the token and pass in the override username
	# to the token manager to add to the token so it can be identified.
	#
	
	if ($user_for_override)
	{
	    my $pw = Apache::Htpasswd->new({ passwdFile => $override_password_file,
						 UseMD5 => 1,
					     });
	    if ($pw->htCheckPassword($user, $pass))
	    {
		#
		# Ensure we do have the user. We need to be using an authority that allows
		# for pulling user profiles.
		#
		if ($authority->can("user_profile"))
		{
		    my $prof = $authority->user_profile($user_for_override);
		    if ($prof)
		    {
			my $val = $mgr->create_signed_token($user_for_override, $client_id, $user);
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
			return send_error("Unauthorized", 401);
		    }
		}
		else
		{
		    return send_error("Unauthorized", 401);
		}	
	    }
	    else
	    {
		return send_error("Unauthorized", 401);
	    }
	}

	$ok = $authority->authenticate($user, $pass);
    }
    else
    {
    	my $auth = request->headers->authorization // request->headers->header("x-globus-goauthtoken");
	
	print STDERR "have auth hdr $auth\n";
	print STDERR Dumper(request->headers);
	if (!$auth)
	{
	    return send_error("Unauthorized", 401);
	}
	
	my($auth_type, $token) = split(/\s+/, $auth, 2);
	if ($auth_type =~ /un=/)
	{
	    $token = $auth_type;
	    $auth_type = 'x-globus-goauthtoken';
	}
	print STDERR Dumper($auth_type, $token);
	unless (lc($auth_type) eq 'oauth' || lc($auth_type) eq 'globus-goauthtoken' || lc($auth_type) eq 'x-globus-goauthtoken')
	{
	    return send_error("permission denied", 403);
	}
	
	my($realm) = $token =~ /realm=([^|]+)/;
	my $this_mgr = $mgr;
	if ($realm ne $url_base)
	{
	    ($ok, $user) = Bio::KBase::NexusEmulation::TokenManager->validate_standalone($token);
	}
	else
	{
	    $user = $this_mgr->validate_and_get_user($token);
	    $ok = $user;
	}
	print STDERR Dumper(USER=>$user);
	$client_id = $user;
	if ($ok)
	{
	    my $val = {
		access_token => $token,
		client_id => $client_id,
		scopes => [],
		user_name => $user,
	    };
	    status 201;
	    return $val;
	}
	else
	{
	    return send_error("error authenticating token");
	}
    }
    print STDERR Dumper(OK => $ok);

    if ($ok)
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
	return send_error("permission denied", 403);
    }
};

get '/users/:user' => sub {
    my $user = param('user');
    my $auth = request->headers->authorization;
    
    if (!$auth)
    {
	return send_error("Unauthorized", 401);
    }

    my($auth_type, $token) = split(/\s+/, $auth, 2);
    unless (lc($auth_type) eq 'oauth' || lc($auth_type) eq 'globus-goauthtoken' || lc($auth_type) eq 'x-globus-oauthtoken')
    {
	return send_error("permission denied", 403);
    }
    unless ($mgr->validate($token, $user))
    {
	return send_error("permission denied", 403);
    }

    #
    # Select an authority based on the contents of the token. 
    #

    my $authority = $authority_manager->find_matching_authority_by_token($token);
    
    my $res = $authority->user_profile($user);

    unless (ref($res))
    {
	return send_error("permission denied", 403);
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
	return send_error("Key $key not found", 404, "Key $key not found");
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

    my $authority = $authority_manager->default_authority();

my $params= params;
#print STDERR Dumper($params);

    my $token;
    if ($token_in)
    {
	$user_id = $mgr->validate_and_get_user($token_in);
	if (!$user_id)
	{
print STDERR "did not validate token $token_in\n";
	    return send_error("invalid token", 403);
	}
	$token = $token_in;
    }
    elsif ($user_id)
    {
	if (!$authority->authenticate($user_id, $password))
	{
print STDERR "did not validate user '$user_id'\n";
	    my $ret = { user_id => $user_id, error_msg => "LoginFailure: Authentication failed." };

	    send_error($ret, 401);
	}
	# not used for now
	my $token_obj = $mgr->create_signed_token($user_id, $user_id);
	$token = $token_obj->{access_token};
    }
    else
    {
	return send_error("No userid or token passed in request", 401);
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

	my $session = sha256_hex(Crypt::OpenSSL::Random::random_bytes(32));
	
	my $ret = { verified => JSON::XS::true,
		    user_id => $user_id,
		    email  => ($profile->{email} ? $profile->{email} : "user\@example.com"),
		    groups => [],
		    name => $profile->{fullname},
		    kbase_sessionid => $session,
		    error_msg => '',
		    opt_in => JSON::XS::true,
		    system_admin => JSON::XS::false,
		    token => $token,
		};

#print STDERR "Returning: " . Dumper($ret);
	return $ret;
    }
    else
    {
	return send_error("error creating token", 403);
    }
};

1;

	
