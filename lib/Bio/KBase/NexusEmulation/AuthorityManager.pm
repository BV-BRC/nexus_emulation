#
# Class to manage multiple authority objects and handle
# finding authority by token or realm.
#

package Bio::KBase::NexusEmulation::AuthorityManager;

use Data::Dumper;
use DBI;
use strict;
use base 'Class::Accessor';

__PACKAGE__->mk_accessors(qw(default_authority auth_objs));

sub new
{
    my($class, $config) = @_;

    my $auth_objs = [];

    my $auths = $config->setting("authority-list");
    my $default_auth = $config->setting("default-authority");
    my $default_obj;

    for my $auth (@$auths)
    {
	my $auth_class = $config->setting("$auth-class");
	my $auth_params = $config->setting("$auth-params");
	my $auth_realm = $config->setting("$auth-realm");
	my $auth_user_suffix = $config->setting("$auth-user-suffix");
	my $auth_signing_subject_match = $config->setting("$auth-signing-subject-match");

	eval "require $auth_class;";
	my $auth_obj = $auth_class->new(@$auth_params);
	$auth_obj->realm($auth_realm);
	$auth_obj->user_suffix($auth_user_suffix);
	$auth_obj->signing_subject_match($auth_signing_subject_match);

	$default_obj = $auth_obj if ($auth eq $default_auth);
	    
	push(@$auth_objs, $auth_obj);
    }

    my($self) = {
	auth_objs => $auth_objs,
	default_authority => $default_obj,
    };
    return bless $self, $class;
    
}

sub find_matching_authority_by_token
{
    my($self, $token) = @_;
    for my $auth (@{$self->auth_objs})
    {
	if ($auth->matches_token($token))
	{
	    return $auth;
	}
    }
    return undef;
}

sub find_matching_authority_by_realm
{
    my($self, $realm) = @_;
    for my $auth (@{$self->auth_objs})
    {
	if ($auth->matches_realm($realm))
	{
	    return $auth;
	}
    }
    return undef;
}

1;
