
package Bio::KBase::NexusEmulation::AuthorityViPR;

use Data::Dumper;
use HTTP::CookieJar::LWP;
use URI::Escape;
use strict;
use base 'Bio::KBase::NexusEmulation::AuthorityBase';

use LWP::UserAgent;

__PACKAGE__->mk_accessors(qw(auth_url home_url));

sub new
{
    my($class, $auth_url, $home_url) = @_;
    
    my $self = $class->SUPER::new();
    bless $self, $class;

    $self->auth_url($auth_url);
    $self->home_url($home_url);

    return $self;
}

sub authenticate
{
    my($self, $login, $pass) = @_;

    #
    # Need to request homepage once to retrieve CSRF token
    # and session cookie.
    #

    my $jar = HTTP::CookieJar::LWP->new;
    my $ua = LWP::UserAgent->new(cookie_jar => $jar);

    my $res = $ua->get($self->home_url);
    if (!$res->is_success)
    {
	die "Failed to retrieve " . $self->home_url;
    }
    my $txt = $res->content;
    my($csrf) = $txt =~ /meta name="_csrf".*content=\"([^\"]+)/;
    # print "csrf=$csrf\n";
    # print Dumper($jar);
    (my $email = $login)  =~ s/\@viprbrc\.org$//;

    #
    # Now authenticate.
    #
    my $res = $ua->post($self->auth_url,
			[_csrf => $csrf,
			 workbenchFlag => 'true',
			 type => 'VIPR',
			 j_username => $email, #uri_escape($email),
			 j_password => $pass],
			'Referer' => 'http://dev2.virusbrc.org/brc/workbench_landing.spg?method=WorkbenchDetail&decorator=corona',
			'X-CSRF-TOKEN' => $csrf);
    print Dumper($res->status_line, $res->headers);

    if ($res->code eq '302')
    {
	my $loc = $res->header('location');
	if ($loc =~ /method=AfterLogin/)
	{
	    return 1;
	}
	else
	{
	    return 0;
	}
    }
    else
    {
	print STDERR "auth lookup failed: " . $res->code . " " . $res->status_line . "\n";
	return 0;
    }
}

sub user_profile
{
    my($self, $login) = @_;

    (my $email = $login)  =~ s/\@viprbrc\.org$//;

    return {
	username => $login,
	email => $email,
	($self->realm ? (realm => $self->realm ) : ()),
    };
}

sub matches_token
{
    my($self, $token) = @_;

    my(undef, $un) = $token =~ /(^|\|)un=([^|]+)/;

    return $un =~ /\@viprbrc\.org$/;
}


1;
