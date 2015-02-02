
package Bio::KBase::NexusEmulation::AuthorityPATRIC;

use Data::Dumper;
use DBI;
use strict;
use base 'Bio::KBase::NexusEmulation::AuthorityBase';

__PACKAGE__->mk_accessors(qw(realm user_suffix signing_subject_match));

sub new
{
    my($class) = @_;

    my $self = $class->SUPER::new();

    return bless $self, $class;
}

sub user_profile
{
    my($self, $login) = @_;

    if ($login !~ /@/ && $self->user_suffix)
    {
	$login .= '@' . $self->user_suffix;
    }

    return {
	username => $login,
	fullname => $login,
    };
}


1;
