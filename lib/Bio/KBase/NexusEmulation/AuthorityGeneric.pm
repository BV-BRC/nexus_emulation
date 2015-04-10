
package Bio::KBase::NexusEmulation::AuthorityGeneric;

use strict;
use base 'Class::Accessor';

use base 'Bio::KBase::NexusEmulation::AuthorityBase';

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
	($self->realm ? (realm => $self->realm ) : ()),
    };
}

1;
