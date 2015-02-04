
package Bio::KBase::NexusEmulation::AuthorityPATRIC;

use Data::Dumper;
use DBI;
use strict;
use base 'Bio::KBase::NexusEmulation::AuthorityBase';

sub new
{
    my($class) = @_;

    my $self = $class->SUPER::new();

    return bless $self, $class;
}


1;
