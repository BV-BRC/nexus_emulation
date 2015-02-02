
package Bio::KBase::NexusEmulation::AuthorityBase;

use strict;
use base 'Class::Accessor';

__PACKAGE__->mk_accessors(qw(realm user_suffix signing_subject_match));

sub new
{
    my($class) = @_;

    my $self = {
    };
    return bless $self, $class;
}

sub matches_realm
{
    my($self, $realm) = @_;
    return $self->{realm} eq $realm;
}

sub matches_token
{
    my($self, $token) = @_;

    my @parts = split(/\|/, $token);
    my($subj) = $token =~ /\|SigningSubject=([^|]+)/;

    return $subj =~ /$self->{signing_subject_match}/;
}

1;
