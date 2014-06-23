
package Bio::KBase::NexusEmulation::AuthoritySEED;

use Data::Dumper;
use DBI;
use strict;
use base 'Class::Accessor';

__PACKAGE__->mk_accessors(qw(dbname dbhost dbuser dbpass));

sub new
{
    my($class, $dbname, $dbhost, $dbuser, $dbpass) = @_;

    my $dbh = DBI->connect("DBI:mysql:database=$dbname;host=$dbhost", $dbuser, $dbpass);

    $dbh or die "Cannot open webapp database\n";
    
    my $self = {
	dbname => $dbname,
	dbhost => $dbhost,
	dbuser => $dbuser,
	dbpass => $dbpass,
	dbh => $dbh,
    };
    return bless $self, $class;
}

sub dbh
{
    my($self) = @_;

    my $dbh = $self->{dbh};
    if ($dbh->ping())
    {
	return $dbh;
    }

    $dbh = DBI->connect("DBI:mysql:database=$self->{dbname};host=$self->{dbhost}", $self->{dbuser}, $self->{dbpass});
    $dbh or die "Cannot open webapp database\n";
    $self->{dbh} = $dbh;
    return $dbh;
}

sub authenticate
{
    my($self, $login, $pass) = @_;

    my $res = $self->dbh->selectall_arrayref(qq(SELECT password FROM User WHERE login = ? AND active = 1), undef, $login);
    if (!ref($res) || @$res == 0)
    {
	return 0;
    }

    my $pw = $res->[0]->[0];
    
    if (crypt($pass, $pw) eq $pw)
    {
	return 1;
    }
    else
    {
	return 0;
    }
}

sub user_profile
{
    my($self, $login) = @_;

    my $res = $self->dbh->selectall_arrayref(qq(SELECT email, firstname, lastname FROM User WHERE login = ? AND active = 1), undef, $login);
    if (!ref($res) || @$res == 0)
    {
	return undef;
    }

    my($email, $fn, $ln) = @{$res->[0]};
    return {
	email => $email,
	fullname => join(" ", $fn, $ln),
    };
}

1;
