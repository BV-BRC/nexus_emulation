package Bio::KBase::NexusEmulation::TokenManager;

use strict;
use Errno;
use Data::UUID;
use File::Slurp;
use Crypt::OpenSSL::RSA;
use DB_File;
use URI;
use Data::Dumper;
use LWP::UserAgent;
use JSON::XS;

use base 'Class::Accessor';

__PACKAGE__->mk_accessors(qw(token_lifetime dir db tied db_hash key_length url_base));

#un=kbasetest|tokenid=3be5a452-0d97-11e2-81d0-12313809f035|expiry=1380831397|client_id=kbasetest|token_type=Bearer|SigningSubject=https://nexus.api.globusonline.org/goauth/keys/efc9fd6e-0ba9-11e2-81d0-12313809f035|sig=7ae1687147d52a5717f5ebc15a64cda67f8648332944220d1e578f847fd1899ed5abd7b7bd4b4e9b568bd959f35517b5722e12f044e173bd23337103643279330b26c897a89e21f44e27ead4bb75ab510dca9f08734b7aa6bc7ab4554821fd70a90a8151f44968cc510e6a64b3b5ff2f7736c199e8a711e151c7422f7d8816db

=head1 NAME

TokenManager

=head1 SYNOPSIS

  $mgr = TokenManager->new($storage_dir);
  $mgr->token_lifetime(86400);

  $key_id = $mgr->default_key();
  $signed_token = $mgr->create_and_sign_token($key, "username");

=head1 DESCRIPTION

The TokenManager keeps a small database of RSA signing keys for the use in
emulating the Globus Nexus authentication service. This database resides in a 
Berekeley DB file in the storage directory specfied by the constructor.

=head2 CONSTRUCTOR METHODS

=over 4 

=item $mgr = TokenManager->new($storage_dir)

Create a new TokenManager instance using the given storage directory. If the
directory does not exist, one will be created. 

=cut

sub new
{
    my($class, $storage_dir, $url_base) = @_;

    if (!$url_base)
    {
	die "TokenManager::new: url_base parameter must be provided";
    }
    
    if (! -d $storage_dir)
    {
	mkdir($storage_dir) or die "Cannot mkdir $storage_dir: $!";
    }

    my $db = "$storage_dir/storage.db";

    my $tie;
    my $hash = {};

    $tie = tie %$hash, 'DB_File', $db, O_RDWR, 0644, $DB_HASH;
    if (!$tie && $!{ENOENT})
    {
	$tie = tie %$hash, 'DB_File', $db, O_RDWR | O_CREAT, 0644, $DB_HASH;
	if (!$tie)
	{
	    die "Cannot create database: $!";
	}
    }

    my $self = { dir => $storage_dir,
		 db => $db,
		 tied => $tie,
		 db_hash => $hash,
		 key_length => 1024,
		 url_base => $url_base,
		 token_lifetime => 86400 * 365,
		 };
    return bless $self, $class;
}

=back

=head2 ACCESS METHODS

=over 4

=item $lifetime = $mgr->token_lifetime()

=item $mgr->token_lifetime(86400)

Get or set the token lifetime (in seconds).

=item $mgr->default_key()

Return the id of the default key. Create one if it does not exist.

=cut

sub default_key
{
    my($self) = @_;

    my $key = $self->db_hash->{default_key};

    if (!$key)
    {
	$key = $self->create_signing_key();
	$self->db_hash->{default_key} = $key;
	$self->tied->sync;
    }

    return $key;
}

=item $pubkey = $mgr->public_key($key_id)

Return the public key text for the given key id.

=cut

sub public_key
{
    my($self, $key_id) = @_;

    $key_id =~ /^[-0-9a-fA-F]+$/ or die "Invalid key id $key_id";

    my $str = $self->db_hash->{"pub.$key_id"};
    print STDERR "Get 'pub.$key_id' returns $str\n";
    $str or die "Key $key_id not found";
    return $str;
}

=back

=head2 KEY AND SIGNING METHODS

=over 4

=item $key = $mgr->create_signing_key()

Create a new signing key and return its key ID. Writes the
public and private keys to the database.

=cut

sub create_signing_key
{
    my($self) = @_;

    my $key_id = Data::UUID->new->create_str();
    my $key = Crypt::OpenSSL::RSA->generate_key($self->key_length);

    $self->db_hash->{"pub.$key_id"} =  $key->get_public_key_string();
    $self->db_hash->{"priv.$key_id"} = $key->get_private_key_string();
    $self->tied->sync();
    
    return $key_id;
}

=item $token = $mgr->create_signed_token("username")

Create and sign a new token for the given username.

=cut

sub create_signed_token
{
    my($self, $user, $client_id, $override_user) = @_;

    my $now = time;

    my $key = $self->default_key;
    my $token_type = 'Bearer';
    my $signing_subject = $self->url_base . "/goauth/keys/$key";
    my $expires_in = $self->token_lifetime;
    my $expiry = $now + $expires_in;

    $client_id = $client_id ? $client_id : $user;

    my $token_id = Data::UUID->new->create_str;

    my $token_data = { un => $user,
		       tokenid => $token_id,
		       expiry => $expiry,
		       client_id => $client_id,
		       token_type => $token_type,
		       this_is_globus => "globus_style_token",
		       SigningSubject => $signing_subject,
		     };

    my $token_str = join("|", map { "$_=$token_data->{$_}" } qw(un tokenid expiry client_id token_type SigningSubject this_is_globus));
    $token_str .= "|override_user=$override_user" if $override_user;

    my $sig = $self->sign($key, $token_str);

    $token_str .= "|sig=$sig";

    my $val = {
	access_token => $token_str,
	client_id => $client_id,
	expires_in => $expires_in,
	expiry => $expiry,
	issued_on => $now,
	lifetime => $expires_in,
	scopes => [],
	token_id => $token_id,
	token_type => $token_type,
	user_name => $user,
    };
    return $val;
}

=item $hex_str = $mgr->sign($key, $plaintext)

Look up the private key in the database for $key and use it to sign the given
plaintext. Return the hex form of the signature.

=cut

sub sign
{
    my($self, $key_id, $plaintext) = @_;

    my $key = $self->db_hash->{"priv.$key_id"};
    $key or die "Cannot find key $key_id in database";

    my $signed = Crypt::OpenSSL::RSA->new_private_key($key)->sign($plaintext);
    my $hex_sig = unpack("H*", $signed);
    return $hex_sig;
}

=item $ok = $mgr->validate($token, $user)

Validate the given token to be valid for the given user. The token is assumed to have been one that
B<this> token manager issued; in other words, the base URL for the signing subject
in the token must be the same as our URL base.

=cut

sub validate
{
    my($self, $token, $user) = @_;

    my @parts = map { [ split(/=/, $_, 2) ] } split(/\|/, $token);
    my $to_sign = join("|", map { join("=", @$_) } grep { $_->[0] ne "sig" } @parts);
    my %parts = map { $_->[0] => $_->[1]} @parts;
    # print Dumper($to_sign, \%parts);

    my $subj = $parts{SigningSubject};
    my $surl = URI->new($subj);
    $surl->path('');
    if ($surl ne $self->url_base)
    {
	print STDERR "validate failed (ignored) on $surl ne $self->{url_base}\n";
	#return 0;
    }

    my($key_id) = $subj =~ m,/goauth/keys/(\S+)$,;
    #$key_id or die "No key found in $subj\n";
    my $key = $self->db_hash->{"priv.$key_id"};

    if (!$key_id || !$key)
    {
	#
	# This is an external token. Validate it.
	# 
	print STDERR "OKing external token from $subj...\n";
	my $ua = LWP::UserAgent->new();
	my $res = $ua->get($subj);
	if ($res->is_success)
	{
	    my $data = decode_json($res->content);
	    if (!$data->{valid})
	    {
		print STDERR "public key is invalid\n";
		return 0;
	    }
	    my $pubkey = $data->{pubkey};
	    my $rsa = Crypt::OpenSSL::RSA->new_public_key($pubkey);
	    $rsa->use_sha1_hash();

	    my $binary_sig = pack('H*', $parts{sig});
	    my $verify = $rsa->verify($to_sign, $binary_sig);

	    print STDERR "verified: $verify\n";
	    return $verify;
	}
	else
	{
	    print STDERR "Error getting pbukey from $subj " . $res->content;
	    return 0;
	}
    }
    my $sig = $self->sign($key_id, $to_sign);

    if ($sig ne $parts{sig})
    {
	print STDERR "signature did not match\n$sig\n$parts{sig}";
	return 0;
    }

    if ($parts{expiry} < time)
    {
	print STDERR "token expired\n";
	return 0;
    }

    if ($parts{un} ne $user)
    {
	print STDERR "user does not match token\n";
	return 0;
    }

    return 1;
}

=item $ok = $mgr->validate_and_get_user($token)

Validate the given token and return its user id. The token is assumed to have been one that
B<this> token manager issued; in other words, the base URL for the signing subject
in the token must be the same as our URL base.

=cut

sub validate_and_get_user
{
    my($self, $token) = @_;

    my @parts = map { [ split(/=/, $_, 2) ] } split(/\|/, $token);
    my $to_sign = join("|", map { join("=", @$_) } grep { $_->[0] ne "sig" } @parts);
    my %parts = map { $_->[0] => $_->[1]} @parts;
    # print Dumper($to_sign, \%parts);

    my $subj = $parts{SigningSubject};
    my $surl = URI->new($subj);
    $surl->path('');
    if ($surl ne $self->url_base)
    {
	print STDERR "validate failed on $surl ne $self->{url_base}\n";
	return undef;
    }

    my($key) = $subj =~ m,/goauth/keys/(\S+)$,;
    $key or die "No key found in $subj\n";
    my $sig = $self->sign($key, $to_sign);

    if ($sig ne $parts{sig})
    {
	print STDERR "signature did not match\n$sig\n$parts{sig}";
	return undef;
    }

    if ($parts{expiry} < time)
    {
	print STDERR "token expired\n";
	return undef;
    }

    return $parts{un};
}

1;
