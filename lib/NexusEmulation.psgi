use Dancer;
use Bio::KBase::NexusEmulation::token_server;
use Plack::Builder;

builder {
	enable 'CrossOrigin', origins => "*", headers => "*", max_age => 86400;
	dance;
};
