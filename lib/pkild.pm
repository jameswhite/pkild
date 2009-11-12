package pkild;

use strict;
use warnings;

use Catalyst::Runtime '5.70';
use YAML qw(LoadFile);
use Path::Class 'file';


# Set flags and add plugins for the application
#
#         -Debug: activates the debug mode for very useful log messages
#   ConfigLoader: will load the configuration from a YAML file in the
#                 application's home directory
# Static::Simple: will serve static files from the application's root 
#                 directory

use Catalyst qw/-Debug ConfigLoader Authentication Authorization::Roles Static::Simple Session Session::Store::FastMmap Session::State::Cookie/;

our $VERSION = '0.01';

# Configure the application. 
#
# Note that settings in pkild.yml (or other external
# configuration file that you set up manually) take precedence
# over this when using ConfigLoader. Thus configuration
# details given here can function as a default configuration,
# with a external configuration file acting as an override for
# local deployment.

__PACKAGE__->config( 
                     'name' => 'pkild',
                     'authentication' => YAML::LoadFile( file(__PACKAGE__->config->{home}, 'Config.yaml')),
                     'layout' => YAML::LoadFile( file(__PACKAGE__->config->{home}, 'Forms.yaml'))
                   );

# Start the application
__PACKAGE__->setup( qw/RequireSSL/ );
__PACKAGE__->config->{require_ssl} = {
                                      #https => 'https://server.example.org:443',
                                      #http => 'http://server.example.org:80',
                                       remain_in_ssl => 1,
                                       no_cache => 1,
                                     };

=head1 NAME

pkild - Catalyst based application

=head1 SYNOPSIS

    script/pkild_server.pl

=head1 DESCRIPTION

[enter your description here]

=head1 SEE ALSO

L<pkild::Controller::Root>, L<Catalyst>

=head1 AUTHOR

James S. White,,,

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
