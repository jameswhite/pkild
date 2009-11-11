package pkild::Controller::Root;

use strict;
use warnings;
use base 'Catalyst::Controller';
use YAML;

#
# Sets the actions in this controller to be registered with no prefix
# so they function identically to actions created in MyApp.pm
#
__PACKAGE__->config->{namespace} = '';

=head1 NAME

pkild::Controller::Root - Root Controller for pkild

=head1 DESCRIPTION

[enter your description here]

=head1 METHODS

=cut

=head2 default

=cut

sub default : Private {
    my ( $self, $c ) = @_;
    $c->require_ssl;
    # Attempt to authenticate
    if( (defined($c->req->param("login")))&&(defined($c->req->param("password")))){
        $c->session->{'user'} = $c->authenticate({
                                                   id       => $c->req->param("username"), 
                                                   password => $c->req->param("password") 
                                                 });
   
        if(!defined $c->session->{'user'}){
                                            $c->stash->{'ERROR'}="Authentication Failed.";
                                          }
    }

    # Log us out if logout was sent
    if(defined($c->req->param("logout"))){ 
        delete $c->session->{'user'}; 
    }

    # Update the default tab if changed
    if(defined($c->req->param("change_tab"))){ 
        $c->session->{'default_tab'} = $c->req->param("change_tab"); 
        $c->res->body("Default tab changed to ".$c->stash->{'default_tab'}.".");
    }

    # If we're logged in, send us to the application, othewise the login page.
    if(!defined $c->session->{'user'}){
        $c->stash->{template}="login.tt";
    }else{
        my $user;
        if($#{$c->session->{'user'}->username}){
            $user=$c->session->{'user'}->username->[0];
        }else{
            $user=$c->session->{'user'}->username;
        }
        $c->stash->{'ERROR'} = "Logged in as: $user ";
        
        my $form_data=YAML::LoadFile("/tmp/pkild.yaml");
        $c->stash->{menunames}=$form_data->{'order'};
        $c->stash->{menudata}=$form_data->{'forms'};
        $c->stash->{'default_tab'} = $c->session->{'default_tab'}||$c->stash->{menunames}->[0];
        $c->stash->{template}="application.tt";
    }
}

sub login : Global {
    my ( $self, $c ) = @_;
    $c->authenticate({
                       id          => $c->req->param("login"), 
                       password    => $c->req->param("password") 
                      });
    $c->res->body("Welcome " . $c->user->username . "!");
}

=head2 end

Attempt to render a view, if needed.

=cut 

sub end : ActionClass('RenderView') {}

=head1 AUTHOR

James S. White,,,

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
