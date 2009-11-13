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

    print STDERR "1::::::::::::::::::::::::::::::::";
    print STDERR ref($c->user);
    print STDERR "::::::::::::::::::::::::::::::::1\n";

    # Attempt to authenticate
    if( (defined($c->req->param("login")))&&(defined($c->req->param("password")))){
        $c->authenticate({
                           id       => $c->req->param("username"), 
                           password => $c->req->param("password") 
                         });
        if(!defined $c->user){ $c->stash->{'ERROR'}="Authentication Failed."; }
    }

    print STDERR "2::::::::::::::::::::::::::::::::";
    print STDERR ref($c->user);
    print STDERR "::::::::::::::::::::::::::::::::2\n";

    # Log us out if logout was sent
    if(defined($c->req->param("logout"))){ 

        # remove all user handles
        delete $c->session->{'user'};
        $c->logout();

        # expire our session
        $c->session_expires(0);

        # send us home, so subsequent page refreshes won't post logout
        $c->res->redirect("/");
        $c->detach();
    }

    print STDERR "3::::::::::::::::::::::::::::::::";
    print STDERR ref($c->user);
    print STDERR "::::::::::::::::::::::::::::::::3\n";

    # Update the default tab if changed
    if(defined($c->req->param("change_tab"))){ 
        $c->session->{'default_tab'} = $c->req->param("change_tab"); 
        $c->res->body("Default tab changed to ".$c->session->{'default_tab'}.".");
    }

    print STDERR "4::::::::::::::::::::::::::::::::";
    print STDERR ref($c->user);
    print STDERR "::::::::::::::::::::::::::::::::4\n";

    # If we're logged in, send us to the application, othewise the login page.
    if(!defined $c->user){
        $c->stash->{template}="login.tt";
    }else{
        if($c->check_user_roles( "certificate_administrators" )){
            my $form_data=$c->config->{'layout'};
            $c->stash->{menunames}=$form_data->{'order'};
            $c->stash->{menudata}=$form_data->{'forms'};
            $c->stash->{'default_tab'} = $c->session->{'default_tab'}||$c->stash->{menunames}->[0];
            $c->stash->{template}="application.tt";
        }else{
            $c->barf();
            $c->stash->{template}="login.tt";
        }
    }
    print STDERR "5::::::::::::::::::::::::::::::::";
    print STDERR ref($c->user);
    print STDERR "::::::::::::::::::::::::::::::::5\n";
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
