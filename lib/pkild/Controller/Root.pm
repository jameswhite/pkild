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
    # remove this if not running in apache (can we do this automatically?)
    $c->require_ssl;
    ############################################################################
    # Attempt to authenticate
    ############################################################################
    if( (defined($c->req->param("login")))&&(defined($c->req->param("password")))){
        $c->authenticate({
                           id       => $c->req->param("username"), 
                           password => $c->req->param("password") 
                         });
        if(defined($c->user)){
            $c->session->{'user'}=$c->user;
        }else{
            $c->stash->{'ERROR'}="Authentication Failed."; 
        }
    }

    ############################################################################
    # Log us out if ?logout=1 was sent
    ############################################################################
    if(defined($c->req->param("logout"))){ 

        # remove all user handles
        delete $c->session->{'user'};
        delete $c->session->{'username'};

        # expire our session
        $c->delete_session("logout");

        # send us home, so subsequent page refreshes won't post logout
        $c->res->redirect("/");
        $c->res->redirect("/");
        $c->detach();
    }

    if( $c->request->arguments){
    ############################################################################
    # Forward me to the certificate controller instead of this:
    ############################################################################
    my @file_names=$c->model('Certificates')->list;
    print STDERR Data::Dumper->Dump([@file_names]);
    if( $c->request->arguments->[0] eq "jstree" ){
        $c->res->body(
                       "{ 
	                  attributes: { id : 'node_0'}, 
	                  data: 'Root Certificate Authority', 
                          state: closed,
                          children: [
	                              {
                                        attributes: { id : 'node_1'}, 
	                                data: 'External Intermediate Certificate Authority', 
                                        state: closed,
                                        children: [
	                                            {
                                                      attributes: { id : 'cert_1_0'}, 
	                                              data: 'some host cert 0', 
                                                    },
	                                            {
                                                      attributes: { id : 'cert_1_1'}, 
	                                              data: 'some host cert 1', 
                                                    },
                                                  ]
                                      },
	                              {
                                        attributes: { id : 'node_2'}, 
	                                data: 'Internal Intermediate Certificate Authority', 
                                        state: closed,
                                        children: [
	                                            {
                                                      attributes: { id : 'cert_2_0'}, 
	                                              data: 'some host cert 2', 
                                                    },
	                                            {
                                                      attributes: { id : 'cert_2_1'}, 
	                                              data: 'some host cert 3', 
                                                    },
                                                  ]
                                      },
                                    ]
                        }"
                      );
    }
}

    ############################################################################
    # Update the default tab in the session if changed
    ############################################################################
    if(defined($c->req->param("change_tab"))){ 
        $c->session->{'default_tab'} = $c->req->param("change_tab"); 
        $c->res->body("Default tab changed to ".$c->session->{'default_tab'}.".");
    }
   
    my $form_data=$c->config->{'layout'};
    if(! defined $c->session->{menudata}){
        $c->session->{menudata}=$form_data->{'forms'};
    }
    # Remember what we set things to.
    foreach my $value ($c->req->param()){
        for(my $idx=0; $idx < $#{ $c->session->{menudata}->{ $c->session->{'default_tab'} }->{'fields'} }; $idx++){
            if($value eq  $c->session->{menudata}->{ $c->session->{'default_tab'} }->{'fields'}->[$idx]->{'name'}){
                $c->session->{menudata}->{ $c->session->{'default_tab'}}->{'fields'}->[$idx]->{'value'} = $c->req->param($value);
            }
        }
    }
    ############################################################################
    # If we're logged in, send us to the application, othewise the login page.
    ############################################################################
    if(!defined $c->session->{'user'}){
        $c->stash->{template}="login.tt";
    }else{
        if($c->check_user_roles( "certificate_administrators" )){
            $c->stash->{menunames}=$form_data->{'order'}->{'administrator'};
        }else{
            my $form_data = $c->config->{'layout'};
            $c->stash->{menunames}=$form_data->{'order'}->{'user'};
        }
        $c->session->{'default_tab'}=$c->stash->{menunames}->[0] unless defined $c->session->{'default_tab'};
        $c->stash->{'default_tab'} = $c->session->{'default_tab'};
        $c->stash->{menudata}=$c->session->{'menudata'};
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
