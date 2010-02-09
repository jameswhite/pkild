package pkild::Controller::Root;

use strict;
use warnings;
use base 'Catalyst::Controller';
use YAML;
use JSON;

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
            $c->forward('logout');
        }
    }
    if(! defined( $c->session->{'user'} )){
        $c->forward('logout');
    }
    ############################################################################
    # Log us out if ?logout=1 was sent
    ############################################################################
    if(defined($c->req->param("logout"))){ 
        # Forward to the logout action/method in this controller
        $c->forward('logout');
    }
    ############################################################################
    # Ajax request handlers
    ############################################################################
    if( $c->request->arguments->[0]){
        if( $c->request->arguments->[0] eq "jstree" ){
            $c->forward('jstreemenu');
        }elsif( $c->request->arguments->[0] eq "action" ){
            # send the new actionbox
            if( $c->request->arguments->[1]){
                # if we've selected a tree item, populate the form as per our forms yaml
                if( $c->request->arguments->[1] eq "select" ){
                    $c->session->{'selected'} = $c->request->arguments->[2];
                    if($c->model('Certificates')->node_type($c->request->arguments->[2])){
                        if($c->model('Certificates')->node_type($c->request->arguments->[2]) eq "file"){
                            $c->forward('renderfile');
                        }else{
                            $c->forward('drawform');
                        }
                    }else{
                        $c->forward('drawform');
                    }
                }elsif($c->request->arguments->[1] eq "open" ){
                    ############################################################
                    # Remember the state of the tree for subsequent page reloads
                    ############################################################
                    shift @{ $c->request->arguments };
                    shift @{ $c->request->arguments };
                    my $path=join ("/",@{ $c->request->arguments });
                    # add the tab node_id to the default open tabs
                    my $found=0;
                    foreach my $item (@{ $c->session->{'open_branches'} }){ if($item eq $path){ $found=1; }  }
                    push (@{ $c->session->{'open_branches'} }, $path ) unless ($found == 1);
                    $c->res->body(to_json($c->session->{'open_branches'}, {'pretty' => 0}));
                }elsif($c->request->arguments->[1] eq "close" ){
                    shift @{ $c->request->arguments };
                    shift @{ $c->request->arguments };
                    my $path=join ("/",@{ $c->request->arguments });
                    my @tmplist=();
                    while (@{ $c->session->{'open_branches'} }){
                        my $tmp=shift(@{ $c->session->{'open_branches'} });
                        push(@tmplist,$tmp) unless ($tmp eq $path);
                    }
                    @{ $c->session->{'open_branches'} }=@tmplist;
                    $c->res->body(to_json($c->session->{'open_branches'}, {'pretty' => 0}));
                }elsif( $c->request->arguments->[1] eq "update" ){
                    # loop through the fields and set the value in the session.
                    if($c->request->arguments->[2]){
                        my @arg_list = @{$c->request->arguments};
                        shift @arg_list; shift @arg_list;
                        my $arg_list=join("/",@arg_list);
                        my ($key,$value)=split(/=/,$arg_list);
                        for(my $idx=0;$idx<=$#{$c->session->{'menudata'}->{$c->session->{'current_node'}}->{'fields'}};$idx++){
                            if($c->session->{'menudata'}->{$c->session->{'current_node'} }->{'fields'}->[$idx]->{'name'} eq $key){
                                $c->session->{'menudata'}->{ $c->session->{'current_node'} }->{'fields'}->[$idx]->{'value'}=$value;
                            }
                        }
                    }
                }
            }
        }
    }
    ############################################################################
    # Update the default tab in the session if changed *deprecated*
    ############################################################################
    if(defined($c->req->param("change_tab"))){ 
        $c->session->{'default_tab'} = $c->req->param("change_tab"); 
        $c->res->body("Default tab changed to ".$c->session->{'default_tab'}.".");
    }
   
    my $form_data=$c->config->{'layout'};
    if(! defined $c->session->{'menudata'}){
        $c->session->{'menudata'}=$form_data->{'forms'};
    }
    # Remember what we set things to.
    if($c->session->{'default_tab'}){
        foreach my $value ($c->req->param()){
            for(my $idx=0; $idx < $#{ $c->session->{'menudata'}->{ $c->session->{'default_tab'} }->{'fields'} }; $idx++){
                if($value eq  $c->session->{'menudata'}->{ $c->session->{'default_tab'} }->{'fields'}->[$idx]->{'name'}){
                    $c->session->{'menudata'}->{ $c->session->{'default_tab'}}->{'fields'}->[$idx]->{'value'} = $c->req->param($value);
                }
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
            if(! defined($c->session->{'selected'}) ){ $c->session->{'selected'} = unpack("H*","new_root_ca"); }
            $c->session->{'menunames'}=$form_data->{'order'}->{'administrator'};
        }else{
            if(! defined($c->session->{'selected'}) ){ $c->session->{'selected'} = unpack("H*","new_cert"); }
            my $form_data = $c->config->{'layout'};
            $c->session->{'menunames'}=$form_data->{'order'}->{'user'};
        }
        $c->session->{'default_tab'}=$c->stash->{menunames}->[0] unless defined $c->session->{'default_tab'};
        $c->stash->{'default_tab'} = $c->session->{'default_tab'};
        $c->stash->{'menunames'}=$c->session->{'menunames'};
        $c->stash->{'menudata'}=$c->session->{'menudata'};
        $c->stash->{'open_branches'}=$c->session->{'open_branches'};
        $c->stash->{'selected'} = $c->session->{'selected'};
        $c->stash->{'selected'} =~s/\./\\\\./g;
        if($c->req->method eq 'POST'){ $c->forward('do_form'); }
        $c->stash->{'template'}="application.tt";
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

sub logout : Global {
    my ( $self, $c ) = @_;
    # remove all user handles
    delete $c->session->{'user'};
    delete $c->session->{'username'};

    # expire our session
    $c->delete_session("logout");

    # send us home, so subsequent page refreshes won't post logout
    #$c->res->redirect("/pkild/"); <-- causes a redirect loop
    $c->detach();
}

sub jstreemenu : Local {
    my ( $self, $c ) = @_;
    my $menu_tree;
    my $certificate_tree=$c->model('Certificates')->tree();
    if($c->check_user_roles( "certificate_administrators" )){
        push( @{ $menu_tree },
              { 
                'attributes' => { 'id' =>  unpack("H*","new_root_ca") },
                'data' => { 'title' => 'Root Certificate Authorities', 'icon' => 'createnew'},
                'children' => $certificate_tree
              }
            );
    }
    push( @{ $menu_tree },
          { 
            'attributes' => { 'id' =>  unpack("H*","new_cert") },
            'data' => { 'title' => 'My Certificate', 'icon' => 'createnew'},
          }
        );
    push( @{ $menu_tree },
          { 
            'attributes' => { 'id' =>  unpack("H*","logout") },
            'data' => { 'title' => 'Logout', 'icon' => 'forbidden'},
          }
        );
    $c->res->body(to_json($menu_tree, {'pretty' => 1}));
}

sub drawform : Global {
    my ( $self, $c ) = @_;
    $c->session->{'current_node'} = $c->request->arguments->[2];
    ############################################################
    # select the template from the template pool based on what
    # was selected and render it. 
    ############################################################
    my $menu = "new_root_ca";
    if($c->model('Certificates')->node_type( $c->session->{'current_node'} )){
        if($c->model('Certificates')->node_type( $c->session->{'current_node'} ) eq "logout"){ $menu='logout'; }
        if($c->model('Certificates')->node_type( $c->session->{'current_node'} ) eq "new_root_ca"){ $menu='new_root_ca'; }
        if($c->model('Certificates')->node_type( $c->session->{'current_node'} ) eq "new_cert"){ $menu='my_cert'; }
        if($c->model('Certificates')->node_type( $c->session->{'current_node'} ) eq "certs"){ $menu='sign'; }
        if($c->model('Certificates')->node_type( $c->session->{'current_node'} ) eq "certificate"){ $menu='revoke'; }
        if($c->model('Certificates')->node_type( $c->session->{'current_node'} ) eq "revoked_certificate"){ $menu='remove'; }
        if($c->model('Certificates')->node_type( $c->session->{'current_node'} ) eq "ca"){ 
            $menu='new_mid_ca'; 
            # load the new_mid_ca form data with the parent node's values if the mid-ca form has not defined them yet
            foreach my $root_field (@{ $c->session->{'menudata'}->{'new_root_ca'}->{'fields'} }){
                for(my $midx=0;$midx<=$#{ $c->session->{'menudata'}->{'new_mid_ca'}->{'fields'} };$midx++){
                    if($root_field->{'name'} eq $c->session->{'menudata'}->{'new_mid_ca'}->{'fields'}->[$midx]->{'name'}){
                        if(! defined($c->session->{'menudata'}->{'new_mid_ca'}->{'fields'}[$midx]->{'value'})){
                            $c->session->{'menudata'}->{'new_mid_ca'}->{'fields'}[$midx]->{'value'} = $root_field->{'value'};
                        }
                    }
                }
            }
            
        }
    }
    if( defined $c->session->{'menudata'}->{$menu}){
        if( !defined($c->session->{'menudata'}->{$menu}->{'template'})){ 
            $c->res->body( $c->view('TT')->render($c , 'form.tt', { 
                                                                    additional_template_paths => [ $c->config->{root} . '/src'],
                                                                    'menudata' => $c->session->{'menudata'}->{$menu},
                                                                    'node' => $c->session->{'current_node'},
                                                                  }
                                                 )
                         );
        }else{
my $entry=$c->session->{'user'}->{'user'}->{'ldap_entry'}->{'asn'};
print STDERR Data::Dumper->Dump([$entry]);
            $c->res->body( $c->view('TT')->render($c , $c->session->{'menudata'}->{$menu}->{'template'}, { 
                                                                    additional_template_paths => [ $c->config->{root} . '/src'],
                                                                    'menudata' => $c->session->{'menudata'}->{$menu},
                                                                    'node' => $c->session->{'current_node'},
                                                                    'user'=> Data::Dumper->Dump([$entry])
                                                                  }
                                                 )
                         );
        }
    }else{
    $c->res->body( $c->view('TT')->render($c , 'plaintext.tt', 
                                          { 
                                            additional_template_paths => [ $c->config->{root} . '/src'],
                                            'plaintext'=>''
                                          }
                                         )
                 );
    }
}

sub renderfile : Global {
    my ( $self, $c ) = @_;
    $c->res->body( $c->view('TT')->render($c , 'plaintext.tt', 
                                          { 
                                            additional_template_paths => [ $c->config->{root} . '/src'],
                                            'plaintext'=>$c->model('Certificates')->contents($c->request->arguments->[2])
                                          }
                                         )
                 );
}

sub do_form : Global {
    my ( $self, $c ) = @_;
    if($c->req->param('action_type')){
        if($c->req->param('action_type') eq 'new_ca'){
            $c->stash->{'result'} = $c->model('Certificates')->ca_create($c->req->params,$c->session);
        }elsif($c->req->param('action_type') eq 'sign_cert'){
            $c->stash->{'result'} = $c->model('Certificates')->sign_certificate($c->req->params,$c->session);
        }elsif($c->req->param('action_type') eq 'create_cert'){
            $c->stash->{'result'} = $c->model('Certificates')->create_certificate($c->req->params,$c->session);
        }elsif($c->req->param('action_type') eq 'revoke_cert'){
            $c->stash->{'result'} = $c->model('Certificates')->revoke_certificate($c->req->params,$c->session);
        }elsif($c->req->param('action_type') eq 'remove_cert'){
            $c->stash->{'result'} = $c->model('Certificates')->remove_certificate($c->req->params,$c->session);
        }
    }
    $c->stash->{'template'}="application.tt";
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
