package pkild::Controller::Root;

use strict;
use warnings;
use base 'Catalyst::Controller';
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

sub json_wrap{
    my $self=shift;
    my $map=shift;
     if($JSON::VERSION >= 2.00){
         return JSON::to_json($map, {'pretty'=>1});
     }else{
         return JSON::objToJson($map, {'pretty'=>1});
     }
}

sub default : Private {
    my ( $self, $c ) = @_;
    # remove this if not running in apache (can we do this automatically?)
    $c->require_ssl;
    ############################################################################
    # Attempt to authenticate
    ############################################################################
    if( (defined($c->req->param("username")))&&(defined($c->req->param("password")))){
        $c->authenticate({
                           id       => $c->req->param("username"), 
                           password => $c->req->param("password") 
                         }, 'ldap-people');
        if(defined($c->user)){
 
            $c->session->{'user'}=$c->user;
        }else{
            $c->authenticate({
                               id       => $c->req->param("username"), 
                               password => $c->req->param("password") 
                             }, 
                             'ldap-hosts');
            if(defined($c->user)){
                $c->session->{'user'}=$c->user;
            }else{
                $c->stash->{'ERROR'}="Authentication Failed."; 
                $c->forward('logout');
            } 
        }
    }
    if(! defined( $c->session->{'user'} )){
        $c->forward('logout');
    }else{
        if($c->session->{'user'}->{'auth_realm'} eq "ldap-hosts"){
                $c->stash->{'orgunit'}='Hosts';
        }
        if($c->session->{'user'}->{'auth_realm'} eq "ldap-people"){
            $c->stash->{'orgunit'}='People';
        }
    }
    ############################################################################
    # Log us out if ?logout=1 was sent
    ############################################################################
    if(defined($c->req->param("logout"))){ 
        # Forward to the logout action/method in this controller
        $c->forward('logout');
    }


    ############################################################################
    # if we have no data to operate on, then forward to the "Create Tree" view
    ############################################################################
    if(! defined($c->model('Certificates')->cert_dn_tree('websages.com',$c->stash->{'orgunit'}))){
        if( $c->check_user_roles( "certificate_administrators" ) ){
            $c->stash->{'template'}='no_cert_tree_admin.tt';
        }else{
            $c->stash->{'template'}='no_cert_tree_user.tt';
        }
        $c->detach();
    }else{
        unless( $c->check_user_roles( "certificate_administrators" ) ){
            print STDERR Data::Dumper->Dump([$c->req->method]);
            # Things a regular user can do:
            if($c->req->method eq 'GET'){ 
                print STDERR Data::Dumper->Dump([$c->req->param]);
            #     if method is GET
            #         get trust chain
            #         get the crl
            #
            }elsif($c->req->method eq 'POST'){
                print STDERR Data::Dumper->Dump([$c->req->param]);
            #     if method is POST
            #         if cert exits:
            #             get their public cert if exists
                if($c->req->param('revoke'){
                    print STDERR "[".$c->req->param('revoke')."]\n";
                }
            #             submit a revokation request
            #         if cert does not exist
            #             post passwords for a pkcs12 cert || post a csr for signing
            }
            if($c->model('Certificates')->user_cert_exists($c->session->{'user'})){
                # display the show certificate page
                $c->stash->{'template'}='show_cert.tt';
                $c->detach();
            }else{
                # display the sign certificate page
                $c->stash->{'user_cert_dn'}=$c->model('Certificates')->user_cert_dn($c->session->{'user'});
                $c->stash->{'template'}='csr_sign.tt';
                $c->detach();
            }
        }
    }
    
    if(defined($c->req->param("get"))){ 
        if($c->req->param("get") eq "ca_trustchain"){
            $c->response->headers->header( 'content-type' => "application/x-x509-ca-cert" );
            # The following line makes it come down like an attachment
            #$c->response->headers->header( 'content-disposition' => "attachment; filename=".$c->model('Certificates')->object_domain($c->model('Certificates')->objectname($c->session->{'user'})).".crt" );
            $c->response->body($c->model('Certificates')->domain_trust_chain($c->model('Certificates')->object_domain($c->model('Certificates')->objectname($c->session->{'user'}))));
            $c->detach();
        }
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
                    # clear this if there is anything selected.
                    if(pack("H*",$c->session->{'selected'}) ne "new_cert"){ $c->session->{'pkcs12cert'}=undef; }
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
                    $c->res->body($self->json_wrap($c->session->{'open_branches'}, {'pretty' => 0}));
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
                    $c->res->body($self->json_wrap($c->session->{'open_branches'}, {'pretty' => 0}));
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
        $c->detach();
    }
   
    my $form_data=$c->config->{'layout'};
    if(! defined $c->session->{'menudata'}){
        $c->session->{'menudata'}=$form_data->{'forms'};
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
        if($c->req->method eq 'POST'){ 
            $c->forward('do_form'); 
            $c->stash->{'template'}="application.tt";
        }else{
            # If we did not post (we did a GET) and no action was specified (no args), 
            # but we have a $c->session->{'pkcs12cert'} defined and # if the $c->session->{'selection'} is 
            # set to "new_cert" ("My Certificate is Selected") then ship the pkcs12 cert
            if( (defined($c->session->{'pkcs12cert'})) &&  (pack("H*",$c->session->{'selected'}) eq "new_cert") ){
                $c->response->headers->header( 'content-type' => "application/x-pkcs12" );
                $c->response->headers->header( 'content-disposition' => "attachment; filename=certificate.p12" );
                $c->response->body($c->session->{'pkcs12cert'});
            }
            $c->stash->{'template'}="application.tt";
        }
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
                'data' => { 'title' => 'Certificate Authorities', 'icon' => 'createnew'},
                'children' => $certificate_tree
              }
            );
    }

#    push( @{ $menu_tree },
#          { 
#            'attributes' => { 'id' =>  unpack("H*","certificate_authority") },
#            'data' => { 'title' => 'Certificate Authority', 'icon' => 'file'},
#          }
#        );

    push( @{ $menu_tree },
          { 
            'attributes' => { 'id' =>  unpack("H*","new_cert") },
            'data' => { 'title' => 'My Certificate', 'icon' => 'file'},
          }
        );
    push( @{ $menu_tree },
          { 
            'attributes' => { 'id' =>  unpack("H*","logout") },
            'data' => { 'title' => 'Logout', 'icon' => 'forbidden'},
          }
        );
    $c->res->body($self->json_wrap($menu_tree, {'pretty' => 1}));
}

sub drawform : Global {
    my ( $self, $c ) = @_;
    $c->session->{'current_node'} = $c->request->arguments->[2];
    ############################################################
    # select the template from the template pool based on what
    # was selected and render it. 
    ############################################################
    my $menu = "new_root_ca";
    my $actual_node;
    if($c->model('Certificates')->node_type( $c->session->{'current_node'} )){
        if($c->model('Certificates')->node_type( $c->session->{'current_node'} ) eq "new_cert"){ 
            my $objectname = $c->session->{'user'}->{'user'}->{'ldap_entry'}->{'asn'}->{'objectName'};
            $actual_node = $c->model('Certificates')->actual_node_from_objectname($objectname);
            # Get the logged in user's valid Cert DN
            $c->stash->{'user_cert_dn'}=$c->model('Certificates')->user_cert_dn($c->session->{'user'});
            $menu='my_cert'; 
        }else{
            $actual_node = $c->session->{'current_node'};
        }
    }
    if($c->model('Certificates')->node_type( $actual_node )){
        if($c->model('Certificates')->node_type( $actual_node ) eq "logout"){              $menu='logout';      }
        if($c->model('Certificates')->node_type( $actual_node ) eq "new_root_ca"){         $menu='new_root_ca'; }
        if($c->model('Certificates')->node_type( $actual_node ) eq "certs"){               $menu='sign';        }
        if($c->model('Certificates')->node_type( $actual_node ) eq "certs"){               $menu='sign';        }
        if($c->model('Certificates')->node_type( $actual_node ) eq "certificate_authority"){
            $menu='certificate_authority';
            $c->stash->{'ca_link'}="<a href=\"?get=ca_trustchain\">Certificate Authority Trust Chain</a>";
        }
        if($c->model('Certificates')->node_type( $actual_node ) eq "certificate"){         
            $menu='revoke';      
            if(defined($c->session->{'pkcs12cert'})){
                $c->stash->{'download_cert_link'}="<a href=\"?download_pkcs12.crt\">Download Certificate (if it didn't auto-download)</a>";
            }else{
                $c->stash->{'download_cert_link'}="";
            }
        }
        if($c->model('Certificates')->node_type( $actual_node ) eq "revoked_certificate"){ 
            $menu='remove'; 
            $c->session->{'selected'}=undef; 
        }
        if($c->model('Certificates')->node_type( $actual_node ) eq "ca"){ 
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
                                                                    'node' => $actual_node,
                                                                    'download_cert_link' => $c->stash->{'download_cert_link'},
                                                                  }
                                                 )
                         );
        }else{
            # Determine if the dn has an existing certificate
            my $objectname=$c->session->{'user'}->{'user'}->{'ldap_entry'}->{'asn'}->{'objectName'};

            # if they don't have a certificate, offer to make them one
            if(!$c->model('Certificates')->has_certificate($objectname)){ 
                $c->res->body( $c->view('TT')->render(
                                                       $c, 
                                                       $c->session->{'menudata'}->{$menu}->{'template'}, 
                                                       { 
                                                         'additional_template_paths' => [ $c->config->{root} . '/src'],
                                                         'menudata'                  => $c->session->{'menudata'}->{$menu},
                                                         'node'                      => $actual_node,
                                                         'user'                      => $objectname,
                                                         'link'                      => $c->stash->{'ca_link'},
                                                         'user_cert_dn'              => $c->stash->{'user_cert_dn'},
                                                       },
                                                     )
                         );
            # otherwise offer to revoke it if it exists, and to remove it if it's revoked, so they can create a new one.
            }else{
                print STDERR "we need a revoke if exists\n";
                print STDERR "we need a remove if revoked here\n";
            }
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
    my $plaintext;
    if( $c->check_user_roles( "certificate_administrators" ) ){
            $plaintext=$c->model('Certificates')->contents($c->request->arguments->[2])
    }else{
        $plaintext="permission denied";
    }
    $c->res->body( $c->view('TT')->render($c , 'plaintext.tt', 
                                          { 
                                            additional_template_paths => [ $c->config->{root} . '/src'],
                                            'plaintext'=>$plaintext,
                                          }
                                         )
                 );
}

sub do_form : Global {
    my ( $self, $c ) = @_;
    if($c->req->param('action_type')){
        if($c->req->param('action_type') eq 'new_ca'){
            $c->stash->{'result'} = $c->model('Certificates')->ca_create($c->req->params,$c->session);
            $c->stash->{'template'}="application.tt";
        }elsif($c->req->param('action_type') eq 'sign_cert'){
            if( $c->check_user_roles( "certificate_administrators" ) ){
                $c->stash->{'result'} = $c->model('Certificates')->sign_certificate($c->req->params,$c->session,1);
            }else{
                $c->stash->{'result'} = $c->model('Certificates')->sign_certificate($c->req->params,$c->session,0);
            }
            $c->stash->{'template'}="application.tt";
        }elsif($c->req->param('action_type') eq 'create_cert'){
            $c->stash->{'result'} = $c->model('Certificates')->create_certificate($c->req->params,$c->session);
            $c->stash->{'template'}="application.tt";
        }elsif($c->req->param('action_type') eq 'revoke_cert'){
            $c->stash->{'result'} = $c->model('Certificates')->revoke_certificate($c->req->params,$c->session);
            $c->stash->{'template'}="application.tt";
        }elsif($c->req->param('action_type') eq 'remove_cert'){
            $c->stash->{'result'} = $c->model('Certificates')->remove_certificate($c->req->params,$c->session);
            $c->stash->{'template'}="application.tt";
        }elsif($c->req->param('action_type') eq 'pkcs12_cert'){
            $c->session->{'pkcs12cert'} = $c->model('Certificates')->create_certificate($c->req->params,$c->session);
            # Set up a refresh that will refresh to the pkcs12 download in the next page load.
            $c->stash->{'refreshto'}="<meta http-equiv=\"refresh\" content=\"5\" />";
            $c->stash->{'instructions'}="Your certificate should start downloading momentarily. Import it into your browser.";
            $c->stash->{'template'}="application.tt";
        }
    }
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
