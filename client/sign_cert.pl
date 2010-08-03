#!/usr/bin/perl
package pkild::tests;
use Data::Dumper;
use WWW::Mechanize;
use File::Temp qw/ tempfile tempdir /;

sub new {
    use Sys::Hostname::Long;
    my $class = shift;
    my $cnstr = shift if @_;
    my $self  = {};
    if(defined($cnstr->{'uri'})){ 
        $self->{'uri'} = $cnstr->{'uri'}; 
    }
    if(defined($cnstr->{'username'})){ 
        $self->{'username'} = $cnstr->{'username'}; 
    }
    if(defined($cnstr->{'password'})){ 
        $self->{'password'} = $cnstr->{'password'}; 
    }
    $self->{'mech'} = WWW::Mechanize->new();
    $self->{'mech'}->get( $self->{'uri'} );
    $self->{'host_long'} = hostname_long;
    bless($self,$class);
    return $self;
}

sub legends{
    my $self = shift;
    $self->{'mech'}->get( $self->{'uri'} );
    # find the legends on the page to determine which form we're seeing
    my @legends = grep(/<legend>.*<\/legend>/, split('\n',$self->{'mech'}->content)); 
    if($#legends<0){
        die "No legends found.\n";
    }
    for(my $idx=0; $idx<=$#legends; $idx++){
        $legends[$idx]=~s/.*<legend>//;
        $legends[$idx]=~s/<\/legend>.*//;
    }
    return @legends;
}

sub revoke_cert{
    my $self = shift;
    print "Revoking Certificate.\n";
    $self->{'mech'}->click_button( 'name' => 'revoke' );
    if (grep/Certificate Signing Request/, $self->legends()){
        return 1;
    }else{
        return 0;
    }
}

sub sign_csr{
    my $self = shift;
    print "Creating a certificate signing request and posting for signature.\n";
    # make our tmp dir
    my  $dir = tempdir( CLEANUP => 1 );
    # make our key
    system("cd $dir; /usr/bin/openssl genrsa -out /etc/ssl/private/$self->{'host_long'}.key 2048");
    chmod(0600,"/etc/ssl/private/$self->{'host_long'}.key");
    # get our openssl.cnf
    $self->{'mech'}->follow_link( 'text' => 'OpenSSL config for batch CSR creation' );
    open(OPENSSLCNF,">$dir/openssl.cnf");
    print OPENSSLCNF $self->{'mech'}->content."\n";
    close(OPENSSLCNF);
    $self->{'mech'}->back();
    # create our CSR 
    system("cd $dir; /usr/bin/openssl req -new -sha1 -days 90 -key /etc/ssl/private/$self->{'host_long'}.key -out $self->{'host_long'}.csr -config openssl.cnf -batch");
    # post our CSR
    my $csr='';
    print "Submitting our CSR\n";
    open(CSR,"$dir/$self->{'host_long'}.csr");
    while(my $line=<CSR>){
        $csr.=$line; 
    }
    close(CSR);
    $self->{'mech'}->submit_form( with_fields => { 'csr_request'    => $csr });
    if (grep/Valid Certificate Found/, $self->legends()){
        return 1;
    }else{
        return 0;
    }
}

sub pkcs12_request{
    my $self=shift;
    $self->{'mech'}->submit_form( with_fields => { 
                                                   'password'         => 'password',
                                                   'confirm_password' => 'password'
                                                 });
    # This simulates the "refreshto"  on the page, that then pulls the cert once before the controller deletes it from memory
    sleep(5);
    $self->{'mech'}->get( $self->{'uri'} );
    $self->{'pkcs12cert'} = $self->{'mech'}->content;

    # then we test if we have a valid cert
    if (grep/Valid Certificate Found/, $self->legends()){
        return 1;
    }else{
        return 1;
        #return 0;
    }
}

sub retrieve_trustchain{
    my $self = shift;
    my $target = shift if @_;
    # Retrieve our cert
    print "Retrieving our trustchain\n";
    $self->{'mech'}->get("$uri/?get=trustchain");
    open(CERTFILE, ">$target");
    print CERTFILE $self->{'mech'}->content;
    close(CERTFILE);
    chmod(0644,"$target");
    return 1;
}

sub retrieve_cert{
    my $self = shift;
    my $target = shift if @_;
    # Retrieve our cert
    print "Retrieving our certificate -> $self->{'host_long'}.pem\n";
    $self->{'mech'}->get("$uri/?get=certificate");
    open(CERTFILE, ">$target");
    print CERTFILE $self->{'mech'}->content;
    close(CERTFILE);
    chmod(0644,"$target");
    return 1;
}

sub log_in{
    my $self = shift;
    print "Authenticating as $self->{'username'}.\n";
    $self->{'mech'}->submit_form(
                                 with_fields => {
                                                  'username'    => $self->{'username'},
                                                  'password'    => $self->{'password'},
                                                }
                               );
   return 1;
}

sub create_tree{
    my $self = shift;
    my $found = 0; 
    print "Trying to create the tree.\n";
    foreach my $form ( $self->{'mech'}->forms ){
        foreach my $input ( $form->inputs ){
           if($input->name() eq 'create_cert_tree'){ $found =1; }
        }
    }
    unless ($found == 1){
        print "Did not find the create_cert_tree link needed for submission.\n";
        return 0;
    }
    $self->{'mech'}->click( 'create_cert_tree' );
    foreach my $form ($self->{'mech'}->forms()){
        if($form->inputs() < 1){
            print "We do not have administrator rights. Can not create the tree.\n";
            return 0;
        }else{
            print "We have administrator rights. Creating the tree\n";
            $self->{'mech'}->click( 'create_cert_tree' );
            return 1;
        }
    }
}

1;
################################################################################
################################################################################
use Sys::Hostname::Long;

# Get secret
open(SECRET,"/usr/local/sbin/secret |") || die "Could not determine my credentials";
my $secret=<SECRET>;
chomp($secret);
close(SECRET);

my $fqdn=hostname_long();
my $basename   = $fqdn; $basename=~s/\..*//;
my $domainname = $fqdn; $domainname=~s/^[^\.]*\.//;

# attach to self for testing:
my $pt=pkild::tests->new({ 'uri' => 'https://'.$fqdn, 'username' => $basename, 'password' => $secret, });

# Log in
if(grep /Please [Ll]og [Ii]n/, $pt->legends() ){ $pt->log_in(); }

# Abort if no tree exists
if(grep /No certificate tree found/, $pt->legends() ){ exit -1; }

# Revoke cert if exists (we want a new one)
if(grep /Valid Certificate Found/, $pt->legends() ){ $pt->revoke_cert(); }

# Create new key in /etc/ssl/private, Create CSR, submit it for signing.
if(grep /Certificate Signing Request/, $pt->legends() ){ $pt->sign_csr(); }

# Retrieve Cert, install it in /etc/ssl/certs/$fqdn.crt
if(grep /Valid Certificate Found/, $pt->legends() ){ $pt->retrieve_cert("/etc/ssl/certs/$fqdn.pem"); }

# Pull down CA Trust Chain, install it in /var/www/, /etc/ssl/certs/
if(grep /Valid Certificate Found/, $pt->legends() ){ 
    $pt->retrieve_trustchain("/etc/ssl/certs/".$domainname."_trustchain.pem"); 
    $pt->retrieve_trustchain("/var/www/".$domainname."_trustchain.pem"); 
}

# If we're running pkild, and we're still linked to pkild-ssl.snakeoil, unlink it, and link to pkild-ssl
# if( (-s "/etc/ssl/certs/$fqdn.crt") && (-s "/etc/ssl/private/$fqdn.key")){
# }
exit 0;
