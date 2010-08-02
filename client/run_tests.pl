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
        print "No legends found.\n";
        return undef;
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
    system("cd $dir; /usr/bin/openssl genrsa -out $self->{'host_long'}.key 2048");
    # get our openssl.cnf
    $self->{'mech'}->follow_link( 'text' => 'OpenSSL config for batch CSR creation' );
    open(OPENSSLCNF,">$dir/openssl.cnf");
    print OPENSSLCNF $self->{'mech'}->content."\n";
    close(OPENSSLCNF);
    $self->{'mech'}->back();
    # create our CSR 
    system("cd $dir; /usr/bin/openssl req -new -sha1 -days 90 -key $self->{'host_long'}.key -out $self->{'host_long'}.csr -config openssl.cnf -batch");
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
    if (grep/Valid Certificate Found/, $self->legends()){
        return 1;
    }else{
        return 0;
    }
}

sub retrieve_cert{
    my $self = shift;
    # Retrieve our cert
    print "Retrieving our certificate -> $self->{'host_long'}.pem\n";
    $self->{'mech'}->get("$uri/?get=certificate");
    ########################################################################
    # install our cert and key                                             #
    #                                                                      #
    open(CERTFILE, ">/tmp/$self->{'host_long'}.pem");
    print CERTFILE $mech->content;
    close(CERTFILE);
    system("/bin/mv $dir/$self->{'host_long'}.key /tmp/$self->{'host_long'}.key");
    #print $mech->content;
    #                                                                      #
    ########################################################################
    return 1;
}

sub log_in{
    my $self = shift;
    print "Authenticating.\n";
    $self->{'mech'}->submit_form(
                                 with_fields => {
                                                  'username'    => $self->{'username'},
                                                  'password'    => $self->{'password'},
                                                }
                               );
   return $self;
}

sub create_tree{
    my $self = shift;
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
# Tests:
# Log in, remove cert if exists
# create csr, sign it, revoke it
# create pkcs12 cert, revoke it
################################################################################
my $pt=pkild::tests->new({ 
                           'uri'      => 'https://loki.websages.com',
                           'username' => 'loki', 
                           'password' => $ENV{'LOKI_PASSWD'} 
                         });

my $test = {
             'csr_signed' => '0',
             'cert_revoke' => '0',
             'pkcs12_create' => '0',
           };

my $idx=0;
while(( ($test->{'csr_signed'} == 0) || ($test->{'cert_revoke'} == 0) || ($test->{'pkcs12_create'} == 0))&&($idx < 10)){
    if(grep /Please [Ll]og [Ii]n/, $pt->legends() ){
        print "We need to log in\n";
        $pt->log_in();
    }elsif(grep /Certificate Signing Request/, $pt->legends() ){

        if($test->{'csr_signed'}){
            print "We need a pkcs#12 created\n";
            $test->{'pkcs12_create'} = $pt->pkcs12_request()
        }else{
            print "We need a CSR signed\n";
            $test->{'csr_signed'} = $pt->sign_csr();
        }
    }elsif(grep /Valid Certificate Found/, $pt->legends() ){
        $test->{'cert_revoke'} = $pt->revoke_cert();
    }elsif(grep /No certificate tree found/, $pt->legends() ){
        print "We need to create the tree.\n";
        unless( $self->create_tree() ){
            my $apt = pkild::tests->new({ 
                                          'uri'      => 'https://loki.websages.com',
                                          'username' => 'whitejs', 
                                          'password' => $ENV{'WHITEJS_PASSWD'} 
                                        });
            $apt->log_in();
            $apt->create_tree();
        }
    }else{
        print "Unhandled legends found:\n";
        print join("\n",$pt->legends())."\n";
    }
    $idx++;
    print STDERR Data::Dumper->Dump([$test]);
}
