package pkild::Model::Certificates;

use strict;
use base 'Catalyst::Model::File';

__PACKAGE__->config(
    root_dir => '/var/tmp/certificate_authority',
);

################################################################################
# Return a list of hashes of lists of hashes that describe the directory tree
################################################################################
sub tree{
    my ($self, $c)=@_;
    my $tree;
    my $node_separator="::";
    my @file_names=$self->list(mode => 'both', recurse =>1);
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    $rootdir=~s/^\///;
    @file_names=sort(@file_names);
    my $previous_node='';
    my $type;
    for my $node (@file_names){
        next if $node eq '.';
        # skip directories containing key data and used for work.
        next if $node=~m/\/private$/;
        next if $node=~m/\/.rnd$/;
        next if $node=~m/\/openssl.cnf$/;
        next if $node=~m/\/index.txt$/;
        next if $node=~m/\/serial$/;
        next if $node=~m/\/crlnumber$/;
        next if $node=~m/\.old$/;
        next if $node=~m/\.attr$/;
        next if $node=~m/\/newcerts$/;
        next if $node=~m/\/crl$/;
        next if $node=~m/\.pem$/;
        next if $node=~m/\.csr$/;
        # We need to know if this is a file, or a directory
        $type="unknown";
        if( -d $node){ $type="folder"; }
        if( -f $node){ $type="file"; }
        $node=~s/$rootdir//g;
        $node=~s/^\///g;
        if(! defined $tree->{$node}){  
            my @nodeparts=split("\/",$node);
            $node=~s/\//$node_separator/g;
            $tree->{$node} = { 
                               'attributes' => { 'id' => $node, 'rel' => $type },
                               'data'       => $nodeparts[$#nodeparts],
                             };
            pop(@nodeparts);
            my $updir=join("$node_separator",@nodeparts);
            if(!defined( $tree->{ $updir }->{'children'} )){
               push( @{ $tree->{ $updir }->{'children'} }, $node );
            }else{
               my $found=0;
               foreach my $child (@{ $tree->{ $updir }->{'children'} }){
                   if($node eq $child){ $found=1;}
               }
               if(! $found){ push( @{ $tree->{ $updir }->{'children'} }, $node ); }
           }
        }
    }
    # now dereference the children to their actual structs.
    foreach my $key (reverse(sort(keys(%{ $tree })))){
        if(defined( $tree->{$key}->{'children'} && $key ne '')){
            for(my $childidx=0; $childidx<=$#{$tree->{$key}->{'children'} }; $childidx++){ 
                if(defined( $tree->{$key}->{'children'}->[$childidx] )){
                    $tree->{$key}->{'children'}->[$childidx] = YAML::Load(YAML::Dump($tree->{ $tree->{$key}->{'children'}->[$childidx] }));
                }else{
                    $tree->{$key}->{'children'}->[$childidx] = undef;
                }
            }
        }
    }
    return $tree->{''}->{'children'};
}

sub create_certificate{
    my ($self, $param,$session)=@_;
    # create openssl.cnf
    # create password-protected private key
    # create csr
    # ship the key to the user for saving locally.
    # add an option for pkcs12
    return $self;  
}

sub remove_certificate{
    my ($self, $param,$session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    # convert the :: delimited node names into a path
    my $node_dir = $param->{'node_name'};
    my @nodepart=split(/::/, $node_dir);
    my $node_name=pop(@nodepart); pop(@nodepart);
    my $parent_name=$nodepart[$#nodepart];
    my $parent_dir="$rootdir/".join("/",@nodepart);
    $node_dir=~s/::/\//g;
    $node_dir="$rootdir/$node_dir";
    opendir(my $dh, "$rootdir/$node_dir");
    my @files = readdir($dh);
    foreach my $file (@files){
        unlink("$rootdir/$node_dir/$file");
        print STDERR "\n\n\nunlink($rootdir/$node_dir/$file\n\n\n";
    }
    closedir $dh;
    rmdir "$rootdir/$node_dir";
    print STDERR "\n\n\nrmdir $rootdir/$node_dir\n\n\n";
}

sub revoke_certificate{
    my ($self, $param,$session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });

    # convert the :: delimited node names into a path
    my $node_dir = $param->{'node_name'};
    my @nodepart=split(/::/, $node_dir);
    my $node_name=pop(@nodepart); pop(@nodepart);
    my $parent_name=$nodepart[$#nodepart];
    my $parent_dir="$rootdir/".join("/",@nodepart);
    $node_dir=~s/::/\//g;
    $node_dir="$rootdir/$node_dir";

    # Revoke the Certificate (updates the Index)
    system("/usr/bin/openssl ca -revoke $node_dir/$node_name.crt -keyfile $parent_dir/private/$parent_name.key -cert $parent_dir/$parent_name.pem -config $parent_dir/openssl.cnf");

    # update the Certificate Revocation list
    system("/usr/bin/openssl ca -gencrl -keyfile $parent_dir/private/$parent_name.key -cert $parent_dir/$parent_name.pem -config $parent_dir/openssl.cnf -out $parent_dir/$parent_name.crl");

    # Rename the cert to indicate it has been revoked
    rename("$node_dir/$node_name.crt","$node_dir/$node_name.revoked");
    return $self;  
}

sub sign_certificate{
    use FileHandle;
    use File::Temp qw/ tempfile tempdir /;
    my ($self, $param,$session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    
    # convert the :: delimited node names into a path
    my $node_dir = $param->{'node_name'};
    $node_dir=~s/::/\//g;
    $node_dir=~s/certs$//g;
    $node_dir="$rootdir/$node_dir";

    # write out the csr to a temp file
    my $tmpdir = tempdir( 'CLEANUP' => 1 );
    my ($fh, $filename) = tempfile( 'DIR' => $tmpdir );
    print $fh $param->{'csr_input'};
    my $common_name;
    open(GETCN, "/usr/bin/openssl req -in $filename -noout -text | ");
    while(my $line=<GETCN>){
        if($line=~m/Subject:/){
            $line=~s/.*CN=//g;
            $line=~s/\/.*//g;
            $line=~s/\s+//g;
            $common_name=$line;
        }
    }
    # delete the temp file
    # create the $root/$param->{'node_name'};/$cn  directory
    if(! -d "$node_dir/certs/$common_name"){
        mkdir("$node_dir/certs/$common_name",0700);
    }
    my $csrfh = FileHandle->new("> $node_dir/certs/$common_name/$common_name.csr");
    # write out the csr to ${cn}.csr in the node directory
    if (defined $csrfh) {
        print $csrfh $param->{'csr_input'};
        $csrfh->close;
    }
    # sign the csr and write it out as a ${cn}.crt int the node directory
    system("/usr/bin/openssl ca -config $node_dir/openssl.cnf -policy policy_anything -out $node_dir/certs/$common_name/$common_name.crt -batch -infiles $node_dir/certs/$common_name/$common_name.csr");
    return "SUCCESS";
}

sub ca_create{
    use FileHandle;
    use Template;
    my ($self, $param,$session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });

    # convert the :: delimited node names into a path
    my $node_dir = $param->{'node_name'};
    $node_dir=~s/new_root_ca/\//g; # get rid of the top node and make our root node_dir ""
    $node_dir=~s/::/\//g;
    $node_dir="$rootdir/$node_dir";
    my $template=Template->new();
    my $tpldata;
    if($param->{'ca_domain'}){
        if( ! -d "$node_dir/$param->{'ca_domain'}" ){
        
            # Create our working environment
            umask(0077);
            mkdir("$node_dir/$param->{'ca_domain'}",0700); 
            mkdir("$node_dir/$param->{'ca_domain'}/private",0700); 
            mkdir("$node_dir/$param->{'ca_domain'}/certs",0700); 
            mkdir("$node_dir/$param->{'ca_domain'}/newcerts",0700); 
            mkdir("$node_dir/$param->{'ca_domain'}/crl",0700); 
            # echo "01" > ${ROOT_CA}/serial
            if(! -f "$node_dir/$param->{'ca_domain'}/serial"){
                my $fh = FileHandle->new("> $node_dir/$param->{'ca_domain'}/serial");
                if (defined $fh) {
                    print $fh "01\n";
                    $fh->close;
                }
            }
            # echo "01" > ${ROOT_CA}/crlnumber
            if(! -f "$node_dir/$param->{'ca_domain'}/crlnumber"){
                my $fh = FileHandle->new("> $node_dir/$param->{'ca_domain'}/crlnumber");
                if (defined $fh) {
                    print $fh "01\n";
                    $fh->close;
                }
            }
            # cp /dev/null ${ROOT_CA}/index.txt
            if(! -f "$node_dir/$param->{'ca_domain'}/index.txt"){
                my $fh = FileHandle->new("> $node_dir/$param->{'ca_domain'}/index.txt");
                if (defined $fh) {
                    print $fh '';
                    $fh->close;
                }
            }
            foreach my $key (keys(%{ $param } )){
                $tpldata->{$key} = $param->{$key};
            }
            foreach my $prefs (@{ $session->{'menudata'}->{'openssl_cnf_prefs'}->{'fields'} }){
                $tpldata->{$prefs->{'name'}} = $prefs->{'value'};
            }
          
            # Create a new openssl.cnf for this CA
            my $text=$self->openssl_cnf_template(); 
            $tpldata->{'cert_home_dir'}="$node_dir/$param->{'ca_domain'}";
            $template->process(\$text,$tpldata,"$node_dir/$param->{'ca_domain'}/openssl.cnf");

            # Create the private key
            system("/usr/bin/openssl genrsa -out $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key 4096");

            if( -d "$node_dir/certs"){
                # only the top-level dir will not have a certs dir , so this is a mid_ca (of some arbitrary level)
                
                # Create a CSR to be signed by our parent
                system("/usr/bin/openssl req -new -sha1 -days $tpldata->{'ca_default_days'} -key $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key  -out $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.csr -config $node_dir/$param->{'ca_domain'}/openssl.cnf -batch");

                # Have the parent sign the CSR
                system("/usr/bin/openssl ca -extensions v3_ca -days $tpldata->{'ca_default_days'} -out $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crt -in $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.csr -config $node_dir/openssl.cnf -batch");
                # Clean up the CSR
                if(-f "$node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crt"){
                    unlink("$node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.csr");
                }

                # Write out the PEM part to the .pem file
                my $write=0;
                my $rfh = FileHandle->new;
                if ($rfh->open("< $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crt")) {
                    my $wfh = FileHandle->new("> $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem");
                    if (defined $wfh) {
                        while(my $line=<$rfh>){
                            if($line=~m/-----BEGIN CERTIFICATE-----/){ $write=1; }
                            if($write == 1){ print $wfh $line;}
                            if($line=~m/-----END CERTIFICATE-----/){ $write=0; }
                        }
                         $wfh->close;
                      
                    }
                    $rfh->close;
                }

                # Determine the name of our parent CA
                my $parent_name=$node_dir;
                $parent_name=~s/.*\///;

                # Write out the trust_chain
                # cat mid-ca.${DOMAIN}.crt root-ca.${DOMAIN}.pem > ca_trust_chain.crt
 
            }else{
                # only the top-level node_type is directory, so this is a root ca

                # Create a self-signed cert in .pem format
                system("/usr/bin/openssl req -new -x509 -nodes -sha1 -days $tpldata->{'ca_default_days'} -key $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key  -out /$node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem -config /$node_dir/$param->{'ca_domain'}/openssl.cnf -batch");

                # Write out the cert in x509 
                system("/usr/bin/openssl x509 -in $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem -text -out $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crt");
            }
            
            # In any event, create the empty certificate revocation list
            system("/usr/bin/openssl ca -gencrl -keyfile $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key -cert $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem -config $node_dir/$param->{'ca_domain'}/openssl.cnf -out $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crl");
            # To Revoke: (run this and then regenerate the CRL with the command above, copy it to it's URI)
            #system("/usr/bin/openssl ca -revoke <PATH/TO/BAD_CERT> -keyfile $node_dir/$param->{'ca_domain'}/private/$param->{'ca_domain'}.key -cert $node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.pem -config $node_dir/$param->{'ca_domain'}/openssl.cnf");
            return "SUCCESS";
        }
    }
    return "ERROR";
}

# by convention, all CAs have a subdir named "certs" and others don't
sub node_type{
    my ($self, $node)=@_;
    my @nodepart=split(/::/, $node);
    $node =~s/::/\//g;
    my $rootdir="/".join("/",@{ $self->{'root_dir'}->{'dirs'} });
    if(-f "$rootdir/$node"){ return "file"; }
    if(-d "$rootdir/$node"){ 
        if(-d "$rootdir/$node/certs"){ return "ca"; }
        my $isacertbucket="$rootdir/$node";
        $isacertbucket=~s/.*\///;
        if($isacertbucket eq "certs") { return "certs"; }
        if($nodepart[$#nodepart - 1]  eq "certs"){ 
            if(-f "$rootdir/$node/$nodepart[$#nodepart].revoked"){
                return "revoked_certificate" ;
            }
            return "certificate" 
        };
        return "directory"; 
    }
    return undef;
}

sub contents{
    use FileHandle;
    my ($self, $node)=@_;
    $node =~s/::/\//g;
    my $rootdir="/".join("/",@{ $self->{'root_dir'}->{'dirs'} });
    my $contents='';
    if(-f "$rootdir/$node"){ 
        my $fh = FileHandle->new;
        if ($fh->open("< $rootdir/$node")) {
            while(my $line=<$fh>){
                $contents.=$line;
            }
            $fh->close;
            return $contents;
        }
    }
    return undef;
}

sub openssl_cnf_template{
    my ($self)=shift;
    my $the_template = <<_END_TEMPLATE_;
HOME = [\% cert_home_dir \%]
RANDFILE = \$HOME/.rnd
ca-domain = [\% ca_domain \%]
 
[ ca ]
default_ca = CA_default # The default ca section
[ CA_default ]
dir = \${HOME}
certs = \$dir/certs
crl_dir = \$dir/crl
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
certificate = \$dir/[\% ca_domain \%].pem
serial = \$dir/serial
crlnumber = \$dir/crlnumber
crl = \$dir/crl.[\% ca_domain \%].pem
private_key = \$dir/private/[\% ca_domain \%].key
RANDFILE = \$dir/private/.rand
x509_extensions = usr_cert
name_opt = ca_default
cert_opt = ca_default
default_days = [\% ca_default_days \%]
default_crl_days= [\% crl_days \%]
default_md = sha1
preserve = no
policy = policy_match
 
[ policy_match ]
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
 
[ policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
 
[ req ]
default_bits = 1024
default_keyfile = [\% ca_domain \%].pem
distinguished_name = req_distinguished_name
attributes = req_attributes
x509_extensions = v3_ca
 
[ req_distinguished_name ]
countryName = Country Name (2 letter code)
countryName_default = [\% ca_country \%]
countryName_min = 2
countryName_max = 2
stateOrProvinceName = State or Province Name (full name)
stateOrProvinceName_default = [\% ca_state \%]
localityName = Locality Name (eg, city)
localityName_default = [\% ca_localitiy \%]
0.organizationName = Organization Name (eg, company)
0.organizationName_default = [\% ca_org \%]
organizationalUnitName = Organizational Unit Name (eg, section)
organizationalUnitName_default = [\% ca_orgunit \%]
commonName = Common Name (eg, YOUR name)
commonName_max = 64
commonName_default = [\% ca_domain \%]
emailAddress = Email Address
emailAddress_max = 64
emailAddress_default = [\% ca_email \%]
 
[ req_attributes ]
challengePassword = A challenge password
challengePassword_min = 4
challengePassword_max = 20
 
[ usr_cert ]
basicConstraints=CA:FALSE
nsComment = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
nsCaRevocationUrl = [\% crl_path \%]
 
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
nsCaRevocationUrl = [\% crl_path \%]
 
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true
nsCaRevocationUrl = [\% crl_path \%]
_END_TEMPLATE_

    return $the_template;
}
=head1 NAME

pkild::Model::Certificates - Catalyst File Model

=head1 SYNOPSIS

See L<pkild>

=head1 DESCRIPTION

L<Catalyst::Model::File> Model storing files under
L<>

=head1 AUTHOR

James White

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
