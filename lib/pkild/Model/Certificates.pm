package pkild::Model::Certificates;

use strict;
use base 'Catalyst::Model::File';

__PACKAGE__->config(
    root_dir => '/var/tmp/certificate_authority',
    node_separator => '::'
);
sub cert_subject{
    my $self=shift;
    my $cert_file=shift;
    my $subject=undef;
    if(-f "$cert_file"){
        my $cacert_fh = FileHandle->new;
        if ($cacert_fh->open("< $cert_file")) {
            while(my $line=<$cacert_fh>){
                if($line=~m/\s*Subject:\s*(.*)/){
                   $subject=$1;
                }
            }
            $cacert_fh->close;
        }
    }else{
        return undef;
    }
    return $subject;
}

sub user_cert_dn{
use FileHandle;
    my ($self,$user_session) = @_;
    my $objectname=$self->objectname($user_session);
    my $cn=$objectname;
    my $type=undef;
    $cn=~s/,.*//g;
    $cn=~tr/A-Z/a-z/;
    if($cn=~m/\s*uid=(.*)/){ $type="user"; $cn=~s/\s*uid=//; }
    if($cn=~m/\s*cn=(.*)/){ $type="host"; $cn=~s/\s*cn=//;}
    my $domain=$self->object_domain($objectname);
    my $ca = $self->ca_for($domain);
    my $ca_subject=$self->cert_subject("$ca/$domain.crt");
    my $subject=$ca_subject;
    if($subject=~m/C=(.*),\s*ST=(.*),\s*L=(.*),\s*O=(.*),\s*OU=(.*),\s*CN=(.*)\/emailAddress=(.*)/){
        if($type eq "user"){
            $subject="C=$1, ST=$2, L=$3, O=$4, OU=$5, CN=$cn/emailAddress=$cn\@$domain";
        }elsif($type eq "host"){
            $subject="C=$1, ST=$2, L=$3, O=$4, OU=$5, CN=$cn.$domain/emailAddress=sysadmins\@$domain";
        }
    }
    return $subject;
}

sub objectname{
    my $self=shift;
    my $user_session=shift;
    if(defined($user_session->{'user'}->{'ldap_entry'}->{'asn'}->{'objectName'})){
        return $user_session->{'user'}->{'ldap_entry'}->{'asn'}->{'objectName'};
    }
    return undef;
}

sub object_domain{
    my $self=shift;
    my $object=shift;
    my ($identity_type, $identity,$orgunit,$domain);
    if($object=~m/\s*(.*)\s*=\s*(.*)\s*,\s*[Oo][Uu]\s*=\s*([^,]+)\s*,\s*dc\s*=\s*(.*)\s*/){
        $identity_type=$1; $identity=$2; $orgunit=$3; $domain=$4; $domain=~s/,dc=/./g;
        # I hate upper case.
        $identity_type=~tr/A-Z/a-z/;
        $identity=~tr/A-Z/a-z/;
        $orgunit=~tr/A-Z/a-z/;
        $domain=~tr/A-Z/a-z/;
    }
    return $domain if $domain;
    return undef;
}

sub domain_trust_chain{
use File::Slurp;
    my $self = shift;
    my $domain=shift;
    my $cert = read_file( $self->ca_for($domain)."/".$domain.".crt", binmode => ':raw' ) ;        
    return $cert;
}

################################################################################
# Return a list of hashes of lists of hashes that describe the directory tree
################################################################################
sub tree{
    my ($self, $c)=@_;
    my $tree;
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
        next if $node=~m/\.p12$/;
        # We need to know if this is a file, or a directory
        $type="unknown";
        if( -d $node){ $type="folder"; }
        if( -f $node){ $type="file"; }
        $node=~s/$rootdir//g;
        $node=~s/^\///g;
        if(! defined $tree->{$node}){  
            my @nodeparts=split("\/",$node);
            $node=~s/\//$self->{'node_separator'}/g;
            $tree->{$node} = { 
                               'attributes' => { 'id' => unpack("H*",$node), 'rel' => $type },
                               'data'       => $nodeparts[$#nodeparts],
                             };
            pop(@nodeparts);
            my $updir=join("$self->{'node_separator'}",@nodeparts);
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

sub actual_node{
    my $self=shift;
    my $unpacked_node=shift;
    return pack("H*",$unpacked_node);
}

sub has_certificate{
    my ($self, $object)=@_;
    return undef;
}

sub ca_domain_from_file{
use FileHandle;
   my $self=shift;
   my $file=shift;
   my $fh = FileHandle->new;
   my $ca_domain;
   if ($fh->open("< $file")) {
       while(my $line=<$fh>){
           chomp($line);
           if($line=~m/^\s*ca-domain\s*=\s*(.*)/){
               $ca_domain=$1; 
               $ca_domain=~s/^\s*//g;
               $ca_domain=~s/\s*$//g;
           }
       }
       $fh->close;
   }
   print return $ca_domain;
}

sub find_file{
    my ($self,$dir,$fileregex)=@_; 
print STDERR Data::Dumper->Dump([$dir,$fileregex]);
    opendir(DIR,$dir);
    if ($dir !~ /\/$/) { $dir .= "/"; }
    my @dirlist=readdir(DIR);
    closedir(DIR);
    splice(@dirlist,0,2);
    foreach my $file (@dirlist){
        if($file ne "." && $file ne ".."){
            my $file = $dir.$file;
            if (-d $file){
                $self->find_file($file,$fileregex);
            }else{
                if($file=~m/$fileregex/){
                   push( @{$self->{'file_list'} },$file)
                }
            }
        }
    }
    return $self;
}

sub create_certificate{
use File::Slurp;
    my ($self, $param, $session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    my $objectname = $session->{'user'}->{'user'}->{'ldap_entry'}->{'asn'}->{'objectName'};
    my $cn = $session->{'user'}->{'user'}->{'ldap_entry'}->{'asn'}->{'cn'};
    my ($identity_type, $identity,$orgunit,$domain);
    if($objectname=~m/\s*(.*)\s*=\s*(.*)\s*,\s*[Oo][Uu]\s*=\s*([^,]+)\s*,\s*dc\s*=\s*(.*)\s*/){
        $identity_type=$1; $identity=$2; $orgunit=$3; $domain=$4; $domain=~s/,dc=/./g;
        # I hate upper case.
        $identity_type=~tr/A-Z/a-z/;
        $identity=~tr/A-Z/a-z/;
        $orgunit=~tr/A-Z/a-z/;
        $domain=~tr/A-Z/a-z/;
    }
    my $directory_map=$identity;
    my $ca_dir=$self->ca_for($domain);
    my $certdata={};
    if($ca_dir){
       $certdata->{'config'}="$ca_dir/openssl.cnf";
       $certdata->{'certs'}="$ca_dir/certs";
       $certdata->{'child_dir'}="$certdata->{'certs'}/$directory_map";
       $certdata->{'child_id'}="$directory_map";
    }else{
        print STDERR "We need code to look for root-ca.$domain, and to create $domain under it.\n";
    }
    
    # only do so if one doesn't exist
    my $pkcs12data=undef;
    if( ! -d "$certdata->{'child_dir'}"){
        mkdir("$certdata->{'child_dir'}",0700);
        # rewrite the openssl.cnf such that commonName_default = userid and emailAddress_default=userid@$domain
        #
        my $pfh = FileHandle->new;
        if ($pfh->open("< $certdata->{'config'}")) {
            my $cfh = FileHandle->new("> $certdata->{'child_dir'}/openssl.cnf");
            if (defined $cfh) {
                while( my $line=<$pfh>){
                    chomp($line);
                    if($line=~m/commonName_default\s*=\s*(.*)/){ $line=~s/$1/$identity/; }
                    if($line=~m/emailAddress_default\s*=\s*(.*)/){ $line=~s/$1/$identity\@$domain/; }
                    print $cfh "$line\n";
                }
                $cfh->close;
            }
            $pfh->close;
        }
        # create password-protected private key
        mkdir("$certdata->{'child_dir'}/private",0700);
        system("/usr/bin/openssl genrsa -out $certdata->{'child_dir'}/private/$certdata->{'child_id'}.key 1024");
        # create the CSR
        system("/usr/bin/openssl req -new -sha1 -days 90 -key $certdata->{'child_dir'}/private/$certdata->{'child_id'}.key  -out $certdata->{'child_dir'}/$certdata->{'child_id'}.csr -config $certdata->{'child_dir'}/openssl.cnf -batch");
        # Validate the request matches our conventions
        print STDERR "We need to ensure the certificate signing request matches the requestor here\n";
        # openssl req -text -noout -in $certdata->{'child_dir'}/$certdata->{'child_id'}.csr


        # if it's valid, Sign it with the parent
        print STDERR "\n/usr/bin/openssl ca -config $certdata->{'config'} -days 90 -policy policy_anything -out $certdata->{'child_dir'}/$certdata->{'child_id'}.crt -batch -infiles $certdata->{'child_dir'}/$certdata->{'child_id'}.csr\n\n";
        system("/usr/bin/openssl ca -config $certdata->{'config'} -days 90 -policy policy_anything -out $certdata->{'child_dir'}/$certdata->{'child_id'}.crt -batch -infiles $certdata->{'child_dir'}/$certdata->{'child_id'}.csr");
        # convert to a pkcs12 container with the passphrase
        system("/bin/echo \"$param->{'password'}\" | /usr/bin/openssl pkcs12 -export -clcerts -passout fd:0 -in $certdata->{'child_dir'}/$certdata->{'child_id'}.crt -inkey $certdata->{'child_dir'}/private/$certdata->{'child_id'}.key -out $certdata->{'child_dir'}/$certdata->{'child_id'}.p12");
        # read in the content fo the pkcs12 cert to memory
        $pkcs12data = read_file( "$certdata->{'child_dir'}/$certdata->{'child_id'}.p12", binmode => ':raw' ) ;        
        # remove the pkcs12 cert from disk
        unlink("$certdata->{'child_dir'}/$certdata->{'child_id'}.p12");
        # return the content of the pkcs12 cert as a blob for file transfer to the client
    }
    return $pkcs12data;
}

sub remove_certificate{
    my ($self, $param,$session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    # convert the $self->{'node_separator'} delimited node names into a path
    my $node_dir = $self->actual_node($param->{'node_name'});
    my @nodepart=split(/$self->{'node_separator'}/, $node_dir);
    my $node_name=pop(@nodepart); pop(@nodepart);
    my $parent_name=$nodepart[$#nodepart];
    my $parent_dir="$rootdir/".join("/",@nodepart);
    $node_dir=~s/$self->{'node_separator'}/\//g;
    $node_dir="$rootdir/$node_dir";
    if( -d "$node_dir/private"){
        opendir(my $pdh, "$node_dir/private");
        my @pfiles = readdir($pdh);
        foreach my $pfile (@pfiles){
            unlink("$node_dir/private/$pfile");
        }
        closedir $pdh;
        rmdir "$node_dir/private";
    }
    opendir(my $dh, "$node_dir");
    my @files = readdir($dh);
    foreach my $file (@files){
        unlink("$node_dir/$file");
    }
    closedir $dh;
    rmdir "$node_dir";
}

sub revoke_certificate{
    my ($self, $param,$session)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });

    # convert the $self->{'node_separator'} delimited node names into a path
    my $node_dir = $self->actual_node($param->{'node_name'});
    my @nodepart=split(/$self->{'node_separator'}/, $node_dir);
    my $node_name=pop(@nodepart); pop(@nodepart);
    my $parent_name=$nodepart[$#nodepart];
    my $parent_dir="$rootdir/".join("/",@nodepart);
    $node_dir=~s/$self->{'node_separator'}/\//g;
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
    my ($self, $param,$session,$admin)=@_;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    
    # convert the $self->{'node_separator'} delimited node names into a path
    my $node_dir;
    if(! defined($param->{'node_name'} )){
        $node_dir = $self->actual_node(
                                       $self->actual_node_from_objectname(
                                                                          $self->objectname($session->{'user'})
                                                                         )
                                      );
        # Strip off the last node as it's the user/host
        $node_dir=~s/::[^:]+$//;
    }else{
        $node_dir = $self->actual_node($param->{'node_name'});
    }
    $node_dir=~s/$self->{'node_separator'}/\//g;
    $node_dir=~s/certs$//g;
    $node_dir="$rootdir/$node_dir";

    # write out the csr to a temp file
    my $tmpdir = tempdir( 'CLEANUP' => 1 );
    my ($fh, $filename) = tempfile( 'DIR' => $tmpdir );
    print $fh $param->{'csr_input'};
    my $common_name;
    my $subject;
    open(GETCN, "/usr/bin/openssl req -in $filename -noout -text | ");
    while(my $line=<GETCN>){
        if($line=~m/Subject:/){
            $subject=$line;
            $line=~s/.*CN=//g;
            $line=~s/\/.*//g;
            $line=~s/\s+//g;
            $common_name=$line;
        }
    }
    chomp($subject);
    $subject=~s/\s+$//;
    $subject=~s/^\s+//;
    $subject=~s/^[Ss]ubject:\s*//;
    ############################################################################
    # Do not let a non-administrator sign a cert that isn't his/it's
    ############################################################################
    if(($admin == 0) && ($subject ne $self->user_cert_dn($session->{'user'})) ){
        print STDERR  "WARNING: ".$self->objectname($session->{'user'})." attempted to sign [$subject]\n";
        return undef;
    }
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

    # convert the $self->{'node_separator'} delimited node names into a path
    my $node_dir = $self->actual_node($param->{'node_name'});
    $node_dir=~s/new_root_ca/\//g; # get rid of the top node and make our root node_dir ""
    $node_dir=~s/$self->{'node_separator'}/\//g;
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
#                if(-f "$node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.crt"){
#                    unlink("$node_dir/$param->{'ca_domain'}/$param->{'ca_domain'}.csr");
#                }

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
################################################################################
# Given the domain name, we traverse the tree to find the top-level openssl.cnf
# that belongs to the domain, if there are more than one, we use the first
# If there are none, we look for root-ca.<domain>, and create a <domain> under
# it. If there is no root-ca.<domain>, we look for any root-ca, (the first if
# more than one) and create the <domain> under it. we then return the path
# to <domain> so we can do sub-ca (cert) operations under it.
################################################################################
sub ca_for{
    my ($self,$ca_domain)=@_;
print STDERR "0) $ca_domain\n";
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
print STDERR "1) $rootdir\n";
    ############################################################################
    # find all the openssl.cnfs with ca_domain=$ca_domain
    $self->{'file_list'}=[];
    my @domain_cnfs;
    my @least_depth_domain_cnfs;
    $self->find_file($rootdir,"openssl.cnf");
    foreach my $cnf_file (@{ $self->{'file_list'} }){
       my $cnf_domain=$self->ca_domain_from_file($cnf_file);
       if($cnf_domain eq $ca_domain){
           push(@domain_cnfs,$cnf_file);
       }
    }
    my $physical_path;
    my $leastdepth=0;
    if($#domain_cnfs >= 0){
       foreach my $domain_dir (@domain_cnfs){
           my $depth=split("/",$domain_dir);
           if(($leastdepth == 0)||($depth < $leastdepth)){
               $leastdepth=$depth;
           } 
       }
       # now that we know the minimum depth, find all that have it.
       foreach my $domain_dir (@domain_cnfs){
           my $depth=split("/",$domain_dir);
           if($leastdepth == $depth){
               push(@least_depth_domain_cnfs,$domain_dir);
           }
       }
       # now we sort them
       my @ordered_least_depth_domain_cnfs = sort(@least_depth_domain_cnfs);
       $physical_path = $least_depth_domain_cnfs[0];
       $physical_path =~s/\/openssl.cnf.*$//;
print STDERR "2) $physical_path\n";
       return $physical_path;
    }
    # if we can't find any, we return undef 
    return undef;
}

sub actual_node_from_objectname{
    my $self=shift;
    my $objectname=shift;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    my ($identity_type, $identity,$orgunit,$domain);
    if($objectname=~m/\s*(.*)\s*=\s*(.*)\s*,\s*[Oo][Uu]\s*=\s*([^,]+)\s*,\s*dc\s*=\s*(.*)\s*/){
        $identity_type=$1; $identity=$2; $orgunit=$3; $domain=$4; $domain=~s/,dc=/./g;
        # I hate upper case.
        $identity_type=~tr/A-Z/a-z/;
        $identity=~tr/A-Z/a-z/;
        $orgunit=~tr/A-Z/a-z/;
        $domain=~tr/A-Z/a-z/;
    }
    my $cacert_dir = $self->ca_for($domain);
    my $cert_dir=undef;
    if($cacert_dir){
        $cert_dir="$cacert_dir/certs/$identity";
    }
    my $actual_node=$cert_dir;
    $actual_node=~s/^$rootdir\///;
    $actual_node=~s/\//::/g;
    return unpack("H*",$actual_node);
}

# by convention, all CAs have a subdir named "certs" and others don't
sub node_type{
    my ($self, $unpacked_node)=@_;
    my $node = pack("H*",$unpacked_node);
    my @nodepart=split(/$self->{'node_separator'}/, $node);
    $node =~s/$self->{'node_separator'}/\//g;
    my $rootdir=join("/",@{ $self->{'root_dir'}->{'dirs'} });
    if($node eq "new_root_ca"){ return "new_root_ca"; }
    if($node eq "certificate_authority"){ return "certificate_authority"; }
    if($node eq "new_cert"){ return "new_cert"; }
    if($node eq "logout"){ return "logout"; }
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
    my ($self, $unpacked_node)=@_;
    my $node = pack("H*",$unpacked_node);
    $node =~s/$self->{'node_separator'}/\//g;
    $node =~ s/\/\.\./\//g;
    $node =~ s/\.\.\//\//g;
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
    }else{
        return "no.";
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
localityName = match
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
