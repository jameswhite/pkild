package pkild::Model::File;

use strict;
use base 'Catalyst::Model::File';

__PACKAGE__->config(
    root_dir => '/var/tmp/certificate_authority',
);

=head1 NAME

pkild::Model::File - Catalyst File Model

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
