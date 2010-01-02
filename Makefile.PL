use inc::Module::Install;

name 'pkild';
all_from 'lib/pkild.pm';

requires 'Catalyst::Runtime' => '5.7011';
requires 'Catalyst::Plugin::ConfigLoader';
requires 'Catalyst::Plugin::Static::Simple';
requires 'Catalyst::Action::RenderView';
requires 'YAML'; # This should reflect the config file format you've chosen
                 # See Catalyst::Plugin::ConfigLoader for supported formats
requires 'Catalyst::Plugin::Authentication';
requires 'Catalyst::Authentication::Store::LDAP';
requires 'Catalyst::Model::File';
requires 'Catalyst::Plugin::Authorization::Roles';
requires 'Catalyst::Plugin::Session';
requires 'Catalyst::Plugin::Session::Store::FastMmap';
requires 'Catalyst::Plugin::Session::State::Cookie';
requires 'Catalyst::View::TT';
requires 'Catalyst::Plugin::RequireSSL';
catalyst;

install_script glob('script/*.pl');
auto_install;
WriteAll;
