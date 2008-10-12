use inc::Module::Install;

BEGIN {
    eval {
        require ModPerl::MM;
        require Apache::TestMM;
    };
    if ($@) {
        exit 0;
    }
    Apache::TestMM->import( qw(test clean) );
}

name 'Apache2-AuthzHatenaPoint';
all_from 'lib/Apache2/AuthzHatenaPoint.pm';
requires 'mod_perl2'  => 2.000001;
requires 'Apache::Test' => 0;
requires 'Apache2::AuthenOpenID' => 0;
requires 'Web::Scraper' => 0;
requires 'WWW::HatenaLogin' => 0;
requires 'Time::Piece' => 0;
build_requires 'Test::More' => 0.32;

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

WriteAll;
