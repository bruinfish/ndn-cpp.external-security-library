# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION='1.0.0'

from waflib import Build, Logs, Utils, Task, TaskGen, Configure

def options(opt):
    opt.add_option('--debug',action='store_true',default=False,dest='debug',help='''debugging mode''')
    opt.add_option('--test', action='store_true',default=False,dest='_test',help='''build unit tests''')
    opt.add_option('--log4cxx', action='store_true',default=False,dest='log4cxx',help='''Compile with log4cxx logging support''')
    opt.add_option('--with-ndn-cpp',action='store',type='string',default=None,dest='ndn_cpp_dir',
                   help='''Use NDN-CPP library from the specified path''')
    opt.add_option('--with-c++11', action='store_true', default=False, dest='use_cxx11',
                   help='''Enable C++11 compiler features''')

    opt.load('compiler_c compiler_cxx gnu_dirs boost doxygen')
    opt.load('cryptopp', tooldir=['waf-tools'])

def configure(conf):
    conf.load("compiler_c compiler_cxx boost gnu_dirs cryptopp")
    try:
        conf.load("doxygen")
    except:
        pass

    if conf.options.debug:
        conf.define ('_DEBUG', 1)
        flags = ['-O0',
                 '-Wall',
                 '-Wno-unused-variable',
                 '-g3',
                 '-Wno-unused-private-field', # only clang supports
                 '-fcolor-diagnostics',       # only clang supports
                 '-Qunused-arguments',        # only clang supports
                 '-Wno-deprecated-declarations',
                 '-Wno-tautological-compare', # suppress warnings from CryptoPP
                 '-Wno-unused-function',      # suppress warnings from CryptoPP
                 '-Wno-unneeded-internal-declaration' # suppress warnings from CryptoPP
                 ]
        conf.add_supported_cxxflags (cxxflags = flags)
    else:
        flags = ['-O3', 
                 '-g', 
                 '-Wno-tautological-compare', 
                 '-Wno-unused-function', 
                 '-Wno-deprecated-declarations',
                 '-Wno-unneeded-internal-declaration'
                 ]
        conf.add_supported_cxxflags (cxxflags = flags)
        
    conf.define ("NDN_CPP_EXTERNAL_TOOLS_VERSION", VERSION)

    if conf.options.use_cxx11:
        conf.add_supported_cxxflags(cxxflags = ['-std=c++11', '-std=c++0x'])

    if not conf.options.ndn_cpp_dir:
        conf.check_cfg(package='libndn-cpp-dev', args=['--cflags', '--libs'], uselib_store='NDN_CPP', mandatory=True)
    else:
        conf.check_cxx(lib='ndn-cpp-dev', uselib_store='NDN_CPP', 
                       cxxflags="-I%s/include" % conf.options.ndn_cpp_dir,
                       linkflags="-L%s/lib" % conf.options.ndn_cpp_dir,
                       mandatory=True)

    if conf.options.log4cxx:
        conf.check_cfg(package='liblog4cxx', args=['--cflags', '--libs'], uselib_store='LOG4CXX', mandatory=True)
        conf.define ("HAVE_LOG4CXX", 1)

    conf.check_cryptopp(path=conf.options.cryptopp_dir);

    conf.check_boost(lib='system unit_test_framework regex thread')

    boost_version = conf.env.BOOST_VERSION.split('_')
    if int(boost_version[0]) < 1 or int(boost_version[1]) < 46:
        Logs.error ("Minumum required boost version is 1.46")
        return

    if conf.options._test:
        conf.define ('_TESTS', 1)
        conf.env['TEST'] = 1

    conf.write_config_header('config.h')

def build (bld):

    libndn_cpp_et = bld (
        target="ndn-cpp-et",
        vnum = "0.0.1",
        features=['cxx', 'cxxshlib', 'cxxstlib'],
        source = bld.path.ant_glob(['ndn-cpp-et/**/*.cpp',
                                    'logging.cc',
                                    'libndn-cpp-et.pc.in']),
        use = 'BOOST NDN_CPP LOG4CXX',
        includes = ".",
        )

    # Unit tests
    if bld.env['TEST']:
      unittests = bld.program (
          target="unit-tests",
          features = "cxx cxxprogram",
          defines = "WAF",
          source = bld.path.ant_glob(['test/*.cpp']),
          use = 'BOOST LOG4CXX ndn-cpp-et CRYPTOPP',
          includes = ".",
          install_prefix = None,
          )

    headers = bld.path.ant_glob(['ndn-cpp-et/**/*.hpp'])
    bld.install_files("%s" % bld.env['INCLUDEDIR'], headers, relative_trick=True)

@Configure.conf
def add_supported_cxxflags(self, cxxflags):
    """
    Check which cxxflags are supported by compiler and add them to env.CXXFLAGS variable
    """
    self.start_msg('Checking allowed flags for c++ compiler')

    supportedFlags = []
    for flag in cxxflags:
        if self.check_cxx (cxxflags=[flag], mandatory=False):
            supportedFlags += [flag]

    self.end_msg (' '.join (supportedFlags))
    self.env.CXXFLAGS += supportedFlags


# doxygen docs
from waflib.Build import BuildContext
class doxy (BuildContext):
    cmd = "doxygen"
    fun = "doxygen"

def doxygen (bld):
    if not bld.env.DOXYGEN:
        bld.fatal ("ERROR: cannot build documentation (`doxygen' is not found in $PATH)")
    bld (features="doxygen",
         doxyfile='doc/doxygen.conf')

# doxygen docs
from waflib.Build import BuildContext
class sphinx (BuildContext):
    cmd = "sphinx"
    fun = "sphinx"

def sphinx (bld):
    bld.load('sphinx_build', tooldir=['waf-tools'])

    bld (features="sphinx",
         outdir = "doc/html",
         source = "doc/source/conf.py")

