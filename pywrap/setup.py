from distutils.core import setup, Extension
import platform 
osname = platform.system()

if osname == "Windows":
    shared_libs = []
else:
    shared_libs = []

module = Extension('pyautoit',
	sources = ['pyautoit.cpp'],
	libraries = shared_libs,
	library_dirs = [],
	extra_objects = ["../build/lib/libautoit.a"],
)

setup(name = 'pyautoit',
    version = '0.2.0',
    description = 'Python module wrapping libautoit',
    author = 'kimzhang',
    author_email = 'analyst004@gmail.com',
    ext_modules = [module])
