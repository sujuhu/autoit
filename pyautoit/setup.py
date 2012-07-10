
import os
from distutils.core import setup, Extension
from distutils.sysconfig import get_python_inc

incdir = os.path.join(get_python_inc(plat_specific=1))

module = Extension('pyautoit',
	include_dirs = [incdir],
	libraries = [],
	library_dirs = [],
	sources = ['../libautoit.cpp', 'pyautoit.cpp'])

setup(name = 'pyautoit',
    version = '0.2.0',
    description = 'Python module wrapping libautoit',
    author = 'Zhang Xiaokang',
    author_email = 'analyst004@gmail.com',
    ext_modules = [module])
