#codeing=utf-8
import os,sys
import pyautoit
import mmap

sample = os.path.abspath("../test/test.bin")
filesize = os.path.getsize(sample)
f = open(sample, "r+b")
m = mmap.mmap(f.fileno(), 0)
logfile = os.path.abspath("../test/test.au")
pyautoit.dump_script(m[0:filesize], filesize, logfile)
m.close()
f.close()
print open(logfile, "r").read()