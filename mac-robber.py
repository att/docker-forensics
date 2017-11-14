#!/usr/bin/env python
#
# Author:  Jim Clausing
# Date:    2017-09-01
# Version: 1.2.0
#
# Desc: rewrite of the sleithkit mac-robber in Python
# Unlinke the TSK version, this one can actually includes the MD5 & inode number
# though I still return a 0 in the MD5 column for non-regular files, but calculating
# hashes likely will modify atime, so it is turned off by default
#
# Note: in Python 2.7.x, st_ino, st_dev, st_nlink, st_uid, and st_gid are dummy variables
# on Windows systems. This is apparently fixed in current Python 3 versions.
# On *ALL* systems, os.stat does not return btime, so we put 0 there. :-(
# 
# A useful way to use this on a live Linux system is with read-only --bind mounts
#
#   # mount --bind / /mnt
#   # mount -o ro,remount,bind /mnt
#   # ./mac-robber.py -5 -x /mnt/tmp -r /mnt -m system-foo:/ /mnt
#
# This gets us hashes, but because the bind mount is read-only doesn't update atimes
#
# Copyright (c) 2017 AT&T Open Source. All rights reserved.
#

import os
import sys
import argparse
import hashlib
from stat import *

__version_info__ = (1,2,1)
__version__ = ".".join(map(str, __version_info__))

def mode_to_string(mode):
    lookup = ['---','--x','-w-','-wx','r--','r-x','rw-','rwx']
    if S_ISDIR(mode):
        mode_str = 'd'
    elif S_ISCHR(mode):
        mode_str = 'c'
    elif S_ISBLK(mode):
        mode_str = 'b'
    elif S_ISREG(mode):
        mode_str = '-'
    elif S_ISFIFO(mode):
        mode_str = 'p'
    elif S_ISLNK(mode):
        mode_str = 'l'
    elif S_ISSOCK:
        mode_str = 's'
    own_mode = lookup[(mode & 0700)>>6]
    if mode & 04000:
        if mode & 0100:
            own_mode = own_mode.replace('x','s')
        else:
            own_mode = own_mode[:1] + 'S'
    mode_str = mode_str + own_mode
    grp_mode = lookup[(mode & 070)>>3]
    if mode & 02000:
        if mode & 010:
            grp_mode = grp_mode.replace('x','s')
        else:
            grp_mode = grp_mode[:1] + 'S'
    mode_str = mode_str + own_mode
    oth_mode = lookup[(mode & 07)]
    if mode & 01000:
        if mode & 01:
            oth_mode = oth_mode.replace('x','t')
        else:
            oth_mode = oth_mode[:1] + 'T'
    mode_str = mode_str + oth_mode
    return mode_str

def process_item(dirpath,item):
    md5 = hashlib.md5()
    fname = os.path.join(dirpath,item)
    if args.exclude and (fname in args.exclude or dirpath in args.exclude):
        return
    try:
        if os.path.islink(fname):
            status = os.lstat(fname)
        else:
            status = os.stat(fname)
    except IOError:
        return
    except OSError:
        return
    if args.hashes and S_ISREG(status.st_mode):
        try:
            if (fname.find('/proc/') == -1 and not fname.endswith('/kcore')) and status.st_size > 0:
                with open(fname, "rb") as f:
                    for block in iter(lambda: f.read(65536), b""):
                        md5.update(block)
                md5str = md5.hexdigest()
            elif status.st_size == 0:
                md5str = "d41d8cd98f00b204e9800998ecf8427e" 
            else:
                md5str = "0"
        except IOError:
            md5str = "0"
    else:
        md5str = "0"
    mode = mode_to_string(status.st_mode)
    if os.path.islink(fname) and status.st_size > 0:
        mode = mode + ' -> ' + os.readlink(fname)
    mtime = '{:20.9f}'.format(status.st_mtime)
    atime = '{:20.9f}'.format(status.st_atime)
    ctime = '{:20.9f}'.format(status.st_mtime)
    btime = 0
    size = status.st_size
    uid = status.st_uid
    gid = status.st_gid
    inode = status.st_ino
    if args.rmprefix:
        if fname.startswith(args.rmprefix):
            fname = fname[len(args.rmprefix):]
    if args.prefix:
        if fname.find('/') == 0:
            fname = args.prefix + fname
        else:
            fname = args.prefix + '/' + fname
    return md5str+'|'+fname+'|'+str(inode)+'|'+mode+'|'+str(uid)+'|'+str(gid)+'|'+str(size)+'|'+atime+'|'+mtime+'|'+ctime+'|'+str(btime)
    

parser = argparse.ArgumentParser(description='collect data on files')
parser.add_argument('directories', metavar='DIR', nargs='+', help='directories to traverse')
parser.add_argument('-m','--prefix', metavar='PREFIX', help='prefix string')
parser.add_argument('-5','--hashes', action='store_true', help='do MD5 calculation (disabled by default)', default=False)
parser.add_argument('-x','--exclude', metavar='EXCLUDE', action='append', help='directory trees or files to exclude, does not handle file extensions or regex', default=[])
parser.add_argument('-r','--rmprefix', metavar='RMPREFIX', help='prefix to remove, useful when using read-only --bind mount to prevent atime updates')
parser.add_argument('-V','--version',  action='version', help='print version number',
                    version='%(prog)s v{version}'.format(version= __version__))

args = parser.parse_args()

for directory in args.directories:
    for dirpath,dirs,files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in args.exclude]
        for directory in dirs:
            outstr = process_item(dirpath,directory)
            if outstr is not None:
                print outstr
                sys.stdout.flush()
        for filename in files:
            if filename in args.exclude:
                continue
            outstr = process_item(dirpath,filename)
            if outstr is not None:
                print outstr
                sys.stdout.flush()
