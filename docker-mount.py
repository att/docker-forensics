#!/usr/bin/env python
#
#  Title: 	docker-mount.py
#  Author:	Jim Clausing
#  Date:	2016-10-12
#  Version:	1.0.0
#
#  Purpose:	Allow the mounting of the AUFS layered/union filesystem from
#		a docker container to be mounted (read-only) for the purposes
#		of forensic examination
#
# Copyright (c) 2016 Jim Clausing,. All rights reserved.
#

from sys import *
import os
import argparse
from subprocess import call
import json

def aufs_mount():
    layers = open(layerid).read().split('\n')
    layers = layers[:-1]
    layers.insert(0,layerid)

    elements = [args.root+args.path+'/'+args.storage+'/diff/'+s for s in layers]

    f=":".join(elements)

    call(["/bin/mount","-t","aufs","-r","-o","br:"+f,"none",args.mntpnt], shell=False)
    return()

def overlay2_mount():
    lowerdir = open(args.root + args.path + '/' + args.storage + '/' + layerid + '/lower').read().rstrip()
    
    os.chdir(dockerpath)

    call(["/bin/mount","-t","overlay","overlay","-r","-o","lowerdir="+lowerdir+",upperdir="+layerid+"/diff,workdir="+layerid+"/work",args.mntpnt], shell=False)
    return()


__version_info__ = (1,0,0)
__version__ = ".".join(map(str, __version_info__))

parser = argparse.ArgumentParser(prog='docker-mount', description='Mount docker container filesystem for forensic examination')
parser.add_argument('container', help='container id (long hex string)')
parser.add_argument('mntpnt', help='mount point where read-only filesystem will be mounted')
#parser.add_argument('--verbose','-v', action='store_true', help='verbose',)
parser.add_argument('-V','--version', action='version', help='print version number', version='%(prog)s v' + __version__)
parser.add_argument('--root','-r', help='root of filesystem (should include trailing /, e.g. /mnt/image/)', default='')  # e.g., /mnt/image/
parser.add_argument('--path','-p', help='path to docker files', default='/var/lib/docker')
parser.add_argument('--storage','-s', help='storage driver, currently aufs and overlay2 are supported, default is aufs', default='aufs')

args=parser.parse_args()

dockerroot = args.root+args.path
config1 = dockerroot + '/containers/' + args.container + '/config.json'
config2 = dockerroot + '/containers/' + args.container + '/config.v2.json'
if (os.path.isfile(config1)):
    dockerversion = 1
elif (os.path.isfile(config2)):
    dockerversion = 2
else:
    raise Exception('Unknown docker version or invalid container id, check and try again')


if (dockerversion == 1):
    layerid = args.container
else:
    layerid = open(args.root + args.path + '/image/' + args.storage + '/layerdb/mounts/' + args.container + '/mount-id').read()
# image/aufs/layerdb/mounts/516ae11fdca97f3228dac2dea2413c6d34a444e24b1d8b2a47cd54fbca091905/mount-id
    
if (args.storage == 'aufs'):
    dockerpath=args.root+args.path+'/'+args.storage+'/layers'
elif (args.storage == 'overlay2'):
    dockerpath=args.root+args.path+'/'+args.storage

os.chdir(dockerpath)

if (args.storage == 'aufs'):
    aufs_mount()
elif (args.storage == 'overlay2'):
    overlay2_mount()

