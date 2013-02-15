#!/usr/bin/env python
#encoding: utf-8

# Build script for tracer
# vim: syntax=python
# #

top = '.'
out = 'build'

def options(opt):
    opt.add_option('--enable_debug', action='store_true', default=False, help='debug')
    opt.load('compiler_c')

header_files = ['functable.h', 'memory_op.h']
c_files = ['functable.c', 'memory_op.c', 'attach.c']

requirements = [ 'mach-o/loader.h', 'mach/mach.h', 'spawn.h' ]

def configure(conf):
    conf.load('compiler_c')

    for header in requirements:
        conf.check(header_name = header, features = 'c cprogram')

    import platform
    if platform.system() != 'Darwin':
        print('This program cannot been built except on MacOS X Darwin')
        return


def build(bld):
    bld.program(
            source = c_files,
            lib = 'udis86',
            target = 'tracer'
            )
