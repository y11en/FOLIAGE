#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import pefile
import argparse
import struct

def main( f = None, o = None, s = None, m = None, y = None, d = None ):
    try:
        raw = open( f, 'rb+' ).read()
        shc = open( s, 'rb+' ).read()
        out = open( o, 'wb+' )

        raw = raw.replace(b'\x41' * 4, struct.pack('<I', len(shc)));
        raw = raw.replace(b'\x42' * 2, struct.pack('<H', m));
        raw = raw.replace(b'\x43' * 2, struct.pack('<H', y));
        raw = raw.replace(b'\x44' * 2, struct.pack('<H', d));

        print('writing %i bytes to %s' % ( len( raw ), o ) );
        out.write( raw + shc );
        out.close( );
    except Exception as e:
        print("[error]: {}".format(e));
        raise SystemExit

if __name__ in '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', help='Path to FOLIAGE bin', required=True);
    parser.add_argument('-s', help='Path to shellcode bin', required=True);
    parser.add_argument('-o', help='Path to output FOLIAGE bin', required=True);
    parser.add_argument('-m', help='Month to trigger on', type=int, required=True);
    parser.add_argument('-y', help='Year to trigger on', type=int, required=True);
    parser.add_argument('-d', help='Day to trigger on', type=int, required=True);

    args = parser.parse_args();
    main(**vars(args));
