#!/usr/bin/env python2

import pefile
import binascii
import struct
import base64
import argparse
import os


#"0x250      0x0   Name:                          .pe
#0x258      0x8   Misc:                          0xE064
#0x258      0x8   Misc_PhysicalAddress:          0xE064
#0x258      0x8   Misc_VirtualSize:              0xE064
#0x25C      0xC   VirtualAddress:                0x3D000
#0x260      0x10  SizeOfRawData:                 0xF000
#0x264      0x14  PointerToRawData:              0x39000
#0x268      0x18  PointerToRelocations:          0x0
#0x26C      0x1C  PointerToLinenumbers:          0x0
#0x270      0x20  NumberOfRelocations:           0x0
#0x272      0x22  NumberOfLinenumbers:           0x0
#0x274      0x24  Characteristics:               0xC0000000
#"

def xorit(d,key):
	kl=len(key)
	return ''.join([chr(ord(c)^ord(key[i%kl])) for i,c in enumerate(d)])

def unpackit(fn,args):
	bfn=os.path.basename(fn)
	pe = pefile.PE(fn)
	flag_pesection=False
	pe_section=None
	for section in pe.sections:
		if(section.Name == binascii.unhexlify('2e70650000000000')):#".pe"):
			flag_pesection=True
			pe_section=section
			if(args.info):
				print "OK: %s - Found PE section - unpacking..." % (bfn)
				print str(section).replace('\x00','')
			else:pass
			break;
		else:pass
	else:pass

	if not flag_pesection:
		if(args.info): print "ERROR: %s - Can't unpack, missing '.pe' section." % (bfn)
		return None
	else:
		#print pe_section
		#If the PE section exists, read it from the file.
		f = open(fn,'rb')
		f.seek(pe_section.PointerToRawData)
		data = f.read(pe_section.SizeOfRawData)
		f.close()
		if(args.info):print "OK: %s - Read '.pe' section: %d bytes" % (bfn,len(data))

		#The last 4 bytes of the section are either a checksum or something similar.
		someDword=struct.unpack("<I",data[-4:])[0]
#		someDword2=struct.unpack(">HH",data[-4:])
		if(args.info):print "OK: %s - Possible Checksum: 0x%08X" % (bfn,someDword)

		#The buffer has a bunch of NULL's in the beginning. Get rid of them. Also get rid of the last 4 bytes.
		data = data.strip('\x00')[:-4]
#		print binascii.hexlify(data)
		if(args.info):print "OK: %s - Stripping NULLs - New Size: %d bytes" % (bfn,len(data))

		#The remaining bytes are base64 encoded. Decode them.
		data = base64.b64decode(data)
		if(args.info):print "OK: %s - Base64 Decode - New Size: %d bytes" % (bfn,len(data))

		#The decoded bytes are null padded. Get rid of the extra NULLS at the end and the 24 byte header in the beginning.
		decode_data_strip = data.rstrip('\x00')[24:]
		if(args.info):print "OK: %s - Remove Header/Padding - New Size: %d bytes" % (bfn,len(decode_data_strip))
#		print someDword,someDword2,len(data),pe_section.SizeOfRawData,len(decode_data),len(decode_data_strip),struct.unpack("<I",decode_data[:4])

		#The remaining data is encrypted with a 13 byte XOR key. It is not known how this key is derived.
		#However, it can be automatically "guessed" with some basic cryptanalysis (KNOWN PLAINTEXT ATTACK)
		#     becaus an EXE usually has lots of NULLS especially at the end.
		dl=len(decode_data_strip)
		off=dl%13
		thekey=decode_data_strip[-13-off:-off]
		if(args.info):print "OK: %s - Guessed XORKEY: %s " % (bfn,binascii.hexlify(thekey))
		#print binascii.hexlify(xorit(decode_data_strip,thekey))
		decrypted = xorit(decode_data_strip,thekey)
		if(decrypted[:2] == "MZ"):
			if(args.info):print "OK: %s - XORKEY correct: %s " % (bfn,binascii.hexlify(thekey))
			return decrypted
		else:
			if(args.info):print "ERROR: %s - XORKEY incorrect: %s - %s" % (bfn,binascii.hexlify(thekey),binascii.hexlify(decrypted[:16]))
		pass
	pass
pass


def main():
	parser = argparse.ArgumentParser(description="Unpack executables packed with the ListDemo packer - imphash:759b0df4f817d82c54a8243a12f90f81" )
	parser.add_argument("--info","--verbose","-v", help="Print out additional info", action="store_true")
	parser.add_argument("--nodump", help="Don't unpack the file.", action="store_true")
	parser.add_argument("--postfix", help="The postfix for the dumped file. Default: .unpacked",default=".unpacked")
	parser.add_argument("--dumppath", help="The Directory where output will be placed. Default is same directory as sample.",default=None)
	parser.add_argument("file", help="The path to the file that needs to be unpacked.",nargs="+")
	args = parser.parse_args()
	for fn in args.file:
		bfn=os.path.basename(fn)
		ofn=os.path.join(os.path.dirname(fn),bfn+args.postfix)
		if(args.dumppath):
			ofn=os.path.join(args.dumppath,bfn+args.postfix)
		pass
		output = unpackit(fn,args)
		if(args.nodump==False and output!=None):
			print "Unpacking to %s" % (ofn)
			f = open(ofn,'wb')
			f.write(output)
			f.close()
		else:pass
	else:pass

if __name__ == "__main__":
	main()
