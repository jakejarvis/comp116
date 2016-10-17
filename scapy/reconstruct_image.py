#! /usr/bin/env python

import base64
import imghdr
import mimetypes
from scapy.all import *

# read pcap using scapy -- assumes pcap in same folder is named picture.pcap
try:
    pcap_file = rdpcap("picture.pcap")
except IOError:
    print "ERROR: picture.pcap not found. Please save the pcap you wish to decode as picture.pcap in this folder."
    exit()

# initialize variable to use for collecting TCP payload
image_data = ""

# loop through each packet and add payload to above string
for packet in pcap_file:
    image_data = "%s%s" % (image_data, packet.load)

# decode the string with all of the payload data
image_data_decode = base64.decodestring(image_data)

# get the MIME type of the image and determine which file extension is appropriate for saving it
image_type = imghdr.what(None, image_data_decode)
image_ext = mimetypes.guess_extension("image/{0}".format(image_type))
image_name = "picture{0}".format(image_ext)

# write the decoded data to a file named picture.EXT (where EXT is the extension determined above)
image_file = open(image_name, "w")
image_file.write(image_data_decode)
image_file.close()

# let the user know we were successful!
print "Image successfully written to \"%s\"" % (image_name)
