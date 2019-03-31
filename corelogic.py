import xmltodict
import os

import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element

from xml.etree.ElementTree import XML, SubElement, Element, tostring


def coreserverReqResogic(Inputdatafile=None, Opdatafile=None):

	#import pdb;pdb.set_trace()

	#with open(Inputdatafile, "rb") as f:
	data = xmltodict.parse(Inputdatafile)

	xml_replace_attibute_file_name = data['soapenv:Envelope']['soapenv:Body']['spmlChangeDirective']['@identifier']
	xml_attribute_name = data['soapenv:Envelope']['soapenv:Body']['spmlChangeDirective']['parameter']['@name']
	xml_attribute_value = data['soapenv:Envelope']['soapenv:Body']['spmlChangeDirective']['parameter']['@value']

	ReadAttributeXmlfile = xml_replace_attibute_file_name
	#Opdatafile = 

	tree = ET.parse(ReadAttributeXmlfile)  
	root = tree.getroot()
	a1 = xml_attribute_name.replace("_","")

	for elem in root.iter(a1):  
	    elem.text = xml_attribute_value

	tree.write(Opdatafile) 

	return True

