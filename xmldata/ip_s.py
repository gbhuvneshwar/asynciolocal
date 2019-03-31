import xmltodict

#a1 = b'<spml:modifyRequest    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"    xmlns:spml="urn:siemens:names:prov:gw:SPML:2:0"    xmlns:sub="urn:siemens:names:prov:gw:HLR_SUBSCRIBER:4:5"    returnResultingObject="none">    <version>HLR_SUBSCRIBER_v45</version>    <objectclass>Subscriber</objectclass>    <identifier>Test1</identifier>    <modification operation="addorset" >       <valueObject  xsi:type="sub:HLR">           <odbic>_odbic</odbic>       </valueObject>     </modification></spml:modifyRequest>'

a1 = b'<spml:modifyRequest    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"    xmlns:spml="urn:siemens:names:prov:gw:SPML:2:0"    xmlns:sub="urn:siemens:names:prov:gw:HLR_SUBSCRIBER:4:5"    returnResultingObject="none">    <version>HLR_SUBSCRIBER_v45</version>    <objectclass>Subscriber</objectclass>    <identifier>Test1</identifier>    <modification operation="addorset" >       <valueObject  xsi:type="sub:HLR">           <odbic>_odbic</odbic>       </valueObject>     </modification></spml:modifyRequest>'


print(a1)

data = xmltodict.parse(a1)


print("-->"*30)
print(data)
"""
xml_replace_attibute_file_name = data['soapenv:Envelope']['soapenv:Body']['spmlChangeDirective']['@identifier']
xml_attribute_name = data['soapenv:Envelope']['soapenv:Body']['spmlChangeDirective']['parameter']['@name']
xml_attribute_value = data['soapenv:Envelope']['soapenv:Body']['spmlChangeDirective']['parameter']['@value']

"""