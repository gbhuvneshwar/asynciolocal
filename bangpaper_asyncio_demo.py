from aiohttp import web

import aiohttp
import asyncio
from asyncio.sslproto import SSLProtocol
import ssl
import time
import datetime
import uuid

from dataclasses import dataclass, field, InitVar
from typing import ClassVar

import inspect

from corelogic import coreserverReqResogic 



def manage_serverReqResCtrl():
    """
    Creates instance
    """
    handler = RequestHandler( 
                             spmlchangelocation = "/media/sf_ubuntu/proxytiltcode_19_02/xml_files",
                             spmlchangetimeout = 0, spmlchangemaxfilesize = 0, northhttpsenable = False,
                             northcertificate = '/home/bhuvneshwar/httpsSetup1902/client_cert.pem',
                             northprivatekey = '/home/bhuvneshwar/httpsSetup1902/client_key.pem',
                             northverifypeer = False, 
                             connect_timeout = 0, 
                             inactivity_timeout = 0                             
                            )


    app = web.Application()
    app.router.add_post('/', handler.process_http_request)
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sslcontext.check_hostname = True
    sslcontext.verify_mode = ssl.CERT_REQUIRED
    sslcontext.load_verify_locations(cafile='/home/bhuvneshwar/httpsSetup1902/ca.pem')
    sslcontext.load_cert_chain("/home/bhuvneshwar/httpsSetup1902/server_cert.pem", "/home/bhuvneshwar/httpsSetup1902/server_key.pem")

    web.run_app(app, host='ma', port=9001, ssl_context=None)

    #curl -X POST -H 'Content-type: text/xml' -d @./change_odbic.xml http://ma:9001

    #curl -X POST -v --cacert /home/bhuvneshwar/httpsSetup1902/ca.pem --cert /home/bhuvneshwar/httpsSetup1902/client_cert.pem  --key /home/bhuvneshwar/httpsSetup1902/client_key.pem -H 'Content-type: text/xml' -d @./change_odbic.xml https://ma:9001




@dataclass(unsafe_hash=True, order=True)
class RequestData:    
    #Purpose of this class to make request from proxy to tilt
    _reqid: str
    _resp: str
    _clientipaddress: str
    _clientport: int
    _hostname: str
    _soapendpoint: str
    _options: dict

@dataclass(unsafe_hash=True, order=True)
class RequestHandler:

    def __init__(self,spmlchangelocation: str = None, spmlchangetimeout: int = 0, 
                 spmlchangemaxfilesize: int = 0, northhttpsenable: bool = False, 
                 northprivatekey: str = None, northcertificate: str = None,
                 northverifypeer: bool = False, connect_timeout: int = 0, 
                 inactivity_timeout: int = 0):

        self._spmlchangelocation = spmlchangelocation
        self._spmlchangetimeout = spmlchangetimeout
        self._spmlchangemaxfilesize = spmlchangemaxfilesize
        self._northhttpsenable = northhttpsenable
        self._northprivatekey = northprivatekey
        self._northcertificate = northcertificate
        self._northverifypeer = northverifypeer
        self._connect_timeout = connect_timeout
        self._inactivity_timeout = inactivity_timeout
        self._closed = False
        self._north_connection_count = 0
        self._remote_ip = None
        self._remote_port = None
        _action_message = 'Info@@:@@Remote connection initiated'

    #@activeProxyClient(self.north_connection_count)
    async def process_http_request(self, request):
        self._north_connection_count += 1
        print("process http request", "_"*49)
        req_id = uuid.uuid1()
        print("request_id","--"*47, "-->", req_id)
        #import pdb;pdb.set_trace()
        _resp = None
        _clientipaddress = None 
        _clientport = None 
        _hostname = None 
        _soapendpoint = None 
        _options = {}
        _groupname = None

        request_obj = RequestData(req_id, 
                                  _resp, 
                                  _clientipaddress, 
                                  _clientport, 
                                  _hostname, 
                                  _soapendpoint, 
                                  _options,                                   
                                  )

          
        
        _lorequest = await self.request_handler(request, request_obj)

        #import pdb;pdb.set_trace()


        print("something has completed.....")
        print("-"*60)            


        return web.Response(text="now_done_complete_end_to_end")      
        


    def close_connection(self, request):
        self._request = request
        self._close = True
        self._north_connection_count -= 1
        self._request.transport.close()
        if self._remote_port:
            #log.info("In close_connection, remote port #{@remote_port} remote ip #{@remote_ip}")
            pass      
        else:
            raise StopProcessing("there is problem in port")

    def unbind(self):
        # Only remove an identifiable client, 
        if self._north_connection_count != 0:
            self._north_connection_count -= 1    
            #log.debug("unbind connection count = #{@@north_connection_count}")
        self._closed = True
        self._request.transport.close()

        if self._remote_port:
            #og.info(In unbind, remote port #{@remote_port} remote ip #{@remote_ip}")
            #clients = ProxyUsersActive()
            #clients.remove(self.remote_ip, self.remote_port)
            pass


    def client_ssl_handshake_completed(self, request):

        try:
            _getpeercert = self._request.transport._ssl_protocol._sslpipe._sslobj.getpeercert()
            #import pdb;pdb.set_trace()
            #import pdb;pdb.set_trace()
            print("-"*30)
            #print(getpeercert, "---->certificate val")

            _common_name_tuple = _getpeercert['subject'][5][0]
            _peer_cert =  _getpeercert['subject'][5][0][1]

            if _common_name_tuple and _peer_cert:
                pass
            else:
                raise Exception("Failure@@:@@Expecting domain name and certificate")
                pass #Info@@:@@


            print(_peer_cert, "# common_name..................")
            #import pdb;pdb.set_trace()

            print("-"*30)
            try:
                #ip,port = request.transport._sock.getpeername()
                _remote_ip ,_remote_port = self._request._transport_peername
                print(_remote_ip, _remote_port,  "# PeerName..........................")

                print("-"*30)

            except:
                _remote_port = None
        except:
            _peer_cert = None 

        #$log.info "remote port #{@remote_port} remote ip #{@remote_ip}"
        #$log.debug "peer cert #{peer_cert}"
        #clients = ProxyUsersActive.instance
        
        if self._northverifypeer:
            if _peer_cert:
                self.client_ssl_verify_peer(_peer_cert)    
                self.client_cert_domain_mathces(_remote_ip)            
          

    def client_ssl_verify_peer(common_name):
        _common_name = common_name
        #$log.info ("ssl verify peer")
        if _common_name:
            #$log.info "VERIFY cert #{trusted}"
            print("-"*40, "VERIFY cert")
        else:
            pass
            #self.close_connection()

    def user_cert_domain_mathces(remote_ip):
        #$log.info host_names
        _remote_ip = remote_ip
        if _remote_ip:
            print("-"*40, "VERIFY domain")
            #$log.info "VERIFIED domain #{name}"
            

    async def request_handler(self, request, request_obj):

        # Need to capture exceptions from this call
        # callback for requests - executes in reactor thread
        request_obj._request = request
        request_obj._resp = web.Response(text="read tilt proxy post data")

        #HTTPS REQUEST
        #import pdb;pdb.set_trace()`
        self.client_ssl_handshake_completed(request_obj._request)
        request_obj._localrequest = await request_obj._request.content.read()                            
        print("reading content -->", "##"*20, request_obj._localrequest)

        print("-->"*47,"above is request post data")    
        OutputXMLfile = "/media/sf_ubuntu/bangPaper/presentationStuff/taskOp.xml"

        InputXmlfile = request_obj._localrequest

        try:
            _status = coreserverReqResogic(InputXmlfile, OutputXMLfile)
        except ValueError as error:
            #raise Exception("Expecting  <type 'str'>, From XML Configuration")     
            _status = None                       
        
        if _status:
            print("relace with read value in xml template has been done")        
            _tilt_response = await self.request_callback(request, request_obj)
            if _tilt_response:
                print("--"*40, "-->", "succesfully send request to tilt")
                return web.Response(text="read tilt proxy post data")
        else:
            print("Problem in xml replacement...")
            return request_obj._resp         

    async def making_request(self):
        #import pdb;pdb.set_trace()
        _data = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">

        <soapenv:Header/>
        <soapenv:Body>
        <spmlChangeDirective mode="add" identifier="/media/sf_ubuntu/bangPaper/presentationStuff/modify_odbic.xml">

        <parameter name="_odbic" value="1"/>
        </spmlChangeDirective>
        </soapenv:Body>
        </soapenv:Envelope>

        """ 

        async with aiohttp.ClientSession() as _session:
            async with _session.post("http://ma:9009", data=_data) as response:
                _response = await response.read()
                if _response:                    
                    print("#"*40)
                    print("succesfully processed tilt request")
                    #print(_tilt_response, "response from tilt servicess..................")
                    print("#---"*40)  
                    #import pdb;pdb.set_trace()                  
                    return web.Response(text="\n ####OK.......Successful tested end to end \n")
                else:
                    return None


    async def request_callback(self, request, request_obj):
            _res = await self.making_request()

            #import pdb;pdb.set_trace()

            _success = _res

            return _success


    # Declare the response handler
    async def response_handler(self, request, request_obj):    
        pass

    





#curl -X POST -H 'Content-type: text/xml' -d @./change_odbic.xml http://ma:9001


#curl -X POST -v --cacert /home/bhuvneshwar/httpsSetup1902/ca.pem --cert /home/bhuvneshwar/httpsSetup1902/client_cert.pem  --key /home/bhuvneshwar/httpsSetup1902/client_key.pem -H 'Content-type: text/xml' -d @./change_odbic.xml https://ma:9001



manage_serverReqResCtrl()


