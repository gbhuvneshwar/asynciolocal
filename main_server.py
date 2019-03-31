from aiohttp import web
import ssl

from config import data_config
import time
import datetime
import asyncio
from asyncio.sslproto import SSLProtocol
from corelogic import coreserverReqResogic 

class RequestData:
    req_id = 0
    connection_count = 0

    def __init__(self):
        self.__class__.req_id = self.__class__.req_id +  1  
        #self.__class__.connection_count = self.__class__.connection_count +  1      
        self.reqid = self.__class__.req_id
        self.resp = None
        self.resp_without_forward = None
        self.pgwrequest = None
        self.pgwresponse_header = None
        self.pgwresponse_code = None
        self.pgwresponse = 0
        self.clientipaddress = None
        self.clientport = None
        self.proxyuser = None
        self.hostname = None
        self.soapendpoint = None
        self.options = None
        self.groupname = None
        #self.connection_count = self.__class__.connection_count
        print("RequestData: init {}".format(self.reqid))



class RequestHandlerMulti():

    proxymode = data_config['proxymode']
    spmlchangelocation = data_config['spmlchangelocation']
    spmlchangetimeout = data_config['spmlchangetimeout']
    spmlchangemaxfilesize = data_config['spmlchangemaxfilesize']    
    northhttpsenable = data_config['northhttpsenable']
    northprivatekey = data_config[ 'northprivatekey' ]
    northcertificate = data_config[ 'northcertificate']
    northverifypeer = data_config[ 'northverifypeer']
    connect_timeout = data_config['connect_timeout']
    inactivity_timeout = data_config['inactivity_timeout']
    defaultproxyuser = data_config['defaultproxyuser']    
    connection_limit = data_config['connectionlimit']    
    closed = False

    def close_connection(self, request):
        self.close = True
        #if self.remote_port != None:
        request.transport.close()
        #print("In close_connection, remote port {} remote ip {}").format(self.remote_port, self.remote_ip)
        #self.unbind()

    async def handle_post_request(self, request):
        print("#"*40)
        print("process pgw request")
        print("#---"*40)

        #print("process_http_request connection count is {}".format(request.transport._server._active_count))
        
        #import pdb;pdb.set_trace()
        """
        if self.connection_limit > 0 and request.transport._server._active_count > self.connection_limit:
            print("Connection limit breached {}, closing connection".format(request.transport._server._active_count))
            self.close_connection(request)
        
        else:
            self.post_init(request)
            self.ssl_handshake_completed(request)
            self.ssl_verify_peer(request)
            self.cert_domain_matches(request)                  
        """

        #local_request = await self.request_handler(request)
        """
        #import pdb;pdb.set_trace()
        if local_request.resp_without_forward == True:
            return local_request.resp
        #request_body = await request.content.read()
        #print(request_body)
        #await asyncio.sleep(5)
        #return web.Response(text="Hello, world")
        """
        return web.Response(text="Hello, world")



    async def request_handler(self, request):
        print("new_object_got_created_for_request")
        local_request = RequestData()
        local_request.resp = web.Response(text="read pgw proxy post data")
        #import pdb;pdb.set_trace()
        #request.resp.keep_connection_open         
        #import pdb;pdb.set_trace()
        ""
        #HTTPS REQUEST
        #getpeercert = request.transport._ssl_protocol._sslpipe._sslobj.getpeercert()
        #print("###############################3")
        #print(getpeercert, "---->certificate val")
        #try:
        #    ip,port = request.transport._sock.getpeername()
        #    print(request.transport._sock.getpeername())
        #except:
        #    ip = None
        """

        proxyusersactive = ProxyUsersActive.instance
        #proxyusersactive.print
        proxyuser = proxyusersactive.search(ip, port)

        if proxyuser:
            print("ProxyUser found {} {} {} {}").format(proxyuser.proxyuser, proxyuser.hostname, proxyuser.ip, proxyuser.port)
            print("Endpoint alive? {}".format(proxyuser.pgwuserObject.alive))
            
            # Touch the proxyuser with the current time, fend off the reaper
            proxyuser.touch = datetime.datetime.now()
            local_request.clientport = port
            local_request.clientipaddress = ip
            # copy in the data from proxyuser record into the request, will use to respond to the configured pgwuser
            local_request.proxyuser = proxyuser.proxyuser
            local_request.hostname = proxyuser.hostname
            local_request.soapendpoint = proxyuser.pgwuserObject.soapendpoint
            local_request.options = proxyuser.pgwuserObject.options
            local_request.groupname = proxyuser.groupname            
            local_request.resp_without_forward = None

            if proxyuser.pgwuserObject.alive == False:
                print("{}: endpoint is unavailable, synthesizing 502 error to client".format(local_request.reqid))
                local_request.resp.status = 502
                local_request.resp.headers['Content-Type'] = 'text/plain'
                local_request.resp.content = "endpoint {} is unavailable, request cannot be serviced".format(local_request.soapendpoint)
                local_request.resp_without_forward = True

        else:
            print("{}: proxyuser refused (check datastores), synthesizing 403 error to client".format(local_request.reqid))
            local_request.resp.status = 403
            local_request.resp.headers['Content-Type'] = 'text/plain'
            local_request.resp.content = 'proxyuser is not authentic, request processing is terminated'
            local_request.resp_without_forward = True
        """

        local_request.pgwrequest = await request.content.read()

        #print(request.data)
        print("reading content -->", local_request.pgwrequest)
        print("-->"*47,"above is request post data")    

        #import pdb;pdb.set_trace()
        
        #InputXmlfile = "/media/sf_ubuntu/python_pgw_proxy/async_code/xml_files/change_odbic.xml"
        #ReadAttributeXmlfile = "/media/sf_ubuntu/python_pgw_proxy/async_code/xml_files/change_odbic.xml"
        OutputXMLfile = "/media/sf_ubuntu/python_pgw_proxy/async_code/xml_files/op_1.xml"

        InputXmlfile = local_request.pgwrequest

        #import pdb;pdb.set_trace()

        status = coreserverReqResogic(InputXmlfile, OutputXMLfile)

        if status:
            print("replace with read value in xml template has been done")
        #import requests
        #/home/bhuvneshwar/ssl_impl/client_cert_key
        #client_ssl_req = requests.get('localhost:8080', cert=('/home/bhuvneshwar/ssl_impl/client_cert_key/client_cert.pem', '/home/bhuvneshwar/ssl_impl/client_cert_key/client_key.pem'))
        #request.data()
        #import request
        #t - request.
        """
        import json

        test = json.loads(local_request.pgwrequest)
        #import pdb;pdb.set_trace()
        print(type(test))

        

        if local_request.resp_without_forward == None:

            if local_request.pgwrequest:
                rewrote_body = False
                if len(local_request.pgwrequest) > 0:
                    #import pdb;pdb.set_trace()
                    print(local_request.pgwrequest)
                    print("reading...")
                    ## Convert Logic

        """

       # request_body = local_request.pgwrequest
        #print(request_body)    
        return local_request.resp  

    async def request_calback_for_pgw_gateway(local_request):
        pass
        # Calling PGW Code




handler = RequestHandlerMulti()
app = web.Application()
app.router.add_post('/', handler.handle_post_request)

sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
sslcontext.check_hostname = True
sslcontext.verify_mode = ssl.CERT_REQUIRED
"""
sslcontext.load_verify_locations(cafile='/home/bhuvneshwar/13_key/ca.crt')
sslcontext.load_cert_chain("/home/bhuvneshwar/13_key/example.org.bundle.crt",
                            "/home/bhuvneshwar/13_key/example.org.key")
"""

web.run_app(app, host='ma', port=9009, ssl_context=None)


#ForHTTPSRequest
#web.run_app(app, host='Nokia', port=9001, ssl_context=sslcontext)
# curl -v --cacert /home/bhuvneshwar/13_key/ca.crt --cert /home/bhuvneshwar/13_key/client_wrong/client.crt  --key /home/bhuvnng/client_key.key -d {'a':10} https://Nokia:9003


#curl -v --cacert /home/bhuvneshwar/13_key/ca.crt --cert /home/bhuvneshwar/13_key/client_wrong/client.crt  --key /home/bhuvnng/client_key.key -F file= @'/home/bhuvneshwar/modify_odbic.xml' http://Nokia:9009


#HTTP Curl:---> curl -X POST -H 'Content-type: text/xml' -d @./change_odbic.xml http://nokia:9009




###################################################3333333
#For HTTPS Request:

#curl -X POST -v --cacert /home/bhuvneshwar/httpsSetup1902/ca.pem --cert /home/bhuvneshwar/httpsSetup1902/client_cert.pem  --key /home/bhuvneshwar/httpsSetup1902/client_key.pem -H 'Content-type: text/xml' -d @./change_odbic.xml https://Nokia:9009


#curl -X POST -H 'Content-type: text/xml' -d @./change_odbic.xml http://10.2.102.105:8081/ProvisioningGateway/services/SPMLHlrSubscriber45Service