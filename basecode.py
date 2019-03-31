from aiohttp import web
import asyncio
from asyncio.sslproto import SSLProtocol

import ssl
from dataclasses import dataclass, field, InitVar
from typing import ClassVar

from config import data_config
import time
import datetime

from corelogic import corePgwProxyLogic 


connectionlimit = 100


@dataclass(unsafe_hash=True, order=True)
class RequestData:    
    # Purpose of this class to make request from proxy to pgw
    reqid: str
    resp: str
    resp_without_forward: str
    pgwrequest: str
    pgwresponse_header: str
    pgwresponse_code: str
    pgwresponse: str
    clientipaddress: str
    clientport: int
    proxyuser: str
    hostname: str
    soapendpoint: str
    options: dict
    groupname: str


@dataclass(unsafe_hash=True, order=True)
class RequestHandler:
    # Basically this class is gonna hanlde curl request.

    remote_ip: str

    remote_port: int
    north_connection_count: int
    # ObjectLevelAttribute.
    proxymode: str
    spmlchangelocation: str
    spmlchangetimeout: str
    spmlchangemaxfilesize: str
    northhttpsenable: str
    northprivatekey: str
    northcertificte: str
    northverifypeer: str

    connecttimeout: int
    inactivitytimeout: int

    defaultproxyuser: str
    closed: str
    pgwuserlive: str



    async def process_http_request(self, request):
        print("process http request")
        #$log.info ("process_http_request")
        # increment our received counter
        #s = Stats()
        #s.inc_req_received()

        # Create instance for the request data
        print("new_object_got_created_for_request")
        local_request = RequestData('1', '2', '33', '44', '444', '555', '55556', '54444', 2222, 'rrr','rrrrrrrr', 'rt444', {'e',33}, 'rrwr3r3r')
        #local_request.connection = self
        #$log.debug ("request_handler conn = #{request.connection}")
        #$log.debug ("request_handler conn closed = #{request.connection.closed}")

        # Need to new object here to get proper delegate creation from object with EM::Connection
        #request.resp = EventMachine::DelegatedHttpResponse.new( self )
        # Keep client connection alive
        #request.resp.keep_connection_open

        #operation = request_handler(request)
        #EM.defer( operation , request_callback )   
        local_request = await self.request_handler(request)
        return local_request      

    def __post_init__(self):

        #import pdb;pdb.set_trace()

        self.closed = False
        #$log.debug ("post_init EM.connection_count = #{EM.connection_count}")
        #$log.debug ("north_connection_count = #{@@north_connection_count}")
        self.north_connection_count += 1
        #$log.debug("$connectionlimit =#{$connectionlimit}")
        #$log.debug("inactivity timeout = #{comm_inactivity_timeout}")
        #$log.debug("proxy user timeout = #{@proxyuser_timeout}")
        
        # Bug EM.connection_count should not be used as this includes client connections
        # instead use class  variable that is incremented/decremeneted in post_init/unbind

        #connection_count = EM.connection_count
        connection_count = self.north_connection_count

        print("-"*30)
        print(connection_count, connectionlimit, "connection_count and connectionlimit......")
        print("-"*30)
       
        if (connectionlimit > 0 and connection_count > connectionlimit):
            #$log.error("Connection limit breached #{connection_count}, closing connection")
            self.close_connection()
            return
    
        else:

            if self.northhttpsenable != None and self.northhttpsenable == True:

                if self.northprivatekey == True:
                    if self.northcertificate == True:        
                        ssl_opts = { }
                        ssl_opts['private_key_file'] = self.northprivatekey
                        ssl_opts['cert_chain_file'] = self.northcertificate
                        ssl_opts['verify_peer'] = self.northverifypeer

                        if self.northverifypeer:
                            try:
                                #@store = EmSSL::Store.new([@northcacert])     
                                pass         
                            except:
                                #$log.error("EmSSL::Store.new failure northcacert=#{northcacert}")
                                self.close_connection()
                                return                              
                        
                            #$log.info("Northbound interface is TLS enabled....")
                            #$log.debug("EM connection count is #{EM.connection_count()}")
                            #$log.debug ssl_opts
                            # exception handling
                        
                            try:
                                print("start https varifications")
                                #start_tls( ssl_opts )
                            except:
                                #$log.error("exception in post_init request handler, #{e}")
                                self.close_connection()
                                return
        
                    else:
                        #$log.error("#{@northcertificate}: error reading file, invalid northcertificate")
                        self.close_connection()
                        return
                        #readable @northcertificate
                else:
                    #$log.error("#{@northprivatekey}: error reading file, invalid northprivatekey")
                    self.close_connection()
                    return

            # When we have case that proxy is running in http mode, there will be no proxyuser info available
            # Have to rely on a default proxyuser (httpuser) configured into datastore. 
            if self.northhttpsenable != None and self.northhttpsenable == False:
           
                # Search for default proxy user and add instance to list of active proxy users
                user = self.defaultproxyuser
                proxyusersactive = ProxyUsersActive()
                if proxyusersactive.permitted(user):
                   #$log.info "plain http proxy user #{user} has connected"
                   # Need to capture exceptions from this call
                   # Need these port and ip vars setup to facilitate add/delete from the proxyusers active store
                    try:
                        print("need to get IP here")
                        #self.remote_port, self.remote_ip = Socket.unpack_sockaddr_in get_peername()
                    except:
                        self.remote_ip = None
          

                    proxyusersactive.add(self.remote_ip, user, self.remote_ip, self.remote_port)

            else:
              # disallowed connection, close it maybe?? or leave to next stage and return http 500 code
              #$log.info "plain http proxy user #{user} is disallowed connection"
              pass



    def close_connection(self):
        self.close = True
        self.request.transport.close()
        if self.remote_port:
            #$log.info "In close_connection, remote port #{@remote_port} remote ip #{@remote_ip}" 
            pass      

    def unbind(self):
        # Only remove an identifiable client, 
        if self.north_connection_count != 0:
            self.north_connection_count -= 1    
            #$log.debug("unbind connection count = #{@@north_connection_count}")

        self.closed = True
        self.request.transport.close()

        if self.remote_port:
            #$log.info "In unbind, remote port #{@remote_port} remote ip #{@remote_ip}"
           clients = ProxyUsersActive()
           clients.remove(self.remote_ip, self.remote_port)


    def ssl_handshake_completed(self):
        pass

    def ssl_verify_peer(pem):
        pass

    def cert_domain_mathces(remote_ip):
        pass           


    async def request_handler(self, request):

        # Need to capture exceptions from this call
        try:
            #port,ip = Socket.unpack_sockaddr_in get_peername()
            print("need to get ip and port")
        except:
            ip = None


      # find the proxyuser and attach info to the request
        #proxyusersactive = ProxyUsersActive()
        #print(proxyusersactive)
        #proxyuser = proxyusersactive.search(ip, port)
        proxyuser = None
        if proxyuser:
            #$log.info "ProxyUser found #{proxyuser.proxyuser} #{proxyuser.hostname} #{proxyuser.ip} #{proxyuser.port}"
            #$log.info "Endpoint alive? #{proxyuser.pgwuserObject.alive}"
            print(proxyuser.proxyuser, proxyuser.hostname, proxyuser.ip, proxyuser.port)
        
            # Touch the proxyuser with the current time, fend off the reaper
            proxyuser.touch = Time.now

            request.clientport = port
            request.clientipaddress = ip

            # copy in the data from proxyuser record into the request, will use to respond to the configured pgwuser
            request.proxyuser = proxyuser.proxyuser
            request.hostname = proxyuser.hostname
            #        request.soapendpoint = proxyuser.pgwuserObject.soapendpoint
            #        request.options = proxyuser.pgwuserObject.options
            request.pgwConnection = proxyuser.pgwuserObject.pgwConnection
            request.groupname = proxyuser.groupname

            # send the request handling off to a background thread
            request.resp_without_forward = None

            # If the endpoint is not alive, send back a 502 response (bad gateway)
            if proxyuser.pgwuserObject.alive == False:
                #$log.error("#{request.reqid}: endpoint is unavailable, synthesizing 502 error to client")
                request.resp.status = 502
                request.resp.headers['Content-Type'] = 'text/plain'
                #request.resp.content = "endpoint #{proxyuser.pgwuserObject.soapendpoint} is unavailable, request cannot be serviced"
                request.resp_without_forward = True
            
            #return request
            #next request
        

        else:
            #$log.error("#{request.reqid}: proxyuser refused (check datastores), synthesizing 403 error to client")
            #request.resp.status = 403
            #request.resp.headers['Content-Type'] = 'text/plain'
            #request.resp.headers['Connection'] = 'close'
 
            #request.resp.content = 'proxyuser is not authentic, request processing is terminated'
            #request.resp_without_forward = true
            #next request
            #return request
            pass
      

        #$log.debug("#{Thread.current} request_handler req #{request} req_id #{request.reqid}")

        #s = Stats.instance
        self.http_post_content = 'dd'
 
        if  self.http_post_content == None:
            #$log.error("#{request.reqid}: no HTTP body content")
            request.resp.status = 400
            request.resp.headers['Content-Type'] = 'text/plain'
            request.resp.content = 'body of request is empty'
            request.resp_without_forward = true
            #next request

        else:
            
            # Always log the POST data before SOAP verifcation to help debugging 
            #
            #$log.debug("Received HTTP request #{@http_post_content}")
            self.verifier = None
            if self.verifier:
                #$log.debug ("Verifying SOAP request...")
                result = self.verifier.verifyMem(self.http_post_content)
           
                if result == 1:  
                    #$log.debug( "VERIFY OK"  )
                    print("VERIFY OK")
                else:
                    #$log.debug( "VERIFY FAIL"  )
                    request.resp.status = 403
                    request.resp.headers['Content-Type'] = 'text/plain'
                    request.resp.content = 'SOAP verification failed'
                    request.resp_without_forward = True
            
        #
        # Cant use return from a "Proc block" as this will cause LocalJumpError runtime error
        # have to use next instead
        #
        #next request 
 


        # exception handling

        try:
            rewrote_body = False
            if True:
            #if request.pgwrequest.length > 0:
                #$log.debug("vars passed - #{@proxymode} #{@spmlchangelocation} #{@spmlchangetimeout} #{@spmlchangemaxfilesize} #{@xmllibrary}")

                # Only enter this code block when spml change mode has been actioned
                #if (self.proxymode != None):
                if True:
                    #self.proxymode.downcase!
                    if True:
                    #if self.proxymode.include == 'spmlchange':
                        # This where the rules will be applied
                        #rule = $ruleds.printEntry(request.groupname)
                        #$log.info "Rule TO BE APPLIED for #{request.groupname} is #{rule}"

                        # Get rules for the request
                        # If no rules retrieved, fail to process request with a 403
                        # If rule is not passed, request has broken rule with a 403

                        #rulez = ruleds.searchObjectEntry(request.groupname)
                        rulez = True
                        if rulez:

                            #cr = ChangeRequest.new(self.spmlchangelocation, self.spmlchangetimeout, self.spmlchangemaxfilesize, self.xmllibrary)

                            #import pdb;pdb.set_trace()
                            local_request = request
                            local_request.resp = web.Response(text="read pgw proxy post data")



                            #HTTPS REQUEST
                            try:
                                getpeercert = request.transport._ssl_protocol._sslpipe._sslobj.getpeercert()
                                #import pdb;pdb.set_trace()
                                print("-"*30)
                                #print(getpeercert, "---->certificate val")
                                common_name_tuple = getpeercert['subject'][5][0]
                                common_name =  getpeercert['subject'][5][0][1]

                                print(common_name, "# common_name..................")
                                #import pdb;pdb.set_trace()

                                print("-"*30)
                                try:
                                    #ip,port = request.transport._sock.getpeername()
                                    ip,port = request._transport_peername
                                    print(ip, port,  "# PeerName..........................")

                                    print("-"*30)

                                except:
                                    ip = None
                            except:
                                pass                      


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

                            status = corePgwProxyLogic(InputXmlfile, OutputXMLfile)

                            if status:
                                print("relace with read value in xml template has been done")        

                            return local_request.resp                            
                            



                            #decision,reason = cr.apply_rules(request.pgwrequest, rulez)              
                            decision, reason = None, None

                            # Successful application of rules (above) will have also applied spmlChangeRequests if present
                            if decision == True:
          
                                if reason:
                                    #$log.error("Modified request #{request.reqid} #{request.pgwrequest}")
                                    rewrote_body = True                 
                            else:
                                # rules not passed, synthesize 403 error to client
                                #$log.error("#{request.reqid}: proxyuser #{request.proxyuser} rule blocks request, synthesizing 403 error to client")
                                request.resp.status = 403
                                request.resp.headers['Content-Type'] = 'text/plain'
                                #request.resp.content = "proxyuser #{request.proxyuser} rule blocks request, request processing is terminated"
                                request.resp_without_forward = true
                  
                        else:
                            # rules not found, synthesize 403 error to client
                            #$log.error("#{request.reqid}: proxyuser #{request.proxyuser} no rules found (check datastores), synthesizing 403 error to client")
                            request.resp.status = 403
                            request.resp.headers['Content-Type'] = 'text/plain'
                            #request.resp.content = "proxyuser #{request.proxyuser} no rules found, request processing is terminated"
                            request.resp_without_forward = true
                            #end # rules application
                        # proxymode is spmlchange

                    if self.proxymode.include == 'noforward':
                        # This is a mode for capturing incoming requests and always responding with a http response of 200
                        # Requests are never forwarded anywhere
                        #$log.error("#{request.reqid}: proxyuser #{request.proxyuser} mode is noforward, synthesizing 200 response to client")
                        request.resp.status = 200
                        request.resp.headers['Content-Type'] = 'text/plain'
                        # request.resp.content = "request was not forwarded"
                        request.resp.content = """
                                                  <?xml version=\"1.0\" encoding=\"UTF-8\"?>
                                                  <soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">
                                                  <soapenv:Body>
                                                  <spml:addResponse xmlns:spml=\"urn:siemens:names:prov:gw:SPML:2:0\" result=\"success\"/>
                                                  </soapenv:Body>
                                                  </soapenv:Envelope>
                                               """
                        request.resp_without_forward = true
                        # noforward change mode

                    if self.proxymode.include == 'reflect':
                        # This is a mode for capturing incoming requests and always responding with a http response of 200
                        # Requests are never forwarded anywhere, the original request (after any spmlchange processing) is reflected back to client
                        #$log.error("#{request.reqid}: proxyuser #{request.proxyuser} mode is reflect, synthesizing 200 response to client")
                        request.resp.status = 200
                        request.resp.headers['Content-Type'] = 'text/plain'
                        request.resp.content = request.pgwrequest
                        request.resp_without_forward = true
                        # reflect change mode

                    if self.proxymode.include =='xsltchange':
                        pass
                        # Nothing here yet!
         

                    # proxymode !nil

                # Add record of request to log
                #req = request.pgwrequest.gsub(/\r/, "")
                #req = req.gsub(/\n/, "")
                #$log.audit("#{request.reqid}: request from client #{request.clientipaddress}: " + req)

                # After SPML changes have been made do the SOAP signing (if configured)
                #if $signer
                    #$log.debug ("Signing PGW SOAP request...")
                #    ptr = $signer.signMem (request.pgwrequest)
                #if ptr == nil
                    #$log.error("Failed to sign SOAP request")
                #else
                    #request.pgwrequest = ptr.read_string()
                    #SoapSecurity::SoapSigner.free(ptr)
                    # Update return payload if in reflect mode
                    #if (@proxymode != nil) && (@proxymode.include? 'reflect') then
                        #request.resp.content = request.pgwrequest
    

            else:
                pass 
                # http content length is 0
        
                #$log.debug("#{request.reqid}: content length is 0")
          
                # http content length is 0

            # increment stats according to what we've done
            if rewrote_body:
                pass
                #$log.debug("#{request.reqid}: incremented converted request counter")
                #s.inc_req_converted()
            else:
                #$log.debug("#{request.reqid}: incremented proxied request counter")
                pass
                s.inc_req_proxied()
          

        except:      
            #Syslog.log(Syslog::LOG_CRIT, "PPX 763 6 XML #{e}")
            #$log.error("#{request.reqid}: exception, forwarding unmodified: #{e}")
            
        
            pass
            #Syslog.log(Syslog::LOG_CRIT, "PPX 763 7 Exception: #{e}")
            #$log.error("#{request.reqid}: exception, synthesizing 500 error to client: #{e}")
            #request.resp.status = 500
            #request.resp.headers['Content-Type'] = 'text/plain'
            #request.resp.content = 'exception in request processing'
            #request.resp_without_forward = true

        # exception handling for request processing  
        request.resp_without_forward  = 'd' 

        if request.resp_without_forward == None:
            #pgwRequestHeaders = { 'SOAPAction' => '', 'X-Pgwproxy-Request' => request.reqid }
            pgwresponse = request.pgwConnection.http_post(request.pgwrequest,pgwRequestHeaders)
            
            if pgwresponse == None:
                #s.inc_resp_error() # increment response error statistic
                #Syslog.log(Syslog::LOG_CRIT, "PPX 763 3 DNS error or timeout from PGW")
                request.resp.status = 502
                request.resp.headers['Content-Type'] = 'text/plain'
                request.resp.content = 'error or timeout sending to PGW'

            else:
                #s.inc_resp_received()
          
                if pgwresponse.code != "200":
                    s.inc_resp_error() # increment response error statistic
                    #Syslog.log(Syslog::LOG_CRIT, "PPX 763 3 HTTP(#{pgwresponse.code}) error from PGW")
          
            #
            # Copy pgw HTTP response status headers and body
            #
            request.resp.status = pgwresponse.code
            
            if pgwresponse['Date']:
                request.resp.headers['Date'] = pgwresponse['Date']
          
            if pgwresponse['Content-Type']:
                request.resp.headers['Content-Type'] = pgwresponse['Content-Type']
          
            request.resp.content = pgwresponse.body
 
        #return request  

    # callback for requests - executes in reactor thread
    async def request_callback(self, request):
        #$log.debug("#{Thread.current} request_callback req #{request} req_id #{request.reqid}")
        # are we responding without forwarding to PGW?
        if request.resp_without_forward:
            # error response to the client
            request.resp.send_response

        else:
            # forward the request asynchronously
            # $log.debug("#{request.reqid}: request to PGW: " + request.pgwrequest)
            #Fiber.new {
            #  begin # exception handling

                # connect to PGW with information extracted from the incoming request. 
            #    (http, success) = fiber_http_post(
            #     request.soapendpoint, #$pgwuri.to_s,
            #     request.pgwrequest,
            #     { 'SOAPAction' => '', 'X-Pgwproxy-Request' => request.reqid },
            #     request.options #  @defaultoptions
            #    )
            try:
                import requests
                url="http://wsf.cdyne.com/WeatherWS/Weather.asmx?WSDL"
                #headers = {'content-type': 'application/soap+xml'}
                headers = {'content-type': 'text/xml'}
                body = """<?xml version="1.0" encoding="UTF-8"?>
                     <SOAP-ENV:Envelope xmlns:ns0="http://ws.cdyne.com/WeatherWS/" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" 
                        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
                        <SOAP-ENV:Header/>
                          <ns1:Body><ns0:GetWeatherInformation/></ns1:Body>
                     </SOAP-ENV:Envelope>"""

                response = requests.post(url, data=body, headers=headers)
                print response.content                

                # Need to send a request to pgw
                
                #s = Stats()
                #$log.debug("#{success} #{http}")

                if success:
                    # succesful response from PGW, process it in a background thread
                    request.pgwresponse_header = http.response_header
                    request.pgwresponse_code = http.response_header.http_status
                    request.pgwresponse = http.response
                    #s.inc_resp_received() #increment response statistic

                    rh = await self.response_handler(request)                  
                    #rh.response_callback()

                else:
                    #log.error("#{request.reqid}: error or timeout sending to PGW, synthesizing 502 error to client")
                    #s.inc_resp_error() # increment response error statistic
                    #Syslog.log(Syslog::LOG_CRIT, "PPX 763 3 DNS error or timeout from PGW")
                    request.resp.status = 502
                    request.resp.headers['Content-Type'] = 'text/plain'
                    request.resp.content = 'error or timeout sending to PGW'
                    request.resp.send_response
                

            except:
                #$log.error("request_callback exception caught #{e}")
                pass
            
        return request



    # Declare the response handler
    async def response_handler(self, request):
    
        #$log.debug("#{Thread.current} response_handler req #{request} req_id #{request.reqid}")
    
        #s = Stats()

        try: # exception handling

            # get the body of the response from PGW
            # responsexml = request.pgwresponse

            # handle non-success (not HTTP code 200) responses from PGW
            if request.pgwresponse_code != 200:
                #$log.debug("#{request.reqid}: pgwresponse_code: #{request.pgwresponse_code}")
                #s.inc_resp_error() # increment response error statistic
                #Syslog.log(Syslog::LOG_CRIT, "PPX 763 3 HTTP(#{request.pgwresponse_code}) error from PGW")

                pass

            # set the code and content in our response
            request.resp.status = request.pgwresponse_code
            request.resp.headers['Content-Type'] = request.pgwresponse_header['Content-Type']
            request.resp.content = request.pgwresponse
            #$log.audit("#{request.reqid}: response to client #{request.clientipaddress}: " + request.pgwresponse)

        except:    
            #Syslog.log(Syslog::LOG_CRIT, "PPX 763 7 Exception: #{e}")
            #$log.error("#{request.reqid}: exception, synthesizing 500 error to client: #{e}")
            request.resp.status = 500
            request.resp.headers['Content-Type'] = 'text/plain'
            request.resp.content = 'exception in response processing'
      
        # exception handling

        return request

     

    async def response_callback(self):
        #$log.debug("#{Thread.current} response_callback req #{request} req_id #{request.reqid}")

        if request.resp.status == None  or request.resp.content == None:
            #$log.audit("sending a response without a status or content")
            pass
      

        return request.resp.send_response

  
  
    # definition of RequestHandler class




#handler = RequestHandler('None', 'None', 'None', 'None', 'None', 'None', 'None', 'None', 1, 'None', 'None', 'None', 'None')
handler = RequestHandler('Hi', 9999, 0, 'tiger', 'h', 'g', 'd', 'a', 'b', 'b', 'b', 11, 22, 'ff', 'ff', 'ffff')


app = web.Application()
app.router.add_post('/', handler.process_http_request)



sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
sslcontext.check_hostname = True
sslcontext.verify_mode = ssl.CERT_REQUIRED
sslcontext.load_verify_locations(cafile='/home/bhuvneshwar/httpsSetup1902/ca.pem')
sslcontext.load_cert_chain("/home/bhuvneshwar/httpsSetup1902/server_cert.pem",
                            "/home/bhuvneshwar/httpsSetup1902/server_key.pem")




web.run_app(app, host='ma', port=9001, ssl_context=sslcontext)



#HTTP Curl:---> curl -X POST -H 'Content-type: text/xml' -d @./change_odbic.xml http://nokia:9009

#https------->  curl -X POST -v --cacert /home/bhuvneshwar/httpsSetup1902/ca.pem --cert /home/bhuvneshwar/httpsSetup1902/client_cert.pem  --key /home/bhuvneshw_key.pem -H 'Content-type: text/xml' -d @./change_odbic.xml https://ma:9001

"""
* SSLv3, TLS handshake, Client hello (1):
* SSLv3, TLS handshake, Server hello (2):
* SSLv3, TLS handshake, CERT (11):
* SSLv3, TLS handshake, Server key exchange (12):
* SSLv3, TLS handshake, Request CERT (13):
* SSLv3, TLS handshake, Server finished (14):
* SSLv3, TLS handshake, CERT (11):
* SSLv3, TLS handshake, Client key exchange (16):
* SSLv3, TLS handshake, CERT verify (15):
* SSLv3, TLS change cipher, Client hello (1):
* SSLv3, TLS handshake, Finished (20):
* SSLv3, TLS change cipher, Client hello (1):
* SSLv3, TLS handshake, Finished (20):

"""
"""

* Connection #0 to host ma left intact
read pgw proxy post databhuvneshwar@bhuvneshwar-VirtualBox:~$ curl -X POST -v --cacert /home/bhuvneshwar/httpsSetup1902/ca.pem --cert /home/bhuvneshwar/httpsSetup1902/client_cert.pem  --key /home/bhuvneshw_key.pem -H 'Content-type: text/xml' -d @./change_odbic.xml https://ma:9001
* Rebuilt URL to: https://ma:9001/
* Hostname was NOT found in DNS cache
*   Trying 127.0.0.1...
* Connected to ma (127.0.0.1) port 9001 (#0)
* successfully set certificate verify locations:
*   CAfile: /home/bhuvneshwar/httpsSetup1902/ca.pem
  CApath: /etc/ssl/certs
* SSLv3, TLS handshake, Client hello (1):
* SSLv3, TLS handshake, Server hello (2):
* SSLv3, TLS handshake, CERT (11):
* SSLv3, TLS handshake, Server key exchange (12):
* SSLv3, TLS handshake, Request CERT (13):
* SSLv3, TLS handshake, Server finished (14):
* SSLv3, TLS handshake, CERT (11):
* SSLv3, TLS handshake, Client key exchange (16):
* SSLv3, TLS handshake, CERT verify (15):
* SSLv3, TLS change cipher, Client hello (1):
* SSLv3, TLS handshake, Finished (20):
* SSLv3, TLS change cipher, Client hello (1):
* SSLv3, TLS handshake, Finished (20):
* SSL connection using ECDHE-RSA-AES256-GCM-SHA384
* Server certificate:
*    subject: C=IN; ST=north; L=silk; O=hi; OU=ims; CN=ma; emailAddress=b20@gmail.com
*    start date: 2019-02-20 04:14:26 GMT
*    expire date: 2021-02-09 04:14:26 GMT
*    common name: ma (matched)
*    issuer: C=IN; ST=South; L=sarja; O=hello; OU=nsw; CN=shivam; emailAddress=b.chouksey@gmail.com
*    SSL certificate verify ok.
> POST / HTTP/1.1
> User-Agent: curl/7.35.0
> Host: ma:9001
> Accept: */*
> Content-type: text/xml
> Content-Length: 476
> 
* upload completely sent off: 476 out of 476 bytes
< HTTP/1.1 200 OK
< Content-Type: text/plain; charset=utf-8
< Content-Length: 24
< Date: Fri, 01 Mar 2019 05:17:41 GMT
* Server Python/3.7 aiohttp/3.5.4 is not blacklisted
< Server: Python/3.7 aiohttp/3.5.4
< 
* Connection #0 to host ma left intact

"""

# sudo service hostname restart/start