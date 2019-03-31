from aiohttp import web
#routes = web.RouteTableDef()

app = web.Application()

class Handler:

    def __init__(self):
        pass

    def handle_intro(self, request):
        import pdb;pdb.set_trace()
        return web.Response(text="Hello, world")

    async def handle_greeting(self, request):
        name = request.match_info.get('name', "Anonymous")
        txt = "Hello, {}".format(name)
        #import pdb;pdb.set_trace()
        return web.Response(text=txt)

handler = Handler()
app.router.add_get('/intro', handler.handle_intro)
app.router.add_get('/greet/{name}', handler.handle_greeting)

web.run_app(app, host='127.0.0.1', port=8080)