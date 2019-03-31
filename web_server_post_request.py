from aiohttp import web
#routes = web.RouteTableDef()

app = web.Application()

class Handler:

    def __init__(self):
        pass

    async def handle_intro(self, request):
        request_body = await request.content.read()
        print(request_body)
        return web.Response(text="Hello, world")



handler = Handler()
app.router.add_post('/', handler.handle_intro)
web.run_app(app, host='127.0.0.1', port=8080)