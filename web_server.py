from aiohttp import web

routes = web.RouteTableDef()
app = web.Application()


@routes.get('/get')
async def handle_get(request):
    print("hello")


@routes.post('/post')
async def handle_post(request):
    ...

app.router.add_routes(routes)


web.run_app(app, host='127.0.0.1', port=8080)