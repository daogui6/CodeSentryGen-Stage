from aiohttp import web


route = web.static(
    "/assets",
    "./assets",
)