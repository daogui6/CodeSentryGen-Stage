from aiohttp import web


route = web.static(
    "/assets",
    "./assets",
    follow_symlinks=True,
)