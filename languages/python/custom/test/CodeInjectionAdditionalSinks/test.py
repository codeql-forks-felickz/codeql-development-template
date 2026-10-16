import PIL.ImageMath
from django.http import HttpResponse
from django.urls import path
from PIL import Image, ImageMath


def imagemath_eval(request):  # $ Source
    function_str = request.POST.get("function")
    img = Image.open(request.FILES["file"]).convert("RGB")
    r, g, b = img.split()
    output = ImageMath.eval(function_str, img=img, b=b, r=r, g=g)  # $ Alert
    return HttpResponse(output.tobytes())


def imagemath_unsafe_eval(request):  # $ Source
    expression = request.GET["expr"]
    ImageMath.unsafe_eval(expression=expression, a=None)  # $ Alert
    PIL.ImageMath.eval(expression)  # $ Alert
    return HttpResponse("ok")


def direct_eval(request):
    # Already reported by the standard `py/code-injection` query, so not reported here.
    eval(request.GET["expr"])
    return HttpResponse("ok")


def constant_expression(request):
    img = Image.open(request.FILES["file"])
    r, g, b = img.convert("RGB").split()
    ImageMath.eval("convert(r+g, '1')", r=r, g=g)
    return HttpResponse("ok")


def allowlisted_expression(request):
    expression = request.GET["expr"]
    if expression == "convert(r+g, '1')":
        ImageMath.eval(expression)
    return HttpResponse("ok")


urlpatterns = [
    path("eval", imagemath_eval),
    path("unsafe-eval", imagemath_unsafe_eval),
    path("direct", direct_eval),
    path("constant", constant_expression),
    path("allowlisted", allowlisted_expression),
]
