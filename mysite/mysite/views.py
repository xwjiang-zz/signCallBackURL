from django.http import HttpResponse
from django.core.signing import Signer, BadSignature

def create_signed_url(url):
    signer = Signer()
    signed_url = signer.sign(url)
    # use Django signer to sign, result is separated by ':'
    # Ex: https://www.google.com/webhp?sourceid=chrome-instant&ion=1&espv=2&ie=UTF-8
    # is signed to be 
    # https://www.google.com/webhp?sourceid=chrome-instant&ion=1&espv=2&ie=UTF-8:checksum=ihLlPhm3-Aoxpzlypa_OKM2syXw
    tokens = signed_url.rsplit(':', 1)
    # use a maximum of 1 split to make sure that it's separated at rightmost ':'
    # use '?' or '&' based on the number of parameters in callback URL
    tokens[1] = 'checksum=' + tokens[1]
    if '?' in tokens[0]:
        return '&'.join(tokens)
    else:
        return '?'.join(tokens)

def check_signed_url(signed_url):
    tokens = signed_url.rsplit('&checksum=', 1)
    # use a maximum of 1 split to make sure that it's separated at rightmost ':'
    if len(tokens) == 1:
        return 'not verified'
    # join the callback url and checksum with ':'
    # this is the format requirement to be fed into signer
    signed_url = ':'.join(tokens)
    try:
        signer = Signer()
        original = signer.unsign(signed_url)
        return 'verified'
    except BadSignature:
        return 'not verified'

def get_query_string(request):
   query_string = request.META['QUERY_STRING']
   return query_string

def create(request):
    url = get_query_string(request)[4:]
    return HttpResponse(status=200, content=create_signed_url(url))

def check(request):
    signed_url = get_query_string(request)[4:]
    return HttpResponse(status=400, content=check_signed_url(signed_url))
