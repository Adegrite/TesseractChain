from calendar import c
import os

# from django.http import HttpResponse
from django.shortcuts import render

from .models import *

menu = [
    
        {'category': 'About', 'url_name': 'about', 'title': 'About project'},
        {'category': 'See blocks', 'url_name': 'blocks', 'title': 'Blocks meta'}, 
        {'category': 'Logout', 'url_name': 'get_start'}
    
]

def index(request):
    users = User.objects.all()
    context = {
        'menu': menu,
        'users': users,
        'title': 'Main'
    }
    return render(request, 'tesseract/pages/index.html', context=context)

def blocks(request):
    return render(request, 'tesseract/pages/blocks.html', {'menu': menu})



def get_start(request):
    return render(request, 'tesseract/get_start.html', {'menu': menu})

def about(request):
    return render(request, 'tesseract/pages/about.html', {'menu': menu})
