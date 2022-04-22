
from django.urls import path
from .views import *

urlpatterns = [
    path('blocks/', blocks, name='blocks'),
    path('', index, name='home'),
    path('about/', about, name='about'),
    path('get_start/', get_start, name='get_start')
]
