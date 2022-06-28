from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('index.html', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('upload.html', views.upload, name='upload'),
    path('captcha.html', views.captcha, name='captcha'),
    path('insert.html', views.insert, name='insert'),
    path('view/',views.view, name='view'),
    path('search/',views.search, name='search'),
    path('select/<str:file_sha256>/', views.select, name='select'),
    path('show/<str:file_sha256>/', views.show, name='show'),
    path('edit/<str:file_sha256>/', views.edit, name='edit')
    ]
