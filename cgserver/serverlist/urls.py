from django.urls import path

from . import views

app_name = 'serverlist'

urlpatterns = [
    path('', views.index, name='index'),
    path('script', views.script, name='script'),
    path('clientreport', views.clientreport, name='clientreport'),
    path('vpn', views.vpn, name='vpn'),
]
