from django.urls import path, re_path

from . import views

app_name = 'serverlist'

urlpatterns = [
    path('', views.index, name='index'),
    re_path('client/(?P<pk>[0-9]+)', views.client, name='client'),
    re_path('client/report/(?P<pk>[0-9]+)', views.clientreport, name='clientreport'),
    path('clientreport', views.recvreport),
    path('vpn', views.vpn, name='vpn'),
]
