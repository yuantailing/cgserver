from django.urls import path, re_path

from . import views

app_name = 'serverlist'

urlpatterns = [
    path('checkpermission', views.permissiondenied, name='permissiondenied'),
    path('', views.index, name='index'),
    re_path('^client/(?P<pk>[0-9]+)$', views.client, name='client'),
    re_path('^client/(?P<client_id>[0-9]+)/report/(?P<report_id>[0-9]+)$', views.clientreport, name='clientreport'),
    path('clientreport', views.recvreport),
    path('vpn', views.vpn, name='vpn'),
    path('proxy', views.proxy, name='proxy'),
    path('login', views.login, name='login'),
    path('githubcallback', views.githubcallback, name='githubcallback'),
    path('vpnauth', views.vpnauth, name='vpnauth'),
    path('resetpassword', views.resetpassword, name='resetpassword'),
    path('logout', views.logout, name='logout'),
]
