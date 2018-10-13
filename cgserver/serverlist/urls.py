from django.urls import path

from . import views

app_name = 'serverlist'

urlpatterns = [
    path('checkpermission', views.permissiondenied, name='permissiondenied'),
    path('', views.index, name='index'),
    path('client/<int:pk>', views.client, name='client'),
    path('client/<int:client_id>/report/<int:report_id>', views.clientreport, name='clientreport'),
    path('clientreport', views.recvreport),
    path('vpn', views.vpn, name='vpn'),
    path('pptp', views.pptp, name='pptp'),
    path('proxy', views.proxy, name='proxy'),
    path('login', views.login, name='login'),
    path('githubcallback', views.githubcallback, name='githubcallback'),
    path('vpnauth', views.vpnauth, name='vpnauth'),
    path('resetpassword', views.resetpassword, name='resetpassword'),
    path('logout', views.logout, name='logout'),
]
