from django.urls import path

from . import views

app_name = 'serverlist'

urlpatterns = [
    path('checkpermission', views.permissiondenied, name='permissiondenied'),
    path('', views.index, name='index'),
    path('client/<int:pk>', views.client, name='client'),
    path('client/<int:pk>/chart', views.clientchart, name='clientchart'),
    path('client/<int:client_id>/report/<int:report_id>', views.clientreport, name='clientreport'),
    path('clientreport', views.recvreport),
    path('vpn', views.vpn, name='vpn'),
    path('pptp', views.pptp, name='pptp'),
    path('nas', views.nas, name='nas'),
    path('ftp', views.ftp, name='ftp'),
    path('download', views.download, name='download'),
    path('proxy', views.proxy, name='proxy'),
    path('login', views.login, name='login'),
    path('githubcallback', views.githubcallback, name='githubcallback'),
    path('vpnauth', views.vpnauth, name='vpnauth'),
    path('cgnas_api', views.cgnas_api, name='cgnas_api'),
    path('resetpassword', views.resetpassword, name='resetpassword'),
    path('logout', views.logout, name='logout'),
]
