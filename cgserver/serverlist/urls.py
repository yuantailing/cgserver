from django.urls import path

from . import views

app_name = 'serverlist'

urlpatterns = [
    path('', views.index, name='index'),
    path('', views.index, name='loginrequired'),
    path('client/<int:pk>', views.client, name='client'),
    path('client/<int:pk>/chart', views.clientchart, name='clientchart'),
    path('client/<int:client_id>/report/<int:report_id>', views.clientreport, name='clientreport'),
    path('clientreport', views.recvreport),
    path('profile', views.profile, name='profile'),
    path('vpn', views.vpn, name='vpn'),
    path('pptp', views.pptp, name='pptp'),
    path('ftp', views.ftp, name='ftp'),
    path('latex', views.latex, name='latex'),
    path('nas', views.nas, name='nas'),
    path('download', views.download, name='download'),
    path('login', views.loginpassword, name='loginpassword'),
    path('logingithuboauth', views.logingithuboauth, name='logingithuboauth'),
    path('githubcallback', views.githubcallback, name='githubcallback'),
    path('opencheckuser', views.opencheckuser, name='opencheckuser'),
    path('vpnauth', views.vpnauth, name='vpnauth'),
    path('ftpauth', views.ftpauth, name='ftpauth'),
    path('ftpinsecurecheck', views.ftpinsecurecheck, name='ftpinsecurecheck'),
    path('cgnas_api', views.cgnas_api, name='cgnas_api'),
    path('radius_api', views.radius_api, name='radius_api'),
    path('resetpassword', views.resetpassword, name='resetpassword'),
    path('logout', views.logout, name='logout'),
]
