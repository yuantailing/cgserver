import base64
import boto3
import crypt
import functools
import json
import math
import os
import pprint
import requests
import threading
import time
import uuid

from .forms import LoginForm, ResetPasswordForm, FtpForm
from .models import AccessLog, Client, ClientReport, Employee, FtpPerm, GithubUser, UnknownReport
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib import auth, messages
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import models, transaction
from django.db.models import Max
from django.http import Http404, HttpResponseBadRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from helper import md4
from six.moves import urllib
from socket import AddressFamily

# Create your views here.

def get_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    else:
        return request.META.get('REMOTE_ADDR')

def get_mac(report, ip):
    for if_addr in report['net_if_addrs'].values():
        internet_interface = False
        for snicaddr in if_addr:
            if snicaddr[0] in (AddressFamily.AF_INET, AddressFamily.AF_INET6) and snicaddr[1] == ip:
                internet_interface = True
        if internet_interface:
            for snicaddr in if_addr:
                if snicaddr[0] == 17 or snicaddr[0] == -1 and 17 == len(snicaddr[1]):  # psutil.AF_LINK is 17 on Linux, and it is -1 on Windows
                    return snicaddr[1]
    return None

def has_access(user):
    return not user.is_anonymous and hasattr(user, 'employee') and user.employee.can_access

def check_access(func):
    @functools.wraps(func)
    def _decorator(request, *args, **kwargs):
        if request.user.is_anonymous:
            return redirect(reverse('serverlist:loginrequired'))
        elif has_access(request.user):
            if not request.user.employee.staff_number:
                request.user.employee.staff_number = 1 + (Employee.objects.all().aggregate(Max('staff_number'))['staff_number__max'] or 0)
                request.user.employee.save()
            return func(request, *args, **kwargs)
        else:
            if not hasattr(request.user, 'employee'):
                Employee.objects.create(user=request.user)
            return redirect(reverse('serverlist:profile'))
    return _decorator

def index(request):
    if request.user.is_anonymous:
        return render(request, 'serverlist/loginrequired.html')
    elif not has_access(request.user):
        return redirect(reverse('serverlist:profile'))

    client_reports = ClientReport.objects.values('client_id').annotate(id=models.Max('id'))
    clients_no_report = Client.objects.exclude(id__in=[c['client_id'] for c in client_reports]).order_by('client_id')
    client_reports = ClientReport.objects.filter(id__in=[c['id'] for c in client_reports]).select_related('client').order_by('client__client_id')
    now = time.time()
    table = []
    for client_report in client_reports:
        client = client_report.client
        report = json.loads(client_report.report)
        status = 'ok'
        if client_report.version != '0.1.1':
            status = '监测脚本不匹配'
        tr = []
        tr.append(client.display_name or client.client_id)
        tr.append(report['platform'])
        ips = [client_report.ip]
        if settings.ROUTE53_DOMAIN_NAME:
            ips.append(client.client_id.lower() + '.' + settings.ROUTE53_DOMAIN_NAME)
        mac = get_mac(report, client_report.ip)
        if mac:
            ips.append(mac)
        tr.append(ips)
        if status == 'ok':
            tr.append([
                    '{:d} 核 (使用率 {:.0f}%)'.format(report['cpu_count'], report['cpu_percent']),
                    '最高主频 {:.1f}GHz'.format(report['cpu_freq'][2] / 1000),
                ])
            tr.append('N/A' if report['loadavg'] is None else '{:.1f}'.format(report['loadavg'][0]))
            tr.append('{:.1f}G ({:.0f}%)'.format(report['virtual_memory'][0] / 1024 ** 3, report['virtual_memory'][2]))
            disks = list(zip(report['disk_partitions'], report['disk_usage']))
            disks.sort(key=lambda a: (a[0][0], -a[1][0]))
            disks = [usage for i, (partition, usage) in enumerate(disks) if partition[0] not in set(p[0] for p, _ in disks[:i])]
            tr.append(['{:.0f}G ({:.0f}%)'.format(disk[0] / 1024**3, disk[3]) for disk in disks if disk[0] / 1024**3 > 9])
            if report['nvml_version']:
                tr.append([dev['nvmlDeviceGetName'] for dev in report['nvmlDevices']])
                tr.append(['{:.1f}G ({:.0f}%)'.format(
                        dev['nvmlDeviceGetMemoryInfo']['total'] / 1024**3,
                        dev['nvmlDeviceGetMemoryInfo']['used'] / dev['nvmlDeviceGetMemoryInfo']['total'] * 100,
                    ) for dev in report['nvmlDevices']])
                tr.append(['{:s}% ({:.0f}W/{:.0f}W) {:d}℃/{:d}℃'.format(
                        '-' if dev['nvmlDeviceGetUtilizationRates']['gpu'] is None else '{:d}'.format(dev['nvmlDeviceGetUtilizationRates']['gpu']),
                        dev['nvmlDeviceGetPowerUsage'] / 1000,
                        dev['nvmlDeviceGetPowerManagementLimit'] / 1000,
                        dev['nvmlDeviceGetTemperature'],
                        dev['nvmlDeviceGetTemperatureThreshold']['slowdown'],
                    ) for dev in report['nvmlDevices']])
            else:
                tr.append('NVML failed')
                tr.append('N/A')
                tr.append('N/A')
            users = [user[0] for user in report['users']]
            users = sorted(list(set(users)))
            if len(users) > 3:
                users = users[:2] + ['...']
            tr.append(users)
            tr.append('{:.0f} 天'.format((now - report['boot_time']) / 86400, 0))
            tr.append('{:d} 分钟前'.format(math.ceil((now - client_report.created_at.timestamp()) / 60)))
        else:
            tr += [''] * 9
            tr.append(status)
        tr.append(client.manager)
        tr.append(client.info)
        table.append({'client': client, 'tr': tr})
    for client in clients_no_report:
        tr = []
        tr.append(client.client_id)
        tr.append('N/A')
        tr.append('N/A')
        tr += [''] * 9
        tr += ['未配置']
        tr.append(client.manager)
        tr.append(client.info)
        table.append({'client': client, 'tr': tr})
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:index')
    return render(request, 'serverlist/index.html', {'table': table})

@check_access
def client(request, pk):
    client = get_object_or_404(Client.objects, pk=pk)
    client_reports = ClientReport.objects.filter(client=client).order_by('-id')
    paginator = Paginator(client_reports, 100)
    client_reports = paginator.get_page(request.GET.get('page'))
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:client', param=pk)
    return render(request, 'serverlist/client.html', {'client': client, 'client_reports': client_reports})

@check_access
def clientchart(request, pk):
    client = get_object_or_404(Client.objects, pk=pk)
    client_reports = ClientReport.objects.filter(client=client).filter(created_at__gt=timezone.now() - timedelta(days=7)).order_by('-created_at')
    data = []
    for report in client_reports:
        day = (report.created_at.timestamp() - timezone.now().timestamp()) / 86400.
        report = json.loads(report.report)
        data.append({
            'day': day,
            'cpu': report['cpu_percent'],
            'virtual_memory': report['virtual_memory'][2],
            'gpu': [{
                'name': dev['nvmlDeviceGetName'],
                'util': dev['nvmlDeviceGetUtilizationRates']['gpu'],
                'memory': dev['nvmlDeviceGetMemoryInfo']['used'] / dev['nvmlDeviceGetMemoryInfo']['total'] * 100,
                'temperature': dev.get('nvmlDeviceGetTemperature', None),
            } for dev in report.get('nvmlDevices', [])],
        })
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:clientchart', param=pk)
    return render(request, 'serverlist/clientchart.html', {'client': client, 'data': base64.b64encode(json.dumps(data, ensure_ascii=True).encode()).decode()})

@check_access
def clientreport(request, client_id, report_id):
    client_report = get_object_or_404(ClientReport.objects.select_related('client'), id=report_id, client_id=client_id)
    report = json.loads(client_report.report)
    mac = get_mac(report, client_report.ip)
    report_str = pprint.pformat(report, width=160)
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:clientreport', param=report_id)
    return render(request, 'serverlist/clientreport.html', {'client_report': client_report, 'mac': mac, 'report_str': report_str})

@csrf_exempt
def recvreport(request):
    client_id = request.POST.get('client_id')
    client_secret = request.POST.get('client_secret')
    report = request.POST.get('report')
    try:
        report = json.loads(report)
        version = report.get('version')
        assert isinstance(version, type(u''))
    except:
        return HttpResponseBadRequest()
    ip = get_ip(request)
    client = Client.objects.filter(client_id=client_id, client_secret=client_secret).first()
    if client is None:
        unknown_report = UnknownReport(client_id=client_id, client_secret=client_secret, ip=ip, version=version)
        unknown_report.save()
        raise Http404
    else:
        client_report = ClientReport.objects.create(client=client, ip=ip, version=version, report=json.dumps(report, sort_keys=True))
        if settings.ROUTE53_DOMAIN_NAME:
            def dns_upsert():
                try:
                    client = boto3.Session(
                        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=settings.AWS_ACCESS_KEY_SECRET,
                    ).client('route53')
                    client.change_resource_record_sets(
                        HostedZoneId=settings.ROUTE53_HOSTED_ZONE_ID,
                        ChangeBatch={
                            'Comment': '',
                            'Changes': [
                                {
                                    'Action': 'UPSERT',
                                    'ResourceRecordSet': {
                                        'Name': client_id.lower() + '.' + settings.ROUTE53_DOMAIN_NAME,
                                        'Type': 'A',
                                        'TTL': 120,
                                        'ResourceRecords': [{'Value': ip},],
                                    }
                                },
                            ],
                        },
                    )
                    client_report.dns_success = True
                    client_report.save()
                except:
                    client_report.dns_success = False
                    client_report.save()
            threading.Thread(target=dns_upsert, daemon=True).start()
    return JsonResponse({'error': 0, 'msg': 'ok'}, json_dumps_params={'sort_keys': True})

def profile(request):
    if request.user.is_anonymous:
        return redirect(reverse('serverlist:loginrequired'))
    password_set = hasattr(request.user, 'employee') and 0 < len(request.user.employee.shadow_password) and 0 < len(request.user.employee.nt_password_hash)
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:profile')
    return render(request, 'serverlist/profile.html', {'password_set': password_set, 'GITHUB_CLIENT_ID': settings.GITHUB_CLIENT_ID})

@check_access
def vpn(request):
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:vpn')
    return render(request, 'serverlist/vpn.html')

@check_access
def pptp(request):
    passwords = dict(
        L2TP_PRESHAREDKEY=settings.L2TP_PRESHAREDKEY,
    )
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:pptp')
    return render(request, 'serverlist/pptp.html', passwords)

@check_access
def ftp(request):
    def isadmin(path, isdir):
        my = request.user.ftpperm_set.filter(permission='admin')
        if my.filter(path=path, isdir=isdir).exists():
            return True
        elif my.filter(isdir=True, path='').exists():
            return True
        elif my.filter(isdir=True).extra(where=['%s LIKE {table}.{column}||%s'.format(table=FtpPerm._meta.db_table, column=FtpPerm._meta.get_field('path').column)], params=(path, '/%')).exists():
            return True
        else:
            return False

    if request.method == 'POST':
        bad = True
        form = FtpForm(request.POST)
        if form.is_valid():
            action = form.cleaned_data.get('action')
            if action == 'post':
                path = form.cleaned_data.get('path')
                isdir = form.cleaned_data.get('isdir')
                if isdir is not None:
                    path = path.replace('\\', '/').strip('/')
                    if path == '':
                        messages.warning(request, '不允许自助申请根目录权限')
                    elif not FtpPerm.issimplepath(path):
                        messages.warning(request, '路径不合法，可能是因为有特殊字符或“..”')
                    elif FtpPerm.objects.filter(user=request.user, path=path).exists():
                        messages.warning(request, '该路径已存在，请勿重复添加：{path}'.format(path=path))
                    else:
                        ftpperm = FtpPerm.objects.create(user=request.user, path=path, isdir=isdir, permission='none')
                        AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:ftp', param='post', info=json.dumps({'id': ftpperm.id, 'path': path, 'isdir': isdir}, sort_keys=True))
                    bad = False
            if action == 'post-admin':
                username = form.cleaned_data.get('username')
                path = form.cleaned_data.get('path')
                isdir = form.cleaned_data.get('isdir')
                permission = form.cleaned_data.get('permission')
                if isdir is not None and FtpPerm.permission_in_choices(permission):
                    path = path.replace('\\', '/').strip('/')
                    user = User.objects.filter(username=username).first()
                    if not user:
                        messages.warning(request, '用户名不存在')
                    elif path == '':
                        messages.warning(request, '不允许自助添加根目录权限')
                    elif not FtpPerm.issimplepath(path):
                        messages.warning(request, '路径不合法，可能是因为有特殊字符或“..”')
                    elif not isadmin(path, isdir):
                        messages.warning(request, '没有此目录权限')
                    elif FtpPerm.objects.filter(user=user, path=path).exists():
                        messages.warning(request, '该路径已存在，请勿重复添加：{path}'.format(path=path))
                    else:
                        ftpperm = FtpPerm.objects.create(user=user, path=path, isdir=isdir, permission=permission)
                        AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:ftp', param='post-admin',
                                info=json.dumps({'id': ftpperm.id, 'username': username, 'path': path, 'isdir': isdir, 'permission': permission}, sort_keys=True))
                    bad = False
            elif action == 'put':
                id = form.cleaned_data.get('id')
                permission = form.cleaned_data.get('permission')
                ftpperm = get_object_or_404(FtpPerm.objects, id=id)
                if isadmin(ftpperm.path, ftpperm.isdir):
                    ftpperm.permission = permission
                    ftpperm.save()
                    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:ftp', param='put', info=json.dumps({'id': id, 'permission': permission}, sort_keys=True))
                    bad = False
            elif action == 'delete':
                id = form.cleaned_data.get('id')
                ftpperm = get_object_or_404(FtpPerm.objects, id=id)
                if ftpperm.user == request.user or isadmin(ftpperm.path, ftpperm.isdir):
                    ftpperm.delete()
                    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:ftp', param='delete', info=json.dumps({'id': id}, sort_keys=True))
                    bad = False
        if bad:
            return HttpResponseBadRequest('bad form')
        else:
            return redirect(reverse('serverlist:ftp'))

    myperms = FtpPerm.objects.filter(user=request.user).order_by('path')
    managedperms = FtpPerm.objects.raw(
        'SELECT MIN(fp1.{pk}) AS id, fp1.{user_id} AS user_id, fp1.{path} AS path, MIN(fp1.{isdir}) AS isdir, MIN(fp1.{permission}) AS permission, MIN(user.{username}) AS username, MIN(user.{email}) AS email FROM {fptb} AS fp1 '
        'INNER JOIN {fptb} AS fp2 '
        'ON (fp1.{isdir}=fp2.{isdir} AND fp1.{path}=fp2.{path}) OR (fp2.{isdir}=1 AND (fp1.{path} LIKE CONCAT(fp2.{path}, "/%%") OR fp2.{path}="")) '
        'LEFT OUTER JOIN {user} AS user '
        'ON fp1.{user_id}=user.{id} '
        'WHERE fp2.{user_id}={request_user_id} AND fp2.{permission}="admin" '
        'GROUP BY fp1.{user_id}, fp1.{path} '
        'ORDER BY fp1.{path}, user.{username}'.format(
            fptb=FtpPerm._meta.db_table,
            pk=FtpPerm._meta.pk.column,
            user_id=FtpPerm._meta.get_field('user_id').column,
            path=FtpPerm._meta.get_field('path').column,
            isdir=FtpPerm._meta.get_field('isdir').column,
            permission=FtpPerm._meta.get_field('permission').column,
            user=User._meta.db_table,
            id=User._meta.get_field('id').column,
            username=User._meta.get_field('username').column,
            email=User._meta.get_field('email').column,
            request_user_id=request.user.id,
        )
    )
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:ftp')
    return render(request, 'serverlist/ftp.html', {'myperms': myperms, 'managedperms': list(managedperms), 'form': FtpForm()})

@check_access
def nas(request):
    uid = '{:d}'.format(request.user.employee.staff_number + 10000)
    home = '/nas/raid/{:s}'.format(uid)
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:nas')
    return render(request, 'serverlist/nas.html', {'uid': uid, 'home': home})

@check_access
def download(request):
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:download')
    return render(request, 'serverlist/download.html')

def loginpassword(request):
    form = LoginForm()
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = User.objects.filter(username=username).first()
            if user:
                if user.check_password(password):
                    AccessLog.objects.create(user=user, ip=get_ip(request), target='serverlist:loginpassword')
                    auth.login(request, user)
                    if request.GET.get('next') is not None:
                        return redirect(request.GET.get('next'))
                    else:
                        return redirect(reverse('serverlist:index'))
                else:
                    form.add_error('password', 'incorrect password')
            else:
                form.add_error('username', 'no such user')
    return render(request, 'serverlist/loginpassword.html', {'form': form})

def logingithuboauth(request):
    return redirect('https://github.com/login/oauth/authorize?client_id={:s}'.format(settings.GITHUB_CLIENT_ID))

def githubcallback(request):
    code = request.GET.get('code')
    if not code:
        return HttpResponseBadRequest('no verification code')
    try:
        res = requests.post(
            'https://github.com/login/oauth/access_token',
            data=urllib.parse.urlencode({
                'client_id': settings.GITHUB_CLIENT_ID,
                'client_secret': settings.GITHUB_CLIENT_SECRET,
                'code': code,
            }).encode(),
            headers={'Accept': 'application/json'},
        )
        res.raise_for_status()
    except requests.exceptions.RequestException:
        return HttpResponseBadRequest('failed to call GitHub API')
    res = res.json()
    if not res.get('access_token'):
        return HttpResponseBadRequest('bad verification code')
    access_token = res['access_token']
    try:
        guser = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': 'token {:s}'.format(access_token)}
        )
        guser.raise_for_status()
    except requests.exceptions.RequestException:
        return HttpResponseBadRequest('failed to call GitHub API')
    guser = guser.json()
    github_user = GithubUser.objects.filter(github_id=guser['id']).first()
    with transaction.atomic():
        if github_user is None:
            try:
                user = User.objects.create(username=guser['login'], email=guser['email'] or '')
            except:
                user = User.objects.create(username=uuid.uuid4(), email=guser['email'] or '')
            github_user = GithubUser.objects.create(user=user, github_id=guser['id'], github_login=guser['login'], github_email=guser['email'] or '')
        else:
            user = github_user.user
            github_user.github_login = guser['login']
            github_user.github_email = guser['email'] or ''
            github_user.save()
    if not hasattr(user, 'employee') or not user.employee.can_access:
        try:
            access_by_org = requests.get(
                'https://api.github.com/orgs/thucg/members/{:s}'.format(guser['login']),
                headers={'Authorization': 'token {:s}'.format(settings.GITHUB_PERSONAL_ACCESS_TOKEN)}
            )
        except requests.exceptions.RequestException:
            return HttpResponseBadRequest('failed to call GitHub API')
        access_by_org = access_by_org.status_code == 204
        if access_by_org:
            employee, created = Employee.objects.get_or_create(user=user)
            employee.can_access = True
            employee.save()
    AccessLog.objects.create(user=user, ip=get_ip(request), target='serverlist:githubcallback')
    auth.login(request, user)
    return redirect(reverse('serverlist:index'))

@csrf_exempt
def vpnauth(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    client_secret = request.POST.get('client_secret')
    ip = request.POST.get('untrusted_ip', '')
    if client_secret != settings.VPN_CLIENT_SECRET:
        return HttpResponseBadRequest('vpn client secret error')
    def try_client():
        client = Client.objects.filter(client_id=username).first()
        if not client:
            return {'error': 1, 'msg': 'no such client'}, None, None
        if password != client.client_secret:
            return {'error': 1, 'msg': 'client secret error'}, None, None
        report = client.clientreport_set.order_by('-id').first()
        if not report or report.ip != ip:
            return {'error': 2, 'msg': 'client ip error'}, client, 'error'
        return {'error': 0, 'msg': 'ok'}, client, 'success'
    def try_user():
        user = User.objects.filter(username=username).first()
        if not user:
            return {'error': 1, 'msg': 'no such user'}, None, None
        if not user.check_password(password):
            return {'error': 2, 'msg': 'password error'}, None, None
        if not has_access(user):
            return {'error': 3, 'msg': 'no access'}, user, 'error'
        return {'error': 0, 'msg': 'ok'}, user, 'success'
    res, client, param = try_client()
    if client:
        AccessLog.objects.create(client=client, ip=ip, target='serverlist:vpnauth', param=param)
    if res['error']:
        res, user, param = try_user()
        if user:
            AccessLog.objects.create(user=user, ip=ip, target='serverlist:vpnauth', param=param)
        return JsonResponse(res, json_dumps_params={'sort_keys': True})
    else:
        return JsonResponse(res, json_dumps_params={'sort_keys': True})

@csrf_exempt
def ftpauth(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    client_secret = request.POST.get('client_secret')
    ip = request.POST.get('peerip', '')
    if client_secret != settings.FTP_CLIENT_SECRET:
        return HttpResponseBadRequest('ftp client secret error')
    user = User.objects.filter(username=username).first()
    if not user:
        res = {'error': 1, 'msg': 'no such user'}
    elif not user.check_password(password):
        res = {'error': 2, 'msg': 'password error'}
        AccessLog.objects.create(user=user, ip=ip, target='serverlist:ftpauth', param='passworderror')
    elif not has_access(user):
        res = {'error': 3, 'msg': 'no access'}
        AccessLog.objects.create(user=user, ip=ip, target='serverlist:ftpauth', param='noaccess')
    else:
        perms = {}
        for perm in user.ftpperm_set.exclude(permission='none'):
            perms[perm.path] = ['w' if perm.permission in ('write', 'admin') else 'r', perm.isdir]
        res = {'error': 0, 'msg': 'ok', 'perms': perms}
        AccessLog.objects.create(user=user, ip=ip, target='serverlist:ftpauth', param='success')
    return JsonResponse(res, json_dumps_params={'sort_keys': True})

@csrf_exempt
def ftpinsecurecheck(request):
    username = request.POST.get('username')
    client_secret = request.POST.get('client_secret')
    ip = request.POST.get('peerip', '')
    if client_secret != settings.FTP_CLIENT_SECRET:
        return HttpResponseBadRequest('ftp client secret error')
    user = User.objects.filter(username=username).first()
    if not user:
        res = {'error': 1, 'msg': 'no such user'}
    elif not has_access(user):
        res = {'error': 3, 'msg': 'no access'}
        AccessLog.objects.create(user=user, ip=ip, target='serverlist:ftpinsecurecheck', param='noaccess')
    elif not user.employee.ftp_insecure:
        res = {'error': 4, 'msg': 'ftp protocol prohibited'}
        AccessLog.objects.create(user=user, ip=ip, target='serverlist:ftpinsecurecheck', param='prohibited')
    else:
        res = {'error': 0, 'msg': 'ftp protocol allowed'}
        AccessLog.objects.create(user=user, ip=ip, target='serverlist:ftpinsecurecheck', param='allowed')
    return JsonResponse(res, json_dumps_params={'sort_keys': True})

@csrf_exempt
def cgnas_api(request):
    api_secret = request.POST.get('api_secret')
    if api_secret != settings.CGNAS_API_SECRET:
        return HttpResponseBadRequest('client secret error')

    def latest_password_update():
        recent_one = Employee.objects.filter(staff_number__isnull=False).order_by('-password_updated_at').first()
        if recent_one is None:
            return -1
        else:
            return recent_one.password_updated_at.timestamp()

    # wait for password updated
    start = time.time()
    while time.time() - start < 30:
        if abs(latest_password_update() - float(request.POST.get('latest_password_update'))) > .01:
            break
        time.sleep(1)

    staffs = Employee.objects.filter(staff_number__isnull=False).order_by('staff_number')
    data = {
        'users': [
            {
                'staff_number': staff.staff_number,
                'username': staff.user.username,
                'shadow_password': staff.shadow_password,
                'nt_password_hash': staff.nt_password_hash,
                'password_updated_at': staff.password_updated_at.timestamp(),
            } for staff in staffs
        ],
        'from_ip': get_ip(request),
    }
    return JsonResponse(data, json_dumps_params={'sort_keys': True})

@csrf_exempt
def radius_api(request):
    username = request.POST.get('username')
    nas_ip = request.POST.get('nas_ip', '')
    nas_type = request.POST.get('nas_type', '')
    ip = request.POST.get('ip', '')
    account_status_type = request.POST.get('account_status_type', '')
    key = request.POST.get('key')
    api_secret = request.POST.get('api_secret')
    if api_secret != settings.RADIUS_API_SECRET:
        return HttpResponseBadRequest('client secret error')
    if key not in ('NT-Password', 'Accounting-Request', ):
        return HttpResponseBadRequest('key does not exist')
    user = User.objects.filter(username=username).first()
    if not user:
        res = {'error': 1, 'msg': 'no such user'}
    elif key == 'Accounting-Request':
        res = {'error': 0}
        AccessLog.objects.create(user=user, ip=ip, target='serverlist:radius_api', param='{:s}-{:s}'.format(nas_type, account_status_type))
    elif not has_access(user):
        res = {'error': 3, 'msg': 'no access'}
        AccessLog.objects.create(user=user, ip=nas_ip, target='serverlist:radius_api', param='noaccess')
    elif not user.employee.nt_password_hash:
        res = {'error': 4, 'msg': 'password not set'}
        AccessLog.objects.create(user=user, ip=nas_ip, target='serverlist:radius_api', param='passwordnotset')
    else:
        res = {'error': 0, 'nt_password_hash': user.employee.nt_password_hash}
        AccessLog.objects.create(user=user, ip=nas_ip, target='serverlist:radius_api', param='checkpassword')
    return JsonResponse(res, json_dumps_params={'sort_keys': True})

@check_access
def resetpassword(request):
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            has_error = True
            username_validator = auth.validators.ASCIIUsernameValidator()
            password_validators = [
                auth.password_validation.UserAttributeSimilarityValidator(),
                auth.password_validation.MinimumLengthValidator(),
                auth.password_validation.CommonPasswordValidator(),
                auth.password_validation.NumericPasswordValidator(),
            ]
            try:
                username_validator(username)
            except ValidationError as e:
                for msg in e:
                    form.add_error('username', msg)
            else:
                with transaction.atomic():
                    exists = User.objects.filter(username=username).exclude(id=request.user.id).select_for_update().exists()
                    if len(username) < 2 and request.user.username != username:
                        form.add_error('username', 'username too short')
                    elif len(username) > 40 and request.user.username != username:
                        form.add_error('username', 'username too long')
                    elif exists:
                        form.add_error('username', 'username taken')
                    else:
                        request.user.username = username
                        try:
                            auth.password_validation.validate_password(password, request.user, password_validators=password_validators)
                        except ValidationError as e:
                            for msg in e:
                                form.add_error('password', msg)
                        else:
                            request.user.set_password(password)
                            request.user.employee.shadow_password = crypt.crypt(password, crypt.mksalt())
                            request.user.employee.nt_password_hash = md4.MD4(password.encode('utf-16-le')).hexdigest().upper()
                            request.user.employee.password_updated_at = timezone.now()
                            request.user.employee.save()
                            request.user.save()
                            if request.user.username == username:
                                changed = 'password'
                            else:
                                changed = 'both'
                            AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:resetpassword', param=changed)
                            has_error = False
            auth.login(request, request.user)
            if has_error:
                return render(request, 'serverlist/resetpassword.html', {'form': form})
            else:
                return render(request, 'serverlist/resetpassword_finish.html')
        return HttpResponseBadRequest('bad form')
    else:
        form = ResetPasswordForm(initial={'username': request.user.username})
        return render(request, 'serverlist/resetpassword.html', {'form': form, 'error': []})

def logout(request):
    if request.method != 'POST':
        return HttpResponseBadRequest('malformed request')
    user = request.user
    auth.logout(request)
    if not user.is_anonymous:
        AccessLog.objects.create(user=user, ip=get_ip(request), target='serverlist:logout')
    return redirect(reverse('serverlist:index'))
