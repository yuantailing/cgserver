import base64
import functools
import json
import math
import os
import pprint
import requests
import time
import uuid

from .forms import ResetPasswordForm
from .models import AccessLog, Client, ClientReport, Employee, GithubUser, UnknownReport
from cgserver import settings
from django.contrib import auth
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.http import Http404, HttpResponseBadRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from six.moves import urllib

# Create your views here.

def get_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    else:
        return request.META.get('REMOTE_ADDR')

def check_access(func):
    @functools.wraps(func)
    def _decorator(request, *args, **kwargs):
        if request.user.is_anonymous:
            return redirect(reverse('serverlist:permissiondenied'))
        if not hasattr(request.user, 'employee'):
            Employee.objects.create(user=request.user)
        if not request.user.employee.can_access:
            return redirect(reverse('serverlist:permissiondenied'))
        return func(request, *args, **kwargs)
    return _decorator

def permissiondenied(request):
    return render(request, 'serverlist/permissiondenied.html', {'GITHUB_CLIENT_ID': settings.GITHUB_CLIENT_ID})

@check_access
def index(request):
    client_reports = ClientReport.objects.values('client_id').annotate(id=models.Max('id'))
    clients_no_report = Client.objects.exclude(id__in=[c['client_id'] for c in client_reports]).order_by('client_id')
    client_reports = ClientReport.objects.filter(id__in=[c['id'] for c in client_reports]).select_related('client').order_by('client__client_id')
    now = time.time()
    table = []
    for client_report in client_reports:
        client = client_report.client
        report = json.loads(client_report.report)
        status = 'ok'
        if client_report.version != '0.1.0':
            status = '监测脚本过旧'
        tr = []
        tr.append(client.display_name or client.client_id)
        tr.append(report['platform'])
        tr.append(client_report.ip)
        if status == 'ok':
            tr.append([
                    '{:d} 核 (使用率 {:.0f}%)'.format(report['cpu_count'], report['cpu_percent'], 0),
                    '最高主频 {:.1f}GHz'.format(report['cpu_freq'][2] / 1000),
                ])
            tr.append('N/A' if report['loadavg'] is None else '{:.1f}'.format(report['loadavg'][0]))
            tr.append('{:.1f}G ({:.0f}%)'.format(report['virtual_memory'][0] / 1024 ** 3, report['virtual_memory'][2], 0))
            tr.append(['{:.0f}G ({:.0f}%)'.format(disk[0] / 1024**3, disk[3]) for disk in report['disk_usage'] if disk[0] / 1024**3 > 9])
            if report['nvml_version']:
                tr.append([dev['nvmlDeviceGetName'] for dev in report['nvmlDevices']])
                tr.append(['{:.1f}G ({:.0f}%)'.format(
                        dev['nvmlDeviceGetMemoryInfo']['total'] / 1024**3,
                        dev['nvmlDeviceGetMemoryInfo']['used'] / dev['nvmlDeviceGetMemoryInfo']['total'] * 100,
                    ) for dev in report['nvmlDevices']])
                tr.append(['{:d}% ({:.0f}W/{:.0f}W)'.format(
                        dev['nvmlDeviceGetUtilizationRates']['gpu'],
                        dev['nvmlDeviceGetPowerUsage'] / 1000,
                        dev['nvmlDeviceGetPowerManagementLimit'] / 1000,
                    ) for dev in report['nvmlDevices']])
            else:
                tr.append('NVML failed')
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
    client_reports = ClientReport.objects.filter(client=client).order_by('-created_at')
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:client', param=pk)
    return render(request, 'serverlist/client.html', {'client': client, 'client_reports': client_reports})

@check_access
def clientreport(request, client_id, report_id):
    client_report = get_object_or_404(ClientReport.objects.select_related('client'), id=report_id, client_id=client_id)
    report_str = pprint.pformat(json.loads(client_report.report), width=160)
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:clientreport', param=report_id)
    return render(request, 'serverlist/clientreport.html', {'client_report': client_report, 'report_str': report_str})

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
        client_report = ClientReport(client=client, ip=ip, version=version, report=json.dumps(report, sort_keys=True))
        client_report.save()
    return JsonResponse({'error': 0, 'msg': 'ok'}, json_dumps_params={'sort_keys': True})

@check_access
def vpn(request):
    AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:vpn')
    return render(request, 'serverlist/vpn.html')

def login(request):
    return redirect('https://github.com/login/oauth/authorize?client_id={:s}'.format(settings.GITHUB_CLIENT_ID))

def githubcallback(request):
    code = request.GET.get('code')
    if not code:
        return HttpResponseBadRequest('no verification code')
    res = requests.post(
        'https://github.com/login/oauth/access_token',
        data=urllib.parse.urlencode({
            'client_id': settings.GITHUB_CLIENT_ID,
            'client_secret': settings.GITHUB_CLIENT_SECRET,
            'code': code,
        }).encode(),
        headers={'Accept': 'application/json'},
    )
    if not res.ok:
        return HttpResponseBadRequest('bad verification code')
    res = res.json()
    if not res.get('access_token'):
        return HttpResponseBadRequest('bad verification code')
    access_token = res['access_token']
    guser = requests.get(
        'https://api.github.com/user',
        headers={'Authorization': 'token {:s}'.format(access_token)}
    )
    guser = guser.json()
    github_user = GithubUser.objects.filter(github_id=guser['id']).first()
    with transaction.atomic():
        if github_user is None:
            try:
                user = User.objects.create(username=guser['login'], email=guser['email'] or '')
            except:
                user = User.objects.create(username=uuid.uuid4(), email=guser['email'] or '')
            github_user = GithubUser.objects.create(user=user, github_id=guser['id'], github_login=guser['login'], github_email=guser['email'])
        else:
            user = github_user.user
            github_user.github_login = guser['login']
            github_user.github_email = guser['email']
            github_user.save()
    members = requests.get(
        'https://api.github.com/orgs/cscg-group/members'.format(login),
        headers={'Authorization': 'token {:s}'.format(settings.GITHUB_PERSONAL_ACCESS_TOKEN)}
    )
    members = members.json()
    access_by_org = github_user.github_id in [o['id'] for o in members]
    if access_by_org:
        employee, created = Employee.objects.get_or_create(user=user)
        employee.can_access = True
        employee.save()
    auth.login(request, user)
    return redirect(reverse('serverlist:index'))

@csrf_exempt
def vpnauth(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    client_secret = request.POST.get('client_secret')
    if client_secret != settings.VPN_CLIENT_SECRET:
        return HttpResponseBadRequest('client secret error')
    user = User.objects.filter(username=username).first()
    if not user:
        return JsonResponse({'error': 1, 'msg': 'no such user'}, json_dumps_params={'sort_keys': True})
    if not user.check_password(password):
        return JsonResponse({'error': 2, 'msg': 'password error'}, json_dumps_params={'sort_keys': True})
    AccessLog.objects.create(user=user, ip=get_ip(request), target='serverlist:vpnauth')
    if not hasattr(user, 'employee') or user.employee.can_access:
        return JsonResponse({'error': 3, 'msg': 'no access'}, json_dumps_params={'sort_keys': True})
    return JsonResponse({'error': 0, 'msg': 'ok'}, json_dumps_params={'sort_keys': True})

@check_access
def resetpassword(request):
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            username_validator = auth.validators.ASCIIUsernameValidator()
            password_validators = [
                auth.password_validation.MinimumLengthValidator(),
                auth.password_validation.UserAttributeSimilarityValidator(),
                auth.password_validation.CommonPasswordValidator(),
                auth.password_validation.NumericPasswordValidator(),
            ]
            try:
                username_validator(username)
            except ValidationError as e:
                error = e
            else:
                with transaction.atomic():
                    exists = User.objects.filter(username=username).exclude(id=request.user.id).select_for_update().exists()
                    if len(username) < 4:
                        error = ['username too short']
                    elif len(username) > 40:
                        error = ['username too long']
                    elif exists:
                        error = ['username taken']
                    else:
                        error = []
                        if request.user.username == username:
                            changed = 'password'
                        else:
                            changed = 'both'
                        request.user.username = username
                        try:
                            auth.password_validation.validate_password(password, request.user, password_validators=password_validators)
                        except ValidationError as e:
                            error = e
                        else:
                            request.user.set_password(password)
                            request.user.employee.save()
                            request.user.save()
                        AccessLog.objects.create(user=request.user, ip=get_ip(request), target='serverlist:resetpassword', param=changed)
            auth.login(request, request.user)
            if error:
                return render(request, 'serverlist/resetpassword.html', {'form': form, 'error': error})
            else:
                return render(request, 'serverlist/resetpassword_finish.html')
        return HttpResponseBadRequest('bad form')
    else:
        form = ResetPasswordForm(initial={'username': request.user.username})
        return render(request, 'serverlist/resetpassword.html', {'form': form, 'error': []})

def logout(request):
    auth.logout(request)
    return redirect(reverse('serverlist:permissiondenied'))
