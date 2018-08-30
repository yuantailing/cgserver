import base64
import functools
import time
import json
import os
import math

from .models import Client, ClientReport, UnknownReport
from django.contrib.auth import authenticate, login
from django.core.exceptions import SuspiciousOperation
from django.db import models
from django.http import FileResponse, Http404, HttpResponse, JsonResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from cgserver import settings

# Create your views here.

def basic_auth_required(func):
    @functools.wraps(func)
    def _decorator(request, *args, **kwargs):
        if 'HTTP_AUTHORIZATION' in request.META:
            authmeth, auth = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
            if authmeth.lower() == 'basic':
                auth = base64.b64decode(auth.strip()).decode('latin1')
                username, password = auth.split(':', 1)
                if username == settings.HTTP_AUTHORIZATION_USERNAME and password == settings.HTTP_AUTHORIZATION_PASSWORD:
                    return func(request, *args, **kwargs)
        res = HttpResponse()
        res.status_code = 401
        res['WWW-Authenticate'] = 'Basic'
        return res
    return _decorator

@basic_auth_required
def index(request):
    client_reports = ClientReport.objects.values('client_id').annotate(id=models.Max('id'))
    clients_no_report = Client.objects.exclude(id__in=[c['client_id'] for c in client_reports]).all()
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
            tr.append('{:d} ({:.0f}%)'.format(report['cpu_count'], report['cpu_percent'], 0))
            tr.append('N/A' if report['loadavg'] is None else '{:.1f}'.format(report['loadavg'][0]))
            tr.append('{:.1f}G ({:.0f}%)'.format(report['virtual_memory'][0] / 1024 ** 3, report['virtual_memory'][2], 0))
            tr.append(['{:.0f}G ({:.0f}%)'.format(disk[0] / 1024**3, disk[3]) for disk in report['disk_usage']])
            if report['nvml_version']:
                tr.append([dev['nvmlDeviceGetName'] for dev in report['nvmlDevices']])
                tr.append(['{:.1f}G ({:.0f}%)'.format(
                    dev['nvmlDeviceGetMemoryInfo']['total'] / 1024**3,
                    dev['nvmlDeviceGetMemoryInfo']['used'] / dev['nvmlDeviceGetMemoryInfo']['total'] * 100) for dev in report['nvmlDevices']])
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
            tr += [''] * 8
            tr.append(status)
        tr.append(client.manager)
        tr.append(client.info)
        table.append(tr)
    for client in clients_no_report:
        tr = []
        tr.append(client.client_id)
        tr.append('N/A')
        tr.append('N/A')
        tr += [''] * 8
        tr += ['未配置']
        tr.append(client.manager)
        tr.append(client.info)
        table.append(tr)
    return render(request, 'serverlist/index.html', {'table': table})

def script(request):
    response = FileResponse(open(os.path.join(settings.BASE_DIR, 'serverlist', 'client-side.sh'), 'rb'))
    response['Content-Type'] = 'application/x-sh'
    response['Content-Disposition'] = 'attachment;filename="script.sh"'
    return response

@csrf_exempt
def clientreport(request):
    client_id = request.POST.get('client_id')
    client_secret = request.POST.get('client_secret')
    report = request.POST.get('report')
    try:
        report = json.loads(report)
        version = report.get('version')
        assert isinstance(version, type(u''))
    except:
        return HttpResponseBadRequest()
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    client = Client.objects.filter(client_id=client_id, client_secret=client_secret).first()
    if client is None:
        unknown_report = UnknownReport(client_id=client_id, client_secret=client_secret, ip=ip, version=version)
        unknown_report.save()
        raise Http404
    else:
        client_report = ClientReport(client=client, ip=ip, version=version, report=json.dumps(report))
        client_report.save()
    return JsonResponse({'error': 0, 'msg': 'ok'}, json_dumps_params={'sort_keys': True})

def vpn(request):
    return render(request, 'serverlist/vpn.html')
