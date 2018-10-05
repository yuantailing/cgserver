import clienttask
import settings
import json

from six.moves import urllib

if __name__ == '__main__':
    url = 'https://cgserver.tsing.net/serverlist/clientreport'
    report = clienttask.alltasks()
    data = dict(
        client_id=settings.CLIENT_ID,
        client_secret=settings.CLIENT_SECRET,
        report=json.dumps(report),
    )
    request = urllib.request.urlopen(url, urllib.parse.urlencode(data).encode('utf-8'))
    assert 200 == request.code
    content = request.read().decode('utf-8')
    content = json.loads(content)
    print(content)

