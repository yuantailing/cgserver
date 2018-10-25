# cgserver
cscg server list

## Usage

### Server-side

```shell
pip3 install -r requirements.txt
cp cgserver/settings.py.sample cgserver/settings.py
cp serverlist/scripts/add_clients.py.sample serverlist/scripts/add_clients.py
```

Then

```shell
python3 manage.py migrate
python3 manage.py runscript add_clients
python3 manage.py runserver
```

### Client-side

```shell
pip3 install -r requirements.txt
cp settings.py.sample settings.py
```

Update crontab, for example:

> 0,15,30,45 * * * * python3 some-path/client-side/report.py

## Todo
