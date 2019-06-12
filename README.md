# cgserver
cscg server list

## Usage

### Server-side

```shell
pip3 install -r requirements.txt
cp cgserver/settings.py.sample cgserver/settings.py
chmod 600 cgserver/settings.py
cp serverlist/scripts/add_clients.py.sample serverlist/scripts/add_clients.py
```

Then

```shell
python3 manage.py migrate
python3 manage.py runscript add_clients
python3 manage.py collectstatic
python3 manage.py runserver
```

You may run `python3 manage.py createsuperuser` to add an administrator.

### Client-side

```shell
pip3 install -r requirements.txt
cp settings.py.sample settings.py
chown 600 settings.py
```

Add *report.py* to crontab, using `crontab -e` is recommended, for example:

```
*/15 *	* * *	cd /path/to/cgserver/client-side && /usr/bin/python3 report.py
```
