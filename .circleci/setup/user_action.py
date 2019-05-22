import argparse
import json
import requests
import shutil

parser = argparse.ArgumentParser()
parser.add_argument('--url', default="", type=str, help='Target url')
parser.add_argument('--data', default="{}", type=str, help='Post data')
parser.add_argument('--action', default="", type=str, help='User action')
args = parser.parse_args()

client = requests.session()
client.get("http://coord:8000/login/")
csrftoken = client.cookies['csrftoken']

# Fixture test user
login_data = dict(username="scion@scionlab.org",
                  password="scion",
                  csrfmiddlewaretoken=csrftoken)

r = client.post("http://coord:8000/login/",
                data=login_data,
                headers=dict(Referer="http://coord:8000/login/"))

r = client.get("http://coord:8000/%s" % args.url)
csrftoken = client.cookies['csrftoken']
as_create_data = json.loads(args.data)
as_create_data['csrfmiddlewaretoken'] = csrftoken
r = client.post("http://coord:8000/%s" % args.url,
                data=as_create_data,
                headers=dict(Referer="http://coord:8000/%s" % args.url))

print(r.url)

if args.action == "add":
    r = client.get(r.url+"/config", stream=True)
    with open("/tmp/host_config.tar", 'wb') as f:
        shutil.copyfileobj(r.raw, f)
