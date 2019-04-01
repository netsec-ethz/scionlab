import argparse
import requests

parser = argparse.ArgumentParser()
parser.add_argument('prev_ia', default=1305, type=int, help='Largest AS ID in the ISD')
parser.add_argument('count', default=1, type=int, help='Number of new core ASes to create')
args = parser.parse_args()

coord_ip = "172.31.0.10"
client = requests.session()
client.get("http://"+coord_ip+":8000/user/login/")
csrftoken = client.cookies['csrftoken']

# Fixture test admin user
login_data = dict(username="admin", password="admin", csrfmiddlewaretoken=csrftoken)

r = client.post("http://"+coord_ip+":8000/user/login/",
                data=login_data,
                headers=dict(Referer="http://"+coord_ip+":8000/user/login/"))

for n in range(args.count):
    as_id = args.prev_ia + n + 1
    r = client.get("http://"+coord_ip+":8000/admin/scionlab/as/add/")
    csrftoken = client.cookies['csrftoken']
    as_create_data = dict(isd="4",
                          as_id="ffaa:0:%s" % as_id,
                          label="New Core %s" % as_id,
                          mtu=1472,
                          is_core="on",
                          owner=2,
                          internal_ip="127.0.0.1",
                          public_ip="127.0.0.1",
                          _save="Save",
                          csrfmiddlewaretoken=csrftoken)
    r = client.post("http://"+coord_ip+":8000/admin/scionlab/as/add/",
                    data=as_create_data,
                    headers=dict(Referer="http://"+coord_ip+":8000/admin/scionlab/as/add/"))

    print(r.url)
    print(r.text)
