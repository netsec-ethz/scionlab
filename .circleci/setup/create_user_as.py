import requests
import shutil

coord_ip = "172.31.0.10"
client = requests.session()
client.get("http://"+coord_ip+":8000/user/login/")
csrftoken = client.cookies['csrftoken']

# Fixture test user
login_data = dict(username="scion@scionlab.org", password="scion", csrfmiddlewaretoken=csrftoken)

r = client.post("http://"+coord_ip+":8000/user/login/",
                data=login_data,
                headers=dict(Referer="http://"+coord_ip+":8000/user/login/"))

r = client.get("http://"+coord_ip+":8000/user/as/add")
csrftoken = client.cookies['csrftoken']
as_create_data = dict(attachment_point="4",
                      label="UserAS1",
                      installation_type="DEDICATED",
                      use_vpn="on",
                      public_port="50000",
                      csrfmiddlewaretoken=csrftoken)
r = client.post("http://"+coord_ip+":8000/user/as/add",
                data=as_create_data,
                headers=dict(Referer="http://"+coord_ip+":8000/user/as/add"))

print(r.url)

r = client.get(r.url+"/config", stream=True)
with open("/tmp/host_config.tar", 'wb') as f:
    shutil.copyfileobj(r.raw, f)
