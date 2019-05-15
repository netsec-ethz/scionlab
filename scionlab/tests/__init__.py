import os
import shutil

from django.conf import settings


def setup_package():
    app_dir = os.path.join(settings.BASE_DIR, "scionlab")
    dev_cert = "dev_root_ca_cert.pem"
    dev_key = "dev_root_ca_key.pem"
    os.makedirs(os.path.join(settings.BASE_DIR, "run/"), exist_ok=True)
    shutil.copyfile(os.path.join(app_dir, "fixtures/", dev_cert),
                    os.path.join(settings.BASE_DIR, "run/", dev_cert))
    shutil.copyfile(os.path.join(app_dir, "fixtures/", dev_key),
                    os.path.join(settings.BASE_DIR, "run/", dev_key))
