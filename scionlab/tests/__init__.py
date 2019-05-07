import os
import shutil


def setup_package():
    cwd = os.path.dirname(os.path.abspath(__file__))
    dev_cert = "dev_root_ca_cert.pem"
    dev_key = "dev_root_ca_key.pem"
    shutil.copyfile(os.path.join(cwd, "../fixtures/", dev_cert),
                    os.path.join(cwd, "../../run/", dev_cert))
    shutil.copyfile(os.path.join(cwd, "../fixtures/", dev_key),
                    os.path.join(cwd, "../../run/", dev_key))
