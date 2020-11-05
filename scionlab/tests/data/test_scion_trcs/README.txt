Data generated following the specs at
https://scion.docs.anapaya.net/en/latest/cryptography/trc-signing-ceremony-phases.html

TRC verified with: scion-pki trcs verify --anchor trc-1.trc trc-1.trc

To recreate:
python manage.py shell -c 'from scionlab.tests.data.test_scion_trcs.regenerate import regenerate; regenerate()'
