# Copyright 2023 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import sys

from typing import List
from django.conf import settings
from django.core.management.base import BaseCommand, CommandParser
from django.core.mail import EmailMessage

from scionlab.models.user import User


class Command(BaseCommand):
    help = 'List or send a message to the unique emails of the users in alphabetical order'

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument('-a', '--action', type=str, required=True,
                            choices=['list', 'send'],
                            help='Action of the command: list or send')
        parser.add_argument('--subject', type=str, required=False,
                            help='Subject of the email to send')
        parser.add_argument('--body', type=argparse.FileType('r'), default='-',
                            help='Input file to read the body of the email from')
        parser.add_argument('--skip_blocks', type=int, default=0,
                            help='skip N initial blocks of recipients. Useful to continue ' +
                            'sending after a crash')

    def handle(self, *args, **kwargs):
        action = kwargs['action']
        if action == 'list':
            self.list()
        elif action == 'send':
            self.send(**kwargs)

    def list(self):
        # print active users emails:
        for email in self._obtain_active_emails():
            print(email)

        # report user stats:
        inactive = []
        active = []
        for u in User.objects.all():
            if not u.is_active:
                inactive.append(u)
            else:
                active.append(u)
        print(f'--------------------------- inactive: {len(inactive)}')
        print(f'--------------------------- active: {len(active)}')

    def send(self, **kwargs):
        # retrieve the email parameters, or complain
        if 'subject' not in kwargs or kwargs['subject'] is None:
            exit('Need a subject')
        subject = kwargs['subject']
        if kwargs['body'] == sys.stdin:
            print('Type the body of the email, end with ^D')
        with kwargs['body'] as f:
            body = f.read()
        skip_blocks = kwargs['skip_blocks']

        self._send(
            subject=subject,
            body=body,
            skip_blocks=skip_blocks,
        )

    def _send(self, subject: str, body: str, skip_blocks: int):
        recipients = self._obtain_active_emails()
        block_count = (len(recipients) - 1) // settings.MAX_EMAIL_RECIPIENTS + 1
        for b in range(skip_blocks, block_count):
            # the recipients are a subset of the total
            dest = recipients[
                b*settings.MAX_EMAIL_RECIPIENTS:
                (b + 1) * settings.MAX_EMAIL_RECIPIENTS]
            # prepare the email and send it
            msg = EmailMessage(
                subject,
                body,
                settings.DEFAULT_FROM_EMAIL,    # From
                [],  # To
                bcc=dest,
            )
            msg.send()
            print(f'sent {b+1}/{block_count} -> {dest}')
        print('done')

    def _obtain_active_emails(self) -> List[str]:
        emails = User.objects.filter(
            is_active=True,
            ).values_list('email', flat=True).order_by('email').distinct()
        return emails


def exit(msg: str):
    print(msg)
    sys.exit(1)
