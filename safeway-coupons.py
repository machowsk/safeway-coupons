#!/usr/bin/python3

import argparse
import configparser
import datetime
import email.mime.text
import itertools
import json
import os
import random
import requests
import subprocess
import sys
import time
import traceback
import logging
from logging.handlers import TimedRotatingFileHandler

# Create a logger that logs to a rotating file as well as stdout
root_logger = logging.getLogger()
if not root_logger.handlers:
    log_format = logging.Formatter('%(asctime)s %(levelname)s:  %(message)s')
    root_logger.setLevel(logging.INFO)

    log_dir = os.path.abspath('logs')
    if os.path.exists(log_dir):
        if not os.path.isdir(log_dir):
            raise(Exception("Logging directory {d} exists but as a file.".format(d=log_dir)))
    else:
        os.makedirs(log_dir)

    file_handler = TimedRotatingFileHandler('logs/safeway_coupon.log', when="midnight", interval=1, backupCount=30)
    file_handler.setFormatter(log_format)
    file_handler.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_format)
    root_logger.addHandler(console_handler)


sleep_multiplier = 1.0

referer_data = 'http://www.safeway.com/ShopStores/Justforu-Coupons.page'

user_agent = ('Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0')
js_req_headers = {
    'Content-Type': 'application/json',
    'DNT': '1',
    'Host': 'www.safeway.com',
    'Origin': 'http://www.safeway.com',
    'User-Agent': user_agent,
    'X-Requested-With': 'XMLHttpRequest',
    'X-SWY_API_KEY': 'emjou',
    'X-SWY_BANNER': 'safeway',
    'X-SWY_VERSION': '1.0',
}


class safeway():
    def __init__(self, auth):
        self.auth = auth
        self.mail_message = []
        self.mail_subject = 'Safeway coupons'
        self.session_headers = {}
        self.store_id = 1

        try:
            self._init_session()
            self._login()
            self._clip_coupons()
        except Exception as e:
            self.mail_subject += ' (error)'
            self._mail_append('Exception: {}'.format(str(e)))
            for line in traceback.format_exc().split(os.linesep):
                self._mail_append(line)
            raise
        finally:
            if self.mail_message:
                self._send_mail()

    def _mail_append(self, line):
        self.mail_message.append(line)

    def _mail_append_exception(self, e, description):
        self._mail_append('{}: {}'.format(description, str(e)))
        for line in traceback.format_exc().split(os.linesep):
            self._mail_append(line)

    def _send_mail(self):
        email_to = self.auth.get('notify') or self.auth.get('username')
        email_from = email_sender

        if self.mail_message[0].startswith('Coupon: '):
            self.mail_message.insert(0, 'Clipped coupons for items you buy:')

        account_str = 'Safeway account: {}'.format(self.auth.get('username'))
        self.mail_message.insert(0, account_str)
        mail_message_str = os.linesep.join(self.mail_message)

        if not options.email:
            print(mail_message_str)
            return

        logging.info('Sending email to {}'.format(email_to))
        logging.info('>>>>>>')
        logging.info(mail_message_str)
        logging.info('<<<<<<')

        email_data = email.mime.text.MIMEText(mail_message_str)
        email_data['To'] = email_to
        email_data['From'] = email_from
        if self.mail_subject:
            email_data['Subject'] = self.mail_subject

        if options.debug:
            logging.debug('Skip sending email due to -d/--debug')
            return

        p = subprocess.Popen(['/usr/sbin/sendmail', '-f', email_from, '-t'],
                             stdin=subprocess.PIPE)
        p.communicate(bytes(email_data.as_string(), 'UTF-8'))


    def _init_session(self):
        self.r_s = requests.Session()
        self.r_a = requests.adapters.HTTPAdapter(pool_maxsize=1)
        self.r_s.mount('https://', self.r_a)
        self.r_s.headers.update({'DNT': '1',
                                 'User-Agent':  user_agent})

    def _login(self):
        rsp = self._run_request('https://www.safeway.com')
        rsp.stream = False

        rsp = self._run_request('https://www.safeway.com/ShopStores/'
                                'OSSO-Login.page')
        rsp.stream = False

        logging.info('Logging in as {}'.format(self.auth.get('username')))

        login_data = {
            'source': 'WEB',
            'rememberMe': False,
            'userId': self.auth.get('username'),
            'password': self.auth.get('password')
        }
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json, text/javascript, */*; q=0.01'}
        rsp = self._run_request(('https://www.safeway.com/iaaw/service/' 'authenticate'), json_data=login_data, headers=headers)
        rsp_data = json.loads(rsp.content.decode('UTF-8'))
        if not rsp_data.get('token') or rsp_data.get('errors'):
            raise Exception('Authentication failure')
        try:
            self.store_id = int(rsp_data['userAccount']['storeID'])
        except KeyError as err:
            logging.warning("KeyError when trying to retrieve store_id. Err: {e}".format(e=err))
        self.session_headers.update({
            'X-swyConsumerDirectoryPro': rsp_data['token'],
            'X-swyConsumerlbcookie': rsp_data['lbcookie']
        })
        self.r_s.headers.update(self.session_headers)


    def _run_request(self, url, data=None, json_data=None, headers=None):

        if data or json_data:
            return self.r_s.post(url, headers=headers, data=data, json=json_data)
        return self.r_s.get(url, headers=headers)


    def _save_coupon_details(self, offer, coupon_type):
        title = ' '.join([
            offer.get('offerPrice', ''),
            offer.get('brand', ''),
            offer.get('description', ''),
            offer.get('name', '')
        ])
        try:
            expires = datetime.datetime.fromtimestamp(
                int(offer['endDate']) / 1000).strftime('%Y.%m.%d')
        except Exception:
            expires = 'Unknown'
        self._mail_append('Coupon: {} (expires: {})'
                          .format(title, expires))


    def _clip_coupon(self, oid, coupon_type, post_data):
        headers = js_req_headers
        headers.update(self.session_headers)
        headers.update({
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json;charset=UTF-8',
            'Referer': referer_data,
        })
        url = (
            'https://www.safeway.com'
            '/abs/pub/web/j4u/api/offers/clip?storeId={}'
            .format(self.store_id)
        )
        rsp = self._run_request(url, json_data=post_data, headers=headers)
        rsp.stream = False
        try:
            c = rsp.json()
        except Exception as e:
            logging.log(logging.ERROR, 'Error loading JSON: {}'.format(e))
            raise
        if 'errorCd' in c:
            raise Exception('Coupon clipping error code: {} ("{}")'
                            .format(c['errorCd'], c['errorMsg']))

        logging.debug('Clip response: {}'.format(c))        
        return (rsp.status_code == 200)


    def _clip_coupons(self):
        clip_counts = {}
        clip_count = 0
        error_count = 0

        try:
            logging.info('Retrieving coupons')
            url = ('https://www.safeway.com'
                   '/abs/pub/web/j4u/api/offers/gallery'
                   '?storeId={}&offerPgm=PD-CC&rand={}'
                   .format(
                       self.store_id,
                       random.randint(100000, 999999)
                   ))
            rsp = self._run_request(url, headers=js_req_headers)
            data = rsp.content.decode('UTF-8')
            offers = json.loads(data)
            if 'errors' in offers:
                raise Exception('Error retrieving offers: {}'.format(offers))


            count = 0
            alreadyClippedCount = 0
            for k,v in offers.items():
                count += len(v)

            logging.info("Retrieved {count} coupons.".format(count=count))
            for offer_type in offers.keys():
                for i, offer in enumerate(offers[offer_type]):

                    offerObj = OfferFactory(offer)

                    logging.debug('Offer data for offer ID {}: {}'.format(offer['offerId'], offer))
                    coupon_type = offer['offerPgm']
                    clip_counts.setdefault(coupon_type, 0)
                    # Check if coupon or offer has been clipped already
                    if offer['status'] == 'C':
                        alreadyClippedCount += 1
                        continue
                    post_data = {'items': []}
                    for clip_type in ['C', 'L']:
                        post_data['items'].append(
                            {
                                'clipType': clip_type,
                                'itemId': offer['offerId'],
                                'itemType': coupon_type,
                            }
                        )
                    oid = offer['offerId']
                    clip_success = self._clip_coupon(
                        oid,
                        coupon_type,
                        post_data
                    )
                    if clip_success:

                        logging.info('Clipped coupon for {offer}.'.format(offer=offerObj))
                        clip_counts[coupon_type] += 1
                    else:
                        logging.error('Error clipping coupon {} {}'.format(coupon_type, oid))
                        error_count += 1
                        if error_count >= 5:
                            raise Exception('Reached error count threshold ({:d})'.format(error_count))
                    if (offer['purchaseInd'] == 'B'):
                        self._save_coupon_details(offer, coupon_type)
                    # Simulate longer pauses for "scrolling" and "paging"
                    if i > 0 and i % 12 == 0:
                        if options.sleep_skip < 1:
                            if i % 48 == 0:
                                w = random.uniform(15.0, 25.0)
                            else:
                                w = random.uniform(4.0, 8.0)
                            w *= sleep_multiplier
                            logging.debug('Waiting {} seconds'.format(str(w)))
                            time.sleep(w)
                    else:
                        if options.sleep_skip < 2:
                            time.sleep(random.uniform(0.3, 0.8) *
                                       sleep_multiplier)
                        pass
                    clip_count += 1
        except Exception as e:
            self._mail_append_exception(e, 'Exception clipping coupons')

        if clip_count > 0 or error_count > 0:
            self.mail_subject += ': {:d} clipped'.format(clip_count)
            self._mail_append('Clipped {:d} coupons total:'.format(clip_count))
            for section_tuple in clip_counts.items():
                self._mail_append('    {} => {:d} '
                                  'coupons'.format(*section_tuple))
            if error_count > 0:
                self.mail_subject += ', {:d} errors'.format(error_count)
                self._mail_append('Coupon clip errors: '
                                  '{:d}'.format(error_count))

        logging.info('Clipped {clip_count} coupons. {ac} coupons were already claimed.'.format(clip_count=clip_count, ac=alreadyClippedCount))





class Offer():
    def __init__(self, o):
        
        self._extractName(o)
        self._extractOfferPrice(o)
        
        try:
            self.regularPrice = o['regularPrice']
        except KeyError as err:            
            logging.log(logging.ERROR, "Failed to find key for object. {e}".format(e=err))

    def __str__(self):
        return "{name} - {offer} (normally {regularPrice})".format(name=self.name, offer=self.offerPrice, regularPrice=self.regularPrice)

    def _extractName(self, o):

        for key in ['name', 'description']:
            if key in o:
                self.name = o[key]
                return

        raise Exception("Failed to find a suitable name in an offer.")

    def _extractOfferPrice(self, o):

        for key in ['offerPrice']:
            if key in o:
                self.offerPrice = o[key]
                return

        raise Exception("Failed to find a suitable offer price key.")


class OfferPctOff(Offer):
    
    def __init__(self, o):
        self._extractName(o)
        self._extractOfferPrice(o)            

    def __str__(self):
        return "{name} - {offer}".format(name=self.name, offer=self.offerPrice)


def OfferFactory(offer):

    if not 'regularPrice' in offer:
        return OfferPctOff(offer)
    return Offer(offer)
    



def main():

    # Parse options
    description = 'Automatically add online coupons to your Safeway card'
    arg_parser = argparse.ArgumentParser(description=description)
    arg_parser.add_argument('-c', '--accounts-config', dest='accounts_config',
                            metavar='file', required=True,
                            help=('Path to configuration file containing Safeway '
                                  'accounts information'))
    arg_parser.add_argument('-d', '--debug', dest='debug', action='count',
                            default=0,
                            help='Print debugging information on stdout. Specify '
                                 'twice to increase verbosity.')
    arg_parser.add_argument('-n', '--no-email', dest='email', action='store_false',
                            help=('Print summary information on standard output '
                                  'instead of sending email'))
    arg_parser.add_argument('-S', '--no-sleep', dest='sleep_skip', action='count',
                            default=0,
                            help=('Don\'t sleep between long requests. Specify '
                                  'twice to never sleep.'))
    options = arg_parser.parse_args()

    email_sender = ''
    auth = []

    if not os.path.isfile(options.accounts_config):
        raise Exception('Accounts configuration file {} does not  exist.'.format(options.accounts_config))

    config = configparser.ConfigParser()
    config.read_file(itertools.chain(['[_no_section]'],
                                     open(options.accounts_config, 'r')))

    if options.debug:
        root_logger.setLevel(logging.DEBUG)

    for section in config.sections():
        if section in ['_no_section', '_global']:
            if config.has_option(section, 'email_sender'):
                email_sender = config.get(section, 'email_sender')
        else:
            account = {'username': section,
                       'password': config.get(section, 'password')}
            if config.has_option(section, 'notify'):
                account.update({'notify': config.get(section, 'notify')})
            auth.append(account)

    if not email_sender:
        if options.email:
            logging.log(logging.WARNING, 'Warning: No email_sender defined. Summary information will be printed on standard output instead.')        
            options.email = False
    if len(auth) == 0:
        raise Exception('No valid accounts defined.')



    exit_code = 0
    for index, user_data in enumerate(auth):
        try:
            safeway(user_data)
        except Exception:
            # The safeway class already handles exceptions, but re-raises them
            # so safeway-coupons can exit with an error code
            exit_code = 1
        if index < len(auth) - 1:
            time.sleep(random.uniform(5.0, 10.0) * sleep_multiplier)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
