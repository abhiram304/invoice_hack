import base64
import io
import os
import pprint
import json
import re
import requests
import datetime

import sys
import subprocess

from flask import Flask, Response, url_for, render_template, send_from_directory
from flask import request
from flask import json

import hashlib
import logging

import logging.config

from werkzeug.utils import redirect

# logging.config.fileConfig('logger.conf')
print("Starting Smart Invoice Hack ")

BASE = 36
BLOCK_SIZE = 4
DISCRETE_VALUES = BASE ** BLOCK_SIZE

UPLOAD_FOLDER = '/tmp/rdisk'
ALLOWED_EXTENSIONS = set(['png', 'jpg'])

#
# The entry point
#
app = Flask(__name__)


#
# default response. we could make it fancy
#
@app.route("/")
def index():
    return Response("Welcome to Smart Invoice Hack v0.0.1"), 200


@app.route('/<name>')
def hello_name(name):
    return "No service found for {}!".format(name)


#
# generate a random file name
#
def uniq_id(output_path, content):
    # orig = datetime.now().strftime("%m%d%H%M%S_") + "{0:04d}".format(random.randint(0, 10000))
    # masked_id = mask_with_hsa(orig)
    #
    # switch to use md5. This will help to group the same uploads together,
    # especially when people test the service with that awesome_invoice.pdf on the web site.
    # Truncate the hash to 16 character to make it shorter, but add length to reduce collision
    #
    masked_id = hashlib.md5(content.encode('utf-8')).hexdigest()
    masked_id = masked_id[0:16] + "_" + str(len(content))
    fan_out_012 = masked_id[0:3]   # first three letters
    fan_out_345 = masked_id[3:6]   # second three letters

    target_folder = "{}/{}/{}/{}".format(output_path, fan_out_012, fan_out_345, masked_id)
    if not os.path.isdir(target_folder):
        os.makedirs(target_folder)
    return target_folder, masked_id


def allowed_file(filename):
    # this has changed from the original example because the original did not work for me
    return filename[-3:].lower() in ALLOWED_EXTENSIONS


def extract_intents(request):

    # if behind a proxy
    ip = request.environ.get('HTTP_X_FORWARDED_FOR')
    if ip is None:
        ip = request.environ['REMOTE_ADDR']
    if ip is None:
        ip = request.remote_addr

    if request.method != 'POST':
        print('Invalid method - ' + request.method + ' - ' + ip)
        return 'Invalid method - ' + request.method, 400

    # if request.headers['Content-Type'] != 'application/json':
    #     print('Invalid content - ' + request.headers['Content-Type'] + ' - ' + ip)
    #     return 'Invalid content', 415

    # if request.data is None:
    #     print('Invalid content - no data' + ' - ' + ip)
    #     return 'Invalid content', 422

    file = request.files['file']
    if file and not allowed_file(file.filename):
        print('Invalid content type - ' + request.method + ' - ' + ip)
        return 'Invalid content type - ' + request.method, 400

    cl = request.content_length
    if cl is not None and cl > 100 * 1024 * 1024:
        print('Invalid content length exceed the limit' + ' - ' + ip)
        return 'Invalid content', 413

    #
    # add all parameters to form a proxy of the content. Eventually, we use it to get an unique id
    #
    content = {
        'length': cl,
    }
    content_str = json.dumps(content)
    target_folder, file_id = uniq_id(UPLOAD_FOLDER, content_str)
    input_file_name = file.filename
    input_file = os.path.join(target_folder, input_file_name)
    file.save(input_file)
    return target_folder, input_file, file_id


@app.route('/status/<oid>', methods=['GET'])
def status(oid=None):

    result_file = "{}.json".format(oid)
    with open(result_file, "r") as fh:
        content = fh.read()

    return content, 200

@app.route('/extract', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        target_folder, input_file, fid = extract_intents(request)

        # img_base64 = base64.b64encode(content.read())
        with open(input_file, 'rb') as image_file:
            img_base64 = base64.b64encode(image_file.read())
        #
        url = 'http://35.232.51.61:5000/extract'
        # url = 'http://localhost:5000/extract'
        data = {'image': img_base64.decode('ascii'),
                'features': [{'donate': '0'}]
                }
        headers = {'Content-type': 'application/json'}
        r = requests.post(url, data=json.dumps(data), headers=headers)

        file_id = r.json()['id']
        status_path = "{}.json".format('latest')
        info = json.dumps(r.json(), indent=4)
        with open(status_path, "w") as fh:
            fh.write(info)

        # return json.dumps(r.json()), 200
        # return redirect(url_for('status', oid='latest'))
        return render_template('status.html', info=info)

    return render_template('extract.html')


@app.route('/hook', methods=['POST'])
def webhook():
    print('Webhook triggered')
    print('data: ', request.get_json())
    print()
    data = request.get_json()
    _data, _ = status(oid='latest')
    status_data = json.loads(_data)
    _extract = status_data['extract']
    _address = _extract['ADDRESS']
    _amount = _extract['AMOUNT']
    _vendor_name = _extract['NAME']
    VENDOR_NAME = _vendor_name
    response_text = None
    intent = data['queryResult']['intent']['displayName']
    if intent == 'verifyDetails':
        print('verify details intent')
        response_text = ('I see that you have spent ${}. '
            'Do you want to schedule a payment?'.format(_amount))
    elif intent == 'helpCreatingBill':
        response_text = ('Sure. I tracked down the details. Is this for'
            ' {}?'.format(_vendor_name))
    elif intent == 'vendorDetailsAdd':
        response_text = ('{} is not in your vendors'
            ' list. Do you want to create one?'.format(_vendor_name))
    elif intent == 'vendorAddressAdd':
        createVendor(_vendor_name)
        createBill(_amount, _vendor_name)
        response_text = ('I see that the vendor address is {}.'
            ' We will send payment to that address. Is that right?'.format(
            _address
            ))
    result = {"fulfillmentText": response_text}
    return str(result), 200


@app.route('/inner_extract', methods=['GET'])
def inner_extract():
    return render_template('wix_page.html')

@app.route('/createBill', methods=['POST'])
def createBill(_amount=0, _vendor_name=None):
    if _vendor_name is None:
        _vendor_name = 'Test_vendor'
        _amount = 0

    {
  "refresh_token": "L0115500996886kRPaLYUvYYwTaBohveTVZ9JV18z5qxSLm5N3",
  "access_token": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..rvFwT0B-1KUlNGJXhJwnkw.nLrRCssflDMwYU6ZsIq0PZGn_ZG71s4cQ6vgLtJP4fkdNXu1U5RksZYLxUgv52voZkccb2NAgmv_A1xRVIYiE6JRXuvXfjCDomTFyKXuKhLMGw2Mt6A8wLNNu0WLFcfBmKqp8q9V0Qu0TdWUtIVX53pfmMJH_9wVdrUmDJ1v3wlfxBYEhytTTZ90Ldg7S8ZaDgqjCj8leFLNUQivtWGawh1zmqV6vC9I-REjKCm_RDULWXvNyhqkjhh7sRncMrduILxz9CVGLX4CXEXmnsnRXYvoyBubu-5WoR7lIQZmzxl2YacND8QjeqXEbBB2EVokA1YO80GRzjQVS0Rkk263lQi8nZHXjBVr_mwGJ_1pMXA5adoCKqJREghmvc7C6MaAMh5Y-zDOyvezyY9sYa6_AlALmxSgwVLQYhh3_nlXaX31Ci7v1HSST83vEsGAbfDbDv6eOZ9mZNnMGBcEXu_IkXNKT9hEoMIMWdsiz9QANC78blFPiQaRbGg5xxmQ6NaLZq2pd2T1c8duWl8sgmoB3PQsK6WFDJWOOmaI7-tJJB2S34IftVvElPJI1877fiYY6rYQnluH1k9YRnIKGJS-7ys5iUhoQeJIjoosn5lXVaQSvkzj8sVy2tJB6fsZPAwQ6KMm9grkaurWC9s-oVqeILHOUc5N4veQtY5q8MwngoToU6oKkN3QV7rBSVqfaSe0.ZlbxRhJ-gwOpfZx7t-AtWw",
  "expires_in": 3600,
  "x_refresh_token_expires_in": 8726400,
  "token_type": "bearer"
}




    config = {"access_token": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..rvFwT0B-1KUlNGJXhJwnkw.nLrRCssflDMwYU6ZsIq0PZGn_ZG71s4cQ6vgLtJP4fkdNXu1U5RksZYLxUgv52voZkccb2NAgmv_A1xRVIYiE6JRXuvXfjCDomTFyKXuKhLMGw2Mt6A8wLNNu0WLFcfBmKqp8q9V0Qu0TdWUtIVX53pfmMJH_9wVdrUmDJ1v3wlfxBYEhytTTZ90Ldg7S8ZaDgqjCj8leFLNUQivtWGawh1zmqV6vC9I-REjKCm_RDULWXvNyhqkjhh7sRncMrduILxz9CVGLX4CXEXmnsnRXYvoyBubu-5WoR7lIQZmzxl2YacND8QjeqXEbBB2EVokA1YO80GRzjQVS0Rkk263lQi8nZHXjBVr_mwGJ_1pMXA5adoCKqJREghmvc7C6MaAMh5Y-zDOyvezyY9sYa6_AlALmxSgwVLQYhh3_nlXaX31Ci7v1HSST83vEsGAbfDbDv6eOZ9mZNnMGBcEXu_IkXNKT9hEoMIMWdsiz9QANC78blFPiQaRbGg5xxmQ6NaLZq2pd2T1c8duWl8sgmoB3PQsK6WFDJWOOmaI7-tJJB2S34IftVvElPJI1877fiYY6rYQnluH1k9YRnIKGJS-7ys5iUhoQeJIjoosn5lXVaQSvkzj8sVy2tJB6fsZPAwQ6KMm9grkaurWC9s-oVqeILHOUc5N4veQtY5q8MwngoToU6oKkN3QV7rBSVqfaSe0.ZlbxRhJ-gwOpfZx7t-AtWw",
    "refresh_token": "L011550034473lIamf37xV0NWbnrqZzHVAt1Bc6X1cGYbq8eSz",
    "realm_id": "123146162818384",
    "qbo_base_url": "https://sandbox-quickbooks.api.intuit.com",
    "client_id": "",
    "client_secret": "",
    "discovery_doc": "https://developer.intuit.com/.well-known/openid_sandbox_configuration/"}
    url = config['qbo_base_url'] + '/v3/company/' + config['realm_id'] + '/bill'

    headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": "Bearer " + config['access_token']
            }

    bill = {
    "Line":[
        {
            "Id":"1",
            "Amount": _amount,
            "DetailType":"AccountBasedExpenseLineDetail",
            "AccountBasedExpenseLineDetail":
            {
                "AccountRef":
                {
                    "value":"7"
                }
            }
        }
    ],
    "VendorRef":
    {
        "value":"56",
        "name": _vendor_name
    }
    }
    r = requests.post(url, headers=headers, data=json.dumps(bill))
    print (r.status_code)
    print (r.content)
    try:
        response = r.json()["Bill"]
    except:
        response = r.content
    return str(response), r.status_code


@app.route('/createVendor', methods=['GET'])
def createVendor(_vendor_name=None):
    if _vendor_name is None:
        _vendor_name = 'Test_vendor'

    {
  "refresh_token": "L0115500996886kRPaLYUvYYwTaBohveTVZ9JV18z5qxSLm5N3",
  "access_token": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..rvFwT0B-1KUlNGJXhJwnkw.nLrRCssflDMwYU6ZsIq0PZGn_ZG71s4cQ6vgLtJP4fkdNXu1U5RksZYLxUgv52voZkccb2NAgmv_A1xRVIYiE6JRXuvXfjCDomTFyKXuKhLMGw2Mt6A8wLNNu0WLFcfBmKqp8q9V0Qu0TdWUtIVX53pfmMJH_9wVdrUmDJ1v3wlfxBYEhytTTZ90Ldg7S8ZaDgqjCj8leFLNUQivtWGawh1zmqV6vC9I-REjKCm_RDULWXvNyhqkjhh7sRncMrduILxz9CVGLX4CXEXmnsnRXYvoyBubu-5WoR7lIQZmzxl2YacND8QjeqXEbBB2EVokA1YO80GRzjQVS0Rkk263lQi8nZHXjBVr_mwGJ_1pMXA5adoCKqJREghmvc7C6MaAMh5Y-zDOyvezyY9sYa6_AlALmxSgwVLQYhh3_nlXaX31Ci7v1HSST83vEsGAbfDbDv6eOZ9mZNnMGBcEXu_IkXNKT9hEoMIMWdsiz9QANC78blFPiQaRbGg5xxmQ6NaLZq2pd2T1c8duWl8sgmoB3PQsK6WFDJWOOmaI7-tJJB2S34IftVvElPJI1877fiYY6rYQnluH1k9YRnIKGJS-7ys5iUhoQeJIjoosn5lXVaQSvkzj8sVy2tJB6fsZPAwQ6KMm9grkaurWC9s-oVqeILHOUc5N4veQtY5q8MwngoToU6oKkN3QV7rBSVqfaSe0.ZlbxRhJ-gwOpfZx7t-AtWw",
  "expires_in": 3600,
  "x_refresh_token_expires_in": 8726400,
  "token_type": "bearer"
}


    config = {"access_token": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..rvFwT0B-1KUlNGJXhJwnkw.nLrRCssflDMwYU6ZsIq0PZGn_ZG71s4cQ6vgLtJP4fkdNXu1U5RksZYLxUgv52voZkccb2NAgmv_A1xRVIYiE6JRXuvXfjCDomTFyKXuKhLMGw2Mt6A8wLNNu0WLFcfBmKqp8q9V0Qu0TdWUtIVX53pfmMJH_9wVdrUmDJ1v3wlfxBYEhytTTZ90Ldg7S8ZaDgqjCj8leFLNUQivtWGawh1zmqV6vC9I-REjKCm_RDULWXvNyhqkjhh7sRncMrduILxz9CVGLX4CXEXmnsnRXYvoyBubu-5WoR7lIQZmzxl2YacND8QjeqXEbBB2EVokA1YO80GRzjQVS0Rkk263lQi8nZHXjBVr_mwGJ_1pMXA5adoCKqJREghmvc7C6MaAMh5Y-zDOyvezyY9sYa6_AlALmxSgwVLQYhh3_nlXaX31Ci7v1HSST83vEsGAbfDbDv6eOZ9mZNnMGBcEXu_IkXNKT9hEoMIMWdsiz9QANC78blFPiQaRbGg5xxmQ6NaLZq2pd2T1c8duWl8sgmoB3PQsK6WFDJWOOmaI7-tJJB2S34IftVvElPJI1877fiYY6rYQnluH1k9YRnIKGJS-7ys5iUhoQeJIjoosn5lXVaQSvkzj8sVy2tJB6fsZPAwQ6KMm9grkaurWC9s-oVqeILHOUc5N4veQtY5q8MwngoToU6oKkN3QV7rBSVqfaSe0.ZlbxRhJ-gwOpfZx7t-AtWw",
    "refresh_token": "L011550034473lIamf37xV0NWbnrqZzHVAt1Bc6X1cGYbq8eSz",
    "realm_id": "123146162818384",
    "qbo_base_url": "https://sandbox-quickbooks.api.intuit.com",
    "client_id": "",
    "client_secret": "",
    "discovery_doc": "https://developer.intuit.com/.well-known/openid_sandbox_configuration/"}
    url = config['qbo_base_url'] + '/v3/company/' + config['realm_id'] + '/vendor?minorversion=12'

    vendor = {
                "DisplayName": _vendor_name,
                "CompanyName": _vendor_name,
                "PrimaryPhone": {
                    "FreeFormNumber": "123-445-6789"
                },
                "PrimaryEmailAddr": {
                    "Address": "info@abcdesigning.net"
                },
                "BillAddr": {
                    "Line1": "123 Mary Ave",
                    "City": "Sunnyvale",
                    "CountrySubDivisionCode": "CA",
                    "Country": "USA",
                    "PostalCode": "1111"
                }
            }

    headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": "Bearer " + config['access_token']
            }

    r = requests.post(url, headers=headers, data=json.dumps(vendor))
    print (r.status_code)
    print (r.content)

    try:
        response = r.json()["Vendor"]
    except:
        response = r.content
    return str(response), r.status_code

if __name__ == "__main__":
      app.secret_key = os.urandom(12)
      app.run(debug=True, use_reloader=True)
#    app.run(debug=True, port=5050)
