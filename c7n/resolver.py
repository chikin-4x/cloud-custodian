# Copyright 2016-2017 Capital One Services, LLC

# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import csv
import io
import json
import logging
import os
import zlib
from contextlib import closing
from urllib.parse import parse_qsl, urlparse
from urllib.request import Request, urlopen

import jmespath

from c7n.utils import format_string_values

log = logging.getLogger('custodian.resolver')

ZIP_OR_GZIP_HEADER_DETECT = zlib.MAX_WBITS | 32


class URIResolver:

    def __init__(self, session_factory, cache):
        self.session_factory = session_factory
        self.cache = cache

    def resolve(self, uri):
        if self.cache:
            contents = self.cache.get(("uri-resolver", uri))
            if contents is not None:
                return contents

        if uri.startswith('s3://'):
            contents = self.get_s3_uri(uri)
        else:
            # TODO: in the case of file: content and untrusted
            # third parties, uri would need sanitization
            req = Request(uri, headers={"Accept-Encoding": "gzip"})
            with closing(urlopen(req)) as response:
                contents = self.handle_response_encoding(response)

        if self.cache:
            self.cache.save(("uri-resolver", uri), contents)
        return contents

    def handle_response_encoding(self, response):
        if response.info().get('Content-Encoding') != 'gzip':
            return response.read().decode('utf-8')

        data = zlib.decompress(response.read(),
                               ZIP_OR_GZIP_HEADER_DETECT).decode('utf8')
        return data

    def get_s3_uri(self, uri):
        parsed = urlparse(uri)
        client = self.session_factory().client('s3')
        params = dict(
            Bucket=parsed.netloc,
            Key=parsed.path[1:])
        if parsed.query:
            params.update(dict(parse_qsl(parsed.query)))
        result = client.get_object(**params)
        body = result['Body'].read()
        if isinstance(body, str):
            return body
        else:
            return body.decode('utf-8')


class ValuesFrom:
    """Retrieve values from a url.

    Supports json, csv and line delimited text files and expressions
    to retrieve a subset of values.

    Expression syntax
    - on json, a jmespath expr is evaluated
    - on csv, an integer column or jmespath expr can be specified
    - on csv2dict, a jmespath expr (the csv is parsed into a dictionary where
    the keys are the headers and the values are the remaining columns)

    Text files are expected to be line delimited values.

    Examples::

      value_from:
         url: s3://bucket/xyz/foo.json
         expr: [].AppId

      value_from:
         url: http://foobar.com/mydata
         format: json
         expr: Region."us-east-1"[].ImageId

      value_from:
         url: s3://bucket/abc/foo.csv
         format: csv2dict
         expr: key[1]

       # inferred from extension
       format: [json, csv, csv2dict, txt]
    """
    supported_formats = ('json', 'txt', 'csv', 'csv2dict')

    # intent is that callers embed this schema
    schema = {
        'type': 'object',
        'additionalProperties': 'False',
        'required': ['url'],
        'properties': {
            'url': {'type': 'string'},
            'format': {'enum': ['csv', 'json', 'txt', 'csv2dict']},
            'expr': {'oneOf': [
                {'type': 'integer'},
                {'type': 'string'}]}
        }
    }

    def __init__(self, data, manager, event=None):
        config_args = {
            'account_id': manager.config.account_id,
            'region': manager.config.region
        }
        self.data = format_string_values(data, **config_args)
        self.manager = manager
        self.event = event
        self.cache = manager._cache
        self.resolver = URIResolver(manager.session_factory, manager._cache)

    def get_contents(self):
        _, format = os.path.splitext(self.data['url'])

        if not format or self.data.get('format'):
            format = self.data.get('format', '')
        else:
            format = format[1:]

        if format not in self.supported_formats:
            raise ValueError(
                "Unsupported format %s for url %s",
                format, self.data['url'])
        contents = str(self.resolver.resolve(self.data['url']))
        return contents, format

    def get_values(self):
        if self.cache:
            # use these values as a key to cache the result so if we have
            # the same filter happening across many resources, we can reuse
            # the results.
            key = [self.data.get(i) for i in ('url', 'format', 'expr')]
            contents = self.cache.get(("value-from", key))
            if contents is not None:
                return contents

        contents = self._get_values()
        if self.cache:
            self.cache.save(("value-from", key), contents)
        return contents

    def _get_values(self):
        contents, format = self.get_contents()

        if format == 'json':
            data = json.loads(contents)
            if 'expr' in self.data:
                # this event is the event passed into the lambda. Slightly different than the CloudTrail event.
                if self.event:
                    try:
                        try:
                            # Remove the account portion from the arn
                            self.event['detail']['userIdentity']['arn'] = self.event['detail']['userIdentity']['arn'].split(':')[5]
                        except KeyError as e:
                            # Failed to simplify the arn so keep it
                            pass

                        expr = self.data['expr'].format(**self.event)
                        log.debug(f"Expression after substitution:  {expr}")
                    except KeyError as e:
                        log.error(f"Failed substituting into expression: {str(e)}")
                        expr = self.data['expr']
                else:
                    expr = self.data['expr']

                res = jmespath.search(expr, data)
                log.debug(f"JMESPath result: {res}")

                # Checking for whitelist expiration
                if res is not None:
                    valid_until = res.get('validUntil', None)
                    value = res.get('value', None)

                    # If value AND valid_until are both not None, then we assume this is whitelisting
                    # However, if only one of them returns, we assume this isn't whitelisting and return
                    # the value. This allows for other jmespath expressions to be used besides just
                    # for whitelisting. Hopefully future proofing this part.
                    if value is None or valid_until is None or value == "" or valid_until == "":
                        log.warning(f"Value is: {value}, ValidUntil is: {valid_until}")
                        log.debug("Returning res since this might not be whitelisting...")
                        return res
                    else:
                        # If we made it here, we assume we are wanting to do whitelisting and need
                        # to check the expiration time to see if it's valid
                        import datetime
                        import time
                        current_time = datetime.datetime.fromtimestamp(time.time())
                        expiration = datetime.datetime.fromtimestamp(int(valid_until))
                        log.debug(f"Current Time: {current_time}, Expiration: {expiration}")
                        if current_time > expiration:
                            log.warning(f"Whitelist has expired, returning None...")
                            return None
                        else:
                            log.debug("Whitelist is valid")
                            return value
                else:
                    log.warning(f"ValueFrom filter: {expr} key returned None")

                return res
        elif format == 'csv' or format == 'csv2dict':
            data = csv.reader(io.StringIO(contents))
            if format == 'csv2dict':
                data = {x[0]: list(x[1:]) for x in zip(*data)}
            else:
                if isinstance(self.data.get('expr'), int):
                    return [d[self.data['expr']] for d in data]
                data = list(data)
            if 'expr' in self.data:
                if self.event:
                    expr = self.data['expr'].format(**self.event)
                else:
                    expr = self.data['expr']
                res = jmespath.search(expr, data)
                if res is None:
                    log.warning('ValueFrom filter: %s key returned None' % self.data['expr'])
                return res
            return data
        elif format == 'txt':
            return [s.strip() for s in io.StringIO(contents).readlines()]
