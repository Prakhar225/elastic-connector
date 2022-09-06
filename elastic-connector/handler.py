import traceback
from os import environ as env
from typing import Dict

from asgiref.sync import async_to_sync
from elasticsearch import Elasticsearch
from fastapi import HTTPException
from pydantic import BaseModel
from starlette.requests import Request

FUNCTION_NAME = 'ElasticSearch-Connector'
FUNCTION_VERSION = '1.0.0'
FUNCTION_SUMMARY = 'Dumps the data into Elastic search'
FUNCTION_RESPONSE_DESC = 'Returns a hardcoded response'

header_key = 'X-Gitlab-Token'
host = env.get('ES_HOST', 'https://sample-elastic-es-http.elastic.svc:9200')
key = env.get('API_KEY', '')
token_value = env.get('ACCESS_TOKEN', '')

try:
    print('Reading host')
    with open('/var/openfaas/secrets/elastic-host', 'r') as file:
        host = file.read()
    print('Reading key')
    with open('/var/openfaas/secrets/elastic-key', 'r') as file:
        key = file.read()
    print('Reading access token')
    with open('/var/openfaas/secrets/access-token', 'r') as file:
        token_value = file.read()
except:
    print('cannot read the secrets')


class ResponseModel(BaseModel):
    data: Dict


def handle(req: Request):
    """handle a request to the function
    Args:
        req (dict): request body
    """
    try:
        if header_key in req.headers:
            if req.headers[header_key] == token_value:
                es = Elasticsearch(hosts=host, api_key=key, verify_certs=False)

                data = async_to_sync(req.json)()
                print(f'Received data - {data}')

                index = 'fail'

                if 'object_kind' in data:
                    index = data['object_kind']
                elif 'event_type' in data:
                    index = data['event_type']
                elif 'event_name' in data:
                    index = data['event_name']

                resp = es.index(index=index, document=data)
                print(f"Post result - {resp['result']}")

                es.close()
                res = ResponseModel(data={'message': 'success'})
            else:
                raise HTTPException(status_code=403, detail='Cannot access resource')
        else:
            raise HTTPException(status_code=401, detail='Unauthorized access')
    except HTTPException as e:
        raise e
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An API Error occurred")
    return res
