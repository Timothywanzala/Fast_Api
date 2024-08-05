
# Import statements remain the same
from dataclasses import Field, dataclass
import OpenSSL
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Any, List, Optional
from datetime import datetime
from uuid import UUID
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
import base64
import json
import httpx
import logging
import pandas as pd
import os
import rsa
from dotenv import load_dotenv
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign, verify

# Setup logging
logging.basicConfig(level=logging.DEBUG, filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI()

# Setup logging

number_details_list = []


#interface body
@dataclass
class Data:
    content: str
    signature: str
    dataDescription: 'DataDescription'

    @staticmethod
    def from_dict(obj: Any) -> 'Data':
        _content = str(obj.get("content"))
        _signature = str(obj.get("signature"))
        _dataDescription = DataDescription.from_dict(obj.get("dataDescription"))
        return Data(_content, _signature, _dataDescription)

@dataclass
class DataDescription:
    codeType: str
    encryptCode: str
    zipCode: str

    #staticmethod
    def from_dict(obj: Any) -> 'DataDescription':
        _codeType = str(obj.get("codeType"))
        _encryptCode = str(obj.get("encryptCode"))
        _zipCode = str(obj.get("zipCode"))
        return DataDescription(_codeType, _encryptCode, _zipCode)

@dataclass
class ExtendField:
    responseDateFormat: str
    responseTimeFormat: str
    referenceNo: str
    operatorName: str
    offlineInvoiceException: 'OfflineInvoiceException'

    @staticmethod
    def from_dict(obj: Any) -> 'ExtendField':
        _responseDateFormat = str(obj.get("responseDateFormat"))
        _responseTimeFormat = str(obj.get("responseTimeFormat"))
        _referenceNo = str(obj.get("referenceNo"))
        _operatorName = str(obj.get("operatorName"))
        _offlineInvoiceException = OfflineInvoiceException.from_dict(obj.get("offlineInvoiceException"))
        return ExtendField(_responseDateFormat, _responseTimeFormat, _referenceNo, _operatorName, _offlineInvoiceException)

@dataclass
class GlobalInfo:
    appId: str #= "AP04"
    version: str #= "1.1.20191201"
    dataExchangeId: UUID
    interfaceCode: str
    requestCode: str
    requestTime: datetime
    responseCode: str
    userName: str
    deviceMAC: str #="FFFFFFFFFFFF"
    deviceNo: str 
    tin: str        
    brn: str
    taxpayerID: str
    longitude: float 
    latitude: float 
    agentType: str
    extendField: ExtendField

    @staticmethod
    def from_dict(obj: Any) -> 'GlobalInfo':
        _appId = str(obj.get("appId"))
        _version = str(obj.get("version"))
        _dataExchangeId = str(obj.get("dataExchangeId"))
        _interfaceCode = str(obj.get("interfaceCode"))
        _requestCode = str(obj.get("requestCode"))
        _requestTime = str(obj.get("requestTime"))
        _responseCode = str(obj.get("responseCode"))
        _userName = str(obj.get("userName"))
        _deviceMAC = str(obj.get("deviceMAC"))
        _deviceNo = str(obj.get("deviceNo"))
        _tin = str(obj.get("tin"))
        _brn = str(obj.get("brn"))
        _taxpayerID = str(obj.get("taxpayerID"))
        _longitude = str(obj.get("longitude"))
        _latitude = str(obj.get("latitude"))
        _agentType = str(obj.get("agentType"))
        _extendField = ExtendField.from_dict(obj.get("extendField"))
        return GlobalInfo(_appId, _version, _dataExchangeId, _interfaceCode, _requestCode, _requestTime, _responseCode, _userName, _deviceMAC, _deviceNo, _tin, _brn, _taxpayerID, _longitude, _latitude, _agentType, _extendField)

@dataclass
class OfflineInvoiceException:
    errorCode: str
    errorMsg: str

    @staticmethod
    def from_dict(obj: Any) -> 'OfflineInvoiceException':
        _errorCode = str(obj.get("errorCode"))
        _errorMsg = str(obj.get("errorMsg"))
        return OfflineInvoiceException(_errorCode, _errorMsg)

@dataclass
class ReturnStateInfo:
    returnCode: str
    returnMessage: str

    @staticmethod
    def from_dict(obj: Any) -> 'ReturnStateInfo':
        _returnCode = str(obj.get("returnCode"))
        _returnMessage = str(obj.get("returnMessage"))
        return ReturnStateInfo(_returnCode, _returnMessage)

@dataclass
class Inter_Face(BaseModel):
    data: Data
    globalInfo: GlobalInfo
    returnStateInfo: ReturnStateInfo

    #staticmethod
    def from_dict(obj: Any) -> 'Inter_Face':
        _data = Data.from_dict(obj.get("data"))
        _globalInfo = GlobalInfo.from_dict(obj.get("globalInfo"))
        _returnStateInfo = ReturnStateInfo.from_dict(obj.get("returnStateInfo"))
        return Inter_Face(_data, _globalInfo, _returnStateInfo)


#Request Body
class InputNumber(BaseModel):
    referenceNo : str

class Page(BaseModel):
    pageCount: int
    pageNo: int
    pageSize: int
    totalSize: int

    @staticmethod
    def from_dict(obj: Any) -> 'Page':
        _pageCount = int(obj.get("pageCount"))
        _pageNo = int(obj.get("pageNo"))
        _pageSize = int(obj.get("pageSize"))
        _totalSize = int(obj.get("totalSize"))
        return Page(_pageCount, _pageNo, _pageSize, _totalSize)

@dataclass
class Record:
    branchId: str
    branchName: str
    businessName: str
    buyerBusinessName: str
    buyerLegalName: str
    buyerTin: str
    currency: str
    dataSource: str
    dateFormat: str
    deviceNo: str
    grossAmount: str
    id: str
    invoiceIndustryCode: str
    invoiceKind: str
    invoiceNo: str
    invoiceType: str
    isInvalid: str
    isRefund: str
    issuedDate: str
    issuedDateStr: str
    legalName: str
    nowTime: str
    operator: str
    pageIndex: int
    pageNo: int
    pageSize: int
    referenceNo: str
    taxAmount: str
    uploadingTime: str
    userName: str

    @staticmethod
    def from_dict(obj: Any) -> 'Record':
        _branchId = str(obj.get("branchId"))
        _branchName = str(obj.get("branchName"))
        _businessName = str(obj.get("businessName"))
        _buyerBusinessName = str(obj.get("buyerBusinessName"))
        _buyerLegalName = str(obj.get("buyerLegalName"))
        _buyerTin = str(obj.get("buyerTin"))
        _currency = str(obj.get("currency"))
        _dataSource = str(obj.get("dataSource"))
        _dateFormat = str(obj.get("dateFormat"))
        _deviceNo = str(obj.get("deviceNo"))
        _grossAmount = str(obj.get("grossAmount"))
        _id = str(obj.get("id"))
        _invoiceIndustryCode = str(obj.get("invoiceIndustryCode"))
        _invoiceKind = str(obj.get("invoiceKind"))
        _invoiceNo = str(obj.get("invoiceNo"))
        _invoiceType = str(obj.get("invoiceType"))
        _isInvalid = str(obj.get("isInvalid"))
        _isRefund = str(obj.get("isRefund"))
        _issuedDate = str(obj.get("issuedDate"))
        _issuedDateStr = str(obj.get("issuedDateStr"))
        _legalName = str(obj.get("legalName"))
        _nowTime = str(obj.get("nowTime"))
        _operator = str(obj.get("operator"))
        _pageIndex = int(obj.get("pageIndex"))
        _pageNo = int(obj.get("pageNo"))
        _pageSize = int(obj.get("pageSize"))
        _referenceNo = str(obj.get("referenceNo"))
        _taxAmount = str(obj.get("taxAmount"))
        _uploadingTime = str(obj.get("uploadingTime"))
        _userName = str(obj.get("userName"))
        return Record(_branchId, _branchName, _businessName, _buyerBusinessName, _buyerLegalName, _buyerTin, _currency, _dataSource, _dateFormat, _deviceNo, _grossAmount, _id, _invoiceIndustryCode, _invoiceKind, _invoiceNo, _invoiceType, _isInvalid, _isRefund, _issuedDate, _issuedDateStr, _legalName, _nowTime, _operator, _pageIndex, _pageNo, _pageSize, _referenceNo, _taxAmount, _uploadingTime, _userName)

@dataclass
class NumberDetails(BaseModel):
    dateFormat: str
    nowTime: str
    page: Page
    records: List[Record]

    @staticmethod
    def from_dict(obj: Any) -> 'NumberDetails':
        _dateFormat = str(obj.get("dateFormat"))
        _nowTime = str(obj.get("nowTime"))
        _page = Page.from_dict(obj.get("page"))
        _records = [Record.from_dict(y) for y in obj.get("records")]
        return NumberDetails(_dateFormat, _nowTime, _page, _records)


# save AES KEYS as Environment varibales 
AES_KEY = bytes.fromhex(os.getenv('AES_KEY', ''))
# AES_KEY = os.getenv('AES_KEY', '')
IV = bytes.fromhex(os.getenv('IV', ''))

def load_keys():  
    with open("efris.nssf.pfx", "rb") as f:
     p12_data = f.read()
    password =  'muTub@wir3'
    # Extract the private key, certificate, and additional certificates (if any)
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
        p12_data, 
        password.encode('utf-8'),
        default_backend()
    )  

    with open('_.ura.go.ug.crt', 'rb') as cert_file:
        cert_data = cert_file.read()
    
        certificate = load_pem_x509_certificate(cert_data)
        public_key = certificate.public_key()
    
    return private_key, public_key



# Function to encrypt data using AES-CBC mode
def encrypt_data(data: str, aes_key: bytes, iv: bytes) -> dict:
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    
    combined_data = {
        "encrypted_data": encrypted_data,
        "iv": iv
    }
    return combined_data

# Signing function(need to be changed)
def sign_data(encrypted_data: str, private_key) -> str:
    signer = private_key.signer(padding.PKCS1v15(), hashes.SHA256())
    signer.update(encrypted_data.encode())
    signature = signer.finalize()
    return base64.b64encode(signature).decode('utf-8')

# Decryption and verification functions

def decrypt_rsa(encrypted_data, private_key) -> str:
    # private_key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    # private_key_rsa = serialization.load_pem_private_key(private_key_pem, password=None)
    
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    f = Fernet(private_key) 
    decrypted_data =  f.decrypt(encrypted_data_bytes)
    
    return decrypted_data

# verification of response signature (might need to be changed )
# Verification function
def verify_signature(signature: str, encrypted_data: str, public_key) -> bool:
    signature_bytes = base64.b64decode(signature)
    verifier = public_key.verifier(signature_bytes, padding.PKCS1v15(), hashes.SHA256())
    verifier.update(encrypted_data.encode())
    try:
        verifier.verify()
        return True
    except:
        return False
   

# send request to efris system
async def send_number_to_external_system(Interface_json_data_sent:str):
    logger.debug('Sending number with data: %s', Interface_json_data_sent)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post("https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation", 
                                         json=Interface_json_data_sent,  timeout=60.0)
            response.raise_for_status()
            # response.status_code == 200
            # response_data = response.json()
            # return  response_data
            if response.status_code == 200:
                response_data = response.json()
                encrypted_data = response_data["data"]["content"]
                response_data_signature = response_data["data"]["signature"]
  

        # this is the main varification and decryption code 
                # Verify the signature
                # import pdb; pdb.set_trace()
                # if not verify_signature( response_data_signature):
                #     raise ValueError("Signature verification failed. The data may be tampered with.")
                
                # else:
                   
                    #   decrypted_data = decrypt_rsa(pass_key, private_key)
                          
                       # Parse the decrypted data to the appropriate data class
                    #   number_details = NumberDetails.from_dict(json.loads(decrypted_data))
                #   return number_details


                # this is the templary code for decrypting the AES keys to be used for encryption 
                private_key, public_key= load_keys()
                # import pdb; pdb.set_trace()
                decrypted= base64.b64decode(encrypted_data)
             
                decrypted_json = json.loads(decrypted)
                pass_key = decrypted_json["passowrdDes"]
                encrypt_key = bytes(pass_key,'ascii')
                sign_key = decrypted_json["sign"]

                import pdb; pdb.set_trace()
                decrypted_data = decrypt_rsa(pass_key, private_key)
                number_details = json.loads(decrypted_data)

                return number_details
                
                        
            else:
                raise ValueError(f"Unexpected status code: {response.status_code}. No valid response from the external system.")
    
        except httpx.HTTPStatusError as e:
            print(f"Unexpected HTTP status: {e.response.status_code}")
        except httpx.ConnectError as e:
             print(f"Connect error occurred: {str(e)}")
        except httpx.ConnectTimeout:
            print("Request timed out")
        except httpx.HTTPStatusError as e:
            logger.debug(e)
            return None
                    # except Exception as e:
        #     print(f"An error occurred: {str(e)}")
    




# @app.get("/process-get-number/", response_model=list[InputNumber])
# async def process_get_number():
#     response_data = 



# main method
@app.post("/process-number/{refno}")
async def get_reference_details(request: Request, refNo:str):
    refNo_data = refNo
    refNo_json = json.dumps(refNo_data, indent=2)

#  Encrypt and sign the data
    private_key, public_key= load_keys()

    encrypted_data = encrypt_data(refNo_json, AES_KEY, IV)
    encrypted_string = encrypted_data.get('encrypted_data', '')
    signed_data= sign_data(encrypted_string, private_key)
    
    encrypted_string_data = base64.b64encode(encrypted_string).decode('utf-8')
    signed_bytes = base64.b64encode(signed_data).decode('utf-8')

    # Create the interface data
    interface_data ={
                "data": {
                "content": "",
                "signature": "",
                "dataDescription": {
                "codeType": "0",
                "encryptCode": "1",
                "zipCode": "0"
                }
                },
                "globalInfo": {
                "appId": "AP04",
                "version": "1.1.20191201",
                "dataExchangeId": "9230489223014123",
                "interfaceCode": "T104",
                "requestCode": "TP",
                "requestTime": "2024-07-31 15:02:37",
                "responseCode": "TA",
                "userName": "admin",
                "deviceMAC": "FFFFFFFFFFFF",
                "deviceNo": "1008686938_01",
                "tin": "1008686938",
                "brn": "001868267/",
                "taxpayerID": "1008686938",
                "longitude": "116.397128",
                "latitude": "39.916527",
                "agentType": "0",
                "extendField": {
                "responseDateFormat": "dd/MM/yyyy",
                "responseTimeFormat": "dd/MM/yyyy HH:mm:ss",
                "referenceNo": " 25PL040000002" ,
                "operatorName": "administrator",
                "offlineInvoiceException": {
                "errorCode": "",
                "errorMsg": ""
                }
                }
                },
                "returnStateInfo": {
                "returnCode": "",
                "returnMessage": ""
                }
                }
#   "referenceNo": "21PL010020807
# 25PL010000073. brn
    
    response = await send_number_to_external_system(interface_data)
    # import pdb;pdb.set_trace()

    df = pd.DataFrame.from_dict(response, orient='index')

        # import pdb;pdb.set_trace()
    data_in_table_format = df.to_dict(orient='records')
  
    return {
            "status": "success", 
            "message": "Number processed successfully", 
            "data": data_in_table_format}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
