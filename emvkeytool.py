import argparse
#from pytlv.TLV import *
from TLV import *
from smartcard.System import readers
from smartcard.util import toHexString,toASCIIString
from smartcard.Exceptions import NoCardException

import Crypto
from Crypto.PublicKey import RSA

import json

import rocatest
import sys

r=readers()
GET_RESPONSE = [0X00, 0XC0, 0x00, 0x00]
#SELECT = [0xA0, 0xA4, 0x00, 0x00, 0x02]
SELECT = [0x00, 0xA4, 0x04, 0x00]
READ_RECORD = [0x00, 0xB2]


MASTERCARD_AID = [0xA0,0x00,0x00,0x00,0x04,0x10,0x10]  
DF_PSE = [0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31]
NAB_EFT_AID = [0xA0,0x00,0x00,0x03,0x84,0x10]

def get_readers():
    try:
        r=readers()
        return r
    except error as message:
        print(error, message)

def list_readers(reader_list):
    for idx,reader in enumerate(reader_list):
        print("{}\t{}".format(idx,reader))

def getATR(connection,reader):
    print(reader, toHexString(connection.getATR()))

def sendSELECT(connection, dfname):
    apdu = SELECT + [len(dfname)] + dfname
    response, sw1, sw2 = connection.transmit(apdu) 
    finalresponse = response 
 
    while(sw1 == 0x61): #response bytes still available
        apdu = GET_RESPONSE + [sw2]
        print toHexString(apdu)
        response, sw1, sw2 = connection.transmit(apdu)
        finalresponse += response
    return dict(response=finalresponse, sw1=sw1, sw2=sw2) 

def readRECORD(connection, sfi, record_num):
    encoded_sfi = ((sfi << 3) | 0x4) & 0xff
    apdu = READ_RECORD + [record_num] + [encoded_sfi] + [0x00] 
    response, sw1, sw2 = connection.transmit(apdu) 
    finalresponse = response 
    while(sw1 == 0x61): #response bytes still available
        apdu = GET_RESPONSE + [sw2]
        response, sw1, sw2 = connection.transmit(apdu)
        finalresponse += response
    if(sw1 == 0x6c):
        apdu = READ_RECORD + [record_num] + [encoded_sfi] + [sw2] 
        response, sw1, sw2 = connection.transmit(apdu)
        finalresponse += response
    return dict(response=finalresponse, sw1=sw1, sw2=sw2) 
     

def getAID(reader):
    apdu = SELECT + [len(MASTERCARD_AID)] + MASTERCARD_AID
    print(apdu) 
    response, sw1, sw2 = connection.transmit(apdu) 
    print("AID Response {}, {}, {}".format(toHexString(response), hex(sw1), hex(sw2)))
             
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='emvkeytool.py')
    parser.add_argument("-V", "--version", help="print version", action="version", version='%(prog)s 0.1')
    parser.add_argument("-v", "--verbose", action="store_true", help="print verbose information")
    parser.add_argument("-l", "--list-readers", action="store_true", help="print connected readers")
    parser.add_argument("-r", "--use-reader", type=int, help="select reader number (default to first detected)")
    parser.add_argument("-j", "--import-json", default="calist.json",help="import a custom CA List")
    parser.add_argument("-A", "--import-aid", default="aidlist.json",help="import a custom AID List")
    parser.add_argument("-D", "--dump-keys",action="store_true", help="import a custom AID List")
    parser.add_argument("-t", "--test-keys",action="store_true", help="test found keys for Infineon weak key")
    args = parser.parse_args()
    reader_list = get_readers()
    selected_reader = 0  
    reader = reader_list[0] 
    #print(args) 
    tlv = TLV()
    if args.list_readers:
        list_readers(reader_list)
    if args.use_reader:
        try:
            selected_reader = args.use_reader
            reader = reader_list[selected_reader] 
        except IndexError:
            print("Reader {} does not exist".format(selected_reader))
            sys.exit()
    #read the calist json 
    if args.import_json:
        try:
            jsonfile = open(args.import_json,'r')
            calist = json.loads(jsonfile.read())
        except IOError:
            print("Could not read file:", args.import_json)
            sys.exit()
    if args.import_aid:
        try:
            aidfile = open(args.import_aid,'r')
            aidlist = json.loads(aidfile.read())
        except IOError:
            print("Could not read file:", args.import_aid)
            sys.exit()
    try:
        connection = reader.createConnection()
        connection.connect()
        getATR(connection, reader)
        #fci_result = sendSELECT(connection, MASTERCARD_AID) # this will give us the FCI
        #fci_result_string = toHexString(fci_result).replace(" ","") 
        #fci = tlv.parse(fci_result_string)
        #fci_parse = tlv.parse(fci['6F'])
        #print fci_parse 
        #df_name = fci_parse['84']
        #print df_name
        #fci_prop = tlv.parse(fci_parse['A5'])
        #print fci_prop
        #application_label = fci_prop['50']
        #print application_label.decode('hex') 
        ##found_aid = parsed_tld['
        ##sendSELECT(connection, MASTERCARD_DFU)
        if args.verbose:
            print("[*]\tSelecting PSE...") 
        pse_result = sendSELECT(connection, DF_PSE)
        aid_list = list() 
        if pse_result['response']: 
            if args.verbose:
                print("[*]\tReading Records for AIDs...") 
            SFI_counter = 1 
            returnval = 0x90 
            rr1 = readRECORD(connection,1,SFI_counter)
            if args.verbose:
                print toHexString(rr1['response']) 
            returnval = rr1['sw1']
            while(returnval == 0x90):
                parse1 = tlv.parse("".join(toHexString(rr1["response"]).replace(" ",""))) 
                parse2 = tlv.parse(parse1['70']) 
                parse3 = tlv.parse(parse2['61']) 
                foundaid = parse3['4F'] 
                aid_list.append(foundaid) 
                SFI_counter += 1
                rr1 = readRECORD(connection,1,SFI_counter)
                returnval = rr1['sw1']
            if args.verbose:
                print("[*]\tRetrieved these AIDs")
                print aid_list
        else: 
            if args.verbose:
                print("[*]\tPSE not found - using known list of AIDs...")
            for aid in aidlist:
                #get the current AID
                currentaidstring = aid['AID'] 
                #convert aid to list
                #currentaidlist = [currentaidstring[i:i+2] for i in range(0, len(currentaidstring), 2)] 
                #currentaid = [int(x,16) for x in currentaidlist]
                currentaid = map(ord,list(currentaidstring.decode('hex')))
                #pse_result = sendSELECT(connection, currentaid)
                pse_result = sendSELECT(connection, currentaid)
                if(pse_result['sw1'] == 0x90): 
                    aid_list.append(currentaidstring) 
        for aid in aid_list:
            if args.verbose:
                print("[*] select the aid: {}".format(aid))
            #select the AID
            #temp_aid_list = list(aid.decode('hex'))
            #print temp_aid_list 
            #print map(ord,temp_aid_list)
            fci_result = sendSELECT(connection, map(ord,list(aid.decode('hex'))))
            #decoded_pse = tlv.parse(toHexString(pse_result).replace(" ",""))
            #print decoded_pse
            print toHexString(fci_result['response'])
            #rr1 = readRECORD(connection,1,2)
            #print toHexString(rr1)
            #loop through records - may be 5 SFI x 5 records?
            CA_PUBLIC_KEY_INDEX = "" 
            ISSUER_CERT = ""
            ISSUER_EXP = ""
            ISSUER_REM = ""
            PIN_CERT = ""
            PIN_EXP = ""
            PIN_REM = ""
            ICC_CERT = ""
            ICC_EXP = ""
            ICC_REM = ""
            for record in xrange(1, 5):
                for sfi in xrange(1, 5):
                    result = readRECORD(connection,record,sfi)
                    if(result['sw1'] == 0x90):
                        if args.verbose:
                            print("[*] found record:{} SFI:{}") 
                        #print toHexString(result['response'])
                        #decode EMVtemplate
                        #print result['response'] 
                        response = tlv.parse(toHexString(result['response']).replace(" ","")) 
                        #print response 
                        EMVtemplate = tlv.parse(response['70']) 
                        #print("[*] EMV Template") 
                        #print EMVtemplate
                        if '8F' in EMVtemplate: #get pub key index
                            CA_PUBLIC_KEY_INDEX = EMVtemplate['8F']
                            if args.verbose:
                                print "CA_PUB_INDEX=" + CA_PUBLIC_KEY_INDEX
                        if '90' in EMVtemplate:
                            ISSUER_CERT = EMVtemplate['90']
                            if args.verbose:
                                print "ISSUERCERT=" + ISSUER_CERT
                        if '92' in EMVtemplate: 
                            ISSUER_REM = EMVtemplate['92']
                            if args.verbose:
                                print "ISSUERREM=" + ISSUER_REM
                        if '9F32' in EMVtemplate: 
                            ISSUER_EXP = EMVtemplate['9F32']
                            if args.verbose:
                                print "ISSERCERT=" + ISSUER_EXP
                        if '9F9D' in EMVtemplate: 
                            PIN_CERT = EMVtemplate['9F2D']
                            if args.verbose:
                                print "PINCERT=" + PIN_CERT
                        if '9F9E' in EMVtemplate: 
                            PIN_EXP = EMVtemplate['9F2E']
                            if args.verbose:
                                print "PINEXP=" + PIN_EXP
                        if '9F2F' in EMVtemplate: 
                            PIN_REM = EMVtemplate['9F2F']
                            if args.verbose:
                                print "PINREM=" + PIN_REM
                        if '9F46' in EMVtemplate: 
                            ICC_CERT = EMVtemplate['9F46']
                            if args.verbose:
                                print "ICCCERT=" + ICC_CERT
                        if '9F47' in EMVtemplate: 
                            ICC_EXP = EMVtemplate['9F47']
                            if args.verbose:
                                print "ICCEXP=" + ICC_EXP
                        if '9F48' in EMVtemplate: 
                            ICC_REM = EMVtemplate['9F48']
                            if args.verbose:
                                print "ICCREM=" + ICC_REM
            #lookup appropriate key in calist
            for CA in calist:
                #print CA['RID List'][0:10].lower()
                #print CA['RID Index']
                #print CA_PUBLIC_KEY_INDEX
                if((CA['RID List'].lower() == aid[0:10].lower()) & (CA['RID Index'] == CA_PUBLIC_KEY_INDEX) & (CA['Key Type'] != "Test")):
                    cakey_entry = CA
                    break
                else:
                    cakey_entry = ""
            if cakey_entry == "":
                if args.verbose: 
                    print("No CA Key located - so we'll bruteforce")
                #lets grab all the CA keys in the for this AID and try them... 
                cakey_brute_list = list()
                for CA in calist:
                    if((CA['RID List'].lower() == aid[0:10].lower())):
                        cakey_brute_list.append(CA)
            #print cakey_entry
            #generate the CA RSA key construct( (mod, exp) )
            if cakey_entry == "": #lets test all the keys!
                for key in cakey_brute_list:
                    if args.verbose: 
                        print key 
                    test_mod = long(key['Modulus'],16)
                    test_exp = long(key['Exponent'],16)
                    #print cakey_mod 
                    #print cakey_exp 
                    testkey = RSA.construct((test_mod, test_exp))
                    #decrypt the Issuer Cert
                    testcert = hex(testkey.encrypt(long(ISSUER_CERT,16), 32)[0]).lstrip('0x').rstrip('L')
                    if((testcert[0:2] == "6a") & (testcert[-2:] == "bc")):
                        if args.verbose: 
                            print("[*] Found Key!")
                        cakey_entry = key 
                        break
                if cakey_entry == "":
                    print("ERROR - NO VALID KEY FOUND")
                     
            if cakey_entry != "": #yes we have a valid emv key 
                cakey_mod = long(cakey_entry['Modulus'],16)
                cakey_exp = long(cakey_entry['Exponent'],16)
                #print cakey_mod 
                #print cakey_exp 
                cakey = RSA.construct((cakey_mod, cakey_exp))
                #decrypt the Issuer Cert
                decissuercert = hex(cakey.encrypt(long(ISSUER_CERT,16), 32)[0]).lstrip('0x').rstrip('L')
                if args.verbose: 
                    print "decissuercert=" + decissuercert
                if((decissuercert[0:2] == "6a") & (decissuercert[-2:] == "bc")):
                    #cert is valid
                    messagelen = (len(decissuercert) - 2 - 40 - 2)
                    #print messagelen 
                    message = decissuercert[2:-42]
                    #print "message=" + message
                    if(message[0:2] == "02"):
                        issueridentifier = int(message[2:10],16)
                        cert_expiry = message[10:14]
                        cert_serial = int(message[14:20],16)
                        hash_indicator = int(message[20:22],16)
                        PK_alg_indicator = int(message[22:24],16)
                        issuer_PK_len = int(message[24:26],16)
                        issuer_PK_exp_len = int(message[26:28],16)
                        issuer_PK_mod = message[28:]
                        if args.verbose: 
                            print("[*] issuer certificate decrypted")
                            print("Issuer Identifier:{}".format(issueridentifier))
                            print("Certificate Expiry Date:{}".format(cert_expiry))
                            print("Certificate Serial Number:{}".format(cert_serial))
                            print("Hash Indicator:{}".format(hash_indicator))
                            print("Issuer Public Key Algorithm Indicator:{}".format(PK_alg_indicator))
                            print("Issuer Public Key Length:{}".format(issuer_PK_len))
                            print("Issuer Public Key Exponent Length:{}".format(issuer_PK_exp_len))
                        if((len(issuer_PK_mod)/2) < issuer_PK_len): #Left most digits - append remainder to get the PK
                            issuer_PK_mod += ISSUER_REM
                        else:
                            issuer_PK_mod = message[28:28+issuer_PK_len]
                        print("[*] Issuer Public Key found:{}".format(issuer_PK_mod))
                        if(args.dump_keys):
                            issuerkey_mod = long(issuer_PK_mod,16)
                            issuerkey_exp = long(ISSUER_EXP,16)
                            issuerkey = RSA.construct((issuerkey_mod, issuerkey_exp)) 
                            dumpfilestring = aid + "_Issuer_PK.pem" 
                            print("[*] Dumping Issuer Key to:{}".format(dumpfilestring))
                            dumpfile = open(dumpfilestring, 'wb')
                            dumpfile.write(issuerkey.exportKey())
                            dumpfile.close() 
                    #print message 
                    #print message.decode('hex')
                #decrypt the ICC cert
                issuerkey_mod = long(issuer_PK_mod,16)
                if(args.test_keys):
                    if(rocatest.is_vulnerable(issuerkey_mod)):
                        print("**** Issuer Key is Vulnerable ****")
                    else:
                        print("Issuer Key is safe")   
                if(ICC_CERT != ""):  
                    issuerkey_exp = long(ISSUER_EXP,16)
                    issuerkey = RSA.construct((issuerkey_mod, issuerkey_exp)) 
                    decicccert = hex(issuerkey.encrypt(long(ICC_CERT,16), 32)[0]).lstrip('0x').rstrip('L')
                    if((decicccert[0:2] == "6a") & (decicccert[-2:] == "bc")):
                        #cert is valid
                        message = decicccert[2:-42]
                        applicationPAN = message[2:22]
                        icc_cert_expiry = message[22:26]
                        icc_cert_serial = int(message[26:32],16)
                        icc_hash_indicator = int(message[32:34],16)
                        icc_PK_alg_indicator = int(message[34:36],16)
                        icc_PK_len = int(message[36:38],16)
                        icc_PK_exp_len = int(message[38:40],16)
                        icc_PK_mod = message[40:]
                        if args.verbose: 
                            print("[*] ICC certificate decrypted")
                            print("Application PAN:{}".format(applicationPAN))
                            print("ICC Expiry Date:{}".format(icc_cert_expiry))
                            print("Certificate Serial Number:{}".format(icc_cert_serial))
                            print("Hash Indicator:{}".format(icc_hash_indicator))
                            print("ICC Public Key Algorithm Indicator:{}".format(icc_PK_alg_indicator))
                            print("ICC Public Key Length:{}".format(icc_PK_len))
                            print("ICC Public Key Exponent Length:{}".format(icc_PK_exp_len))
                        if((len(icc_PK_mod)/2) < icc_PK_len): #Left most digits - append remainder to get the PK
                            icc_PK_mod += ICC_REM
                        else:
                            icc_PK_mod = message[40:40+(icc_PK_len*2)]
                        print("[*] ICC Public Key found:{}".format(icc_PK_mod))
                        icckey_mod = long(icc_PK_mod,16)
                        icckey_exp = long(ICC_EXP,16)
                        if(args.test_keys):
                            if(rocatest.is_vulnerable(icckey_mod)):
                                print("**** ICC Key is Vulnerable ****")
                            else:
                                print("ICC Key is safe")
                        if(args.dump_keys):
                            icckey = RSA.construct((icckey_mod, icckey_exp)) 
                            dumpfilestring = aid + "_ICC_PK.pem" 
                            dumpfile = open(dumpfilestring, "wb")
                            print("[*] Dumping ICC Key to:{}".format(dumpfilestring))
                            dumpfile.write(icckey.exportKey())
                            dumpfile.close() 
 
        #print cakey.decrypt( 
        #find possible AIDs
        #else loop though list of AIDs....
 
        #rr1 = readRECORD(connection,1,1)
        #print toHexString(rr1) 
        ##fci_result = sendSELECT(connection, MASTERCARD_AID) # this will give us the FCI
        #fci_result = sendSELECT(connection, MASTERCARD_AID) # this will give us the FCI
        #print tlv.parse(toHexString(fci_result).replace(" ",""))
        #print decoded_pse
        #print "#read record" 
        #rr1 = readRECORD(connection,1,1)
        #print toHexString(rr1)
        #print "#select the NAB_EFT" 
        #fci_result = sendSELECT(connection, NAB_EFT_AID) # this will give us the FCI
        #print toHexString(fci_result) 
        #print "#READ RECORD" 
         
        #fci_result = sendSELECT(connection, MASTERCARD_AID) # this will give us the FCI
        #print toHexString(fci_result)
        #rr1 = readRECORD(connection,2,1)
        #print toHexString(rr1)
        #loop thr
    except NoCardException:
        print(reader, 'no card inserted')
