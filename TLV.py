#!/usr/bin/env python

import binascii
from collections import OrderedDict

#known_tags = ['82', '8A', '95', '9A', '9F10', '9F26', '9F36', '9F37', '9F1A']

emv_tags = {
    '9F01': 'Acquirer Identifier',
    '9F02': 'Amount, Authorised (Numeric)',
    '9F03': 'Amount, Other (Numeric)',
    '9F04': 'Amount, Other (Binary)',
    '9F05': 'Application Discretionary Data',
    '9F06': 'Application Identifier (AID) - terminal',
    '9F07': 'Application Usage Control',
    '9F08': 'Application Version Number',
    '9F09': 'Application Version Number',
    '9F0B': 'Cardholder Name Extended',
    'BF0C': 'FCI Issuer Discretionary Data',
    '9F0D': 'Issuer Action Code - Default',
    '9F0E': 'Issuer Action Code - Denial',
    '9F0F': 'Issuer Action Code - Online',
    '9F10': 'Issuer Application Data',
    '9F11': 'Issuer Code Table Index',
    '9F12': 'Application Preferred Name',
    '9F13': 'Last Online Application Transaction Counter (ATC) Register',
    '9F14': 'Lower Consecutive Offline Limit',
    '9F15': 'Merchant Category Code',
    '9F16': 'Merchant Identifier',
    '9F17': 'Personal Identification Number (PIN) Try Counter',
    '9F18': 'Issuer Script Identifier',
    '9F1A': 'Terminal Country Code',
    '9F1B': 'Terminal Floor Limit',
    '9F1C': 'Terminal Identification',
    '9F1D': 'Terminal Risk Management Data',
    '9F1E': 'Interface Device (IFD) Serial Number',
    '9F1F': 'Track 1 Discretionary Data',
    '5F20': 'Cardholder Name',
    '9F21': 'Transaction Time',
    '9F22': 'Certification Authority Public Key Index',
    '9F23': 'Upper Consecutive Offline Limit',
    '5F24': 'Application Expiration Date',
    '5F25': 'Application Effective Date',
    '9F26': 'Application Cryptogram',
    '9F27': 'Cryptogram Information Data',
    '5F28': 'Issuer Country Code',
    '5F2A': 'Transaction Currency Code',
    '5F2D': 'Language Preference',
    '9F2E': 'Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent',
    '9F2F': 'Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder',
    '5F30': 'Service Code',
    '9F32': 'Issuer Public Key Exponent',
    '9F33': 'Terminal Capabilities',
    '5F34': 'Application Primary Account Number (PAN)',
    '9F35': 'Terminal Type',
    '5F36': 'Transaction Currency Exponent',
    '9F37': 'Unpredictable Number',
    '9F38': 'Processing Options Data Object List (PDOL)',
    '9F34': 'Cardholder Verification Method (CVM) Results',
    '9F3A': 'Amount, Reference Currency',
    '9F3B': 'Application Reference Currency',
    '9F3C': 'Transaction Reference Currency Code',
    '9F3D': 'Transaction Reference Currency Exponent',
    '9F40': 'Additional Terminal Capabilities',
    '9F41': 'Transaction Sequence Counter',
    '42': 'Issuer Identification Number (IIN)',
    '9F43': 'Application Reference Currency Exponent',
    '9F44': 'Application Currency Exponent',
    '9F2D': 'Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate',
    '9F46': 'Integrated Circuit Card (ICC) Public Key Certificate',
    '9F47': 'Integrated Circuit Card (ICC) Public Key Exponent',
    '9F48': 'Integrated Circuit Card (ICC) Public Key Remainder',
    '9F49': 'Dynamic Data Authentication Data Object List (DDOL)',
    '9F4A': 'Static Data Authentication Tag List',
    '9F4B': 'Signed Dynamic Application Data',
    '9F4C': 'ICC Dynamic Number',
    '9F4D': 'Log Entry',
    '9F4E': 'Merchant Name and Location',
    '4F': 'Application Identifier (AID)',
    '50': 'Application Label',
    '9F51': 'Application Currency Code',
    '9F52': 'Card Verification Results (CVR)',
    '5F53': 'International Bank Account Number (IBAN)',
    '5F54': 'Bank Identifier Code (BIC)',
    '5F55': 'Issuer Country Code (alpha2 format)',
    '5F56': 'Issuer Country Code (alpha3 format)',
    '57': 'Track 2 Equivalent Data',
    '9F58': 'Lower Consecutive Offline Limit (Card Check)',
    '9F59': 'Upper Consecutive Offline Limit (Card Check)',
    '5A': 'Application Primary Account Number (PAN)',
    '9F5C': 'Cumulative Total Transaction Amount Upper Limit',
    '9F72': 'Consecutive Transaction Limit (International - Country)',
    '61': 'Application Template',
    '9F65': 'Track 2 Bit Map for CVC3',
    '9F66': 'Track 2 Bit Map for UN and ATC',
    '9F68': 'Mag Stripe CVM List',
    '9F69': 'Unpredictable Number Data Object List (UDOL)',
    '9F6B': 'Track 2 Data',
    '9F6C': 'Mag Stripe Application Version Number (Card)',
    '9F6E': 'Unknown Tag',
    '6F': 'File Control Information (FCI) Template',
    '70': 'EMV Proprietary Template',
    '71': 'Issuer Script Template 1',
    '72': 'Issuer Script Template 2',
    '73': 'Directory Discretionary Template',
    '9F74': 'VLP Issuer Authorization Code',
    '9F75': 'Cumulative Total Transaction Amount Limit - Dual Currency',
    '9F76': 'Secondary Application Currency Code',
    '77': 'Response Message Template Format 2',
    '9F7D': 'Unknown Tag',
    '9F7F': 'Card Production Life Cycle (CPLC) History File Identifiers',
    '80': 'Response Message Template Format 1',
    '81': 'Amount, Authorised (Binary)',
    '82': 'Application Interchange Profile',
    '83': 'Command Template',
    '84': 'Dedicated File (DF) Name',
    '86': 'Issuer Script Command',
    '87': 'Application Priority Indicator',
    '88': 'Short File Identifier (SFI)',
    '89': 'Authorisation Code',
    '8A': 'Authorisation Response Code',
    '8C': 'Card Risk Management Data Object List 1 (CDOL1)',
    '8D': 'Card Risk Management Data Object List 2 (CDOL2)',
    '8E': 'Cardholder Verification Method (CVM) List',
    '8F': 'Certification Authority Public Key Index',
    '90': 'Issuer Public Key Certificate',
    '91': 'Issuer Authentication Data',
    '92': 'Issuer Public Key Remainder',
    '93': 'Signed Static Application Data',
    '94': 'Application File Locator (AFL)',
    '95': 'Terminal Verification Results',
    '97': 'Transaction Certificate Data Object List (TDOL)',
    '98': 'Transaction Certificate (TC) Hash Value',
    '99': 'Transaction Personal Identification Number (PIN) Data',
    '9A': 'Transaction Date',
    '9B': 'Transaction Status Information',
    '9C': 'Transaction Type',
    '9D': 'Directory Definition File (DDF) Name',
    '9F45': 'Data Authentication Code',
    'A5': 'File Control Information (FCI) Proprietary Template',
    '9F57': 'Issuer Country Code',
    '9F39': 'Point-of-Service (POS) Entry Mode',
    '9F73': 'Currency Conversion Factor',
    '9F42': 'Application Currency Code',
    '9F56': 'Issuer Authentication Indicator',
    '9F20': 'Track 2 Discretionary Data',
    'DF01': 'Reference PIN',
    '9F36': 'Application Transaction Counter (ATC)',
    '9F4F': 'Log Format',
    '5F50': 'Issuer URL',
    '9F5A': 'Issuer URL2',
    '9F53': 'Consecutive Transaction Limit (International)',
    '9F54': 'Cumulative Total Transaction Amount Limit',
    '9F55': 'Geographic Indicator'
}


def hexify(number):
    """
    Convert integer to hex string representation, e.g. 12 to '0C'
    """
    if number < 0:
        raise ValueError('Invalid number to hexify - must be positive')

    result = hex(int(number)).replace('0x', '').upper()
    if divmod(len(result), 2)[1] == 1:
        # Padding
        result = '0{}'.format(result)
    return result


class TLV:

    def __init__(self, tags=None):
        self.tags = {}

        if tags:
            if type(tags) == list:
                for tag in tags:
                    self.tags[tag] = tag
            elif type(tags) == dict:
                self.tags = tags
            else:
                print('Invalid tags dictionary given - use list of tags or dict as {tag: tag_name}')
        else:
            self.tags = emv_tags

        self.tlv_string = ''
        
        self.tag_lengths = set()
        for tag, tag_name in self.tags.items():
            self.tag_lengths.add(len(tag))

    def decodeTag(self, tlv_string):
        """properly decode the TLV tag 
        see EMV BOOK 3 Annex B for details"""
        tag = 0 
        tag_length = 0
        tag_value = 0
        
        #encode received tag as a int list
        tlv_list = map(ord,list(tlv_string.decode('hex')))
        counter = 0 
        #grab 1st byte and test
        if((tlv_list[0] & 0x1f) < 0x1f):
            tag = tlv_list[counter]
            counter += 1
        else : 
            tag = tlv_list[counter]
            counter += 1
            if((tlv_list[counter] & 0x80) != 0x80):
                tag = (tag << 8) | tlv_list[counter]
                counter += 1
            else: 
                while((tlv_list[counter] & 0x80) == 0x80): #test high bit
                    tag = (tag << 8) | tlv_list[counter]
                    counter += 1
        #now decode the length
        if(tlv_list[counter] & 0x80): #test b8 if true
            #get how many bytes long length value is
            num_bytes = tlv_list[counter] & 0x7F
            last_val = counter + num_bytes #point to the last value of length
            if(num_bytes == 1): 
                tag_length = tlv_list[last_val]
            else:
                while last_val != counter:
                    tag_length += tlv_list[last_val] << 8
                    last_val = last_val - 1 
            counter += num_bytes 
        else: #length is only 1 byte
            tag_length = tlv_list[counter]
        counter +=1
        total_len = counter+tag_length
        tag_value = tlv_list[counter:total_len]
        return dict(tag=tag, length=tag_length, value=tag_value, total_len=total_len)
  
    def parse(self, tlv_string):
        """
        """
        parsed_data = OrderedDict()
        i=0
        while i < len(tlv_string):
            self.tlv_string = tlv_string
            decoded_tlv = self.decodeTag(tlv_string[i:])
            decoded_tag = "{:X}".format(decoded_tlv['tag']) 
            parsed_data[decoded_tag] = binascii.hexlify(bytearray(decoded_tlv['value'])) 
            i += decoded_tlv['total_len'] * 2
        #i = 0
        #while i < len(self.tlv_string): 
        #    tag_found = False
        #    for tag_length in self.tag_lengths:
        #        for tag, tag_name in self.tags.items():
        #            if self.tlv_string[i:i+tag_length] == tag:
        #                try:
        #                    value_length = int(self.tlv_string[i+tag_length:i+tag_length+2], 16)
        #                except ValueError:
        #                    raise ValueError('Parse error: tag ' + tag + ' has incorrect data length')

        #                value_start_position = i+tag_length+2
        #                value_end_position = i+tag_length+2+value_length*2

        #                if value_end_position > len(self.tlv_string):
        #                    raise ValueError('Parse error: tag ' + tag + ' declared data of length ' + str(value_length) + ', but actual data length is ' + str(int(len(self.tlv_string[value_start_position-1:-1])/2)))

        #                value = self.tlv_string[value_start_position:value_end_position]
        #                parsed_data[tag] = value

        #                i = value_end_position
        #                tag_found = True
        #    if not tag_found:
        #        msg = 'Unknown tag found: ' + self.tlv_string[i:i+10]
        #        raise ValueError(msg)
        return parsed_data


    def build(self, data_dict):
        """
        """
        self.tlv_string = ''
        for tag, value in data_dict.items():
            if not value:
                return self.tlv_string

            if divmod(len(value), 2)[1] == 1:
                raise ValueError('Invalid value length - the length must be even')

            self.tlv_string = self.tlv_string + tag.upper() + hexify(len(value) / 2) + value.upper()

        return self.tlv_string

             
    def _parse_tvr(self, tvr, left_indent='', desc_column_width=48):
        """
        Parse terminal verification results
        """
        tvr_dump = ''

        tvr_bit_names = {
            1: ['RFU', 'SDA was selected', 'CDA failed', 'DDA failed', 'Card number appears on hotlist', 'ICC data missing', 'SDA failed', 'Offline data processing was not performed'],
            2: ['RFU', 'RFU', 'RFU', 'New card', 'Requested service not allowed for card product', 'Application not yet effective', 'Expired application', 'Card and terminal have different application versions'],
            3: ['RFU', 'RFU', 'On-line PIN entered', 'PIN entry required, PIN pad present, but PIN was not entered', 'PIN entry required, but no PIN pad present or not working', 'PIN try limit exceeded', '   Unrecognised CVM', 'Cardholder verification was not successful'],
            4: ['RFU', 'RFU', 'RFU', 'Merchant forced transaction on-line', 'Transaction selected randomly of on-line processing', 'Upper consecutive offline limit exceeded', 'Lower consecutive offline limit exceeded', 'Transaction exceeds floor limit'],
            5: ['RFU', 'RFU', 'RFU', 'RFU', 'Script processing failed after final Generate AC', 'Script processing failed before final Generate AC', 'Issuer authentication failed', 'Default TDOL Used']
        }

        for byte in range(1, 6):
            byte_value = int(tvr[byte*2-2:byte*2], 16)
            if byte_value > 0:
                byte_value_binary = '{0:b}'.format(byte_value).rjust(8, '0')
                tvr_dump = tvr_dump + '\n' + left_indent + 'Byte {}: [{}]\n'.format(byte, byte_value_binary)
                
                for j in range(0, 8):
                    if (byte_value >> j & 1) == 1:
                        tvr_dump = tvr_dump + left_indent + tvr_bit_names[byte][j][:desc_column_width].rjust(desc_column_width, ' ') + ': [1]\n'

        return tvr_dump


    def dump(self, data_dict, left_indent='', desc_column_width=48):
        """
        Trace the parsed data from tags_dict
        """
        dump = ''
        for tag, value in data_dict.items():
            dump = dump + left_indent + '[' + tag.upper().rjust(4, ' ') + '] [' + self.tags[tag.upper()][:desc_column_width].rjust(desc_column_width, ' ') + ']:[' + value + ']\n'
            # Special tag processing:
            # TVR
            if tag == '95':
                tvr_indent = left_indent + '     '
                parsed_tvr = self._parse_tvr(value, left_indent=tvr_indent, desc_column_width=48)
                if parsed_tvr:
                    dump = dump + tvr_indent + '======================== TVR ========================\n' + parsed_tvr + tvr_indent + '=====================================================\n'

        return dump
